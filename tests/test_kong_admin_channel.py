"""The private Admin channel that replaces the removed host Admin publication."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
HOST_ADMIN = "http://127.0.0.1:8001"
STANDBY_CLIENTS = ("scripts/apply_kong_standby.py", "scripts/rollback_kong_standby.py")
REHEARSAL = "operations/kong-database/kong-database-restore-rehearsal.sh"
# Naming the container-loopback origin is only safe inside the channel itself and
# in clients that reach it exclusively through the channel.
CHANNEL_MEDIATED = {"scripts/kong_admin_channel.py", REHEARSAL}


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def module():
    return load(ROOT / "scripts/kong_admin_channel.py", "kong_admin_channel")


def metadata():
    return {"id": "a" * 64, "running": True, "network_mode": "codestra_edge", "ports": {},
            "service": "kong-gateway", "listeners": [
                "KONG_ADMIN_LISTEN=127.0.0.1:8001", "KONG_ADMIN_GUI_LISTEN=off", None]}


def stubbed(channel, monkeypatch, stdout=b'{"data": []}\n200', returncode=0):
    calls = []
    monkeypatch.setattr(channel, "verify_container", lambda container: "a" * 64)

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=b"")

    monkeypatch.setattr(channel.subprocess, "run", run)
    return calls


def test_standby_clients_reach_admin_only_through_the_private_channel():
    for name in STANDBY_CLIENTS:
        source = (ROOT / name).read_text()
        assert HOST_ADMIN not in source, f"{name} still dials a host Admin endpoint"
        assert "from kong_admin_channel import" in source
        assert "admin_request(" in source and "confirm_unchanged()" in source


def test_restore_rehearsal_reads_live_admin_inside_the_gateway_container():
    value = (ROOT / REHEARSAL).read_text()
    assert "verify_live_gateway" in value
    assert 'live_channel="container:$live_gateway_container"' in value
    for collection in ("services", "routes", "plugins"):
        assert f'kong_inventory "$live_channel" {HOST_ADMIN} {collection}' in value
        # The isolated restore gateway keeps its own private-network endpoint.
        assert f'kong_inventory direct "http://$restore_ip:8001" {collection}' in value
    assert 'page="$(kong_admin_get "$channel" "$next")"' in value
    assert 'curl -fsS "$next"' not in value


def test_no_other_operational_client_assumes_a_published_host_admin_port():
    sources = list((ROOT / "scripts").rglob("*.py")) + list((ROOT / "operations").rglob("*.sh"))
    offenders = sorted(path.relative_to(ROOT).as_posix() for path in sources
                       if HOST_ADMIN in path.read_text()
                       and path.relative_to(ROOT).as_posix() not in CHANNEL_MEDIATED)
    assert offenders == []


def test_channel_and_read_only_capture_require_the_same_admin_contract():
    channel = module()
    capture = load(ROOT / "tools/capture_kong_server_baseline.py", "capture")
    assert channel.INSPECT_FORMAT == capture.INSPECT_FORMAT
    assert channel.DOCKER == capture.DOCKER
    assert channel.ADMIN_ORIGIN == HOST_ADMIN
    assert channel.ADMIN_PORTS == ("8001/tcp", "8444/tcp", "8002/tcp", "8445/tcp")
    environment = yaml.safe_load((ROOT / "deploy/kong/compose.kong.yaml").read_text())[
        "services"]["kong-gateway"]["environment"]
    assert channel.REQUIRED_LISTENERS == {
        f"KONG_ADMIN_LISTEN={environment['KONG_ADMIN_LISTEN']}",
        f"KONG_ADMIN_GUI_LISTEN={environment['KONG_ADMIN_GUI_LISTEN']}"}


@pytest.mark.parametrize("change", [
    {"running": False}, {"network_mode": "host"}, {"network_mode": "none"},
    {"network_mode": "container:other"}, {"service": "middleware"}, {"id": "--privileged"},
    {"ports": {"8001/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8001"}]}},
    {"ports": {"8444/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8444"}]}},
    {"listeners": ["KONG_ADMIN_LISTEN=0.0.0.0:8001", "KONG_ADMIN_GUI_LISTEN=off", None]},
    {"listeners": ["KONG_ADMIN_LISTEN=127.0.0.1:8001", None]},
    {"listeners": ["KONG_ADMIN_LISTEN=127.0.0.1:8001", "KONG_ADMIN_LISTEN=0.0.0.0:8001",
                   "KONG_ADMIN_GUI_LISTEN=off", None]},
])
def test_unapproved_gateway_topology_fails_closed(monkeypatch, change):
    channel = module()
    info = metadata()
    info.update(change)
    monkeypatch.setattr(channel, "run_json", lambda argv: info)
    with pytest.raises(channel.AdminError):
        channel.verify_container("codestra-kong-kong-gateway-1")


def test_requests_run_inside_the_container_on_the_local_daemon(monkeypatch):
    channel = module()
    calls = stubbed(channel, monkeypatch)
    assert channel.admin_request("GET", "/routes?size=1000") == {"data": []}
    argv, kwargs = calls[0]
    assert argv[:3] == ["docker", "--host", "unix:///var/run/docker.sock"]
    assert argv[3:6] == ["exec", "a" * 64, "curl"]
    assert argv[argv.index("--request") + 1] == "GET"
    assert argv[-1] == HOST_ADMIN + "/routes?size=1000"
    assert "--location" not in argv and "--privileged" not in argv
    assert "--noproxy" in argv and "--max-filesize" in argv
    assert "--interactive" not in argv
    assert not kwargs.get("shell")
    assert kwargs["timeout"] == channel.PROCESS_TIMEOUT


def test_write_payloads_travel_on_stdin_not_argv(monkeypatch):
    channel = module()
    calls = stubbed(channel, monkeypatch, stdout=b'{"id": "created"}\n201')
    payload = {"name": "standby", "tags": ["codestra-kong-standby-20260820"]}
    assert channel.admin_request("POST", "/services", payload) == {"id": "created"}
    argv, kwargs = calls[0]
    assert "--interactive" in argv
    assert argv[argv.index("--data-binary") + 1] == "@-"
    assert kwargs["input"] == json.dumps(payload).encode()
    assert not any("standby" in item for item in argv)


@pytest.mark.parametrize("method", ["PUT", "OPTIONS", "HEAD", "get", "POST;rm"])
def test_unsupported_methods_are_refused(method):
    channel = module()
    with pytest.raises(channel.AdminError):
        channel.admin_request(method, "/services")


@pytest.mark.parametrize("path", [
    "services", "//evil.invalid/services", "/routes/../consumers",
    "http://evil.invalid/services", "/routes\n/x", "/routes?tags=a b", "/" + "a" * 4096])
def test_unsafe_admin_paths_are_refused(path):
    channel = module()
    with pytest.raises(channel.AdminError):
        channel.admin_request("GET", path)


def test_get_must_not_carry_a_body():
    channel = module()
    with pytest.raises(channel.AdminError):
        channel.admin_request("GET", "/services", {"name": "x"})


@pytest.mark.parametrize("status", [b"301", b"302", b"400", b"409", b"500"])
def test_non_success_status_raises_with_bounded_detail(monkeypatch, status):
    channel = module()
    stubbed(channel, monkeypatch, stdout=b"x" * 4000 + b"\n" + status)
    with pytest.raises(channel.AdminError) as error:
        channel.admin_request("PATCH", "/services/abc", {"name": "x"})
    assert status.decode() in str(error.value)
    assert len(str(error.value)) < 700


def test_delete_accepts_no_content(monkeypatch):
    channel = module()
    stubbed(channel, monkeypatch, stdout=b"\n204")
    assert channel.admin_request("DELETE", "/services/abc") is None


@pytest.mark.parametrize("stdout,returncode", [
    (b'{"data": []}\n200', 7), (b"{}", 0), (b"{}\nnot-a-status", 0), (b'"text"\n200', 0)])
def test_transport_and_response_failures_fail_closed(monkeypatch, stdout, returncode):
    channel = module()
    stubbed(channel, monkeypatch, stdout=stdout, returncode=returncode)
    with pytest.raises(channel.AdminError):
        channel.admin_request("GET", "/status")


def test_oversized_replies_fail_closed(monkeypatch):
    channel = module()
    stubbed(channel, monkeypatch, stdout=b"x" * (channel.MAX_BYTES + 1) + b"\n200")
    with pytest.raises(channel.AdminError):
        channel.admin_request("GET", "/status")


def test_container_replacement_during_the_operation_is_detected(monkeypatch):
    channel = module()
    identities = iter(["a" * 64, "b" * 64])
    monkeypatch.setattr(channel, "verify_container", lambda container: next(identities))
    assert channel.container_identity() == "a" * 64
    with pytest.raises(channel.AdminError):
        channel.confirm_unchanged()
