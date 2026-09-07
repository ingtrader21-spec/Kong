#!/usr/bin/env python3
"""Private Kong Admin channel for host-side operational clients.

Admin listens on container loopback and is not published on the host, so
operational clients enter the existing verified gateway namespace instead of
reopening a management port. Requests are method- and path-checked, bounded in
time and size, carry bodies on stdin rather than argv, and never use a shell.
Docker access must already be authorized; this module grants no privileges.
"""
from __future__ import annotations

import json
import re
import subprocess

DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]
ADMIN_ORIGIN = "http://127.0.0.1:8001"
DEFAULT_CONTAINER = "codestra-kong-kong-gateway-1"
COMPOSE_SERVICE = "kong-gateway"
REQUIRED_LISTENERS = {"KONG_ADMIN_LISTEN=127.0.0.1:8001", "KONG_ADMIN_GUI_LISTEN=off"}
ADMIN_PORTS = ("8001/tcp", "8444/tcp", "8002/tcp", "8445/tcp")
METHODS = frozenset({"GET", "POST", "PATCH", "DELETE"})
SUCCESS = frozenset({200, 201, 204})
MAX_BYTES = 2 * 1024 * 1024
CONNECT_TIMEOUT = "2"
REQUEST_TIMEOUT = "10"
PROCESS_TIMEOUT = 20
CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
ADMIN_PATH = re.compile(r"/[A-Za-z0-9._~%!$&'()*+,;:@/=?-]{0,2048}\Z")
IDENTITY = re.compile(r"[0-9a-f]{64}\Z")
# Only the two listener settings are selected, never the whole environment.
INSPECT_FORMAT = (
    '{"id":{{json .Id}},"running":{{json .State.Running}},'
    '"network_mode":{{json .HostConfig.NetworkMode}},'
    '"ports":{{json .HostConfig.PortBindings}},'
    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
    '"listeners":[{{range .Config.Env}}'
    '{{if or (eq (index (split . "=") 0) "KONG_ADMIN_LISTEN") '
    '(eq (index (split . "=") 0) "KONG_ADMIN_GUI_LISTEN")}}{{json .}},{{end}}'
    '{{end}}null]}'
)

_IDENTIFIED: dict[str, str] = {}


class AdminError(RuntimeError):
    """Raised for any channel, topology, or Kong Admin failure."""


def run_json(argv: list[str]) -> dict:
    result = subprocess.run(argv, input=b"", capture_output=True,
                            timeout=PROCESS_TIMEOUT, check=False)
    if result.returncode or len(result.stdout) > MAX_BYTES:
        raise AdminError("kong gateway inspection failed")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise AdminError("invalid kong gateway metadata")
    return value


def verify_container(container: str) -> str:
    """Return the runtime ID of a running, Admin-isolated gateway container."""
    if not isinstance(container, str) or not CONTAINER_NAME.fullmatch(container):
        raise AdminError("invalid kong gateway container name")
    value = run_json(DOCKER + ["inspect", "--format", INSPECT_FORMAT, container])
    identifier = value.get("id", "")
    if not isinstance(identifier, str) or not IDENTITY.fullmatch(identifier):
        raise AdminError("invalid kong gateway identity")
    if value.get("running") is not True or value.get("service") != COMPOSE_SERVICE:
        raise AdminError("selected container is not the running kong gateway")
    mode = value.get("network_mode")
    if not isinstance(mode, str) or mode in {"host", "none"} or mode.startswith("container:"):
        raise AdminError("kong gateway shares a network namespace")
    listeners = value.get("listeners")
    if (not isinstance(listeners, list) or len(listeners) != 3
            or {item for item in listeners if isinstance(item, str)} != REQUIRED_LISTENERS
            or listeners[-1] is not None):
        raise AdminError("unapproved kong admin listener configuration")
    ports = value.get("ports") or {}
    if not isinstance(ports, dict) or any(ports.get(port) for port in ADMIN_PORTS):
        raise AdminError("kong admin is published on the host")
    return identifier


def container_identity(container: str = DEFAULT_CONTAINER) -> str:
    """Verify once per process; confirm_unchanged re-checks before reporting PASS."""
    if container not in _IDENTIFIED:
        _IDENTIFIED[container] = verify_container(container)
    return _IDENTIFIED[container]


def confirm_unchanged(container: str = DEFAULT_CONTAINER) -> str:
    """Fail if the gateway container was replaced while the operation ran."""
    previous = _IDENTIFIED.get(container)
    current = verify_container(container)
    if previous is not None and current != previous:
        raise AdminError("kong gateway container changed during the operation")
    _IDENTIFIED[container] = current
    return current


def admin_request(method: str, path: str, payload=None, container: str = DEFAULT_CONTAINER):
    """Run one bounded Admin request inside the verified gateway container."""
    if method not in METHODS:
        raise AdminError(f"unsupported Kong Admin method: {method}")
    if (not isinstance(path, str) or path.startswith("//") or ".." in path
            or not ADMIN_PATH.fullmatch(path)):
        raise AdminError("unsafe Kong Admin path")
    if payload is not None and method == "GET":
        raise AdminError(f"Kong Admin GET must not carry a body: {path}")
    identifier = container_identity(container)
    argv = DOCKER + ["exec"]
    body = None
    if payload is not None:
        body = json.dumps(payload).encode()
        if len(body) > MAX_BYTES:
            raise AdminError(f"oversized Kong Admin payload: {path}")
        # Bodies travel on stdin so they never reach argv or the process table.
        argv.append("--interactive")
    argv += [identifier, "curl", "--disable", "--noproxy", "*", "--proto", "=http",
             "--request", method, "--silent", "--show-error",
             "--connect-timeout", CONNECT_TIMEOUT, "--max-time", REQUEST_TIMEOUT,
             "--max-filesize", str(MAX_BYTES), "--write-out", "\n%{http_code}"]
    if body is not None:
        argv += ["--header", "Content-Type: application/json", "--data-binary", "@-"]
    argv.append(ADMIN_ORIGIN + path)
    result = subprocess.run(argv, input=body or b"", capture_output=True,
                            timeout=PROCESS_TIMEOUT, check=False)
    if result.returncode or len(result.stdout) > MAX_BYTES:
        raise AdminError(f"Kong Admin {method} {path}: private channel transport failure")
    raw, separator, status = result.stdout.rpartition(b"\n")
    if not separator or not re.fullmatch(rb"[0-9]{3}", status):
        raise AdminError(f"Kong Admin {method} {path}: unreadable response")
    code = int(status)
    if code not in SUCCESS:
        # Redirects are neither followed nor accepted; only 2xx replies proceed.
        raise AdminError(f"Kong Admin {method} {path}: {code} {raw.decode(errors='replace')[:500]}")
    if code == 204 or not raw.strip():
        return None
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise AdminError(f"Kong Admin {method} {path}: unexpected response shape")
    return value
