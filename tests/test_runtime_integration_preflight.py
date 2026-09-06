import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify_runtime_integration.py"


def module():
    spec = importlib.util.spec_from_file_location("runtime_preflight", SCRIPT)
    assert spec and spec.loader
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def fixture(networks, healthy=True):
    return {
        "State": {"Running": True, "Health": {"Status": "healthy" if healthy else "unhealthy"}},
        "NetworkSettings": {"Networks": {name: {} for name in networks}},
    }


def test_helpers_require_running_healthy_container_and_exact_networks():
    preflight = module()
    container = fixture(["codestra_edge", "codestra_backend"])
    assert preflight.healthy(container)
    assert preflight.networks(container) == {"codestra_edge", "codestra_backend"}
    assert not preflight.healthy(fixture(["codestra_edge"], healthy=False))


def test_compose_places_kong_on_redis_backend():
    source = (ROOT / "deploy/kong/compose.kong.yaml").read_text()
    assert "codestra_backend: {}" in source
    assert "name: codestra_backend" in source


def test_script_never_reads_or_prints_container_environment():
    source = SCRIPT.read_text()
    assert 'Config"]["Env' not in source
    assert "docker exec" not in source
    assert "password" not in source.lower()


def test_each_hop_requires_its_designated_network():
    source = SCRIPT.read_text()
    assert '("caddy", "kong", "codestra_edge")' in source
    assert '("kong", "redis", "codestra_backend")' in source
    assert "required_network in networks" in source
