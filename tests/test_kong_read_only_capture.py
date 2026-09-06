from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_server_capture_is_loopback_get_only_and_sanitized() -> None:
    source = (ROOT / "tools/capture_kong_server_baseline.sh").read_text()
    assert "http://127.0.0.1:8001" in source
    assert 'refusing non-loopback Kong Admin URL' in source
    assert "POST" not in source and "PATCH" not in source and "DELETE" not in source
    assert "client_secret" not in source and "rsa_private_key" not in source
    assert "secretsCaptured:false" in source
    assert "runtimeMutated:false" in source


def test_compose_exposes_admin_only_on_host_loopback_for_capture() -> None:
    source = (ROOT / "deploy/kong/compose.kong.yaml").read_text()
    assert "kong-gateway:" in source
    assert 'KONG_ADMIN_LISTEN: 0.0.0.0:8001' in source
    assert '"127.0.0.1:8001:8001"' in source
    assert '"0.0.0.0:8001:8001"' not in source
