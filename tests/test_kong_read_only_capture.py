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
