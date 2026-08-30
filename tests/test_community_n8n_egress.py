import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_community_n8n_route_is_https_and_fail_closed():
    data = json.loads((ROOT / "config/kong-community-n8n-egress.v1.json").read_text())
    assert data["status"] == "PROPOSED_NOT_APPLIED"
    assert data["service"]["protocol"] == "https"
    assert data["service"]["port"] == 443
    assert data["service"]["tls_verify"] is True
    assert data["route"]["protocols"] == ["https"]
    assert data["route"]["methods"] == ["GET", "POST"]
    assert data["safety"]["external_effects_enabled"] is False


def test_firewall_rejects_default_routes_and_has_rollback():
    source = (ROOT / "operations/community-n8n/enforce-docker-egress.sh").read_text()
    assert "n.prefixlen != 0" in source
    assert "n.version == 4" in source
    assert "iptables -D DOCKER-USER" in source
    assert "iptables -X" in source
    assert "no active Kong source addresses detected" in source
    assert "--ctstate ESTABLISHED,RELATED" in source
    assert 'codestra.egress.scope=kong' in source
    assert '-i "$interface" -j REJECT' in source
