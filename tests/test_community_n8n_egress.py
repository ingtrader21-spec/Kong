import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_collector():
    path = ROOT / "operations/community-n8n/collect_topology_evidence.py"
    spec = importlib.util.spec_from_file_location("community_n8n_topology", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_community_n8n_route_is_https_and_fail_closed():
    data = json.loads((ROOT / "config/kong-community-n8n-egress.v1.json").read_text())
    assert data["schema_version"] == "1.1"
    assert data["status"] == "PROPOSED_NOT_APPLIED"
    assert data["service"]["protocol"] == "https"
    assert data["service"]["port"] == 443
    assert data["service"]["tls_verify"] is True
    assert data["route"]["protocols"] == ["https"]
    assert data["route"]["methods"] == ["GET", "POST"]
    assert data["identity"]["client_id"] == "n8n-automation"
    assert data["safety"]["external_effects_enabled"] is False
    assert data["promotion_gates"]["promotion_authorized"] is False


def test_verified_current_runtime_cannot_be_replaced_by_generic_alias():
    proposed = json.loads(
        (ROOT / "config/kong-community-n8n-egress.v1.json").read_text()
    )
    production = json.loads(
        (ROOT / "config/kong-n8n-control-plane-routes.json").read_text()
    )
    current = proposed["current_runtime_authority"]
    assert current["service_host"] == "appolon-middleware-integration-api"
    assert current["ambiguous_aliases_denied"] == ["middleware-integration-api"]
    assert current["mutation_authorized"] is False
    assert production["service"]["host"] == current["service_host"]
    assert production["service"]["host"] not in current["ambiguous_aliases_denied"]


def test_topology_collector_is_read_only_and_sanitized():
    source = (
        ROOT / "operations/community-n8n/collect_topology_evidence.py"
    ).read_text()
    for required in (
        "git",
        "rev-parse",
        "docker",
        "inspect",
        "getent",
        "openssl",
        "curl",
        '"secrets_captured": False',
        '"runtime_mutations_performed": False',
    ):
        assert required in source
    for forbidden in (
        "docker network connect",
        "docker network disconnect",
        "docker restart",
        "docker stop",
        "docker rm",
        "iptables",
    ):
        assert forbidden not in source


def test_topology_helpers_reject_ip_literals_and_parse_ipv4():
    collector = load_collector()
    assert collector.valid_dns_name("middleware.internal.codestra.co")
    assert not collector.valid_dns_name("https://middleware.internal.codestra.co")
    assert not collector.valid_dns_name("10.40.0.1")
    assert not collector.valid_dns_name("middleware.invalid")
    assert collector.parse_ipv4(
        "10.0.0.2 STREAM host\n10.0.0.2 DGRAM host\ninvalid value\n10.0.0.3 RAW host\n"
    ) == ["10.0.0.2", "10.0.0.3"]
    assert len(collector.container_id_hash("container-id")) == 64


def test_source_sha_verification_fails_closed(monkeypatch):
    collector = load_collector()

    class Result:
        stdout = "1" * 40

    monkeypatch.setattr(collector, "run", lambda *args, **kwargs: Result())
    assert collector.verified_source_sha("1" * 40) == "1" * 40
    try:
        collector.verified_source_sha("2" * 40)
    except collector.EvidenceError:
        pass
    else:
        raise AssertionError("mismatched source SHA must fail closed")


def test_topology_evidence_schema_forbids_secret_and_runtime_mutation_claims():
    schema = json.loads(
        (ROOT / "operations/community-n8n/topology-evidence.schema.json").read_text()
    )
    assert schema["properties"]["secrets_captured"] == {"const": False}
    assert schema["properties"]["runtime_mutations_performed"] == {"const": False}
    required_gates = set(schema["properties"]["gates"]["required"])
    assert required_gates == {
        "source_sha_verified",
        "current_runtime_unique",
        "ambiguous_alias_not_current_runtime",
        "tls_candidate_resolves",
        "tls_candidate_same_runtime",
        "tls_certificate_verified",
        "tls_hostname_verified",
        "readiness_response_fail_closed",
        "no_runtime_mutations_performed",
    }


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
