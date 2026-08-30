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


def candidate(identity: str, *addresses: str):
    return {
        "container_id_sha256": identity * 64,
        "configured_image": "kong:3.14",
        "image_id": "sha256:" + identity * 64,
        "networks": ["codestra-kong"],
        "ipv4": list(addresses),
    }


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
        "--porcelain=v1",
        "docker",
        "inspect",
        "getent",
        "openssl",
        "curl",
        '"secrets_captured": False',
        '"runtime_mutations_performed": False',
        "tls_targets_exclusively_match_current_runtime",
        "validated_kong_container",
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


def test_source_sha_verification_requires_exact_clean_checkout(monkeypatch):
    collector = load_collector()

    class Result:
        def __init__(self, stdout):
            self.stdout = stdout

    responses = iter([Result("1" * 40), Result("")])
    monkeypatch.setattr(
        collector, "run", lambda *args, **kwargs: next(responses)
    )
    assert collector.verified_source_sha("1" * 40) == "1" * 40

    responses = iter([Result("1" * 40), Result("")])
    monkeypatch.setattr(
        collector, "run", lambda *args, **kwargs: next(responses)
    )
    try:
        collector.verified_source_sha("2" * 40)
    except collector.EvidenceError:
        pass
    else:
        raise AssertionError("mismatched source SHA must fail closed")

    responses = iter([Result("1" * 40), Result(" M tracked-file")])
    monkeypatch.setattr(
        collector, "run", lambda *args, **kwargs: next(responses)
    )
    try:
        collector.verified_source_sha("1" * 40)
    except collector.EvidenceError:
        pass
    else:
        raise AssertionError("modified checkout must fail closed")


def test_explicit_container_must_be_a_running_kong_gateway(monkeypatch):
    collector = load_collector()
    kong_id = "a" * 64

    kong_row = {
        "Id": kong_id,
        "Name": "/codestra-kong",
        "State": {"Running": True},
        "Config": {
            "Image": "kong:3.14",
            "Labels": {"com.docker.compose.service": "kong"},
        },
    }
    monkeypatch.setattr(collector, "inspect_one_container", lambda value: kong_row)
    assert collector.validated_kong_container("selected") == kong_id

    unrelated_row = {
        "Id": "b" * 64,
        "Name": "/redis",
        "State": {"Running": True},
        "Config": {"Image": "redis:7", "Labels": {}},
    }
    monkeypatch.setattr(
        collector, "inspect_one_container", lambda value: unrelated_row
    )
    try:
        collector.validated_kong_container("selected")
    except collector.EvidenceError:
        pass
    else:
        raise AssertionError("non-Kong container must be rejected")

    stopped_row = {
        "Id": "c" * 64,
        "Name": "/codestra-kong",
        "State": {"Running": False},
        "Config": {
            "Image": "kong:3.14",
            "Labels": {"com.docker.compose.service": "kong"},
        },
    }
    monkeypatch.setattr(collector, "inspect_one_container", lambda value: stopped_row)
    try:
        collector.validated_kong_container("selected")
    except collector.EvidenceError:
        pass
    else:
        raise AssertionError("stopped Kong container must be rejected")


def test_every_tls_target_must_exclusively_match_current_runtime():
    collector = load_collector()
    current = [candidate("a", "10.0.0.2")]
    same_runtime_alias = [candidate("a", "10.0.0.3")]
    legacy_runtime_alias = [candidate("b", "10.0.0.4")]

    assert collector.tls_targets_exclusively_match_current_runtime(
        current_ips=["10.0.0.2"],
        current_candidates=current,
        tls_ips=["10.0.0.2"],
        tls_candidates=[],
    )
    assert collector.tls_targets_exclusively_match_current_runtime(
        current_ips=["10.0.0.2"],
        current_candidates=current,
        tls_ips=["10.0.0.3"],
        tls_candidates=same_runtime_alias,
    )
    assert not collector.tls_targets_exclusively_match_current_runtime(
        current_ips=["10.0.0.2"],
        current_candidates=current,
        tls_ips=["10.0.0.3", "10.0.0.4"],
        tls_candidates=same_runtime_alias,
    )
    assert not collector.tls_targets_exclusively_match_current_runtime(
        current_ips=["10.0.0.2"],
        current_candidates=current,
        tls_ips=["10.0.0.4"],
        tls_candidates=legacy_runtime_alias,
    )
    assert not collector.tls_targets_exclusively_match_current_runtime(
        current_ips=["10.0.0.2"],
        current_candidates=current,
        tls_ips=["10.0.0.3", "10.0.0.4"],
        tls_candidates=same_runtime_alias + legacy_runtime_alias,
    )


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
