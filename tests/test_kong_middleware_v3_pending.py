"""The prepared Middleware V3 kernel routes stay disabled until the V3 contract is frozen.

The file config/kong-middleware-v3-command-routes.v1.json is source-only preparation:
it must keep V3_PENDING_FINAL_MIDDLEWARE_CONTRACT=true, never authorise runtime apply,
bind only the canonical middleware-integration-api:8095 upstream, keep business
authorization out of Kong, and require Idempotency-Key on every command. Each of
those properties is enforced fail-closed by the foundation loader, and this module
proves both directions: the committed file loads, and every weakening is rejected.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
V3_PATH = ROOT / "config/kong-middleware-v3-command-routes.v1.json"
FOUNDATION_PATH = ROOT / "config/kong-gateway-foundation.v1.json"
ACCESS_POLICY_PATH = ROOT / "config/kong-access-policy.v1.json"
VENDORED_CONTRACT_PATH = ROOT / "config/middleware-public-api-route-contract.v1.json"
VALIDATOR_PATH = ROOT / "scripts/validate_kong_foundation.py"

EXPECTED_ROUTES = {
    "middleware-v3-submit-command": ("POST", "/platform/v1/commands", "platform.command"),
    "middleware-v3-describe-kernel": ("GET", "/platform/v1/kernel/describe", "platform.command.read"),
    "middleware-v3-read-operation": ("GET", "/platform/v1/operations/{operation_id}", "platform.command.read"),
    "middleware-v3-cancel-operation": ("POST", "/platform/v1/operations/{operation_id}/cancel", "platform.command"),
    "middleware-v3-replay-operation": ("POST", "/platform/v1/operations/{operation_id}/replay", "platform.command.replay"),
    "middleware-v3-read-operation-timeline": ("GET", "/platform/v1/operations/{operation_id}/timeline", "platform.command.read"),
}


def _load_validator():
    spec = importlib.util.spec_from_file_location("kong_foundation_validator_v3_pending", VALIDATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve string annotations through sys.modules
    spec.loader.exec_module(module)
    return module


def _contract() -> dict:
    return json.loads(V3_PATH.read_text(encoding="utf-8"))


def test_pending_v3_contract_declares_exactly_the_six_kernel_operations():
    contract = _contract()
    assert contract["status"] == "V3_PENDING_FINAL_MIDDLEWARE_CONTRACT"
    assert contract["V3_PENDING_FINAL_MIDDLEWARE_CONTRACT"] is True
    assert contract["runtimeApplyAuthorized"] is False
    assert contract["activation"]["runtimeApplyAuthorized"] is False
    assert "BLOCKED_ON_MIDDLEWARE_V3_FINAL_SHA" in contract["activation"]["prerequisites"]
    assert (contract["service"]["host"], contract["service"]["port"]) == ("middleware-integration-api", 8095)
    assert contract["service"]["retries"] == 0
    assert contract["security"]["businessAuthorizationInKong"] is False
    assert contract["commonPolicy"]["gatewayRetriesNonIdempotentPosts"] is False
    found = {r["name"]: (" ".join(r["methods"]), r["path"], r["requiredScope"]) for r in contract["routes"]}
    assert found == EXPECTED_ROUTES
    for route in contract["routes"]:
        assert route["idempotencyRequired"] is ("POST" in route["methods"])
    assert set(contract["identity"]["preservedClientHeaders"]) == {
        "Authorization", "X-Correlation-ID", "Idempotency-Key", "traceparent", "tracestate",
    }
    assert "X-Authenticated-Client" in contract["identity"]["stripInboundHeaders"]


def test_pending_v3_routes_are_not_yet_in_the_vendored_middleware_contract():
    """Activation is impossible until Middleware freezes the V3 contract: none of the
    six operations exists in the vendored copy Kong is pinned to today."""
    vendored = json.loads(VENDORED_CONTRACT_PATH.read_text(encoding="utf-8"))
    vendored_keys = {(r["method"], r["path"]) for r in vendored["routes"]}
    for method, path, _scope in EXPECTED_ROUTES.values():
        assert (method, path) not in vendored_keys


def test_pending_v3_routes_are_registered_prepared_disabled():
    foundation = json.loads(FOUNDATION_PATH.read_text(encoding="utf-8"))
    policy = json.loads(ACCESS_POLICY_PATH.read_text(encoding="utf-8"))
    routes = {r["routeId"]: r for r in foundation["routes"]}
    policies = {r["routeId"]: r for r in policy["routes"]}
    service = next(s for s in foundation["services"] if s["serviceId"] == "middleware-v3-command-api")
    assert service["upstream"] == {"protocol": "http", "host": "middleware-integration-api", "port": 8095}
    assert service["lifecycle"] == "PREPARED_DISABLED"
    assert service["bindings"] == [{"source": "config/kong-middleware-v3-command-routes.v1.json", "service": "middleware-v3-command-api", "role": "DESIRED"}]
    assert service["retryProfile"] == "NONE"
    for route_id, (_method, _path, scope) in EXPECTED_ROUTES.items():
        entry = routes[route_id]
        assert entry["lifecycle"] == "PREPARED_DISABLED" and entry["activation"] == "PREPARED_DISABLED"
        assert entry["serviceId"] == "middleware-v3-command-api"
        assert entry["requiredScopes"] == [scope]
        row = policies[route_id]
        assert row["accessClass"] == "SERVICE_AUTHENTICATED"
        assert row["authorizedParties"] == "consumer-mapped"
        assert row["identityPropagation"] == "OIDC_STRIP_AND_CONTRACT_METADATA"
        assert any("BLOCKED_ON_MIDDLEWARE_V3_FINAL_SHA" in item for item in row["activationPrerequisites"])


def test_committed_pending_v3_contract_loads_through_the_foundation():
    validator = _load_validator()
    document = validator.load_middleware_v3_command_contract(str(V3_PATH.relative_to(ROOT)), _contract())
    assert set(document.routes) == set(EXPECTED_ROUTES)
    for route in document.routes.values():
        assert (route.upstream_host, route.upstream_port) == ("middleware-integration-api", 8095)
        assert route.audience == "middleware-api"


@pytest.mark.parametrize(
    "mutate, reason",
    [
        (lambda d: d.__setitem__("status", "SOURCE_CANDIDATE_NO_RUNTIME_APPLY"), "status flipped away from pending"),
        (lambda d: d.__setitem__("V3_PENDING_FINAL_MIDDLEWARE_CONTRACT", False), "pending flag cleared"),
        (lambda d: d.__setitem__("runtimeApplyAuthorized", True), "runtime apply authorised"),
        (lambda d: d["activation"].__setitem__("runtimeApplyAuthorized", True), "activation runtime apply authorised"),
        (lambda d: d["service"].__setitem__("port", 8080), "retired 8080 upstream"),
        (lambda d: d["service"].__setitem__("host", "appolon-middleware-integration-api"), "retired upstream alias"),
        (lambda d: d["security"].__setitem__("businessAuthorizationInKong", True), "business authorization moved into Kong"),
        (lambda d: d["routes"][0].__setitem__("idempotencyRequired", False), "command without Idempotency-Key"),
    ],
)
def test_weakened_pending_v3_contract_is_rejected(mutate, reason):
    validator = _load_validator()
    document = copy.deepcopy(_contract())
    mutate(document)
    with pytest.raises(validator.FoundationError):
        validator.load_middleware_v3_command_contract("config/kong-middleware-v3-command-routes.v1.json", document)
