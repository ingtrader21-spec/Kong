from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/validate_kong_calling_policy.py"
SPEC = importlib.util.spec_from_file_location("calling_policy_validator", MODULE_PATH)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

RENDERER_PATH = ROOT / "scripts/render_kong_calling_routes.py"
RENDERER_SPEC = importlib.util.spec_from_file_location("calling_policy_renderer", RENDERER_PATH)
assert RENDERER_SPEC and RENDERER_SPEC.loader
renderer = importlib.util.module_from_spec(RENDERER_SPEC)
RENDERER_SPEC.loader.exec_module(renderer)


def load_policy() -> dict:
    value = validator.parse_json(ROOT / "config/kong-calling-routes.v1.json")
    assert isinstance(value, dict)
    return value


def test_complete_calling_policy_passes() -> None:
    validator.validate_files()


def test_canonical_route_surface_is_exact() -> None:
    policy = load_policy()
    routes = {item["name"]: item for item in policy["routes"]}
    assert set(routes) == set(validator.EXPECTED_ROUTES)
    assert routes["codestra-calling-command-submit"]["path"] == "/v1/telephony/commands"
    assert routes["codestra-calling-operation-read"]["methods"] == ["GET"]
    assert routes["codestra-calling-operation-cancel"]["requiredScope"] == "telephony:command"
    assert routes["codestra-calling-operation-reconcile"]["requiredScope"] == "telephony:status"
    assert routes["codestra-realtime-session-create"]["path"] == "/api/v1/realtime/sessions"
    assert all(route["path"] != "/ws/agent" for route in routes.values())
    assert all(not route["path"].startswith("/internal") for route in routes.values())


def test_identity_tenant_campaign_and_header_policy_is_fail_closed() -> None:
    policy = load_policy()
    identity = policy["identity"]
    assert identity["issuer"].startswith("https://auth.codestra.co/realms/codestra/")
    assert identity["audience"] == "middleware-api"
    assert identity["tenantClaim"] == "tenant_id"
    assert identity["campaignMembershipClaim"] == "campaign_ids"
    assert set(identity["stripInboundHeaders"]) == {
        "X-Authenticated-Client",
        "X-Authenticated-Subject",
        "X-Authenticated-Tenant",
        "X-Authenticated-Campaign",
        "X-Authenticated-Role",
    }
    assert policy["commonPolicy"]["correlationRequired"] is True
    assert policy["commonPolicy"]["rateLimitPolicy"] == "redis"
    assert policy["commonPolicy"]["rateLimitFaultTolerant"] is False
    assert policy["runtimeApplyAuthorized"] is False


def test_websocket_and_private_boundaries_are_explicit() -> None:
    policy = load_policy()
    assert policy["websocket"] == {
        "path": "/ws/agent",
        "decision": "BYPASS_KONG_DIRECT_CADDY_TO_WEBSOCKET_GATEWAY",
        "kongRouteForbidden": True,
    }
    assert policy["privateBoundary"]["publicKongRouteForbidden"] is True
    assert policy["privateBoundary"]["prefixes"] == ["/internal", "/internal/"]


def test_lua_guard_contains_all_scope_and_isolation_controls() -> None:
    source = (ROOT / "deploy/kong/calling-policy.lua").read_text(encoding="utf-8")
    for marker in (
        "telephony:command",
        "telephony:status",
        "realtime:session:create",
        "cross_tenant_denied",
        "campaign_membership_required",
        "Idempotency-Key",
        "X-Correlation-ID",
        "X-Authenticated-Tenant",
        "X-Authenticated-Campaign",
        "/ws/agent",
        "^/internal/?",
    ):
        assert marker in source


def test_duplicate_json_keys_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate JSON field"):
        json.loads(
            '{"external_effects_enabled":true,"external_effects_enabled":false}',
            object_pairs_hook=validator.reject_duplicate_pairs,
        )


def test_negative_policy_self_test() -> None:
    validator.self_test()


def test_calling_policy_renders_as_executable_kong_configuration() -> None:
    policy = load_policy()
    document = renderer.render()
    assert document["_format_version"] == "3.0"
    assert len(document["services"]) == 1
    service = document["services"][0]
    assert service["name"] == policy["service"]["name"]
    assert service["host"] == policy["service"]["host"]
    assert service["enabled"] is True

    routes = {route["name"]: route for route in service["routes"]}
    assert set(routes) == set(validator.EXPECTED_ROUTES)
    for source in policy["routes"]:
        rendered = routes[source["name"]]
        assert rendered["hosts"] == [policy["host"]]
        assert rendered["paths"] == [source["path"]]
        assert rendered["methods"] == source["methods"]
        rate = rendered["plugins"][0]
        assert rate["name"] == "rate-limiting"
        assert rate["config"]["minute"] == source["ratePerMinute"]
        assert rate["config"]["policy"] == "redis"
        assert rate["config"]["fault_tolerant"] is False

    plugins = {plugin["name"]: plugin for plugin in service["plugins"]}
    assert set(plugins) == {
        "openid-connect",
        "post-function",
        "correlation-id",
        "request-size-limiting",
    }
    assert plugins["openid-connect"]["config"]["audience"] == ["middleware-api"]
    assert plugins["openid-connect"]["config"]["cache_tokens_salt"] == "{vault://env/kong-oidc-cache-tokens-salt}"
    assert plugins["post-function"]["config"]["access"] == [
        (ROOT / "deploy/kong/calling-policy.lua").read_text(encoding="utf-8")
    ]


def test_renderer_refuses_runtime_apply() -> None:
    result = subprocess.run(
        [sys.executable, str(RENDERER_PATH), "--apply"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "runtime apply is not authorized" in result.stderr
