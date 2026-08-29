import json
from pathlib import Path


MANIFEST = json.loads(
    Path("config/kong-canonical-middleware-routes.json").read_text()
)
SOURCE = Path("scripts/reconcile_kong_canonical_routes.py").read_text()


def test_only_proven_middleware_routes_are_managed_public_routes():
    assert {route["path"] for route in MANIFEST["routes"]} == {
        "/v1/crm",
        "/v1/email",
        "/v1/sms",
        "/v1/webhooks",
        "/v1/sms/dlr/telnexa",
    }
    assert MANIFEST["legacyHostEnabled"] is False


def test_authenticated_middleware_contract_routes_are_canonical():
    routes = {route["name"]: route for route in MANIFEST["contractRoutes"]}
    assert {path for route in routes.values() for path in route["paths"]} == {
        "/api/v1/callbacks",
        "/api/v1/control/callbacks",
        "/api/v1/automation/policy-check",
        "/api/v1/integrations/n8n/results",
        "/v1/intake/leads",
    }
    for route in routes.values():
        assert route["hosts"] == ["api.codestra.co"]
        assert route["serviceHost"] == "codestra-middleware-integration-api-1"
        assert route["servicePort"] == 8095
        assert route["securityAuthority"].startswith("config/kong-")
        assert {
            "jwt",
            "correlation-id",
            "rate-limiting",
            "request-size-limiting",
        } <= set(route["requiredPlugins"])
        assert {"pre-function", "post-function"} & set(route["requiredPlugins"])

    intake = routes["codestra-intake-leads"]
    assert intake["methods"] == ["POST"]
    assert intake["securityAuthority"] == "config/kong-intake-routes.json"
    assert "openid-connect" in intake["requiredPlugins"]
    assert "request-termination" in intake["requiredPlugins"]


def test_every_managed_route_has_explicit_security_controls():
    for route in MANIFEST["routes"]:
        assert route["methods"]
        assert route["auth"] == "key-auth"
        assert route["maxBodyMb"] > 0
        assert route["ratePerMinute"] > 0


def test_unverified_existing_routes_are_not_approval_authority():
    assert MANIFEST["unverifiedExistingRouteNames"]
    assert "allowedExistingRouteNames" not in MANIFEST
    assert "name-only public routes require exact source contracts" in SOURCE


def test_reconciler_is_dry_run_by_default_and_fail_closed():
    assert 'parser.add_argument("--apply", action="store_true")' in SOURCE
    assert "expected exactly one managed route" in SOURCE
    assert "required auth plugin absent" in SOURCE
    assert "unsafe Kong pagination URL" in SOURCE
    assert "unexpected_public" in SOURCE
    assert "legacy public host remains enabled" in SOURCE
