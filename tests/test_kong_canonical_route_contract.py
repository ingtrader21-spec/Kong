import json
from pathlib import Path


MANIFEST = json.loads(
    Path("config/kong-canonical-middleware-routes.json").read_text()
)
SOURCE = Path("scripts/reconcile_kong_canonical_routes.py").read_text()
N8N_AUTHORITY = json.loads(
    Path("config/kong-n8n-control-plane-routes.json").read_text()
)
PLATFORM_CONTRACT = json.loads(
    Path("contracts/platform-control-plane.v1.json").read_text()
)


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
        "/v1/integrations/n8n/commands",
        "/v1/integrations/n8n/operations",
    }
    for name, route in routes.items():
        assert route["hosts"] == ["api.codestra.co"]
        if name.startswith("codestra-n8n-command-"):
            assert route["serviceHost"] == "middleware-integration-api"
            assert route["servicePort"] == 8080
        assert route["securityAuthority"].startswith("config/kong-")
        assert {
            "jwt",
            "correlation-id",
            "rate-limiting",
            "request-size-limiting",
        } <= set(route["requiredPlugins"])
        assert {"pre-function", "post-function"} & set(route["requiredPlugins"])


def test_n8n_control_plane_preserves_identity_for_middleware_revalidation():
    assert N8N_AUTHORITY["status"] == "APPROVED_PRODUCTION"
    assert N8N_AUTHORITY["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert N8N_AUTHORITY["audience"] == "middleware-api"
    assert N8N_AUTHORITY["client_id"] == "n8n-automation"
    assert N8N_AUTHORITY["preserve_authorization_header"] is True
    assert N8N_AUTHORITY["token_exchange"] is False
    assert N8N_AUTHORITY["service"]["host"] == "middleware-integration-api"
    assert N8N_AUTHORITY["service"]["port"] == 8080
    routes = {route["name"]: route for route in N8N_AUTHORITY["routes"]}
    assert routes["codestra-n8n-command-submit"]["scope"] == "middleware.request.forward"
    assert routes["codestra-n8n-command-read"]["scope"] == "middleware.status.read"
    assert N8N_AUTHORITY["safety"]["direct_provider_routes"] is False
    assert N8N_AUTHORITY["safety"]["reconciliation_apply"] is True
    assert PLATFORM_CONTRACT["status"] == "APPROVED_PRODUCTION"
    assert PLATFORM_CONTRACT["safety"]["deployment_permitted_by_contract"] is True
    canonical = {route["name"]: route for route in MANIFEST["contractRoutes"]}
    for name in ("codestra-n8n-command-submit", "codestra-n8n-command-read"):
        assert "openid-connect" not in canonical[name]["requiredPlugins"]
        assert {"jwt", "post-function"} <= set(canonical[name]["requiredPlugins"])


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
