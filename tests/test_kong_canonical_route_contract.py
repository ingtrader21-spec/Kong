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
INTAKE_AUTHORITY = json.loads(Path("config/kong-intake-routes.json").read_text())


def test_only_proven_middleware_routes_are_managed_public_routes():
    assert MANIFEST["runtimeApplyAuthorized"] is False
    assert "runtime apply is not authorized by the reviewed manifest" in SOURCE
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
        "~/api/v1/integrations/n8n/results/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "~/api/v1/integrations/odoo/campaigns/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "~/api/v1/integrations/odoo/campaigns/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/desired-state$",
        "/v1/integrations/n8n/commands",
        "/v1/integrations/n8n/operations",
        "/v1/intake/leads",
        "/v1/intake/surveys/responses",
    }
    for name, route in routes.items():
        assert route["hosts"] == ["api.codestra.co"]
        if name.startswith("codestra-n8n-command-"):
            assert route["serviceHost"] == "appolon-middleware-integration-api"
            assert route["servicePort"] == 8080
        elif name.startswith("codestra-intake-"):
            assert route["serviceHost"] == "codestra-middleware-integration-api-1"
            assert route["servicePort"] == 8095
        assert route["securityAuthority"].startswith("config/kong-")
        assert {
            "jwt",
            "correlation-id",
            "rate-limiting",
            "request-size-limiting",
        } <= set(route["requiredPlugins"])
        assert "post-function" in route["requiredPlugins"]
        assert "pre-function" not in route["requiredPlugins"]

    for name in ("codestra-intake-leads", "codestra-intake-survey-responses"):
        route = routes[name]
        assert route["methods"] == ["POST"]
        assert route["securityAuthority"] == "config/kong-intake-routes.json"
        assert "openid-connect" in route["requiredPlugins"]
        assert "request-termination" in route["requiredPlugins"]


def test_intake_authority_is_service_only_and_fail_closed():
    routes = {route["name"]: route for route in INTAKE_AUTHORITY["routes"]}
    assert INTAKE_AUTHORITY["host"] == "api.codestra.co"
    assert INTAKE_AUTHORITY["service"]["host"] == "codestra-middleware-integration-api-1"
    assert INTAKE_AUTHORITY["service"]["port"] == 8095
    assert routes["codestra-intake-leads"]["requiredClientId"] == "sdk-intake"
    assert routes["codestra-intake-leads"]["requiredScope"] == "leads.write"
    assert routes["codestra-intake-survey-responses"]["requiredScope"] == "surveys.write"
    for route in routes.values():
        assert set(route["requiredHeaders"]) == {
            "Authorization",
            "X-Tenant-ID",
            "X-Correlation-ID",
            "Idempotency-Key",
        }
        assert route["maxBodyMb"] == 1
        assert route["ratePerMinute"] > 0
    assert INTAKE_AUTHORITY["security"]["browserTokensForbidden"] is True
    assert INTAKE_AUTHORITY["security"]["sameOriginBffRequired"] is True
    assert INTAKE_AUTHORITY["security"]["directOdooRoutingForbidden"] is True
    assert INTAKE_AUTHORITY["activation"]["runtimeApplyAuthorized"] is False


def test_n8n_control_plane_preserves_identity_for_middleware_revalidation():
    assert N8N_AUTHORITY["status"] == "APPROVED_PRODUCTION"
    assert N8N_AUTHORITY["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert N8N_AUTHORITY["audience"] == "middleware-api"
    assert N8N_AUTHORITY["client_id"] == "n8n-automation"
    assert N8N_AUTHORITY["preserve_authorization_header"] is True
    assert N8N_AUTHORITY["token_exchange"] is False
    assert N8N_AUTHORITY["service"]["host"] == "appolon-middleware-integration-api"
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
