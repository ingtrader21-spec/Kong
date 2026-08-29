import json
from pathlib import Path


MANIFEST = json.loads(
    Path("config/kong-canonical-middleware-routes.json").read_text()
)
PRODUCT_COMMANDS = json.loads(
    Path("config/kong-product-command-routes.json").read_text()
)
SOURCE = Path("scripts/reconcile_kong_canonical_routes.py").read_text()
PRODUCT_SOURCE = Path("scripts/reconcile_kong_product_command_routes.py").read_text()


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
        "/v1/commands",
        "/v1/operations",
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


def test_product_command_routes_preserve_registered_product_tokens():
    assert PRODUCT_COMMANDS["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert PRODUCT_COMMANDS["audience"] == "middleware-api"
    assert PRODUCT_COMMANDS["consumerHeader"] == "X-Codestra-Consumer-Id"
    assert {route["name"] for route in PRODUCT_COMMANDS["routes"]} == {
        "codestra-middleware-command-submit",
        "codestra-middleware-operation-readback",
    }
    assert {consumer["client_id"]: consumer["scope"] for consumer in PRODUCT_COMMANDS["consumers"]} == {
        "beyvra-backend": "beyvra.middleware.command.write",
        "breero-backend": "breero.middleware.command.write",
        "larim-a-backend": "larim-a.middleware.command.write",
        "moneybee-backend": "moneybee.middleware.command.write",
        "klyrow": "klyrow.middleware.command.write",
        "kyqra": "kyqra.middleware.command.write",
        "social-codestra": "social.middleware.command.write",
        "transportation-backend": "transportation.middleware.command.write",
    }
    assert "product_consumer_denied" in PRODUCT_SOURCE
    assert "kong.service.request.set_header" in PRODUCT_SOURCE
    assert PRODUCT_COMMANDS["consumerHeader"] == "X-Codestra-Consumer-Id"
    assert "tenant_ids" in PRODUCT_SOURCE


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
