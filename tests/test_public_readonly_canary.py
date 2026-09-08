import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANARY = json.loads(
    (ROOT / "config/kong-public-readonly-canary.v1.json").read_text(encoding="utf-8")
)
INVENTORY = json.loads(
    (ROOT / "config/kong-production-route-inventory.v2.json").read_text(encoding="utf-8")
)


def test_canary_is_source_only_and_exactly_read_only():
    assert CANARY["status"] == "SOURCE_ONLY_NOT_ACTIVATED"
    assert CANARY["runtimeApplyAuthorized"] is False
    assert CANARY["host"] == "api.codestra.co"
    assert {item["path"] for item in CANARY["routes"]} == {
        "/healthz",
        "/readyz",
        "/version",
    }
    for route in CANARY["routes"]:
        assert route["methods"] == ["GET", "HEAD"]
        assert route["upstreamAuthority"] == "websocket-gateway"
        assert route["kongRoute"] is None


def test_canary_excludes_effect_admin_and_callback_families():
    excluded = set(CANARY["excludedPathPrefixes"])
    for prefix in (
        "/api/v1/admin",
        "/api/v1/automation",
        "/api/v1/control",
        "/api/v1/integrations/n8n",
        "/api/v1/mail",
        "/api/v1/results",
        "/metrics",
        "/debug",
        "/v1/admin",
        "/v1/crm",
        "/v1/email",
        "/v1/integrations/n8n",
        "/v1/sms",
        "/v1/webhooks",
    ):
        assert prefix in excluded
    assert set(CANARY["writeMethodsDeniedAtEdge"]) == {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }


def test_no_existing_kong_route_is_misrepresented_as_canary():
    canary_paths = {item["path"] for item in CANARY["routes"]}
    public_routes = [
        route
        for route in INVENTORY["routes"]
        if "api.codestra.co" in route.get("hosts", [])
    ]
    assert public_routes
    for route in public_routes:
        assert canary_paths.isdisjoint(route.get("paths", []))
    assert CANARY["existingInternalWriteRoutesPreserved"] is True
