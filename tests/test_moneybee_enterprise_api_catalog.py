import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / "config/kong-moneybee-enterprise-api-catalog.json").read_text())


def _route(name: str) -> dict:
    return next(item for item in CATALOG["routeClasses"] if item["name"] == name)


def test_moneybee_enterprise_catalog_is_complete_and_fail_closed():
    assert CATALOG["state"] == "desired-not-activated"
    assert CATALOG["canonicalHost"] == "api.moneybeeloan.com"
    assert CATALOG["canonicalApiVersion"] == "v2"
    assert CATALOG["legacyApiVersion"]["deprecated"] is True
    assert CATALOG["legacyApiVersion"]["newRoutesProhibited"] is True

    names = {item["name"] for item in CATALOG["routeClasses"]}
    assert names == {
        "public-origination",
        "borrower-portal",
        "borrower-application-api",
        "lender-portal",
        "admin-control-plane",
        "finance-control-plane",
        "provider-webhooks",
        "health",
    }

    identity = CATALOG["identity"]
    assert identity["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert identity["requiredAudience"] == "moneybee-api"
    assert identity["backendMustRevalidateJwt"] is True


def test_public_origination_requires_idempotency_and_bot_protection():
    route = _route("public-origination")
    assert route["authentication"] == "public"
    assert route["idempotencyRequired"] is True
    assert route["botProtectionRequired"] is True
    assert route["maxBodyBytes"] <= 131072


def test_portal_and_finance_classes_have_distinct_identity_policies():
    borrower = _route("borrower-portal")
    lender = _route("lender-portal")
    admin = _route("admin-control-plane")
    finance = _route("finance-control-plane")

    assert borrower["allowedAuthorizedParties"] == ["moneybee-borrower"]
    assert lender["allowedAuthorizedParties"] == ["moneybee-lender"]
    assert admin["allowedAuthorizedParties"] == ["moneybee-admin"]
    assert admin["mfaRequired"] is True
    assert finance["mfaRequired"] is True
    assert finance["idempotencyRequiredForWrites"] is True
    assert "openid-connect" in borrower["plugins"]
    assert "pre-function" in admin["plugins"]


def test_webhooks_are_signature_authenticated_and_durable_before_ack():
    route = _route("provider-webhooks")
    assert route["authentication"] == "provider-signature"
    assert route["oidcProhibited"] is True
    assert route["timestampWindowRequired"] is True
    assert route["durableInboxBeforeAck"] is True
    assert route["duplicatePayloadConflictRequired"] is True


def test_global_security_prohibits_identity_secret_transit_and_caching():
    security = CATALOG["globalSecurity"]
    assert security["tlsRequired"] is True
    assert security["passwordTransit"] is False
    assert security["otpTransit"] is False
    assert security["keycloakAdminApiExposure"] is False
    assert security["cacheFinancialResponses"] is False
    assert security["cacheAuthenticationResponses"] is False
    assert security["activationRequiresReviewedRuntimeChange"] is True
