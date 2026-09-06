import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads((ROOT / "config/kong-moneybee-identity-routes.json").read_text())


def test_moneybee_identity_edge_is_fail_closed():
    assert CONTRACT["state"] == "desired-not-activated"
    assert CONTRACT["canonicalHost"] == "api.moneybeeloan.com"
    assert CONTRACT["identity"] == {
        "issuer": "https://auth.codestra.co/realms/codestra",
        "jwksUri": "https://auth.codestra.co/realms/codestra/protocol/openid-connect/certs",
        "requiredAudience": "moneybee-api",
        "registrationClient": "moneybee-borrower",
    }
    route = CONTRACT["routes"][0]
    assert route["path"] == "/api/v2/account/bootstrap"
    assert route["methods"] == ["POST"]
    assert route["allowedAuthorizedParties"] == ["moneybee-borrower"]
    assert route["emailVerifiedRequired"] is True
    assert route["backendMustRevalidateJwt"] is True
    assert route["rateLimitPerMinute"] <= 10
    assert route["maxBodyBytes"] <= 65536
    assert "openid-connect" in route["requiredPlugins"]
    assert "pre-function" in route["requiredPlugins"]
    assert route["openidConnect"] == {
        "authMethods": ["bearer"],
        "issuerDiscovery": "https://auth.codestra.co/realms/codestra/.well-known/openid-configuration",
        "audience": ["moneybee-api"],
        "consumerClaim": ["azp"],
    }
    assert route["claimEnforcement"] == {
        "hook": "pre-function",
        "failClosed": True,
        "requireExactIssuer": True,
        "requireAudience": "moneybee-api",
        "requireAuthorizedParty": "moneybee-borrower",
        "requireEmailVerified": True,
        "denyMissingRequiredClaims": True,
    }

    security = CONTRACT["security"]
    assert security["tlsRequired"] is True
    assert security["wildcardHostsAllowed"] is False
    assert security["browserPasswordTransit"] is False
    assert security["otpTransit"] is False
    assert security["keycloakAdminApiExposure"] is False
    assert security["activationRequiresReviewedRuntimeChange"] is True

    prohibited = " ".join(CONTRACT["prohibitedPublicPaths"])
    assert "/admin/realms" in prohibited
    assert "/identity/otp" in prohibited
    assert "/identity/password" in prohibited
