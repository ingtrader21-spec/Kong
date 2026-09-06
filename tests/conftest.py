import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def pytest_sessionstart(session):
    contract_path = ROOT / "config/kong-moneybee-identity-routes.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))

    assert contract["state"] == "desired-not-activated"
    assert contract["canonicalHost"] == "api.moneybeeloan.com"

    identity = contract["identity"]
    assert identity["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert identity["requiredAudience"] == "moneybee-api"
    assert identity["registrationClient"] == "moneybee-borrower"

    route = contract["routes"][0]
    assert route["path"] == "/api/v2/account/bootstrap"
    assert route["methods"] == ["POST"]
    assert route["allowedAuthorizedParties"] == ["moneybee-borrower"]
    assert route["emailVerifiedRequired"] is True
    assert route["backendMustRevalidateJwt"] is True
    assert route["rateLimitPerMinute"] <= 10
    assert route["maxBodyBytes"] <= 65536

    security = contract["security"]
    assert security["tlsRequired"] is True
    assert security["wildcardHostsAllowed"] is False
    assert security["browserPasswordTransit"] is False
    assert security["otpTransit"] is False
    assert security["keycloakAdminApiExposure"] is False
    assert security["activationRequiresReviewedRuntimeChange"] is True
