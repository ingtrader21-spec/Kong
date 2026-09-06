import json
import importlib.util
import subprocess
import sys
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
    assert "post-function" in route["requiredPlugins"]
    assert "pre-function" not in route["requiredPlugins"]
    assert route["openidConnect"] == {
        "authMethods": ["bearer"],
        "issuerDiscovery": "https://auth.codestra.co/realms/codestra/.well-known/openid-configuration",
        "audience": ["moneybee-api"],
        "consumerClaim": ["azp"],
    }
    assert route["claimEnforcement"] == {
        "hook": "post-function",
        "source": "deploy/kong/moneybee-identity-policy.lua",
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


def test_moneybee_contract_renders_to_executable_fail_closed_kong_config():
    path = ROOT / "scripts/render_kong_moneybee_identity.py"
    spec = importlib.util.spec_from_file_location("moneybee_renderer", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    document = module.render()
    service = document["services"][0]
    assert service["routes"][0]["paths"] == ["/api/v2/account/bootstrap"]
    plugins = {item["name"]: item for item in service["plugins"]}
    assert "post-function" in plugins and "pre-function" not in plugins
    assert plugins["openid-connect"]["config"]["cache_tokens_salt"] == "{vault://env/kong-oidc-cache-tokens-salt}"
    assert plugins["rate-limiting"]["config"]["policy"] == "redis"
    assert plugins["rate-limiting"]["config"]["fault_tolerant"] is False
    assert "email_verified" in plugins["post-function"]["config"]["access"][0]
    result = subprocess.run([sys.executable, str(path), "--apply"], capture_output=True, text=True)
    assert result.returncode != 0
    assert "runtime apply is not authorized" in result.stderr
