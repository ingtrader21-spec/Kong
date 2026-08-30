from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "kong" / "plugins" / "oidc" / "keycloak.yml"
N8N = ROOT / "config" / "kong-n8n-control-plane-routes.json"
CONTROL_PLANE = ROOT / "deploy" / "kong" / "control-plane.yml"


def test_canonical_keycloak_oidc_contract_exists_and_is_secret_free():
    config = yaml.safe_load(PLUGIN.read_text())
    plugin = config["plugins"][0]
    assert plugin["name"] == "openid-connect"
    assert plugin["enabled"] is True
    assert plugin["config"]["issuer"] == (
        "https://auth.codestra.co/realms/codestra/.well-known/openid-configuration"
    )
    assert plugin["config"]["auth_methods"] == ["bearer"]
    assert plugin["config"]["audience"] == ["middleware-api"]
    assert plugin["config"]["consumer_claim"] == ["azp"]
    serialized = PLUGIN.read_text().lower()
    assert "client_secret" not in serialized
    assert "access_token" not in serialized


def test_existing_control_plane_already_uses_keycloak_oidc():
    config = yaml.safe_load(CONTROL_PLANE.read_text())
    service = next(item for item in config["services"] if item["name"] == "codestra-control-plane")
    plugins = {item["name"]: item for item in service["plugins"]}
    oidc = plugins["openid-connect"]["config"]
    assert oidc["issuer"] == (
        "https://auth.codestra.co/realms/codestra/.well-known/openid-configuration"
    )
    assert oidc["auth_methods"] == ["bearer"]


def test_n8n_authority_is_bound_to_same_keycloak_realm():
    spec = json.loads(N8N.read_text())
    assert spec["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert spec["oidc_discovery"] == spec["issuer"] + "/.well-known/openid-configuration"
    assert spec["jwks_uri"] == spec["issuer"] + "/protocol/openid-connect/certs"
    assert spec["audience"] == "middleware-api"
    assert spec["client_id"] == "n8n-automation"
    assert spec["safety"]["oidc_required"] is True
    assert spec["safety"]["oidc_enforcement"] == "jwt-rs256-plus-claim-guard"
    assert spec["safety"]["legacy_jwt_validation_retained"] is True
    assert spec["preserve_authorization_header"] is True
    assert spec["token_exchange"] is False


def test_only_health_is_allowed_as_an_auth_exception_in_this_contract():
    config = yaml.safe_load(CONTROL_PLANE.read_text())
    service = next(item for item in config["services"] if item["name"] == "codestra-control-plane")
    protected = [route for route in service["routes"] if route["name"] != "control-plane-health"]
    assert protected
    assert all(route["paths"] != ["/api/v1/health"] for route in protected)
