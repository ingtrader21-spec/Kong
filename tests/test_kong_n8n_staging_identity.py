from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_PATH = ROOT / "config/kong-n8n-control-plane-routes.json"
STAGING_PATH = ROOT / "config/staging/kong-n8n-control-plane-routes.json"
RECONCILER_PATH = ROOT / "scripts/reconcile_kong_n8n_control_plane.py"


def load_reconciler():
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location(
        "reconcile_kong_n8n_control_plane_staging",
        RECONCILER_PATH,
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_staging_manifest_is_prepared_but_not_apply_authorized():
    staging = load(STAGING_PATH)
    assert staging["environment"] == "staging"
    assert staging["status"] == "PREPARED_STAGING_NO_RUNTIME_APPLY"
    assert staging["safety"]["reconciliation_apply"] is False
    assert staging["production_authority"] == "config/kong-n8n-control-plane-routes.json"
    assert staging["issuer"] == "https://auth-staging.codestra.co/realms/codestra"
    assert staging["oidc_discovery"] == staging["issuer"] + "/.well-known/openid-configuration"
    assert staging["jwks_uri"] == staging["issuer"] + "/protocol/openid-connect/certs"
    serialized = STAGING_PATH.read_text(encoding="utf-8")
    assert "https://auth.codestra.co/" not in serialized
    assert "auth-staging.codestra.co" in serialized
    assert staging["safety"]["production_identity_allowed"] is False
    assert staging["safety"]["application_mutations_authorized_by_reconciliation"] is False
    assert staging["safety"]["provider_effects_authorized"] is False


def test_staging_keeps_exact_production_route_and_service_contract():
    production = load(PRODUCTION_PATH)
    staging = load(STAGING_PATH)
    for key in (
        "schema_version",
        "service",
        "consumer",
        "audience",
        "client_id",
        "host",
        "preserve_authorization_header",
        "token_exchange",
        "routes",
        "legacy_contract_items",
    ):
        assert staging[key] == production[key]
    for key in (
        "credentials_in_repository",
        "direct_provider_routes",
        "middleware_revalidates_identity",
        "oidc_required",
        "oidc_enforcement",
        "legacy_jwt_validation_retained",
    ):
        assert staging["safety"][key] == production["safety"][key]


def test_staging_claim_guards_embed_only_the_staging_issuer():
    reconciler = load_reconciler()
    staging = load(STAGING_PATH)
    for route in staging["routes"]:
        guard = reconciler.claim_guard(staging, route)
        assert staging["issuer"] in guard
        assert "https://auth.codestra.co/realms/codestra" not in guard
        assert staging["audience"] in guard
        assert staging["client_id"] in guard
        assert route["scope"] in guard
        assert "X-Tenant-ID" in guard
        assert "c.exp-c.iat>300" in guard
        expected = reconciler.expected_plugin_configs(staging, route)
        assert "jwt" in expected
        assert "post-function" in expected
        assert "openid-connect" not in expected


def test_existing_reconciler_refuses_unbound_staging_authority_for_apply():
    source = RECONCILER_PATH.read_text(encoding="utf-8")
    assert 'spec.get("status") not in {"APPROVED_STAGING", "APPROVED_PRODUCTION"}' in source
    staging = load(STAGING_PATH)
    assert staging["status"] not in {"APPROVED_STAGING", "APPROVED_PRODUCTION"}
    assert staging["safety"]["reconciliation_apply"] is False
    assert staging["preserve_authorization_header"] is True
    assert staging["token_exchange"] is False
    assert staging["safety"]["middleware_revalidates_identity"] is True


def test_staging_read_route_matches_caddy_runtime_proof():
    staging = load(STAGING_PATH)
    route = next(item for item in staging["routes"] if item["name"] == "codestra-n8n-command-read")
    probe = "/v1/integrations/n8n/operations/00000000-0000-0000-0000-000000000000"
    assert route["method"] == "GET"
    assert route["scope"] == "middleware.status.read"
    assert probe.startswith(route["path"] + "/")
