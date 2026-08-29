import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SPEC_PATH = ROOT / "config" / "kong-product-control-plane-routes.json"
RECONCILER_PATH = SCRIPTS / "reconcile_kong_product_control_plane.py"


def _load():
    scripts = str(SCRIPTS)
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location("reconcile_kong_product_control_plane", RECONCILER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_product_authority_is_oidc_original_bearer_and_prepared_disabled():
    spec = json.loads(SPEC_PATH.read_text())
    assert spec["status"] == "PREPARED_DISABLED"
    assert spec["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert spec["oidc_discovery"].endswith("/.well-known/openid-configuration")
    assert spec["jwks_uri"].endswith("/protocol/openid-connect/certs")
    assert spec["audience"] == "middleware-api"
    assert spec["preserve_authorization_header"] is True
    assert spec["token_exchange"] is False
    assert spec["safety"]["reconciliation_apply"] is False
    assert spec["safety"]["direct_provider_routes"] is False


def test_exact_product_clients_scopes_and_namespaces():
    spec = json.loads(SPEC_PATH.read_text())
    assert set(spec["clients"]) == {
        "moneybee-backend", "breero-backend", "larim-a-backend",
        "transportation-backend", "beyvra-backend", "social-codestra",
    }
    for cid in ("moneybee-backend", "breero-backend", "larim-a-backend", "transportation-backend", "beyvra-backend"):
        assert spec["clients"][cid]["command_scope"] == f"{cid.removesuffix('-backend')}.middleware.command.write"
        assert spec["clients"][cid]["command_prefixes"] == ["crm."]
        assert spec["clients"][cid]["targets"] == ["odoo-19"]
    assert spec["clients"]["social-codestra"]["command_scope"] == "social.middleware.command.write"
    assert spec["clients"]["social-codestra"]["command_prefixes"] == ["social."]
    assert spec["clients"]["social-codestra"]["targets"] == ["postly-social"]


def test_requested_negative_authorization_matrix():
    module = _load()
    spec = json.loads(SPEC_PATH.read_text())
    assert module.authorize_contract(spec, client_id="moneybee-backend", scopes={"moneybee.middleware.command.write"}, route_kind="command", command_type="crm.lead.create", target="odoo-19")
    assert not module.authorize_contract(spec, client_id="moneybee-backend", scopes={"wrong.scope"}, route_kind="command", command_type="crm.lead.create", target="odoo-19")
    assert not module.authorize_contract(spec, client_id="social-codestra", scopes={"social.middleware.command.write"}, route_kind="command", command_type="crm.lead.create", target="odoo-19")
    for cid in ("breero-backend", "transportation-backend", "larim-a-backend"):
        assert not module.authorize_contract(spec, client_id=cid, scopes={spec["clients"][cid]["command_scope"]}, route_kind="command", command_type="telephony.call.start", target="vicidial-restricted")


def test_oidc_plugin_and_guard_enforce_audience_tenant_scopes_and_body_authority():
    module = _load()
    spec = json.loads(SPEC_PATH.read_text())
    submit = spec["routes"][0]
    plugins = module.expected_plugin_configs(spec, submit)
    assert plugins["openid-connect"] == {
        "issuer": spec["oidc_discovery"],
        "auth_methods": ["bearer"],
        "audience": ["middleware-api"],
    }
    guard = plugins["post-function"]["access"][0]
    for value in ("tenant_id", "command_type", "target", "command_namespace_denied", "command_target_denied", "c.exp-c.iat>300"):
        assert value in guard
    for cid, policy in spec["clients"].items():
        assert cid in guard
        assert policy["command_scope"] in guard


def test_apply_is_fail_closed_while_prepared_disabled():
    source = RECONCILER_PATH.read_text()
    assert 'spec.get("status") not in {"APPROVED_STAGING", "APPROVED_PRODUCTION"}' in source
    assert 'spec.get("safety", {}).get("reconciliation_apply") is not True' in source
    assert 'raise RuntimeError("product control-plane authority is not approved for --apply")' in source


def test_exact_plugin_verifier_rejects_drift():
    module = _load()
    spec = json.loads(SPEC_PATH.read_text())
    route = spec["routes"][0]
    plugins = {name: {"name": name, "enabled": True, "config": config} for name, config in module.expected_plugin_configs(spec, route).items()}
    module.verify_plugins(plugins, route, spec)
    plugins["post-function"]["config"]["access"] = ["return true"]
    with pytest.raises(RuntimeError):
        module.verify_plugins(plugins, route, spec)
