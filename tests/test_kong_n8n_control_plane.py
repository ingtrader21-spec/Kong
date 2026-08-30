import importlib.util
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SPEC_PATH = ROOT / "config" / "kong-n8n-control-plane-routes.json"
CANONICAL_PATH = ROOT / "config" / "kong-canonical-middleware-routes.json"
RECONCILER_PATH = SCRIPTS / "reconcile_kong_n8n_control_plane.py"
CANONICAL_RECONCILER_PATH = SCRIPTS / "reconcile_kong_canonical_routes.py"


def _load(path: Path, name: str):
    scripts = str(SCRIPTS)
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _plugin_set(module, spec, route):
    return {
        name: {"name": name, "enabled": True, "config": config}
        for name, config in module.expected_plugin_configs(spec, route).items()
    }


def test_admin_form_encoding_uses_lowercase_kong_booleans(monkeypatch):
    module = _load(RECONCILER_PATH, "reconcile_kong_n8n_control_plane_boolean_form")
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return b"{}"

    def fake_urlopen(request, timeout):
        captured["form"] = parse_qs(request.data.decode())
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(module, "urlopen", fake_urlopen)
    module.request("http://kong-admin", "POST", "/services", {"enabled": True, "flag": False})
    assert captured == {
        "form": {"enabled": ["true"], "flag": ["false"]},
        "timeout": 15,
    }


def test_n8n_authority_is_production_approved_and_identity_exact():
    spec = json.loads(SPEC_PATH.read_text())
    assert spec["status"] == "APPROVED_PRODUCTION"
    assert spec["safety"]["reconciliation_apply"] is True
    assert spec["client_id"] == "n8n-automation"
    assert spec["consumer"]["custom_id"] == "n8n-automation"
    assert spec["audience"] == "middleware-api"
    assert spec["preserve_authorization_header"] is True
    assert spec["token_exchange"] is False
    assert spec["safety"]["middleware_revalidates_identity"] is True
    assert spec["service"]["enabled"] is True


def test_claim_guard_covers_identity_scope_tenant_headers_and_short_token_lifetime():
    module = _load(RECONCILER_PATH, "reconcile_kong_n8n_control_plane_guard")
    spec = json.loads(SPEC_PATH.read_text())
    route = spec["routes"][0]
    guard = module.claim_guard(spec, route)
    assert spec["issuer"] in guard
    assert spec["client_id"] in guard
    assert spec["audience"] in guard
    assert route["scope"] in guard
    assert "X-Tenant-ID" in guard
    assert "tenant_ids" in guard
    assert "c.exp-c.iat>300" in guard
    for header in route["required_headers"]:
        assert header in guard


def test_exact_plugin_verifier_accepts_contract_and_rejects_scope_drift():
    module = _load(RECONCILER_PATH, "reconcile_kong_n8n_control_plane_plugins")
    spec = json.loads(SPEC_PATH.read_text())
    route = spec["routes"][0]
    plugins = _plugin_set(module, spec, route)
    assert plugins["jwt"]["config"]["hide_credentials"] is False
    module.verify_plugins(plugins, route, spec)
    plugins["post-function"]["config"]["access"] = ["return true"]
    with pytest.raises(RuntimeError):
        module.verify_plugins(plugins, route, spec)


def test_exact_plugin_verifier_rejects_authorization_header_stripping():
    module = _load(RECONCILER_PATH, "reconcile_kong_n8n_control_plane_bearer_preservation")
    spec = json.loads(SPEC_PATH.read_text())
    route = spec["routes"][0]
    plugins = _plugin_set(module, spec, route)
    plugins["jwt"]["config"]["hide_credentials"] = True
    with pytest.raises(RuntimeError):
        module.verify_plugins(plugins, route, spec)


def test_canonical_manifest_uses_exact_n8n_security_authority():
    canonical = json.loads(CANONICAL_PATH.read_text())
    routes = [
        route for route in canonical["contractRoutes"]
        if route["securityAuthority"] == "config/kong-n8n-control-plane-routes.json"
    ]
    assert {route["name"] for route in routes} == {
        "codestra-n8n-command-submit",
        "codestra-n8n-command-read",
    }
    for route in routes:
        assert route["hosts"] == ["api.codestra.co"]
        assert route["serviceHost"] == "appolon-middleware-integration-api"
        assert route["servicePort"] == 8080
        assert "codestra-middleware-integration-api-1" not in json.dumps(route)
        assert "post-function" in route["requiredPlugins"]
        assert "pre-function" not in route["requiredPlugins"]


def test_operations_uuid_path_matches_the_canonical_prefix_route():
    canonical = json.loads(CANONICAL_PATH.read_text())
    route = next(
        item for item in canonical["contractRoutes"]
        if item["name"] == "codestra-n8n-command-read"
    )
    sample = "/v1/integrations/n8n/operations/00000000-0000-0000-0000-000000000000"
    assert any(sample.startswith(prefix + "/") for prefix in route["paths"])


def test_n8n_authority_has_no_direct_provider_or_legacy_repository_reference():
    serialized = SPEC_PATH.read_text().lower()
    assert "codestra-srl" not in serialized
    assert "odoo" not in json.dumps(json.loads(SPEC_PATH.read_text())["service"]).lower()
    assert "vicidial" not in json.dumps(json.loads(SPEC_PATH.read_text())["service"]).lower()
    assert json.loads(SPEC_PATH.read_text())["service"]["host"] == "appolon-middleware-integration-api"
    assert json.loads(SPEC_PATH.read_text())["service"]["host"] != "middleware-integration-api"
    legacy = json.loads(SPEC_PATH.read_text())["legacy_contract_items"]
    assert legacy == [{
        "path": "/webhooks/vicidial/call-result/",
        "owner": "legacy-vicidial-ingress",
        "included_in_n8n_control_plane_gate": False,
    }]


def test_reconciler_requires_explicit_approved_status_and_apply_gate():
    source = RECONCILER_PATH.read_text()
    assert 'spec.get("status") not in {"APPROVED_STAGING", "APPROVED_PRODUCTION"}' in source
    assert 'spec.get("safety", {}).get("reconciliation_apply") is not True' in source
    assert 'raise RuntimeError("N8N control-plane authority is not approved for --apply")' in source


def test_reconciler_stages_routes_inertly_before_plugin_installation():
    source = RECONCILER_PATH.read_text()
    inert = source.index('"hosts[]": ["staged.invalid"]')
    plugins = source.index("plugin_configs = expected_plugin_configs")
    activation = source.index('request(admin, "PATCH", f"/routes/{route[\'id\']}", payload)', plugins)
    assert inert < plugins < activation


def test_reconciler_requires_middleware_identity_revalidation():
    source = RECONCILER_PATH.read_text()
    assert 'get("middleware_revalidates_identity") is not True' in source
    assert 'raise RuntimeError("Middleware identity revalidation must be explicitly required")' in source


def test_canonical_reconciler_dispatches_n8n_security_authority():
    source = CANONICAL_RECONCILER_PATH.read_text()
    assert 'kong-n8n-control-plane-routes.json' in source
    assert 'reconcile_kong_n8n_control_plane' in source
    assert 'n8n.verify_plugins' in source


def test_n8n_reconciler_requires_keycloak_openid_connect():
    module = _load(RECONCILER_PATH, "reconcile_kong_n8n_control_plane_oidc")
    spec = json.loads(SPEC_PATH.read_text())
    route = spec["routes"][0]
    expected = module.expected_plugin_configs(spec, route)
    assert expected["openid-connect"] == {
        "issuer": spec["oidc_discovery"],
        "auth_methods": ["bearer"],
        "audience": ["middleware-api"],
        "consumer_claim": ["azp"],
    }
    assert "jwt" in expected  # retained as second validation layer until staging certification
