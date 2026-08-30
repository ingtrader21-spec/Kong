import importlib.util
import json
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "config/kong-canonical-middleware-routes.json"
RECONCILER_PATH = ROOT / "scripts/reconcile_kong_canonical_routes.py"
EXPORTER_PATH = ROOT / "scripts/export_kong_public_route_contracts.py"
CONTROL_PLANE_PATH = ROOT / "deploy/kong/control-plane.yml"
SCOPE_POLICY_PATH = ROOT / "deploy/kong/scope-policy.lua"
STANDBY_APPLIER_PATH = ROOT / "scripts/apply_kong_standby.py"
CAMPAIGN_RECONCILER_PATH = ROOT / "scripts/reconcile_kong_campaign_automation.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _module():
    return _load(RECONCILER_PATH, "reconcile_kong_canonical_routes")


def _exporter():
    return _load(EXPORTER_PATH, "export_kong_public_route_contracts")


def test_standby_apply_refuses_unowned_name_collisions(monkeypatch):
    module = _load(STANDBY_APPLIER_PATH, "apply_kong_standby")
    calls = []

    def fake_request(method, path, payload=None):
        calls.append((method, path, payload))
        return {"data": [{"id": "existing", "name": "standby-service", "tags": ["production"]}]}

    monkeypatch.setattr(module, "request", fake_request)
    with pytest.raises(RuntimeError, match="refusing to adopt unowned"):
        module.upsert("services", "standby-service", {"tags": [module.TAG]})
    assert [method for method, _, _ in calls] == ["GET"]


def test_standby_apply_updates_only_resources_it_already_owns(monkeypatch):
    module = _load(STANDBY_APPLIER_PATH, "apply_kong_standby_owned")

    def fake_request(method, path, payload=None):
        if method == "GET":
            return {"data": [{"id": "owned", "tags": [module.TAG]}]}
        return {"id": "owned", **payload}

    monkeypatch.setattr(module, "request", fake_request)
    result = module.upsert("services", "standby-service", {"tags": [module.TAG]})
    assert result["id"] == "owned"


def test_campaign_reconciler_validates_manifest_consumer_identity():
    source = CAMPAIGN_RECONCILER_PATH.read_text()
    assert 'f"/consumers/{consumer[\'id\']}"' in source
    assert 'require_exact_fields(consumer, manifest["consumer"], "campaign service consumer")' in source


def _inline_scope_policy() -> str:
    document = yaml.safe_load(CONTROL_PLANE_PATH.read_text())
    plugins = document["services"][0]["plugins"]
    pre_function = next(plugin for plugin in plugins if plugin["name"] == "pre-function")
    return pre_function["config"]["access"][0].strip()


def test_public_route_manifest_disables_legacy_and_name_only_trust():
    manifest = json.loads(MANIFEST_PATH.read_text())
    assert manifest["schema"] == "codestra.kong.canonical-routes.v2"
    assert manifest["legacyHost"] == "api.codestra.agency"
    assert manifest["legacyHostEnabled"] is False
    assert "allowedExistingRouteNames" not in manifest
    assert manifest["unverifiedExistingRouteNames"]
    approved = {
        item["name"] for item in manifest["routes"] + manifest["contractRoutes"]
    }
    assert approved.isdisjoint(manifest["unverifiedExistingRouteNames"])


def test_contract_routes_bind_exact_dedicated_security_authority():
    manifest = json.loads(MANIFEST_PATH.read_text())
    for route in manifest["contractRoutes"]:
        authority = ROOT / route["securityAuthority"]
        assert authority.is_file()
        assert route["hosts"] == ["api.codestra.co"]
        if route["securityAuthority"] == "config/kong-n8n-control-plane-routes.json":
            assert route["serviceHost"] == "middleware-integration-api"
            assert route["servicePort"] == 8080
        else:
            assert route["serviceHost"] == "codestra-middleware-integration-api-1"
            assert route["servicePort"] == 8095
        assert {"jwt", "correlation-id", "rate-limiting", "request-size-limiting"} <= set(
            route["requiredPlugins"]
        )
        assert {"pre-function", "post-function"} & set(route["requiredPlugins"])


def test_callback_contract_rejects_security_plugin_config_drift():
    module = _module()
    canonical = json.loads(MANIFEST_PATH.read_text())
    expected = next(
        row for row in canonical["contractRoutes"] if row["name"] == "codestra-callback-control"
    )
    authority_path, spec, route = module.security_authority(ROOT, expected)
    callback = module.security_module(ROOT, "reconcile_kong_callback_routes")
    plugins = {
        "jwt": {
            "enabled": True,
            "config": {
                "header_names": ["authorization"],
                "uri_param_names": [],
                "cookie_names": [],
                "claims_to_verify": ["exp"],
                "key_claim_name": "azp",
                "run_on_preflight": False,
                "secret_is_base64": False,
                "anonymous": None,
            },
        },
        "pre-function": {
            "enabled": True,
            "config": {"access": [callback.claim_guard(spec, route["requiredScope"])]},
        },
        "request-size-limiting": {
            "enabled": True,
            "config": {"allowed_payload_size": route["maxBodyMb"]},
        },
        "rate-limiting": {
            "enabled": True,
            "config": {
                "minute": route["ratePerMinute"],
                "policy": "local",
                "limit_by": "ip",
            },
        },
        "correlation-id": {
            "enabled": True,
            "config": {
                "header_name": "X-Correlation-ID",
                "generator": "uuid",
                "echo_downstream": True,
            },
        },
    }
    module.verify_security_plugins(ROOT, authority_path, spec, route, plugins, expected)
    plugins["jwt"]["config"]["key_claim_name"] = "sub"
    with pytest.raises(RuntimeError, match="jwt_key_claim"):
        module.verify_security_plugins(ROOT, authority_path, spec, route, plugins, expected)


def test_campaign_contract_rejects_scope_guard_drift():
    module = _module()
    canonical = json.loads(MANIFEST_PATH.read_text())
    expected = next(
        row for row in canonical["contractRoutes"] if row["name"] == "codestra-campaign-policy-check"
    )
    authority_path, spec, route = module.security_authority(ROOT, expected)
    campaign = module.security_module(ROOT, "reconcile_kong_campaign_automation")
    plugins = {
        "jwt": {
            "enabled": True,
            "config": {
                "key_claim_name": "azp",
                "claims_to_verify": ["exp"],
                "header_names": ["authorization"],
                "run_on_preflight": True,
            },
        },
        "post-function": {
            "enabled": True,
            "config": {"access": [campaign.claim_guard(spec, route["scope"])]},
        },
        "request-size-limiting": {
            "enabled": True,
            "config": {"allowed_payload_size": route["max_body_mb"]},
        },
        "rate-limiting": {
            "enabled": True,
            "config": {
                "minute": route["rate_per_minute"],
                "policy": "local",
                "limit_by": "consumer",
            },
        },
        "correlation-id": {
            "enabled": True,
            "config": {
                "header_name": "X-Correlation-ID",
                "generator": "uuid",
                "echo_downstream": True,
            },
        },
    }
    module.verify_security_plugins(ROOT, authority_path, spec, route, plugins, expected)
    plugins["post-function"]["config"]["access"] = ["return true"]
    with pytest.raises(RuntimeError, match="claim_guard"):
        module.verify_security_plugins(ROOT, authority_path, spec, route, plugins, expected)


def test_reconciler_pagination_cannot_leave_the_selected_admin_origin():
    module = _module()
    assert module.safe_next("http://127.0.0.1:8001", "/routes?offset=next") == (
        "http://127.0.0.1:8001/routes?offset=next"
    )
    assert module.safe_next(
        "http://127.0.0.1:8001", "http://127.0.0.1:8001/routes?offset=next"
    ) == "http://127.0.0.1:8001/routes?offset=next"
    with pytest.raises(RuntimeError, match="unsafe Kong pagination URL"):
        module.safe_next(
            "http://127.0.0.1:8001", "https://attacker.invalid/routes?offset=next"
        )


def test_reconciler_is_exact_and_never_unions_legacy_hosts():
    source = RECONCILER_PATH.read_text()
    assert "name-only public route allowlists are forbidden" in source
    assert "name-only public routes require exact source contracts" in source
    assert "unsafe Kong pagination URL" in source
    assert 'desired_hosts = [manifest["canonicalHost"]]' in source
    assert "original_hosts +" not in source
    assert "LEGACY_PUBLIC_ROUTE_NAMES" in source
    assert "duplicate enabled route plugins" in source
    assert "securityAuthority" in source
    assert "verify_security_plugins" in source
    assert "correlation-id" in source
    assert 'return "true" if value else "false"' in source


def test_read_only_route_exporter_redacts_secret_values_without_exporting_credentials():
    module = _exporter()
    source = EXPORTER_PATH.read_text()
    value = {
        "client_secret": "do-not-export",
        "nested": {"password": "do-not-export", "secret_is_base64": True},
        "key_claim_name": "azp",
        "allowed_payload_size": 2,
        "headers": [
            "Authorization: Bearer do-not-export-token",
            "X-API-Key: do-not-export-key",
            "X-Safe-Header: safe-value",
        ],
        "upstream_url": "https://user:do-not-export@example.invalid/path",
    }
    sanitized = module.sanitize(value)
    assert sanitized["client_secret"]["redacted"] is True
    assert sanitized["nested"]["password"]["redacted"] is True
    assert sanitized["nested"]["secret_is_base64"] is True
    assert sanitized["key_claim_name"] == "azp"
    assert sanitized["headers"][0]["redacted"] is True
    assert sanitized["headers"][1]["redacted"] is True
    assert sanitized["headers"][2] == "X-Safe-Header: safe-value"
    assert sanitized["upstream_url"]["redacted"] is True
    rendered = json.dumps(sanitized)
    assert "do-not-export" not in rendered
    assert "method=\"GET\"" in source
    assert "credentials_exported" in source
    assert "consumers" not in source.lower()
    assert "unsafe Kong pagination URL" in source


def test_exporter_pagination_cannot_leave_the_selected_admin_origin():
    module = _exporter()
    with pytest.raises(RuntimeError, match="unsafe Kong pagination URL"):
        module.safe_next(
            "http://127.0.0.1:8001", "http://attacker.invalid/routes?offset=next"
        )


def test_inline_and_standalone_control_plane_scope_policies_are_identical():
    assert _inline_scope_policy() == SCOPE_POLICY_PATH.read_text().strip()


def test_control_plane_scope_policy_covers_exact_admin_and_message_roots():
    policy = SCOPE_POLICY_PATH.read_text()
    assert 'path == "/v1/admin/system" or path:find("^/v1/admin/system/")' in policy
    assert 'required = "platform.admin"' in policy
    assert 'path == "/api/v1/messages" or path:find("^/api/v1/messages/")' in policy
    assert 'required = "communications.message.read"' in policy
    assert 'error="route_scope_undefined"' in policy
    assert 'path == "/api/v1/health"' in policy
    assert 'path:find("^/api/v1/events/")' in policy
    assert 'X-Authenticated-Role", "platform_admin"' in policy


def _control_plane_live_objects():
    declared = yaml.safe_load(CONTROL_PLANE_PATH.read_text())
    expected_service = declared["services"][0]
    service = {
        "id": "service-1",
        "name": expected_service["name"],
        "protocol": "http",
        "host": "codestra-control-plane",
        "port": 8096,
        "path": None,
        "enabled": expected_service["enabled"],
        "connect_timeout": 3000,
        "read_timeout": 30000,
        "write_timeout": 30000,
    }
    routes = [
        {
            "id": f"route-{index}",
            "name": route["name"],
            "hosts": route["hosts"],
            "paths": route["paths"],
            "methods": route["methods"],
            "protocols": route["protocols"],
            "strip_path": route["strip_path"],
            "preserve_host": route["preserve_host"],
            "path_handling": route["path_handling"],
            "https_redirect_status_code": route["https_redirect_status_code"],
            "request_buffering": route["request_buffering"],
            "response_buffering": route["response_buffering"],
            "regex_priority": route["regex_priority"],
            "headers": route.get("headers"),
            "snis": route.get("snis"),
            "sources": route.get("sources"),
            "destinations": route.get("destinations"),
            "service": {"id": service["id"]},
        }
        for index, route in enumerate(expected_service["routes"])
    ]
    service_plugins = [
        {"name": plugin["name"], "enabled": True, "config": plugin.get("config", {})}
        for plugin in expected_service["plugins"]
    ]
    route_plugins = {
        route["name"]: [
            {"name": plugin["name"], "enabled": True, "config": plugin.get("config", {})}
            for plugin in route.get("plugins", [])
        ]
        for route in expected_service["routes"]
    }
    return declared, service, routes, service_plugins, route_plugins


def _stub_control_plane_plugins(monkeypatch, module, service_plugins, route_plugins, routes):
    route_names = {route["id"]: route["name"] for route in routes}

    def fake_all_rows(_base, path):
        if path.startswith("/services/"):
            return service_plugins
        route_id = path.split("/")[2]
        return route_plugins[route_names[route_id]]

    monkeypatch.setattr(module, "all_rows", fake_all_rows)


def test_control_plane_verifier_accepts_exact_declarative_authority(monkeypatch):
    module = _module()
    declared, service, routes, service_plugins, route_plugins = _control_plane_live_objects()
    _stub_control_plane_plugins(monkeypatch, module, service_plugins, route_plugins, routes)
    assert module.verify_control_plane("http://admin.invalid", declared, routes, {service["id"]: service}) == {
        route["name"] for route in declared["services"][0]["routes"]
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda service, routes, plugins: service.update(protocol="https"), "service.protocol"),
        (lambda service, routes, plugins: service.update(path="/wrong"), "service.path"),
        (lambda service, routes, plugins: service.update(enabled=False), "service.enabled"),
        (lambda service, routes, plugins: service.update(read_timeout=60000), "service.read_timeout"),
        (lambda service, routes, plugins: routes[0].update(protocols=["https"]), "protocols"),
        (lambda service, routes, plugins: routes[0].update(strip_path=True), "strip_path"),
        (lambda service, routes, plugins: routes[0].update(preserve_host=True), "preserve_host"),
        (lambda service, routes, plugins: routes[0].update(path_handling="v1"), "path_handling"),
        (lambda service, routes, plugins: routes[0].update(https_redirect_status_code=308), "https_redirect"),
        (lambda service, routes, plugins: routes[0].update(request_buffering=False), "request_buffering"),
        (lambda service, routes, plugins: routes[0].update(response_buffering=False), "response_buffering"),
        (lambda service, routes, plugins: routes[0].update(regex_priority=10), "regex_priority"),
        (lambda service, routes, plugins: routes[0].update(headers={"x-drift": ["1"]}), "headers"),
        (
            lambda service, routes, plugins: plugins.append(
                {"name": "cors", "enabled": True, "config": {}}
            ),
            "service_plugins",
        ),
    ],
)
def test_control_plane_verifier_rejects_declarative_drift(monkeypatch, mutation, message):
    module = _module()
    declared, service, routes, service_plugins, route_plugins = _control_plane_live_objects()
    mutation(service, routes, service_plugins)
    _stub_control_plane_plugins(monkeypatch, module, service_plugins, route_plugins, routes)
    with pytest.raises(RuntimeError, match=message):
        module.verify_control_plane("http://admin.invalid", declared, routes, {service["id"]: service})


def test_control_plane_verifier_rejects_duplicate_and_undeclared_route_plugins(monkeypatch):
    module = _module()
    declared, service, routes, service_plugins, route_plugins = _control_plane_live_objects()
    protected = next(name for name, plugins in route_plugins.items() if plugins)
    route_plugins[protected].append(route_plugins[protected][0].copy())
    _stub_control_plane_plugins(monkeypatch, module, service_plugins, route_plugins, routes)
    with pytest.raises(RuntimeError, match="duplicate enabled route plugins"):
        module.verify_control_plane("http://admin.invalid", declared, routes, {service["id"]: service})

    route_plugins[protected] = route_plugins[protected][:1]
    unprotected = next(name for name, plugins in route_plugins.items() if not plugins)
    route_plugins[unprotected].append({"name": "cors", "enabled": True, "config": {}})
    with pytest.raises(RuntimeError, match="route_plugins"):
        module.verify_control_plane("http://admin.invalid", declared, routes, {service["id"]: service})


def test_undefined_control_plane_paths_are_denied_before_proxy_identity_headers():
    policy = SCOPE_POLICY_PATH.read_text()
    deny = policy.index('return kong.response.exit(403,{error="route_scope_undefined"})')
    identity = policy.index('kong.service.request.set_header("X-Authenticated-Client"')
    assert deny < identity
