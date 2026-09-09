#!/usr/bin/env python3
"""Fail-closed reconciliation for the canonical public Kong route surface."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
import yaml
from pathlib import Path
from urllib.parse import urlsplit

SCRIPTS = str(Path(__file__).resolve().parent)
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from kong_admin_channel import (
    PRIVATE_ADMIN_URL,
    AdminError,
    admin_request,
    collect_admin_rows,
    http_admin_request,
    http_admin_url,
    normalize_admin_reference,
    open_admin_request as urlopen,
)


def request(base: str, method: str, path: str, payload=None) -> dict:
    if base == PRIVATE_ADMIN_URL:
        return admin_request(
            method, normalize_admin_reference(path), payload, payload_encoding="form"
        ) or {}
    return http_admin_request(base, method, path, payload, opener=urlopen) or {}


def safe_next(base: str, value: str | None) -> str | None:
    if not value:
        return None
    if base == PRIVATE_ADMIN_URL:
        return normalize_admin_reference(value)
    try:
        return http_admin_url(base, value)
    except AdminError:
        raise RuntimeError("unsafe Kong pagination URL") from None


def all_rows(base: str, path: str) -> list[dict]:
    return collect_admin_rows(lambda value: request(base, "GET", value), path,
                              lambda value: safe_next(base, value))


def one(rows: list[dict], label: str) -> dict:
    if len(rows) != 1:
        raise RuntimeError(f"expected exactly one {label}")
    return rows[0]


def require_equal(actual, expected, label: str) -> None:
    if actual != expected:
        # Config values may contain resolved credentials; report the field only.
        raise RuntimeError(f"{label} drift")


def form_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def plugin_form(config: dict) -> dict:
    result = {}
    def add(prefix, value):
        if isinstance(value, dict):
            for key, item in value.items():
                add(f"{prefix}.{key}", item)
        elif isinstance(value, list):
            result[f"{prefix}[]"] = [form_value(item) for item in value]
        else:
            result[prefix] = form_value(value)
    for key, value in config.items():
        add(f"config.{key}", value)
    return result


def enabled_plugins(base: str, route_id: str) -> dict[str, dict]:
    plugins = all_rows(base, f"/routes/{route_id}/plugins?size=1000")
    grouped: dict[str, list[dict]] = {}
    for plugin in plugins:
        if plugin.get("enabled"):
            grouped.setdefault(plugin["name"], []).append(plugin)
    duplicates = sorted(name for name, values in grouped.items() if len(values) != 1)
    if duplicates:
        raise RuntimeError(f"duplicate enabled route plugins: {duplicates}")
    return {name: values[0] for name, values in grouped.items()}


def enabled_service_plugins(base: str, service_id: str) -> dict[str, dict]:
    plugins = all_rows(base, f"/services/{service_id}/plugins?size=1000")
    grouped: dict[str, list[dict]] = {}
    for plugin in plugins:
        if plugin.get("enabled"):
            grouped.setdefault(plugin["name"], []).append(plugin)
    duplicates = sorted(name for name, values in grouped.items() if len(values) != 1)
    if duplicates:
        raise RuntimeError(f"duplicate enabled service plugins: {duplicates}")
    return {name: values[0] for name, values in grouped.items()}


def require_config_subset(actual, expected, label: str) -> None:
    if isinstance(expected, dict):
        for key, value in expected.items():
            if key not in actual:
                raise RuntimeError(f"{label}: missing config key {key}")
            require_config_subset(actual[key], value, f"{label}.{key}")
    else:
        require_equal(actual, expected, label)


def verify_control_plane(admin: str, declared: dict, routes: list[dict], services: dict[str, dict]) -> set[str]:
    verified: set[str] = set()
    for expected_service in declared.get("services", []):
        service = one([item for item in services.values() if item.get("name") == expected_service["name"]], "control-plane service")
        declared_url = urlsplit(expected_service["url"])
        require_equal(service.get("protocol"), declared_url.scheme, "control-plane.service.protocol")
        require_equal(service.get("host"), declared_url.hostname, "control-plane.service.host")
        require_equal(service.get("port"), declared_url.port, "control-plane.service.port")
        declared_path = declared_url.path or None
        require_equal(service.get("path"), declared_path, "control-plane.service.path")
        require_equal(
            service.get("enabled"),
            expected_service["enabled"],
            "control-plane.service.enabled",
        )
        for field in ("connect_timeout", "read_timeout", "write_timeout"):
            require_equal(service.get(field), expected_service[field], f"control-plane.service.{field}")
        service_plugins = enabled_service_plugins(admin, service["id"])
        expected_service_plugins = {plugin["name"] for plugin in expected_service.get("plugins", [])}
        require_equal(sorted(service_plugins), sorted(expected_service_plugins), "control-plane.service_plugins")
        for plugin in expected_service.get("plugins", []):
            require_config_subset(service_plugins[plugin["name"]].get("config", {}), plugin.get("config", {}), f"control-plane.{plugin['name']}")
        for expected in expected_service.get("routes", []):
            route = one([item for item in routes if item.get("name") == expected["name"]], f"control-plane route {expected['name']}")
            for field in ("hosts", "paths", "methods", "protocols"):
                require_equal(sorted(route.get(field) or []), sorted(expected.get(field) or []), f"{expected['name']}.{field}")
            for field in (
                "strip_path",
                "preserve_host",
                "path_handling",
                "https_redirect_status_code",
                "request_buffering",
                "response_buffering",
                "regex_priority",
            ):
                require_equal(route.get(field), expected[field], f"{expected['name']}.{field}")
            for field, empty in (("headers", {}), ("snis", []), ("sources", []), ("destinations", [])):
                require_equal(route.get(field) or empty, expected.get(field) or empty, f"{expected['name']}.{field}")
            require_equal(route.get("service", {}).get("id"), service["id"], f"{expected['name']}.service")
            route_plugins = enabled_plugins(admin, route["id"])
            expected_route_plugins = {plugin["name"] for plugin in expected.get("plugins", [])}
            require_equal(sorted(route_plugins), sorted(expected_route_plugins), f"{expected['name']}.route_plugins")
            for plugin in expected.get("plugins", []):
                require_config_subset(route_plugins[plugin["name"]].get("config", {}), plugin.get("config", {}), f"{expected['name']}.{plugin['name']}")
            verified.add(expected["name"])
    return verified


def security_authority(root: Path, expected: dict) -> tuple[Path, dict, dict]:
    path = root / expected["securityAuthority"]
    manifest = json.loads(path.read_text())
    route_name = expected["name"]
    route = one(
        [item for item in manifest["routes"] if item["name"] == route_name],
        f"security authority route {route_name}",
    )
    if path.name in {"kong-callback-routes.json", "kong-intake-routes.json"}:
        require_equal(route["paths"], expected["paths"], f"{route_name}.authority.paths")
        require_equal(sorted(route["methods"]), sorted(expected["methods"]), f"{route_name}.authority.methods")
        if path.name == "kong-intake-routes.json":
            require_equal(
                route["stripPath"],
                expected["stripPath"],
                f"{route_name}.authority.stripPath",
            )
            require_equal(
                route["preserveHost"],
                expected["preserveHost"],
                f"{route_name}.authority.preserveHost",
            )
            require_equal(
                set(route["requiredPlugins"]),
                set(expected["requiredPlugins"]),
                f"{route_name}.authority.requiredPlugins",
            )
    elif path.name == "kong-campaign-automation-routes.json":
        require_equal([route["path"]], expected["paths"], f"{route_name}.authority.paths")
        require_equal(expected["methods"], ["POST"], f"{route_name}.authority.methods")
    elif path.name == "kong-n8n-control-plane-routes.json":
        require_equal([route["path"]], expected["paths"], f"{route_name}.authority.paths")
        require_equal([route["method"]], expected["methods"], f"{route_name}.authority.methods")
    else:
        raise RuntimeError(f"unsupported route security authority: {path}")
    require_equal(manifest["host"], expected["hosts"][0], f"{route_name}.authority.host")
    require_equal(manifest["service"]["host"], expected["serviceHost"], f"{route_name}.authority.serviceHost")
    require_equal(manifest["service"]["port"], expected["servicePort"], f"{route_name}.authority.servicePort")
    return path, manifest, route


def security_module(root: Path, module_name: str):
    scripts = str(root / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    return importlib.import_module(module_name)


def _verify_intake_plugins(
    manifest: dict,
    route: dict,
    plugins: dict[str, dict],
    expected: dict,
) -> None:
    require_config_subset(
        plugins["jwt"].get("config", {}),
        {
            "key_claim_name": "azp",
            "claims_to_verify": ["exp"],
            "header_names": ["authorization"],
        },
        f"{expected['name']}.jwt",
    )
    oidc = plugins["openid-connect"].get("config", {})
    require_config_subset(
        oidc,
        {"auth_methods": ["bearer"], "consumer_claim": ["azp"]},
        f"{expected['name']}.openid_connect",
    )
    issuer = str(oidc.get("issuer", ""))
    if not issuer.startswith("https://auth.codestra.co/realms/codestra"):
        raise RuntimeError(f"{expected['name']}.openid_connect.issuer drift")
    if route["requiredClientId"] not in set(oidc.get("audience") or []):
        raise RuntimeError(f"{expected['name']}.openid_connect.audience drift")
    if route["requiredScope"] not in set(oidc.get("scopes_required") or []):
        raise RuntimeError(f"{expected['name']}.openid_connect.scope drift")

    access = "\n".join(plugins["post-function"].get("config", {}).get("access") or [])
    for required_text in (
        route["requiredClientId"],
        route["requiredScope"],
        "X-Tenant-ID",
        "Idempotency-Key",
    ):
        if required_text not in access:
            raise RuntimeError(f"{expected['name']}.post_function missing {required_text}")
    require_config_subset(
        plugins["request-size-limiting"].get("config", {}),
        {"allowed_payload_size": route["maxBodyMb"]},
        f"{expected['name']}.body_limit",
    )
    require_config_subset(
        plugins["rate-limiting"].get("config", {}),
        {"minute": route["ratePerMinute"], "policy": "redis", "fault_tolerant": False,
         "redis": {"host": "codestra-redis", "port": 6379}},
        f"{expected['name']}.rate_limit",
    )
    require_config_subset(
        plugins["correlation-id"].get("config", {}),
        {
            "header_name": "X-Correlation-ID",
            "generator": "uuid",
            "echo_downstream": True,
        },
        f"{expected['name']}.correlation_id",
    )
    if not isinstance(plugins["request-termination"].get("config", {}), dict):
        raise RuntimeError(f"{expected['name']}.request_termination invalid")
    if manifest.get("activation", {}).get("runtimeApplyAuthorized") is not False:
        raise RuntimeError(f"{expected['name']}.runtime_apply_authority must remain false")


def verify_security_plugins(
    root: Path,
    authority_path: Path,
    manifest: dict,
    authority_route: dict,
    plugins: dict[str, dict],
    expected: dict,
) -> None:
    required = set(expected["requiredPlugins"])
    require_equal(set(plugins), required, f"{expected['name']}.route_plugins")
    if authority_path.name == "kong-intake-routes.json":
        _verify_intake_plugins(manifest, authority_route, plugins, expected)
        return
    if authority_path.name == "kong-callback-routes.json":
        callback = security_module(root, "reconcile_kong_callback_routes")
        callback.verify_plugins(plugins, authority_route, manifest)
        return
    if authority_path.name == "kong-n8n-control-plane-routes.json":
        n8n = security_module(root, "reconcile_kong_n8n_control_plane")
        n8n.verify_plugins(plugins, authority_route, manifest)
        return
    if authority_path.name != "kong-campaign-automation-routes.json":
        raise RuntimeError(f"unsupported route security authority: {authority_path}")

    campaign = security_module(root, "reconcile_kong_campaign_automation")
    campaign.require_plugin(
        plugins["jwt"],
        {
            "key_claim_name": "azp",
            "claims_to_verify": ["exp"],
            "header_names": ["authorization"],
            "run_on_preflight": True,
        },
        f"{expected['name']}.jwt",
    )
    campaign.require_plugin(
        plugins["post-function"],
        {"access": [campaign.claim_guard(manifest, authority_route["scope"])]},
        f"{expected['name']}.claim_guard",
    )
    campaign.require_plugin(
        plugins["request-size-limiting"],
        {"allowed_payload_size": authority_route["max_body_mb"]},
        f"{expected['name']}.body_limit",
    )
    campaign.require_plugin(
        plugins["rate-limiting"],
        {
            "minute": authority_route["rate_per_minute"],
            "policy": "redis",
            "fault_tolerant": False,
            "redis": {"host": "codestra-redis", "port": 6379},
            "limit_by": "consumer",
        },
        f"{expected['name']}.rate_limit",
    )
    campaign.require_plugin(
        plugins["correlation-id"],
        {
            "header_name": "X-Correlation-ID",
            "generator": "uuid",
            "echo_downstream": True,
        },
        f"{expected['name']}.correlation_id",
    )


def verify_contract_route(
    admin: str,
    root: Path,
    expected: dict,
    routes: list[dict],
    services: dict[str, dict],
) -> dict:
    authority_path, authority_manifest, authority_route = security_authority(root, expected)
    route = one(
        [item for item in routes if item.get("name") == expected["name"]],
        f"contract route {expected['name']}",
    )
    for field in ("hosts", "paths", "methods", "protocols"):
        require_equal(
            sorted(route.get(field) or []),
            sorted(expected[field]),
            f"{expected['name']}.{field}",
        )
    require_equal(route.get("strip_path"), expected["stripPath"], f"{expected['name']}.strip_path")
    require_equal(route.get("preserve_host"), expected["preserveHost"], f"{expected['name']}.preserve_host")
    service = services[route["service"]["id"]]
    require_equal(service.get("host"), expected["serviceHost"], f"{expected['name']}.service.host")
    require_equal(service.get("port"), expected["servicePort"], f"{expected['name']}.service.port")
    plugins = enabled_plugins(admin, route["id"])
    missing = sorted(set(expected["requiredPlugins"]) - set(plugins))
    if missing:
        raise RuntimeError(f"contract plugin drift: {expected['name']}: missing={missing}")
    verify_security_plugins(
        root,
        authority_path,
        authority_manifest,
        authority_route,
        plugins,
        expected,
    )
    return {
        "ROUTE": ";".join(expected["paths"]),
        "METHOD": ";".join(expected["methods"]),
        "CALLER": "authenticated Codestra client",
        "AUTH": "dedicated exact security authority",
        "EXPECTED_HOST": ";".join(expected["hosts"]),
        "EXPECTED_UPSTREAM": f"{expected['serviceHost']}:{expected['servicePort']}",
        "KONG_PRESENT": "PASS",
        "STATUS": "PASS",
        "SECURITY_AUTHORITY": expected["securityAuthority"],
    }


def ensure_plugin(
    admin: str,
    route_id: str,
    name: str,
    expected_config: dict,
    apply: bool,
) -> dict:
    plugins = enabled_plugins(admin, route_id)
    plugin = plugins.get(name)
    form = plugin_form(expected_config)
    if plugin is None:
        if not apply:
            raise RuntimeError(f"required route plugin absent: {name}")
        request(admin, "POST", f"/routes/{route_id}/plugins", {"name": name, **form})
        plugin = enabled_plugins(admin, route_id)[name]
    elif apply:
        request(admin, "PATCH", f"/plugins/{plugin['id']}", {"name": name, **form})
        plugin = enabled_plugins(admin, route_id)[name]
    require_config_subset(plugin.get("config", {}), expected_config, f"{name} plugin")
    return plugin


def verify_managed_route(
    admin: str,
    manifest: dict,
    expected: dict,
    routes: list[dict],
    services: dict[str, dict],
    apply: bool,
) -> dict:
    matches = [item for item in routes if item.get("name") == expected["name"]]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one managed route: {expected['name']}")
    route = matches[0]
    require_equal(sorted(route.get("paths") or []), [expected["path"]], f"{expected['name']}.paths")
    require_equal(sorted(route.get("methods") or []), sorted(expected["methods"]), f"{expected['name']}.methods")
    desired_hosts = [manifest["canonicalHost"]]
    if manifest["legacyHostEnabled"]:
        desired_hosts.append(manifest["legacyHost"])
    desired_hosts = sorted(desired_hosts)
    if apply:
        request(
            admin,
            "PATCH",
            f"/routes/{route['id']}",
            {
                "hosts[]": desired_hosts,
                "methods[]": expected["methods"],
                "paths[]": [expected["path"]],
                "https_redirect_status_code": 426,
            },
        )
        route = request(admin, "GET", f"/routes/{route['id']}")
    require_equal(sorted(route.get("hosts") or []), desired_hosts, f"{expected['name']}.hosts")
    require_equal(route.get("https_redirect_status_code"), 426, f"{expected['name']}.https_redirect")
    plugins = enabled_plugins(admin, route["id"])
    if expected["auth"] not in plugins:
        raise RuntimeError(f"required auth plugin absent: {expected['name']}")
    ensure_plugin(
        admin,
        route["id"],
        "request-size-limiting",
        {"allowed_payload_size": expected["maxBodyMb"]},
        apply,
    )
    ensure_plugin(
        admin,
        route["id"],
        "rate-limiting",
        {"minute": expected["ratePerMinute"], "policy": "redis", "limit_by": "consumer", "fault_tolerant": False,
         "redis": {"host": "codestra-redis", "port": 6379}},
        apply,
    )
    ensure_plugin(
        admin,
        route["id"],
        "correlation-id",
        {"header_name": "X-Correlation-ID", "generator": "uuid", "echo_downstream": True},
        apply,
    )
    service = services[route["service"]["id"]]
    return {
        "ROUTE": expected["path"],
        "METHOD": ";".join(expected["methods"]),
        "CALLER": "production application/provider",
        "AUTH": expected["auth"],
        "EXPECTED_HOST": manifest["canonicalHost"],
        "EXPECTED_UPSTREAM": f"{service.get('host')}:{service.get('port')}",
        "KONG_PRESENT": "PASS",
        "STATUS": "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admin-url", default=PRIVATE_ADMIN_URL)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("config/kong-canonical-middleware-routes.json"),
    )
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads(args.manifest.read_text())
    require_equal(manifest.get("schema"), "codestra.kong.canonical-routes.v2", "manifest.schema")
    if not isinstance(manifest.get("runtimeApplyAuthorized"), bool):
        raise RuntimeError("runtimeApplyAuthorized must be an explicit boolean")
    if args.apply and manifest["runtimeApplyAuthorized"] is not True:
        raise RuntimeError("runtime apply is not authorized by the reviewed manifest")
    if "allowedExistingRouteNames" in manifest:
        raise RuntimeError("name-only public route allowlists are forbidden")
    if not isinstance(manifest.get("legacyHostEnabled"), bool):
        raise RuntimeError("legacyHostEnabled must be an explicit boolean")

    routes = all_rows(args.admin_url, "/routes?size=1000")
    services = {
        service["id"]: service
        for service in all_rows(args.admin_url, "/services?size=1000")
    }
    managed_names = {route["name"] for route in manifest["routes"]}
    contract_names = {route["name"] for route in manifest["contractRoutes"]}
    control_plane = yaml.safe_load((root / "deploy/kong/control-plane.yml").read_text())
    control_plane_names = verify_control_plane(args.admin_url, control_plane, routes, services)
    approved_names = managed_names | contract_names | control_plane_names
    unverified_names = set(manifest.get("unverifiedExistingRouteNames", []))
    if approved_names & unverified_names:
        raise RuntimeError("a route cannot be both approved and unverified")

    public_hosts = {manifest["canonicalHost"], manifest["legacyHost"]}
    public_routes = [
        route for route in routes
        if not route.get("hosts") or public_hosts.intersection(route.get("hosts") or [])
    ]
    unverified_public = sorted(
        route.get("name") or route["id"]
        for route in public_routes
        if route.get("name") in unverified_names
    )
    unexpected_public = sorted(
        route.get("name") or route["id"]
        for route in public_routes
        if route.get("name") not in approved_names | unverified_names
    )
    if unverified_public:
        print("UNVERIFIED_PUBLIC_ROUTE_NAMES=" + ";".join(unverified_public))
        raise RuntimeError("name-only public routes require exact source contracts")
    if unexpected_public:
        print("UNEXPECTED_PUBLIC_ROUTE_NAMES=" + ";".join(unexpected_public))
        raise RuntimeError("unexpected public Kong routes")

    matrix: list[dict] = []
    for expected in manifest["contractRoutes"]:
        matrix.append(verify_contract_route(args.admin_url, root, expected, routes, services))
    for expected in manifest["routes"]:
        matrix.append(
            verify_managed_route(
                args.admin_url,
                manifest,
                expected,
                routes,
                services,
                args.apply,
            )
        )

    routes_after = all_rows(args.admin_url, "/routes?size=1000") if args.apply else routes
    legacy_routes = sorted(
        route.get("name") or route["id"]
        for route in routes_after
        if manifest["legacyHost"] in (route.get("hosts") or [])
    )
    if not manifest["legacyHostEnabled"] and legacy_routes:
        print("LEGACY_PUBLIC_ROUTE_NAMES=" + ";".join(legacy_routes))
        raise RuntimeError("legacy public host remains enabled")

    args.evidence.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n")
    print("REQUIRED_PUBLIC_ROUTES_PRESENT=PASS")
    print("UNNECESSARY_PUBLIC_ROUTES=0")
    print("LEGACY_PUBLIC_ROUTES=0" if not legacy_routes else f"LEGACY_PUBLIC_ROUTES={len(legacy_routes)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
