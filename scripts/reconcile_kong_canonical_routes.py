#!/usr/bin/env python3
"""Fail-closed reconciliation for the canonical public Kong route surface."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
import yaml
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import Request, urlopen


def request(base: str, method: str, path: str, payload=None) -> dict:
    data = None if payload is None else urlencode(payload, doseq=True).encode()
    url = path if path.startswith(("http://", "https://")) else base.rstrip("/") + path
    with urlopen(Request(url, method=method, data=data), timeout=10) as response:
        raw = response.read()
        return json.loads(raw) if raw else {}


def safe_next(base: str, value: str | None) -> str | None:
    if not value:
        return None
    base_url = urlsplit(base)
    resolved = urlsplit(urljoin(base.rstrip("/") + "/", value))
    if (resolved.scheme, resolved.netloc) != (base_url.scheme, base_url.netloc):
        raise RuntimeError("unsafe Kong pagination URL")
    return resolved.geturl()


def all_rows(base: str, path: str) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    next_url: str | None = path
    while next_url:
        if next_url in seen:
            raise RuntimeError("Kong pagination loop detected")
        seen.add(next_url)
        page = request(base, "GET", next_url)
        rows.extend(page.get("data", []))
        next_url = safe_next(base, page.get("next"))
    return rows


def one(rows: list[dict], label: str) -> dict:
    if len(rows) != 1:
        raise RuntimeError(f"expected exactly one {label}")
    return rows[0]


def require_equal(actual, expected, label: str) -> None:
    if actual != expected:
        raise RuntimeError(
            f"{label} drift: expected={json.dumps(expected, sort_keys=True)} "
            f"actual={json.dumps(actual, sort_keys=True)}"
        )


def form_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


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
    if path.name == "kong-callback-routes.json":
        route = one(
            [item for item in manifest["routes"] if item["name"] == route_name],
            f"security authority route {route_name}",
        )
        require_equal(route["paths"], expected["paths"], f"{route_name}.authority.paths")
        require_equal(sorted(route["methods"]), sorted(expected["methods"]), f"{route_name}.authority.methods")
    elif path.name == "kong-campaign-automation-routes.json":
        route = one(
            [item for item in manifest["routes"] if item["name"] == route_name],
            f"security authority route {route_name}",
        )
        require_equal([route["path"]], expected["paths"], f"{route_name}.authority.paths")
        require_equal(expected["methods"], ["POST"], f"{route_name}.authority.methods")
    elif path.name == "kong-product-command-routes.json":
        route = one(
            [item for item in manifest["routes"] if item["name"] == route_name],
            f"security authority route {route_name}",
        )
        require_equal(route["paths"], expected["paths"], f"{route_name}.authority.paths")
        require_equal(sorted(route["methods"]), sorted(expected["methods"]), f"{route_name}.authority.methods")
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
    if authority_path.name == "kong-callback-routes.json":
        callback = security_module(root, "reconcile_kong_callback_routes")
        callback.verify_plugins(plugins, authority_route, manifest)
        return
    if authority_path.name == "kong-product-command-routes.json":
        product_commands = security_module(root, "reconcile_kong_product_command_routes")
        product_commands.require_plugin(
            plugins["jwt"],
            {
                "key_claim_name": "azp",
                "claims_to_verify": ["exp"],
                "header_names": ["authorization"],
                "run_on_preflight": True,
            },
            f"{expected['name']}.jwt",
        )
        product_commands.require_plugin(
            plugins["post-function"],
            {"access": [product_commands.claim_guard(manifest)]},
            f"{expected['name']}.claim_guard",
        )
        product_commands.require_plugin(
            plugins["request-size-limiting"],
            {"allowed_payload_size": authority_route["max_body_mb"]},
            f"{expected['name']}.body_limit",
        )
        product_commands.require_plugin(
            plugins["rate-limiting"],
            {
                "minute": authority_route["rate_per_minute"],
                "policy": "local",
                "limit_by": "consumer",
            },
            f"{expected['name']}.rate_limit",
        )
        product_commands.require_plugin(
            plugins["correlation-id"],
            {
                "header_name": "X-Correlation-ID",
                "generator": "uuid",
                "echo_downstream": True,
            },
            f"{expected['name']}.correlation_id",
        )
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
            "policy": "local",
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
    form = {f"config.{key}": form_value(value) for key, value in expected_config.items()}
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
        {"minute": expected["ratePerMinute"], "policy": "local", "limit_by": "consumer"},
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
    parser.add_argument("--admin-url", required=True)
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
