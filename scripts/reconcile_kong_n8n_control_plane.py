#!/usr/bin/env python3
"""Exact, fail-closed reconciliation for the N8N -> Middleware Kong boundary."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from reconcile_kong_campaign_automation import (
    active_rsa_key,
    plugin_form,
    require_exact_fields,
    require_plugin,
    rsa_public_key_pem,
)


def request(base: str, method: str, path: str, payload=None) -> dict:
    data = None if payload is None else urlencode(payload, doseq=True).encode()
    with urlopen(Request(base.rstrip("/") + path, method=method, data=data), timeout=15) as response:
        raw = response.read()
        return json.loads(raw) if raw else {}


def all_rows(base: str, path: str) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    while path:
        if path in seen:
            raise RuntimeError("Kong pagination loop detected")
        seen.add(path)
        page = request(base, "GET", path)
        rows.extend(page.get("data", []))
        next_path = page.get("next")
        if next_path and not str(next_path).startswith("/"):
            raise RuntimeError("unsafe Kong pagination URL")
        path = next_path
    return rows


def one(rows: list[dict], label: str) -> dict | None:
    if len(rows) > 1:
        raise RuntimeError(f"ambiguous {label}")
    return rows[0] if rows else None


def claim_guard(spec: dict, route: dict) -> str:
    issuer = json.dumps(spec["issuer"])
    audience = json.dumps(spec["audience"])
    client = json.dumps(spec["client_id"])
    scope = json.dumps(route["scope"])
    required_headers = "".join(
        "if not kong.request.get_header(%s) then return kong.response.exit(400,{error='missing_required_header'}) end;"
        % json.dumps(header)
        for header in route["required_headers"]
    )
    return (
        "local h=kong.request.get_header('authorization') or '';"
        "local t=h:match('[Bb]earer%s+(.+)') or '';"
        "local p=t:match('^[^.]+%.([^.]+)%.') or '';"
        "p=p:gsub('-','+'):gsub('_','/');p=p..string.rep('=',(4-#p%4)%4);"
        "local raw=ngx.decode_base64(p);local c=raw and require('cjson.safe').decode(raw) or {};"
        "local scopes={};for x in string.gmatch(c.scope or '','%S+') do scopes[x]=true end;"
        f"if c.iss~={issuer} then return kong.response.exit(401,{{error='invalid_issuer'}}) end;"
        f"if c.azp~={client} then return kong.response.exit(403,{{error='service_identity_denied'}}) end;"
        f"local a=c.aud;local aud=a=={audience};"
        f"if type(a)=='table' then for _,v in ipairs(a) do if v=={audience} then aud=true end end end;"
        "if not aud then return kong.response.exit(401,{error='invalid_audience'}) end;"
        "if type(c.exp)~='number' or type(c.iat)~='number' or c.exp<=c.iat or c.exp-c.iat>300 "
        "then return kong.response.exit(401,{error='invalid_token_lifetime'}) end;"
        f"if not scopes[{scope}] then return kong.response.exit(403,{{error='insufficient_scope'}}) end;"
        + required_headers
        + "local requested=kong.request.get_header('X-Tenant-ID') or '';"
        "if requested=='' or requested=='*' then return kong.response.exit(403,{error='tenant_denied'}) end;"
        "local tenant_ok=c.tenant_id==requested;"
        "if type(c.tenant_ids)=='table' then for _,v in ipairs(c.tenant_ids) do if v==requested then tenant_ok=true end end end;"
        "if not tenant_ok then return kong.response.exit(403,{error='tenant_denied'}) end"
    )


def expected_plugin_configs(spec: dict, route: dict) -> dict[str, dict]:
    return {
        "openid-connect": {
            "issuer": spec["oidc_discovery"],
            "auth_methods": ["bearer"],
            "audience": [spec["audience"]],
            "consumer_claim": ["azp"],
        },
        "jwt": {
            "key_claim_name": "azp",
            "claims_to_verify": ["exp"],
            "header_names": ["authorization"],
            "run_on_preflight": True,
        },
        "post-function": {"access": [claim_guard(spec, route)]},
        "request-size-limiting": {"allowed_payload_size": route["max_body_mb"]},
        "rate-limiting": {
            "minute": route["rate_per_minute"],
            "policy": "local",
            "limit_by": "consumer",
        },
        "correlation-id": {
            "header_name": "X-Correlation-ID",
            "generator": "uuid",
            "echo_downstream": True,
        },
    }


def verify_plugins(by_name: dict[str, dict], route: dict, spec: dict) -> None:
    expected = expected_plugin_configs(spec, route)
    if set(by_name) != set(expected):
        raise RuntimeError(
            f"{route['name']} route plugin drift: expected={sorted(expected)} actual={sorted(by_name)}"
        )
    for name, config in expected.items():
        require_plugin(by_name[name], config, f"{route['name']}.{name}")


def enabled_plugins(admin: str, route_id: str) -> dict[str, dict]:
    rows = all_rows(admin, f"/routes/{route_id}/plugins?size=1000")
    grouped: dict[str, list[dict]] = {}
    for plugin in rows:
        if plugin.get("enabled"):
            grouped.setdefault(plugin["name"], []).append(plugin)
    duplicates = [name for name, values in grouped.items() if len(values) != 1]
    if duplicates:
        raise RuntimeError(f"duplicate enabled route plugins: {sorted(duplicates)}")
    return {name: values[0] for name, values in grouped.items()}


def ensure_plugin(admin: str, route_id: str, name: str, config: dict, apply: bool) -> None:
    existing = enabled_plugins(admin, route_id).get(name)
    payload = {"name": name, **plugin_form(config)}
    if existing and apply:
        request(admin, "PATCH", f"/plugins/{existing['id']}", payload)
    elif not existing and apply:
        request(admin, "POST", f"/routes/{route_id}/plugins", payload)
    elif not existing:
        raise RuntimeError(f"missing route plugin: {name}")
    current = enabled_plugins(admin, route_id)[name]
    require_plugin(current, config, f"{name} plugin")


def ensure_service(admin: str, spec: dict, apply: bool) -> dict:
    expected = spec["service"]
    service = one(
        request(admin, "GET", "/services?" + urlencode({"name": expected["name"]})).get("data", []),
        "N8N control-plane service",
    )
    if service and apply:
        request(admin, "PATCH", f"/services/{service['id']}", expected)
    elif not service and apply:
        request(admin, "POST", "/services", expected)
    elif not service:
        raise RuntimeError("N8N control-plane service is missing")
    service = one(
        request(admin, "GET", "/services?" + urlencode({"name": expected["name"]})).get("data", []),
        "N8N control-plane service",
    )
    assert service is not None
    require_exact_fields(service, expected, "N8N control-plane service")
    return service


def ensure_consumer(admin: str, spec: dict, public_key: str, apply: bool) -> dict:
    expected = spec["consumer"]
    consumer = one(
        [row for row in all_rows(admin, "/consumers?size=1000") if row.get("username") == expected["username"]],
        "N8N service consumer",
    )
    if consumer and apply:
        request(admin, "PATCH", f"/consumers/{consumer['id']}", expected)
    elif not consumer and apply:
        request(admin, "POST", "/consumers", expected)
    elif not consumer:
        raise RuntimeError("N8N service consumer is missing")
    consumer = one(
        [row for row in all_rows(admin, "/consumers?size=1000") if row.get("username") == expected["username"]],
        "N8N service consumer",
    )
    assert consumer is not None
    require_exact_fields(consumer, expected, "N8N service consumer")
    credentials = request(admin, "GET", f"/consumers/{consumer['id']}/jwt").get("data", [])
    credential = one(
        [row for row in credentials if row.get("key") == spec["client_id"]],
        "N8N JWT credential",
    )
    jwt_payload = {"key": spec["client_id"], "algorithm": "RS256", "rsa_public_key": public_key}
    if credential and apply:
        request(admin, "PATCH", f"/consumers/{consumer['id']}/jwt/{credential['id']}", jwt_payload)
    elif not credential and apply:
        request(admin, "POST", f"/consumers/{consumer['id']}/jwt", jwt_payload)
    elif not credential:
        raise RuntimeError("N8N JWT credential is missing")
    credentials = request(admin, "GET", f"/consumers/{consumer['id']}/jwt").get("data", [])
    credential = one([row for row in credentials if row.get("key") == spec["client_id"]], "N8N JWT credential")
    assert credential is not None
    require_exact_fields(credential, jwt_payload, "N8N JWT credential")
    return consumer


def select_route(routes: list[dict], spec: dict, expected: dict) -> dict | None:
    named = [row for row in routes if row.get("name") == expected["name"]]
    route = one(named, f"route {expected['name']}")
    collisions = [
        row for row in routes
        if row.get("id") != (route or {}).get("id")
        and spec["host"] in (row.get("hosts") or [])
        and expected["path"] in (row.get("paths") or [])
        and expected["method"] in (row.get("methods") or [])
    ]
    if collisions:
        raise RuntimeError(f"conflicting route for {spec['host']}{expected['path']}")
    return route


def ensure_route(admin: str, spec: dict, service: dict, expected: dict, apply: bool) -> dict:
    route = select_route(all_rows(admin, "/routes?size=1000"), spec, expected)
    payload = {
        "name": expected["name"],
        "service.id": service["id"],
        "hosts[]": [spec["host"]],
        "paths[]": [expected["path"]],
        "methods[]": [expected["method"]],
        "protocols[]": ["http"],
        "strip_path": "false",
        "preserve_host": "false",
        "https_redirect_status_code": 426,
    }
    if route and apply:
        request(admin, "PATCH", f"/routes/{route['id']}", payload)
    elif not route and apply:
        request(admin, "POST", "/routes", payload)
    elif not route:
        raise RuntimeError(f"missing route: {expected['name']}")
    route = one(
        [row for row in all_rows(admin, "/routes?size=1000") if row.get("name") == expected["name"]],
        f"route {expected['name']}",
    )
    assert route is not None
    require_exact_fields(
        route,
        {
            "name": expected["name"],
            "hosts": [spec["host"]],
            "paths": [expected["path"]],
            "methods": [expected["method"]],
            "protocols": ["http"],
            "strip_path": False,
            "preserve_host": False,
            "https_redirect_status_code": 426,
        },
        expected["name"],
    )
    if route.get("service", {}).get("id") != service["id"]:
        raise RuntimeError(f"{expected['name']} service binding drift")
    plugin_configs = expected_plugin_configs(spec, expected)
    for name, config in plugin_configs.items():
        ensure_plugin(admin, route["id"], name, config, apply)
    verify_plugins(enabled_plugins(admin, route["id"]), expected, spec)
    return route


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--jwks-url", required=True)
    parser.add_argument("--manifest", type=Path, default=Path("config/kong-n8n-control-plane-routes.json"))
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--active-kid")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    spec = json.loads(args.manifest.read_text())
    expected_discovery = spec.get("issuer", "") + "/.well-known/openid-configuration"
    expected_jwks = spec.get("issuer", "") + "/protocol/openid-connect/certs"
    if spec.get("oidc_discovery") != expected_discovery:
        raise RuntimeError("N8N OIDC discovery must match canonical Keycloak issuer")
    if spec.get("jwks_uri") != expected_jwks:
        raise RuntimeError("N8N JWKS URI must match canonical Keycloak issuer")
    if args.jwks_url.rstrip("/") != expected_jwks.rstrip("/"):
        raise RuntimeError("runtime JWKS URL differs from reviewed N8N authority")
    if spec.get("client_id") != spec.get("consumer", {}).get("custom_id"):
        raise RuntimeError("N8N client identity and Kong consumer custom_id differ")
    if spec.get("preserve_authorization_header") is not True or spec.get("token_exchange") is not False:
        raise RuntimeError("N8N bearer token must be preserved for Middleware revalidation")
    if args.apply and (
        spec.get("status") not in {"APPROVED_STAGING", "APPROVED_PRODUCTION"}
        or spec.get("safety", {}).get("reconciliation_apply") is not True
    ):
        raise RuntimeError("N8N control-plane authority is not approved for --apply")

    signing_key = active_rsa_key(args.jwks_url, args.active_kid)
    public_key = rsa_public_key_pem(signing_key)
    ensure_consumer(args.admin_url, spec, public_key, args.apply)
    service = ensure_service(args.admin_url, spec, args.apply)
    evidence = []
    for expected in spec["routes"]:
        ensure_route(args.admin_url, spec, service, expected, args.apply)
        evidence.append(
            {
                "route": expected["path"],
                "method": expected["method"],
                "scope": expected["scope"],
                "issuer": spec["issuer"],
                "audience": spec["audience"],
                "client_id": spec["client_id"],
                "middleware_revalidation": True,
                "status": "PASS",
            }
        )
    args.evidence.write_text(
        json.dumps(
            {
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "mode": "apply" if args.apply else "dry-run",
                "routes": evidence,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    print("KONG_N8N_CONTROL_PLANE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
