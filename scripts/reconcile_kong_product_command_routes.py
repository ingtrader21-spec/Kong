#!/usr/bin/env python3
"""Reconcile JWT-protected product command routes in Kong."""

from __future__ import annotations

import argparse
import base64
import json
import textwrap
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def request(base: str, method: str, path: str, payload=None):
    data = None if payload is None else urlencode(payload, doseq=True).encode()
    with urlopen(Request(base.rstrip("/") + path, method=method, data=data), timeout=15) as response:
        raw = response.read()
        return json.loads(raw) if raw else None


def _der_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value


def _integer(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") or b"\0"
    if raw[0] & 0x80:
        raw = b"\0" + raw
    return _der(0x02, raw)


def rsa_public_key_pem(jwk: dict[str, str]) -> str:
    decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    modulus = int.from_bytes(decode(jwk["n"]), "big")
    exponent = int.from_bytes(decode(jwk["e"]), "big")
    rsa_key = _der(0x30, _integer(modulus) + _integer(exponent))
    algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
    subject = _der(0x30, algorithm + _der(0x03, b"\0" + rsa_key))
    encoded = base64.b64encode(subject).decode()
    lines = "\n".join(textwrap.wrap(encoded, 64))
    return f"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n"


def active_rsa_key(jwks_url: str, active_kid: str | None = None) -> dict[str, str]:
    with urlopen(jwks_url, timeout=15) as response:
        keys = json.load(response).get("keys", [])
    candidates = [
        key for key in keys
        if key.get("kty") == "RSA" and key.get("alg") == "RS256" and key.get("use") == "sig"
    ]
    if active_kid:
        candidates = [key for key in candidates if key.get("kid") == active_kid]
    if len(candidates) != 1:
        raise RuntimeError(
            "Keycloak RS256 signing key is ambiguous; pass --active-kid from a freshly issued product token"
        )
    return candidates[0]


def require_exact_fields(actual: dict, expected: dict, description: str) -> None:
    drift = {
        key: {"expected": value, "actual": actual.get(key)}
        for key, value in expected.items()
        if actual.get(key) != value
    }
    if drift:
        raise RuntimeError(f"{description} configuration drift: {json.dumps(drift, sort_keys=True)}")


def require_plugin(plugin: dict, expected_config: dict, description: str) -> None:
    require_exact_fields(plugin.get("config", {}), expected_config, description)


def plugin_form(config: dict) -> dict:
    def form_value(value):
        if isinstance(value, bool):
            return "true" if value else "false"
        return value

    return {
        f"config.{key}{'[]' if isinstance(value, list) else ''}": (
            [form_value(item) for item in value] if isinstance(value, list)
            else form_value(value)
        )
        for key, value in config.items()
    }


def consumer_scopes(manifest: dict) -> dict[str, str]:
    consumers = manifest.get("consumers")
    if not isinstance(consumers, list) or not consumers:
        raise RuntimeError("product command manifest must declare consumers")
    result: dict[str, str] = {}
    for item in consumers:
        client_id = item.get("client_id")
        scope = item.get("scope")
        if not isinstance(client_id, str) or not isinstance(scope, str):
            raise RuntimeError("product command consumers require client_id and scope")
        if client_id in result:
            raise RuntimeError(f"duplicate product command consumer: {client_id}")
        result[client_id] = scope
    return result


def claim_guard(manifest: dict) -> str:
    issuer = json.dumps(manifest["issuer"])
    audience = json.dumps(manifest["audience"])
    scopes = json.dumps(consumer_scopes(manifest), sort_keys=True)
    consumer_header = json.dumps(manifest["consumerHeader"])
    tenant_header = json.dumps(manifest["tenantHeader"])
    return (
        "local h=kong.request.get_header('authorization') or '';"
        "local t=h:match('[Bb]earer%s+(.+)') or '';"
        "local p=t:match('^[^.]+%.([^.]+)%.') or '';"
        "p=p:gsub('-','+'):gsub('_','/');p=p..string.rep('=',(4-#p%4)%4);"
        "local raw=ngx.decode_base64(p);local c=raw and require('cjson.safe').decode(raw) or {};"
        "local s={};for x in string.gmatch(c.scope or '','%S+') do s[x]=true end;"
        f"if c.iss~={issuer} then return kong.response.exit(401,{{error='invalid_issuer'}}) end;"
        f"local a=c.aud;local ok=a=={audience};"
        f"if type(a)=='table' then for _,v in ipairs(a) do if v=={audience} then ok=true end end end;"
        "if not ok then return kong.response.exit(401,{error='invalid_audience'}) end;"
        f"local scopes=require('cjson.safe').decode({scopes});"
        "local required=scopes[c.azp or ''];"
        "if not required then return kong.response.exit(403,{error='product_consumer_denied'}) end;"
        "if not s[required] then return kong.response.exit(403,{error='insufficient_scope',required_scope=required}) end;"
        f"local tenant=kong.request.get_header({tenant_header});"
        "if not tenant or tenant=='' then return kong.response.exit(400,{error='tenant_header_required'}) end;"
        "local authorized=false;"
        "if c.tenant_id==tenant then authorized=true end;"
        "if type(c.tenant_ids)=='table' then for _,v in ipairs(c.tenant_ids) do if v==tenant then authorized=true end end end;"
        "if c.tenant_id=='*' then authorized=false end;"
        "if type(c.tenant_ids)=='table' then for _,v in ipairs(c.tenant_ids) do if v=='*' then authorized=false end end end;"
        "if not authorized then return kong.response.exit(403,{error='cross_tenant_denied'}) end;"
        f"kong.service.request.set_header({consumer_header},c.azp)"
    )


def one(items: list[dict], description: str) -> dict | None:
    if len(items) > 1:
        raise RuntimeError(f"ambiguous {description}")
    return items[0] if items else None


def ensure_entity(admin: str, collection: str, query: str, payload: dict, apply: bool) -> dict:
    existing = one(request(admin, "GET", f"/{collection}?" + urlencode({"name": query}))["data"], query)
    if existing:
        if apply:
            request(admin, "PATCH", f"/{collection}/{existing['id']}", payload)
        existing = request(admin, "GET", f"/{collection}/{existing['id']}")
        require_exact_fields(existing, payload, query)
        return existing
    if not apply:
        raise RuntimeError(f"missing {collection}: {query}")
    created = request(admin, "POST", f"/{collection}", payload)
    created = request(admin, "GET", f"/{collection}/{created['id']}")
    require_exact_fields(created, payload, query)
    return created


def ensure_consumer_and_jwt(admin: str, client_id: str, public_key: str, apply: bool) -> None:
    consumers = request(admin, "GET", "/consumers?size=1000")["data"]
    payload = {"username": client_id, "custom_id": client_id}
    consumer = one([row for row in consumers if row.get("username") == client_id], f"consumer {client_id}")
    if not consumer:
        if not apply:
            raise RuntimeError(f"product consumer is missing: {client_id}")
        consumer = request(admin, "POST", "/consumers", payload)
    elif apply:
        request(admin, "PATCH", f"/consumers/{consumer['id']}", payload)
        consumer = request(admin, "GET", f"/consumers/{consumer['id']}")
    require_exact_fields(consumer, payload, f"consumer {client_id}")

    credentials = request(admin, "GET", f"/consumers/{consumer['id']}/jwt")["data"]
    jwt_payload = {"key": client_id, "algorithm": "RS256", "rsa_public_key": public_key}
    credential = one([row for row in credentials if row.get("key") == client_id], f"JWT credential {client_id}")
    if credential and apply:
        request(admin, "PATCH", f"/consumers/{consumer['id']}/jwt/{credential['id']}", jwt_payload)
    elif not credential and apply:
        credential = request(admin, "POST", f"/consumers/{consumer['id']}/jwt", jwt_payload)
    elif not credential:
        raise RuntimeError(f"product JWT credential is missing: {client_id}")
    credential = request(admin, "GET", f"/consumers/{consumer['id']}/jwt/{credential['id']}")
    require_exact_fields(credential, jwt_payload, f"JWT credential {client_id}")


def select_route(routes: list[dict], name: str, host: str, path: str) -> dict | None:
    route = one([row for row in routes if row.get("name") == name], name)
    collisions = [
        row for row in routes
        if row.get("id") != (route or {}).get("id")
        and host in (row.get("hosts") or [])
        and path in (row.get("paths") or [])
    ]
    if route and collisions:
        raise RuntimeError(f"conflicting live route for {host}{path}")
    return route or one(collisions, f"legacy route for {host}{path}")


def ensure_plugin(admin: str, route_id: str, name: str, config: dict, apply: bool) -> None:
    plugins = request(admin, "GET", f"/routes/{route_id}/plugins")["data"]
    existing = one([item for item in plugins if item["name"] == name and item.get("enabled")], name)
    if existing:
        if apply:
            request(admin, "PATCH", f"/plugins/{existing['id']}", {"name": name, **plugin_form(config)})
        current = request(admin, "GET", f"/plugins/{existing['id']}")
        require_plugin(current, config, f"{name} plugin")
        return
    if not apply:
        raise RuntimeError(f"missing route plugin: {name}")
    created = request(admin, "POST", f"/routes/{route_id}/plugins", {"name": name, **plugin_form(config)})
    require_plugin(created, config, f"{name} plugin")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--jwks-url", required=True)
    parser.add_argument("--manifest", type=Path, default=Path("config/kong-product-command-routes.json"))
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--active-kid")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text())
    signing_key = active_rsa_key(args.jwks_url, args.active_kid)
    public_key = rsa_public_key_pem(signing_key)
    service = ensure_entity(args.admin_url, "services", manifest["service"]["name"], manifest["service"], args.apply)
    for client_id in consumer_scopes(manifest):
        ensure_consumer_and_jwt(args.admin_url, client_id, public_key, args.apply)

    evidence = []
    guard = claim_guard(manifest)
    for expected in manifest["routes"]:
        routes = request(args.admin_url, "GET", "/routes?size=1000")["data"]
        route = select_route(routes, expected["name"], manifest["host"], expected["paths"][0])
        route_payload = {
            "name": expected["name"],
            "service.id": service["id"],
            "hosts[]": [manifest["host"]],
            "paths[]": expected["paths"],
            "methods[]": expected["methods"],
            "protocols[]": ["http"],
            "strip_path": "false",
            "https_redirect_status_code": 426,
        }
        if route and args.apply:
            route = request(args.admin_url, "PATCH", f"/routes/{route['id']}", route_payload)
        elif not route and args.apply:
            route = request(args.admin_url, "POST", "/routes", route_payload)
        elif not route:
            raise RuntimeError(f"missing route: {expected['name']}")
        route = request(args.admin_url, "GET", f"/routes/{route['id']}")
        require_exact_fields(
            route,
            {
                "name": expected["name"],
                "hosts": [manifest["host"]],
                "paths": expected["paths"],
                "methods": expected["methods"],
                "protocols": ["http"],
                "strip_path": False,
                "https_redirect_status_code": 426,
            },
            expected["name"],
        )
        if route.get("service", {}).get("id") != service["id"]:
            raise RuntimeError(f"{expected['name']} service binding drift")
        ensure_plugin(args.admin_url, route["id"], "jwt", {
            "key_claim_name": "azp", "claims_to_verify": ["exp"],
            "header_names": ["authorization"], "run_on_preflight": True,
        }, args.apply)
        ensure_plugin(args.admin_url, route["id"], "post-function", {"access": [guard]}, args.apply)
        ensure_plugin(args.admin_url, route["id"], "request-size-limiting", {
            "allowed_payload_size": expected["max_body_mb"],
        }, args.apply)
        ensure_plugin(args.admin_url, route["id"], "rate-limiting", {
            "minute": expected["rate_per_minute"], "policy": "local", "limit_by": "consumer",
        }, args.apply)
        ensure_plugin(args.admin_url, route["id"], "correlation-id", {
            "header_name": "X-Correlation-ID", "generator": "uuid", "echo_downstream": True,
        }, args.apply)
        evidence.append({
            "route": expected["paths"][0],
            "methods": expected["methods"],
            "issuer": manifest["issuer"],
            "audience": manifest["audience"],
            "consumer_header": manifest["consumerHeader"],
            "jwt_signature": "RS256",
            "signing_kid": signing_key.get("kid"),
            "status": "PASS",
        })
    args.evidence.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print("KONG_PRODUCT_COMMAND_ROUTES=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
