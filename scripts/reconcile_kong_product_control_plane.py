#!/usr/bin/env python3
"""Fail-closed Kong authority for product-backend -> Middleware commands."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from reconcile_kong_n8n_control_plane import (
    enabled_plugins,
    ensure_plugin,
    ensure_route,
    ensure_service,
)
from reconcile_kong_campaign_automation import require_plugin

ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "config" / "kong-product-control-plane-routes.json"


def load_spec() -> dict:
    return json.loads(SPEC_PATH.read_text(encoding="utf-8"))


def authorize_contract(
    spec: dict,
    *,
    client_id: str,
    scopes: set[str],
    route_kind: str,
    command_type: str | None = None,
    target: str | None = None,
) -> bool:
    policy = spec["clients"].get(client_id)
    if not policy:
        return False
    if route_kind == "status":
        return policy["status_scope"] in scopes
    if route_kind != "command" or policy["command_scope"] not in scopes:
        return False
    if not isinstance(command_type, str) or not isinstance(target, str):
        return False
    if target not in policy["targets"]:
        return False
    return any(command_type.startswith(prefix) for prefix in policy["command_prefixes"])


def claim_guard(spec: dict, route: dict) -> str:
    clients = spec["clients"]
    policy_json = json.dumps(clients, separators=(",", ":"))
    issuer = json.dumps(spec["issuer"])
    audience = json.dumps(spec["audience"])
    route_kind = json.dumps(route["kind"])
    required_headers = "".join(
        "if not kong.request.get_header(%s) then return kong.response.exit(400,{error='missing_required_header'}) end;"
        % json.dumps(header)
        for header in route["required_headers"]
    )
    command_checks = ""
    if route["kind"] == "command":
        command_checks = (
            "local raw_body=kong.request.get_raw_body() or '';"
            "local body=require('cjson.safe').decode(raw_body);"
            "if type(body)~='table' then return kong.response.exit(400,{error='invalid_command_body'}) end;"
            "local ct=body.command_type;local target=body.target;"
            "if type(ct)~='string' or type(target)~='string' then return kong.response.exit(400,{error='command_authority_fields_required'}) end;"
            "local prefix_ok=false;for _,prefix in ipairs(policy.command_prefixes or {}) do if ct:sub(1,#prefix)==prefix then prefix_ok=true end end;"
            "if not prefix_ok then return kong.response.exit(403,{error='command_namespace_denied'}) end;"
            "local target_ok=false;for _,allowed in ipairs(policy.targets or {}) do if target==allowed then target_ok=true end end;"
            "if not target_ok then return kong.response.exit(403,{error='command_target_denied'}) end;"
        )
    return (
        "local h=kong.request.get_header('authorization') or '';"
        "local t=h:match('[Bb]earer%s+(.+)') or '';"
        "if t=='' then return kong.response.exit(401,{error='bearer_token_required'}) end;"
        "local p=t:match('^[^.]+%.([^.]+)%.') or '';"
        "p=p:gsub('-','+'):gsub('_','/');p=p..string.rep('=',(4-#p%4)%4);"
        "local raw=ngx.decode_base64(p);local c=raw and require('cjson.safe').decode(raw) or {};"
        "if type(c)~='table' then return kong.response.exit(401,{error='invalid_token_claims'}) end;"
        f"if c.iss~={issuer} then return kong.response.exit(401,{{error='invalid_issuer'}}) end;"
        f"local expected_aud={audience};local a=c.aud;local aud=a==expected_aud;"
        "if type(a)=='table' then for _,v in ipairs(a) do if v==expected_aud then aud=true end end end;"
        "if not aud then return kong.response.exit(401,{error='invalid_audience'}) end;"
        "if type(c.exp)~='number' or type(c.iat)~='number' or c.exp<=c.iat or c.exp-c.iat>300 then return kong.response.exit(401,{error='invalid_token_lifetime'}) end;"
        f"local policies=require('cjson.safe').decode({json.dumps(policy_json)});"
        "local client=c.azp;local policy=policies and policies[client] or nil;"
        "if not policy then return kong.response.exit(403,{error='product_identity_denied'}) end;"
        "local scopes={};for x in string.gmatch(c.scope or '','%S+') do scopes[x]=true end;"
        f"local route_kind={route_kind};local needed=route_kind=='command' and policy.command_scope or policy.status_scope;"
        "if type(needed)~='string' or not scopes[needed] then return kong.response.exit(403,{error='insufficient_scope'}) end;"
        + required_headers
        + "local requested=kong.request.get_header('X-Tenant-ID') or '';"
        "if requested=='' or requested=='*' then return kong.response.exit(403,{error='tenant_denied'}) end;"
        "if c.tenant_id~=requested then return kong.response.exit(403,{error='tenant_denied'}) end;"
        + command_checks
    )


def expected_plugin_configs(spec: dict, route: dict) -> dict[str, dict]:
    return {
        "openid-connect": {
            "issuer": spec["oidc_discovery"],
            "auth_methods": ["bearer"],
            "audience": [spec["audience"]],
        },
        "post-function": {"access": [claim_guard(spec, route)]},
        "request-size-limiting": {"allowed_payload_size": route["max_body_mb"]},
        "rate-limiting": {
            "minute": route["rate_per_minute"],
            "policy": "local",
            "limit_by": "ip",
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


def validate_source(spec: dict) -> None:
    if spec.get("status") != "PREPARED_DISABLED":
        raise RuntimeError("product control-plane source must start PREPARED_DISABLED")
    if spec.get("issuer") != "https://auth.codestra.co/realms/codestra":
        raise RuntimeError("canonical issuer drift")
    if spec.get("audience") != "middleware-api":
        raise RuntimeError("product tokens must target middleware-api")
    if spec.get("preserve_authorization_header") is not True:
        raise RuntimeError("original bearer must be preserved")
    if spec.get("token_exchange") is not False:
        raise RuntimeError("token exchange is prohibited")
    if spec.get("tenant_claim") != "tenant_id":
        raise RuntimeError("tenant_id must be authoritative")
    expected_clients = {
        "moneybee-backend", "breero-backend", "larim-a-backend",
        "transportation-backend", "beyvra-backend", "social-codestra",
    }
    if set(spec.get("clients", {})) != expected_clients:
        raise RuntimeError("product client set drift")
    if authorize_contract(spec, client_id="social-codestra", scopes={"social.middleware.command.write"}, route_kind="command", command_type="crm.lead.create", target="odoo-19"):
        raise RuntimeError("social-codestra must not submit CRM commands")
    for client in ("breero-backend", "larim-a-backend", "transportation-backend"):
        if authorize_contract(spec, client_id=client, scopes={spec["clients"][client]["command_scope"]}, route_kind="command", command_type="telephony.call.start", target="vicidial-restricted"):
            raise RuntimeError(f"{client} must not submit telephony commands")


def reconcile(admin: str, spec: dict, apply: bool) -> None:
    if apply and (
        spec.get("status") not in {"APPROVED_STAGING", "APPROVED_PRODUCTION"}
        or spec.get("safety", {}).get("reconciliation_apply") is not True
    ):
        raise RuntimeError("product control-plane authority is not approved for --apply")
    service = ensure_service(admin, spec, apply)
    for route_spec in spec["routes"]:
        route = ensure_route(admin, spec, service, route_spec, apply)
        expected = expected_plugin_configs(spec, route_spec)
        for name, config in expected.items():
            ensure_plugin(admin, route["id"], name, config, apply)
        verify_plugins(enabled_plugins(admin, route["id"]), route_spec, spec)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admin-url")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    spec = load_spec()
    validate_source(spec)
    if args.admin_url:
        reconcile(args.admin_url, spec, args.apply)
        print("PRODUCT_KONG_RUNTIME_CHECK=PASS")
    else:
        if args.apply:
            raise RuntimeError("--apply requires --admin-url")
        print("PRODUCT_KONG_SOURCE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
