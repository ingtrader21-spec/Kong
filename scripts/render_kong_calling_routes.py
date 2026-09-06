#!/usr/bin/env python3
"""Render the reviewed calling contract as an executable Kong declarative fragment.

This command is deliberately source-only.  It never contacts the Kong Admin API;
runtime promotion remains a separate, protected operation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config/kong-calling-routes.v1.json"
LUA_PATH = ROOT / "deploy/kong/calling-policy.lua"


def load_policy() -> dict[str, Any]:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    if policy.get("runtimeApplyAuthorized") is not False:
        raise ValueError("calling source candidate must keep runtime apply disabled")
    return policy


def route_entry(spec: dict[str, Any], route: dict[str, Any]) -> dict[str, Any]:
    common = spec["commonPolicy"]
    return {
        "name": route["name"],
        "protocols": common["protocols"],
        "hosts": [spec["host"]],
        "paths": [route["path"]],
        "methods": route["methods"],
        "strip_path": common["stripPath"],
        "preserve_host": common["preserveHost"],
        "path_handling": "v0",
        "https_redirect_status_code": common["httpsRedirectStatusCode"],
        "request_buffering": common["requestBuffering"],
        "response_buffering": common["responseBuffering"],
        "regex_priority": 0,
        "plugins": [
            {
                "name": "rate-limiting",
                "config": {
                    "minute": route["ratePerMinute"],
                    "policy": common["rateLimitPolicy"],
                    "fault_tolerant": common["rateLimitFaultTolerant"],
                    "limit_by": "credential",
                    "hide_client_headers": False,
                    "redis": {
                        "host": "codestra-redis",
                        "port": 6379,
                        "database": 0,
                        "timeout": 2000,
                        "password": "{vault://env/kong-rate-limit-redis-password}",
                    },
                },
            }
        ],
    }


def render() -> dict[str, Any]:
    spec = load_policy()
    service = spec["service"]
    identity = spec["identity"]
    common = spec["commonPolicy"]
    lua_source = LUA_PATH.read_text(encoding="utf-8")
    return {
        "_format_version": "3.0",
        "_transform": True,
        "services": [
            {
                "name": service["name"],
                "enabled": True,
                "protocol": service["protocol"],
                "host": service["host"],
                "port": service["port"],
                "connect_timeout": service["connectTimeoutMs"],
                "read_timeout": service["readTimeoutMs"],
                "write_timeout": service["writeTimeoutMs"],
                "routes": [route_entry(spec, route) for route in spec["routes"]],
                "plugins": [
                    {
                        "name": "openid-connect",
                        "config": {
                            "issuer": identity["issuer"],
                            "auth_methods": identity["authMethods"],
                            "audience": [identity["audience"]],
                            "consumer_claim": [identity["consumerClaim"]],
                        },
                    },
                    {
                        "name": "post-function",
                        "config": {"access": [lua_source]},
                    },
                    {
                        "name": "correlation-id",
                        "config": {
                            "header_name": common["correlationHeader"],
                            "generator": "uuid",
                            "echo_downstream": True,
                        },
                    },
                    {
                        "name": "request-size-limiting",
                        "config": {
                            "allowed_payload_size": common["requestBodyLimitMb"],
                            "size_unit": "megabytes",
                            "require_content_length": True,
                        },
                    },
                ],
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("json", "yaml"), default="yaml")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="refused by design; runtime changes require a separate protected release",
    )
    args = parser.parse_args()
    if args.apply:
        parser.error("runtime apply is not authorized by this source-only reconciler")
    document = render()
    if args.format == "json":
        print(json.dumps(document, indent=2, sort_keys=False))
    else:
        print(yaml.safe_dump(document, sort_keys=False), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
