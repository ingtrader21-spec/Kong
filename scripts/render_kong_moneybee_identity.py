#!/usr/bin/env python3
"""Render the source-only MoneyBee identity contract for decK validation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def render() -> dict:
    spec = json.loads((ROOT / "config/kong-moneybee-identity-routes.json").read_text())
    if spec["state"] != "desired-not-activated":
        raise ValueError("MoneyBee runtime activation is not authorized")
    upstream = spec["upstream"]
    route = spec["routes"][0]
    guard = (ROOT / route["claimEnforcement"]["source"]).read_text()
    return {
        "_format_version": "3.0",
        "_transform": True,
        "services": [{
            "name": upstream["serviceName"], "enabled": True,
            "protocol": upstream["protocol"], "host": upstream["host"], "port": upstream["port"],
            "connect_timeout": 3000, "read_timeout": 30000, "write_timeout": 30000, "retries": 0,
            "routes": [{
                "name": route["name"], "protocols": ["http"],
                "hosts": [spec["canonicalHost"]], "paths": [route["path"]],
                "methods": route["methods"], "strip_path": False, "preserve_host": False,
                "path_handling": "v0", "https_redirect_status_code": 426,
                "request_buffering": True, "response_buffering": True,
            }],
            "plugins": [
                {"name": "openid-connect", "config": {
                    "auth_methods": route["openidConnect"]["authMethods"],
                    "issuer": route["openidConnect"]["issuerDiscovery"],
                    "audience": route["openidConnect"]["audience"],
                    "consumer_claim": route["openidConnect"]["consumerClaim"],
                    "cache_tokens_salt": "{vault://env/kong-oidc-cache-tokens-salt}",
                }},
                {"name": "post-function", "config": {"access": [guard]}},
                {"name": "correlation-id", "config": {"header_name": "X-Correlation-ID", "generator": "uuid", "echo_downstream": True}},
                {"name": "rate-limiting", "config": {"minute": route["rateLimitPerMinute"], "policy": "redis", "fault_tolerant": False,
                    "redis": {"host": "codestra-redis", "port": 6379, "database": 0, "timeout": 2000,
                              "password": "{vault://env/kong-rate-limit-redis-password}"}}},
                {"name": "request-size-limiting", "config": {"allowed_payload_size": route["maxBodyBytes"], "size_unit": "bytes", "require_content_length": True}},
                {"name": "response-transformer", "config": {"remove": {"headers": ["Server"]}}},
            ],
        }],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if args.apply:
        parser.error("runtime apply is not authorized")
    print(yaml.safe_dump(render(), sort_keys=False), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
