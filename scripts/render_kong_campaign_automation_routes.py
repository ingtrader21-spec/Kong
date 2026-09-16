#!/usr/bin/env python3
"""Render a campaign-automation manifest as a Kong declarative fragment for validation.

Source-only: the output exists so ``deck file validate`` can parse the exact
routes, methods, regex paths and plugin configuration the reconciler would
apply. Consumer JWT credentials are deliberately absent; the reconciler
provisions them from the realm's live JWKS and this repository never carries
key material. Nothing here contacts a Kong node.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = str(ROOT / "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import reconcile_kong_campaign_automation as campaign  # noqa: E402

MANIFESTS = {
    "production": ROOT / "config/kong-campaign-automation-routes.json",
    "staging": ROOT / "config/staging/kong-campaign-automation-routes.json",
}


def load_manifest(environment: str) -> dict[str, Any]:
    manifest = json.loads(MANIFESTS[environment].read_text(encoding="utf-8"))
    if manifest["environment"] != environment:
        raise ValueError(f"manifest environment {manifest['environment']!r} is not {environment!r}")
    campaign.validate_manifest_routes(manifest)
    return manifest


def route_entry(manifest: dict[str, Any], route: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": route["name"],
        "protocols": ["http"],
        "hosts": [manifest["host"]],
        "paths": [route["path"]],
        "methods": [campaign.route_method(route)],
        "strip_path": False,
        "preserve_host": False,
        "https_redirect_status_code": 426,
        "tags": [f"scope:{route['scope']}", f"environment:{manifest['environment']}"],
        "plugins": [
            {
                "name": "jwt",
                "config": {
                    "key_claim_name": "azp",
                    "claims_to_verify": ["exp"],
                    "header_names": ["authorization"],
                    "run_on_preflight": True,
                },
            },
            {
                "name": "post-function",
                "config": {"access": [campaign.claim_guard(manifest, route["scope"])]},
            },
            {
                "name": "request-size-limiting",
                "config": {"allowed_payload_size": route["max_body_mb"]},
            },
            {
                "name": "rate-limiting",
                "config": {
                    "minute": route["rate_per_minute"],
                    "policy": "redis",
                    "limit_by": "consumer",
                    "fault_tolerant": False,
                    "redis": {
                        "host": "codestra-redis",
                        "port": 6379,
                        "database": 0,
                        "timeout": 2000,
                        "password": "{vault://env/kong-rate-limit-redis-password}",
                    },
                },
            },
            {
                "name": "correlation-id",
                "config": {
                    "header_name": "X-Correlation-ID",
                    "generator": "uuid",
                    "echo_downstream": True,
                },
            },
        ],
    }


def render(environment: str) -> dict[str, Any]:
    manifest = load_manifest(environment)
    service = manifest["service"]
    return {
        "_format_version": "3.0",
        "_info": {"select_tags": [f"codestra-campaign-automation-{environment}"]},
        "services": [
            {
                "name": service["name"],
                "protocol": service["protocol"],
                "host": service["host"],
                "port": service["port"],
                "routes": [route_entry(manifest, route) for route in manifest["routes"]],
            }
        ],
        "consumers": [
            campaign.consumer_entity(consumer) for consumer in campaign.manifest_consumers(manifest)
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", choices=sorted(MANIFESTS), default="production")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    document = render(args.environment)
    if args.json:
        print(json.dumps(document, indent=2, sort_keys=False))
    else:
        print(yaml.safe_dump(document, sort_keys=False), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
