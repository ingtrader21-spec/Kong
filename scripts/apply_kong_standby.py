#!/usr/bin/env python3
"""Idempotently apply private, mock-only Kong standby routes.

This script never creates a route for api.codestra.co and never targets a
provider. It is safe to rerun and tags every object for exact rollback.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SCRIPTS = str(Path(__file__).resolve().parent)
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from kong_admin_channel import admin_request, confirm_unchanged  # noqa: E402

TAG = "codestra-kong-standby-20260820"
HOST = "kong-standby.internal.codestra.agency"
ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "deploy/kong-production-standby/kong/standby.json").read_text())


def request(method: str, path: str, payload=None):
    # Admin has no host publication; every call enters the verified gateway
    # container instead of crossing a management port.
    return admin_request(method, path, payload)


def upsert(collection: str, name: str, payload: dict):
    query = urllib.parse.urlencode({"name": name})
    existing = (request("GET", f"/{collection}?{query}") or {}).get("data", [])
    if len(existing) > 1:
        raise RuntimeError(f"ambiguous Kong {collection} named {name}")
    if existing:
        if TAG not in (existing[0].get("tags") or []):
            raise RuntimeError(
                f"refusing to adopt unowned Kong {collection} named {name}"
            )
        return request("PATCH", f"/{collection}/{existing[0]['id']}", payload)
    return request("POST", f"/{collection}", payload)


def plugin(route_id: str, name: str, config: dict):
    current = (request("GET", f"/routes/{route_id}/plugins") or {}).get("data", [])
    same_name = [item for item in current if item["name"] == name]
    unowned = [item for item in same_name if TAG not in (item.get("tags") or [])]
    if unowned:
        raise RuntimeError(f"refusing to replace unowned route plugin {name}")
    matches = [item for item in same_name if TAG in (item.get("tags") or [])]
    if len(matches) > 1:
        raise RuntimeError(f"ambiguous managed route plugin {name}")
    payload = {"name": name, "enabled": True, "config": config, "tags": [TAG]}
    if matches:
        return request("PATCH", f"/plugins/{matches[0]['id']}", payload)
    return request("POST", f"/routes/{route_id}/plugins", payload)


def main():
    applied = []
    for item in CONFIG["services"]:
        service = upsert("services", item["name"], {
            "name": item["name"], "protocol": "http", "host": "codestra-kong-standby-auth",
            "port": 8080, "path": None, "retries": 0,
            "connect_timeout": item["connectTimeoutMs"],
            "write_timeout": item["writeTimeoutMs"], "read_timeout": item["readTimeoutMs"],
            "tags": [TAG, "mock-only", "no-provider-delivery"],
        })
        route_name = item["name"] + "-route"
        route = upsert("routes", route_name, {
            "name": route_name, "service": {"id": service["id"]},
            "hosts": [HOST], "paths": [item["path"]], "methods": item["methods"],
            "protocols": ["http", "https"], "strip_path": False,
            "preserve_host": False, "tags": [TAG, "private-staging-only"],
        })
        plugin(route["id"], "request-transformer", {
            "remove": {"headers": CONFIG["trustedHeadersToStrip"]},
        })
        plugin(route["id"], "ip-restriction", {"allow": ["127.0.0.1", "172.19.0.1"], "deny": None, "status": 403})
        plugin(route["id"], "request-size-limiting", {
            "allowed_payload_size": item["bodyLimitBytes"], "size_unit": "bytes",
            "require_content_length": True,
        })
        plugin(route["id"], "rate-limiting", {
            "minute": item["ratePerMinute"], "limit_by": "ip", "policy": "local",
            "fault_tolerant": False, "hide_client_headers": False,
        })
        applied.append(route_name)
    expected_plugins = {"request-transformer", "ip-restriction", "request-size-limiting", "rate-limiting"}
    for route_name in applied:
        routes = (request("GET", "/routes?" + urllib.parse.urlencode({"name": route_name})) or {}).get("data", [])
        if len(routes) != 1:
            raise RuntimeError(f"route read-back failed: {route_name}")
        route = routes[0]
        if route.get("hosts") != [HOST] or TAG not in (route.get("tags") or []):
            raise RuntimeError(f"route isolation read-back failed: {route_name}")
        names = {item["name"] for item in (request("GET", f"/routes/{route['id']}/plugins") or {}).get("data", []) if item.get("enabled")}
        if not expected_plugins.issubset(names):
            raise RuntimeError(f"plugin read-back failed: {route_name}: {sorted(names)}")
    # Kong workers update their router/plugin cache asynchronously.  Wait until
    # the data plane observes the newly applied policy before reporting PASS.
    for attempt in range(10):
        probe = urllib.request.Request(
            "http://127.0.0.1:8000/v1/sms",
            data=b'{}', method="POST",
            headers={"Host": HOST, "Content-Type": "application/json", "Idempotency-Key": "apply-probe"},
        )
        try:
            urllib.request.urlopen(probe, timeout=2)
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                break
        if attempt == 9:
            raise RuntimeError("Kong data-plane policy synchronization failed")
        time.sleep(0.5)
    confirm_unchanged()
    print("KONG_PRIVATE_STANDBY_APPLY=PASS")
    print("ROUTES=" + ",".join(applied))
    print("PUBLIC_HOST_ATTACHED=NO")


if __name__ == "__main__":
    main()
