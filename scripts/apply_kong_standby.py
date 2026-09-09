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

from kong_admin_channel import admin_request, confirm_unchanged, entity_id  # noqa: E402

TAG = "codestra-kong-standby-20260820"
HOST = "kong-standby.internal.codestra.agency"
ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "deploy/kong-production-standby/kong/standby.json").read_text())


def request(method: str, path: str, payload=None):
    # Admin has no host publication; every call enters the verified gateway
    # container instead of crossing a management port.
    return admin_request(method, path, payload)


def collection_rows(response, context: str) -> list[dict]:
    """Return one complete, structurally valid Kong collection page."""
    if not isinstance(response, dict):
        raise RuntimeError(f"invalid Kong {context} response")
    data = response.get("data")
    if (not isinstance(data, list) or not all(isinstance(item, dict) for item in data)
            or response.get("next")):
        raise RuntimeError(f"incomplete or invalid Kong {context} collection")
    return data


def upsert(collection: str, name: str, payload: dict):
    query = urllib.parse.urlencode({"name": name, "size": 1000})
    collection_page = request("GET", f"/{collection}?{query}")
    existing = collection_rows(collection_page, collection)
    if len(existing) > 1:
        raise RuntimeError(f"ambiguous Kong {collection} named {name}")
    if existing:
        if TAG not in (existing[0].get("tags") or []):
            raise RuntimeError(
                f"refusing to adopt unowned Kong {collection} named {name}"
            )
        identifier = entity_id(existing[0].get("id"), collection.rstrip("s"))
        return request("PATCH", f"/{collection}/{identifier}", payload)
    return request("POST", f"/{collection}", payload)


def plugin(route_id: str, name: str, config: dict):
    route_id = entity_id(route_id, "route")
    current = collection_rows(
        request("GET", f"/routes/{route_id}/plugins?size=1000"), "route plugins"
    )
    same_name = [item for item in current if item.get("name") == name]
    unowned = [item for item in same_name if TAG not in (item.get("tags") or [])]
    if unowned:
        raise RuntimeError(f"refusing to replace unowned route plugin {name}")
    matches = [item for item in same_name if TAG in (item.get("tags") or [])]
    if len(matches) > 1:
        raise RuntimeError(f"ambiguous managed route plugin {name}")
    payload = {"name": name, "enabled": True, "config": config, "tags": [TAG]}
    if matches:
        identifier = entity_id(matches[0].get("id"), "plugin")
        return request("PATCH", f"/plugins/{identifier}", payload)
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
        service_id = entity_id(service.get("id"), "service")
        route_name = item["name"] + "-route"
        route = upsert("routes", route_name, {
            "name": route_name, "service": {"id": service_id},
            "hosts": [HOST], "paths": [item["path"]], "methods": item["methods"],
            "protocols": ["http", "https"], "strip_path": False,
            "preserve_host": False, "tags": [TAG, "private-staging-only"],
        })
        route_id = entity_id(route.get("id"), "route")
        plugin(route_id, "request-transformer", {
            "remove": {"headers": CONFIG["trustedHeadersToStrip"]},
        })
        plugin(route_id, "ip-restriction", {"allow": ["127.0.0.1", "172.19.0.1"], "deny": None, "status": 403})
        plugin(route_id, "request-size-limiting", {
            "allowed_payload_size": item["bodyLimitBytes"], "size_unit": "bytes",
            "require_content_length": True,
        })
        plugin(route_id, "rate-limiting", {
            "minute": item["ratePerMinute"], "limit_by": "ip", "policy": "local",
            "fault_tolerant": False, "hide_client_headers": False,
        })
        applied.append(route_name)
    expected_plugins = {"request-transformer", "ip-restriction", "request-size-limiting", "rate-limiting"}
    for route_name in applied:
        routes = collection_rows(
            request("GET", "/routes?" + urllib.parse.urlencode({"name": route_name, "size": 1000})),
            "route read-back",
        )
        if len(routes) != 1:
            raise RuntimeError(f"route read-back failed: {route_name}")
        route = routes[0]
        if route.get("hosts") != [HOST] or TAG not in (route.get("tags") or []):
            raise RuntimeError(f"route isolation read-back failed: {route_name}")
        route_id = entity_id(route.get("id"), "route")
        plugins = collection_rows(
            request("GET", f"/routes/{route_id}/plugins?size=1000"),
            "plugin read-back",
        )
        names = {item.get("name") for item in plugins if item.get("enabled")}
        if not all(isinstance(name, str) for name in names):
            raise RuntimeError(f"invalid plugin read-back: {route_name}")
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
            with urllib.request.urlopen(probe, timeout=2):
                pass
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            if code == 401:
                break
        except urllib.error.URLError:
            # The router can briefly refuse connections while workers reload.
            pass
        if attempt == 9:
            raise RuntimeError("Kong data-plane policy synchronization failed")
        time.sleep(0.5)
    confirm_unchanged()
    print("KONG_PRIVATE_STANDBY_APPLY=PASS")
    print("ROUTES=" + ",".join(applied))
    print("PUBLIC_HOST_ATTACHED=NO")


if __name__ == "__main__":
    main()
