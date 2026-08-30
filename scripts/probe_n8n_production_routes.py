#!/usr/bin/env python3
"""Read-only production route-registration probe for the N8N control plane."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request


PROBES = (
    ("POST", "/v1/integrations/n8n/commands"),
    ("GET", "/v1/integrations/n8n/operations/00000000-0000-0000-0000-000000000000"),
)
REACHABLE_STATUSES = {400, 401, 403, 404}


def probe(base_url: str, method: str, path: str) -> tuple[int, str]:
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=b"{}" if method == "POST" else None,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def is_framework_404(status: int, body: str) -> bool:
    if status != 404:
        return False
    lowered = body.lower()
    return '"detail":"not found"' in lowered or "404 page not found" in lowered


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="https://api.codestra.co")
    args = parser.parse_args()
    blocked = False
    for method, path in PROBES:
        status, body = probe(args.base_url, method, path)
        framework_404 = is_framework_404(status, body)
        reached = status in REACHABLE_STATUSES and not framework_404
        print(json.dumps({
            "method": method,
            "path": path,
            "status": status,
            "registered_route_reached": reached,
            "framework_404": framework_404,
        }, sort_keys=True))
        blocked = blocked or not reached
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
