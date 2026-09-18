#!/usr/bin/env python3
"""Validate the canonical 29-route production candidate without applying it."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "config/kong-production-route-inventory.v2.json"
EVIDENCE = ROOT / "docs/evidence/PRODUCTION_ROUTE_READBACK_20260906.json"
FORBIDDEN_DIRECT_HOSTS = {"scraper.internal.codestra.agency", "10.40.0.3"}


def validate() -> None:
    candidate = json.loads(INVENTORY.read_text())
    evidence = json.loads(EVIDENCE.read_text())
    assert candidate["schema"] == "codestra.kong.production-route-inventory.v2"
    assert candidate["status"] == "SOURCE_CANDIDATE_NO_RUNTIME_APPLY"
    assert candidate["runtimeApplyAuthorized"] is False
    routes = candidate["routes"]
    assert candidate["expectedRouteCount"] == len(routes) == 27
    names = [route["name"] for route in routes]
    assert len(names) == len(set(names)), "duplicate route names"
    retired = {item["route"] for item in candidate["retiredDuplicateRoutes"]}
    assert retired == {"cod-web-out-email-production", "codestra-communication-oauth-shadow-create"}
    assert set(names) | retired == {route["name"] for route in evidence["routes"]}, "unknown or missing route"

    keys: set[tuple[str, str, str]] = set()
    for route in routes:
        assert route["hosts"] and route["paths"] and route["methods"]
        assert route["plugins"] == sorted(set(route["plugins"])), f"plugin drift: {route['name']}"
        assert route["service"]["host"] not in FORBIDDEN_DIRECT_HOSTS
        for host in route["hosts"]:
            for path in route["paths"]:
                for method in route["methods"]:
                    key = (host, path, method)
                    assert key not in keys, f"duplicate route match: {key}"
                    keys.add(key)

    blocked = {item["route"]: item for item in candidate["activationBlockedRoutes"]}
    assert set(blocked) == {"codestra-mail-api", "gateway-test-route"}
    assert set(blocked) <= set(names), "activation gate names an unknown route"
    for item in blocked.values():
        assert item["activationAuthorized"] is False and item["reason"] and item["requiredBeforeActivation"]
    by_name = {route["name"]: route for route in routes}
    assert by_name["codestra-mail-api"]["plugins"] == [], "mail route gate assumes the observed empty plugin set"
    assert by_name["gateway-test-route"]["service"]["host"] == "kong-test-upstream"
    migrations = {item["route"] for item in candidate["intentionalFailClosedMigrations"]}
    assert migrations == {"breero-production-api-route", "codestra-website-api-route"}
    assert evidence["actualRouteCount"] == 29
    assert evidence["secretsCaptured"] is False
    assert evidence["runtimeMutated"] is False


if __name__ == "__main__":
    validate()
    print("KONG_PRODUCTION_INVENTORY=PASS ROUTES=27 RETIRED_DUPLICATES=2 ACTIVATION_BLOCKED=2 UNKNOWN=0 DUPLICATES=0 DIRECT_PROVIDER=0")
