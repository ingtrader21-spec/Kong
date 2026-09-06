#!/usr/bin/env python3
"""Validate the source-only Codestra Kong cell platform contract."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str) -> dict:
    path = ROOT / "config" / name
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate() -> None:
    cells = load("codestra-kong-cells.v1.json")
    policies = load("codestra-kong-policy-chains.v1.json")
    routes = load("codestra-kong-route-registry.v1.json")

    assert cells["schema_version"] == "1.0"
    expected = {"core-communications", "beyvra-financial", "telephony-private"}
    actual = {cell["id"] for cell in cells["cells"]}
    assert actual == expected, (actual, expected)

    databases = [cell["control_plane_database"] for cell in cells["cells"]]
    namespaces = [cell["rate_limit_namespace"] for cell in cells["cells"]]
    assert len(databases) == len(set(databases)), "cell databases must be unique"
    assert len(namespaces) == len(set(namespaces)), "rate-limit namespaces must be unique"
    assert all(value is False for value in cells["capabilities"].values())

    required_chains = {"global", "browser", "service", "webhook"}
    assert set(policies["chains"]) == required_chains
    assert policies["chains"]["webhook"]["direct_n8n_target"] is False
    assert policies["mutation_retry_authority"] == "MIDDLEWARE"

    route_ids: set[str] = set()
    route_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    for route in routes["routes"]:
        assert route["id"] not in route_ids, f"duplicate route id: {route['id']}"
        route_ids.add(route["id"])
        assert route["cell"] in expected
        assert route["policy_chain"] in required_chains
        assert route["methods"] and all(method.isupper() for method in route["methods"])
        assert route["upstream"].startswith("middleware-")
        assert "n8n" not in route["upstream"].lower()
        key = (route["host"], route["path_prefix"], tuple(sorted(route["methods"])))
        assert key not in route_keys, f"route collision: {key}"
        route_keys.add(key)

    invariants = routes["invariants"]
    assert invariants["all_upstreams_are_middleware"] is True
    assert invariants["direct_n8n_routes"] is False
    assert invariants["direct_provider_routes"] is False
    assert invariants["live_sync_authorized"] is False


if __name__ == "__main__":
    validate()
    print("CODESTRA_KONG_CELL_PLATFORM=PASS")
