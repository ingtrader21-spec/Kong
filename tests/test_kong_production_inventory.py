from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "scripts/validate_kong_production_inventory.py"
SPEC = importlib.util.spec_from_file_location("production_inventory", PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def test_canonical_production_inventory_passes() -> None:
    module.validate()


def test_exact_readback_is_sanitized_and_complete() -> None:
    evidence = json.loads(module.EVIDENCE.read_text())
    assert evidence["captureMode"] == "READ_ONLY_ADMIN_GET_SANITIZED"
    assert evidence["adminExposure"] == "LOOPBACK_ONLY"
    assert evidence["databaseReachable"] is True
    assert evidence["expectedRouteCount"] == evidence["actualRouteCount"] == 29
    assert all(set(route) == {
        "name", "hosts", "paths", "methods", "protocols", "strip_path",
        "preserve_host", "service", "plugins"
    } for route in evidence["routes"])


def test_direct_provider_drift_is_replaced_by_middleware_candidate() -> None:
    candidate = json.loads(module.INVENTORY.read_text())
    routes = {route["name"]: route for route in candidate["routes"]}
    for name in ("breero-production-api-route", "codestra-website-api-route"):
        assert routes[name]["service"]["host"] == "codestra-middleware-integration-api-1"
        assert routes[name]["service"]["port"] == 8095
        assert routes[name]["service"]["protocol"] == "http"


def test_v2_successor_retires_overlapping_public_routes() -> None:
    candidate = json.loads(module.INVENTORY.read_text())
    assert candidate["expectedRouteCount"] == len(candidate["routes"]) == 27
    retired = {item["route"] for item in candidate["retiredDuplicateRoutes"]}
    assert retired == {"cod-web-out-email-production", "codestra-communication-oauth-shadow-create"}
