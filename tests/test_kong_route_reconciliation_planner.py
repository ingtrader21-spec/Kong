import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pas244_planner", ROOT / "scripts" / "plan_kong_route_reconciliation.py"
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MOD)


def manifest():
    return json.loads((ROOT / "config" / "kong-route-reconciliation.pas236.json").read_text())


def live_rows():
    services = []
    routes = []
    for idx, spec in enumerate(manifest()["routes"], start=1):
        sid = f"00000000-0000-0000-0000-{idx:012d}"
        decision = spec["decision"]
        upstream = (
            spec["target"] if decision == "REPOINT"
            else spec["expected"] if decision == "EXCEPTION"
            else {"host": "legacy-upstream", "port": 8080}
        )
        services.append({
            "id": sid,
            "name": f"service-{idx}",
            "host": upstream["host"],
            "port": upstream["port"],
            "protocol": "http",
        })
        routes.append({"id": f"route-{idx}", "name": spec["name"], "service": {"id": sid}})
    return routes, services


def test_manifest_is_bounded_and_apply_disabled():
    value = manifest()
    MOD.validate_manifest(value)
    assert value["runtime_apply_authorized"] is False
    assert len(value["routes"]) == 24
    assert sum(r["decision"] == "REPOINT" for r in value["routes"]) == 13
    assert sum(r["decision"] == "RETIRE" for r in value["routes"]) == 7
    assert sum(r["decision"] == "EXCEPTION" for r in value["routes"]) == 4


def test_plan_is_deterministic_and_never_applies():
    routes, services = live_rows()
    first = MOD.build_plan(manifest(), routes, services)
    second = MOD.build_plan(manifest(), list(reversed(routes)), list(reversed(services)))
    assert first == second
    assert first["runtime_apply_performed"] is False
    assert first["summary"] == {"DELETE": 7, "KEEP": 17}


def test_repoint_drift_becomes_update():
    routes, services = live_rows()
    target = next(r for r in routes if r["name"] == "breero-production-api-route")
    sid = target["service"]["id"]
    service = next(s for s in services if s["id"] == sid)
    service["host"] = "scraper.internal.codestra.agency"
    service["port"] = 8443
    plan = MOD.build_plan(manifest(), routes, services)
    row = next(r for r in plan["plan"] if r["route"] == "breero-production-api-route")
    assert row["action"] == "UPDATE"


def test_exception_drift_is_error_not_update():
    routes, services = live_rows()
    target = next(r for r in routes if r["name"] == "codestra-email-standby-route")
    sid = target["service"]["id"]
    service = next(s for s in services if s["id"] == sid)
    service["host"] = "unexpected"
    plan = MOD.build_plan(manifest(), routes, services)
    row = next(r for r in plan["plan"] if r["route"] == "codestra-email-standby-route")
    assert row["action"] == "ERROR"
