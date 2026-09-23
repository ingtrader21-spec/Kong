#!/usr/bin/env python3
"""Read-only PAS-236 Kong route reconciliation planner.

This tool never mutates Kong. It reads the bounded private Admin API, compares
live route/service bindings with the governed PAS-236 disposition manifest, and
emits a deterministic plan for later independently gated apply/rollback work.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPTS = str(Path(__file__).resolve().parent)
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from kong_admin_channel import (
    PRIVATE_ADMIN_URL,
    admin_request,
    collect_admin_rows,
    http_admin_request,
    http_admin_url,
    normalize_admin_reference,
    open_admin_request as urlopen,
)

ALLOWED_DECISIONS = {"REPOINT", "RETIRE", "EXCEPTION"}


def request(base: str, path: str) -> dict:
    if base == PRIVATE_ADMIN_URL:
        return admin_request("GET", normalize_admin_reference(path)) or {}
    return http_admin_request(base, "GET", path, timeout=15, opener=urlopen) or {}


def all_rows(base: str, path: str) -> list[dict]:
    normalize = (
        normalize_admin_reference
        if base == PRIVATE_ADMIN_URL
        else lambda value: http_admin_url(base, value)
    )
    return collect_admin_rows(lambda value: request(base, value), path, normalize)


def upstream_for(route: dict, services: dict[str, dict]) -> dict:
    service_id = (route.get("service") or {}).get("id")
    service = services.get(service_id, {})
    return {
        "service": service.get("name"),
        "host": service.get("host"),
        "port": service.get("port"),
        "protocol": service.get("protocol"),
    }


def validate_manifest(manifest: dict) -> None:
    if manifest.get("runtime_apply_authorized") is not False:
        raise RuntimeError("planner manifest must keep runtime_apply_authorized=false")
    rows = manifest.get("routes")
    if not isinstance(rows, list) or len(rows) != 24:
        raise RuntimeError("PAS-236 manifest must contain exactly 24 route dispositions")
    names = [row.get("name") for row in rows]
    if any(not isinstance(name, str) or not name for name in names) or len(set(names)) != len(names):
        raise RuntimeError("route disposition names must be unique non-empty strings")
    for row in rows:
        decision = row.get("decision")
        if decision not in ALLOWED_DECISIONS:
            raise RuntimeError(f"unsupported route disposition: {row.get('name')}")
        if decision == "REPOINT":
            target = row.get("target")
            if not isinstance(target, dict) or target.get("port") != 8095 or not target.get("host"):
                raise RuntimeError(f"invalid canonical target: {row.get('name')}")
        if decision == "EXCEPTION":
            expected = row.get("expected")
            if not isinstance(expected, dict) or not expected.get("host") or not expected.get("port"):
                raise RuntimeError(f"invalid exception target: {row.get('name')}")


def build_plan(manifest: dict, routes: list[dict], services: list[dict]) -> dict:
    validate_manifest(manifest)
    by_route: dict[str, list[dict]] = {}
    for route in routes:
        if route.get("name"):
            by_route.setdefault(route["name"], []).append(route)
    service_by_id = {row["id"]: row for row in services if isinstance(row.get("id"), str)}

    plan = []
    for spec in sorted(manifest["routes"], key=lambda item: item["name"]):
        matches = by_route.get(spec["name"], [])
        if len(matches) != 1:
            plan.append({
                "route": spec["name"],
                "decision": spec["decision"],
                "action": "ERROR",
                "reason": "missing_live_route" if not matches else "duplicate_live_route",
            })
            continue

        route = matches[0]
        current = upstream_for(route, service_by_id)
        decision = spec["decision"]
        item = {
            "route": spec["name"],
            "decision": decision,
            "current": current,
        }

        if decision == "REPOINT":
            target = spec["target"]
            item["target"] = target
            item["action"] = (
                "KEEP"
                if current["host"] == target["host"] and current["port"] == target["port"]
                else "UPDATE"
            )
        elif decision == "RETIRE":
            item["action"] = "DELETE"
            if spec.get("successor"):
                item["successor"] = spec["successor"]
                item["successor_present"] = len(by_route.get(spec["successor"], [])) == 1
                if not item["successor_present"]:
                    item["action"] = "ERROR"
                    item["reason"] = "required_successor_missing"
        else:
            expected = spec["expected"]
            item["expected"] = expected
            item["action"] = (
                "KEEP"
                if current["host"] == expected["host"] and current["port"] == expected["port"]
                else "ERROR"
            )
            if item["action"] == "ERROR":
                item["reason"] = "exception_upstream_drift"
        if spec.get("note"):
            item["note"] = spec["note"]
        plan.append(item)

    counts = {}
    for item in plan:
        counts[item["action"]] = counts.get(item["action"], 0) + 1
    return {
        "schema": "codestra.kong.route-reconciliation-plan.pas236.v1",
        "mode": "dry-run",
        "runtime_apply_performed": False,
        "source_main_sha": manifest["source_main_sha"],
        "summary": dict(sorted(counts.items())),
        "plan": plan,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admin-url", default=PRIVATE_ADMIN_URL)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("config/kong-route-reconciliation.pas236.json"),
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    result = build_plan(
        manifest,
        all_rows(args.admin_url, "/routes?size=1000"),
        all_rows(args.admin_url, "/services?size=1000"),
    )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)

    if any(item["action"] == "ERROR" for item in result["plan"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
