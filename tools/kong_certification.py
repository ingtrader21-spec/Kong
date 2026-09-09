"""Validate bounded staging observations; source checks are never runtime proof.

The protected runtime-certification workflow is the observation trust boundary.
These predicates validate completeness and candidate identity, not provenance;
verify_staging_certification authenticates the producing run and artifact.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MAX_DOCUMENT = 1024 * 1024
MAX_AGE_SECONDS = 86400
SHA = re.compile(r"[0-9a-f]{40}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SCHEMA = "codestra.kong.runtime-certification.v1"
EFFECTS = (
    "calls", "emails", "sms", "payments", "social_posts", "advertising_actions",
    "odoo_writes", "n8n_provider_deliveries", "external_ai_effects",
)
GLOBAL_CHECKS = (
    "private_admin_peer_denial", "private_manager_peer_denial", "private_database",
    "private_redis", "designated_networks", "redis_failure_closed", "no_direct_provider_routes",
    "upstream_mtls", "certificate_sni", "certificate_expiry", "observability_metrics",
    "observability_alerts", "backup_restore", "pitr", "configuration_rollback",
    "previous_digest_restored", "websocket_upgrade", "webhook_signature_preservation",
    "webhook_replay_denied", "idempotency_replay", "idempotency_conflict",
    "cors_denied", "forwarded_identity_spoof_denied", "all_targets_unhealthy_closed",
    "read_only_canary", "bounded_soak", "zero_route_plugin_drift",
)
ROUTE_CHECKS = (
    "route_match", "upstream_identity", "plugin_state", "health_readiness",
    "authentication", "authorization", "request_body_limit", "rate_limit",
    "upstream_timeout", "upstream_failure", "write_effect_boundary",
)
JWT_CHECKS = ("wrong_issuer", "wrong_audience", "wrong_azp", "wrong_scope", "wrong_tenant")
CANDIDATE_FIELDS = (
    "source_sha", "source_tree", "kong_image_digest", "standby_auth_image_digest",
    "kong_declarative_config_sha256", "rollback_source_sha",
)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError("nonfinite_json")


def decode(raw: bytes) -> dict:
    require(len(raw) <= MAX_DOCUMENT, "oversized_certification")
    value = json.loads(raw, object_pairs_hook=object_pairs, parse_constant=reject_constant)
    require(isinstance(value, dict), "invalid_certification_shape")
    return value


def timestamp(value) -> datetime:
    require(isinstance(value, str) and value.endswith("Z"), "invalid_evidence_time")
    result = datetime.fromisoformat(value[:-1] + "+00:00")
    require(result.utcoffset().total_seconds() == 0, "invalid_evidence_time")
    return result


def contract_matrix(inventory: dict) -> dict[str, tuple[str, ...]]:
    require(inventory.get("schema") == "codestra.kong.production-route-inventory.v2",
            "unrecognized_route_authority")
    routes = inventory.get("routes")
    require(isinstance(routes, list) and routes and
            type(inventory.get("expectedRouteCount")) is int and
            inventory["expectedRouteCount"] == len(routes), "invalid_route_authority")
    result = {}
    for route in routes:
        require(isinstance(route, dict), "invalid_route_authority")
        name, plugins = route.get("name"), route.get("plugins")
        require(isinstance(name, str) and name and name not in result and
                isinstance(plugins, list) and all(isinstance(p, str) for p in plugins),
                "invalid_route_authority")
        result[name] = ROUTE_CHECKS + (JWT_CHECKS if {"openid-connect", "jwt"}.intersection(plugins) else ())
    return result


def checks(observed, required) -> None:
    require(isinstance(observed, dict) and set(observed) == set(required), "incomplete_check_matrix")
    for value in observed.values():
        require(isinstance(value, dict) and set(value) == {"passed", "observation_sha256"},
                "invalid_check_record")
        require(value["passed"] is True, "runtime_check_failed")
        require(isinstance(value["observation_sha256"], str) and
                bool(HASH.fullmatch(value["observation_sha256"])), "observation_reference_missing")


def validate(document: dict, candidate: dict, inventory: dict, *, now=None) -> None:
    fields = {"schema", "environment", "candidate", "candidate_manifest_sha256",
              "route_inventory_sha256", "started_at", "completed_at", "route_checks",
              "global_checks", "effects_before", "effects_after", "rollback",
              "canary", "secrets_captured", "public_traffic_percent"}
    require(isinstance(document, dict) and set(document) == fields, "invalid_certification_fields")
    require(document["schema"] == SCHEMA and document["environment"] == "isolated-staging",
            "not_isolated_staging")
    require(document["secrets_captured"] is False and
            type(document["public_traffic_percent"]) is int and document["public_traffic_percent"] == 0,
            "unsafe_staging_observation")
    identity = document["candidate"]
    require(isinstance(identity, dict) and set(identity) == set(CANDIDATE_FIELDS), "invalid_candidate_identity")
    for field in CANDIDATE_FIELDS:
        pattern = DIGEST if field.endswith("image_digest") else HASH if field.endswith("sha256") else SHA
        value = identity[field]
        require(isinstance(value, str) and bool(pattern.fullmatch(value)) and value == candidate.get(field),
                "certification_candidate_mismatch")
    for field in ("candidate_manifest_sha256", "route_inventory_sha256"):
        require(isinstance(document[field], str) and bool(HASH.fullmatch(document[field])), "invalid_authority_hash")
    start, end = timestamp(document["started_at"]), timestamp(document["completed_at"])
    current = now or datetime.now(timezone.utc)
    require(start <= end <= current and (current - end).total_seconds() <= MAX_AGE_SECONDS and
            (end - start).total_seconds() <= MAX_AGE_SECONDS, "stale_or_invalid_certification")
    matrix = contract_matrix(inventory)
    routes = document["route_checks"]
    require(isinstance(routes, dict) and set(routes) == set(matrix), "incomplete_route_matrix")
    for name, required in matrix.items():
        checks(routes[name], required)
    checks(document["global_checks"], GLOBAL_CHECKS)
    for field in ("effects_before", "effects_after"):
        values = document[field]
        require(isinstance(values, dict) and set(values) == set(EFFECTS) and
                all(type(value) is int and value == 0 for value in values.values()), "external_effects_not_zero")
    rollback = document["rollback"]
    require(isinstance(rollback, dict) and set(rollback) == {
        "source_sha", "image_digest", "config_sha256", "backup_sha256", "restore_observation_sha256"},
        "invalid_rollback_proof")
    require(rollback["source_sha"] == candidate["rollback_source_sha"], "wrong_rollback_source")
    for field, pattern in (("image_digest", DIGEST), ("config_sha256", HASH),
                           ("backup_sha256", HASH), ("restore_observation_sha256", HASH)):
        require(isinstance(rollback[field], str) and bool(pattern.fullmatch(rollback[field])), "incomplete_rollback_proof")
    canary = document["canary"]
    require(isinstance(canary, dict) and set(canary) == {"methods", "traffic_basis_points", "observed_requests"},
            "invalid_canary_proof")
    require(canary["methods"] == ["GET", "HEAD"] and type(canary["traffic_basis_points"]) is int and
            0 < canary["traffic_basis_points"] <= 100 and type(canary["observed_requests"]) is int and
            canary["observed_requests"] > 0, "unsafe_or_empty_canary")


def validate_bytes(raw: bytes, candidate_raw: bytes, inventory_raw: bytes, *, now=None) -> dict:
    document, candidate, inventory = decode(raw), decode(candidate_raw), decode(inventory_raw)
    validate(document, candidate, inventory, now=now)
    require(document["candidate_manifest_sha256"] == hashlib.sha256(candidate_raw).hexdigest(),
            "candidate_manifest_hash_mismatch")
    require(document["route_inventory_sha256"] == hashlib.sha256(inventory_raw).hexdigest(),
            "route_inventory_hash_mismatch")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a source-only certification matrix, never a PASS report.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, default=ROOT / "config/kong-production-route-inventory.v2.json")
    args = parser.parse_args()
    try:
        raw = args.inventory.read_bytes()
        matrix = contract_matrix(decode(raw))
        plan = {"schema": "codestra.kong.runtime-certification-plan.v1", "runtime_certified": False,
                "route_inventory_sha256": hashlib.sha256(raw).hexdigest(),
                "route_checks": {name: list(required) for name, required in sorted(matrix.items())},
                "global_checks": list(GLOBAL_CHECKS), "effect_counters": list(EFFECTS),
                "evidence_max_age_seconds": MAX_AGE_SECONDS}
        args.output.write_text(json.dumps(plan, sort_keys=True, indent=2) + "\n")
        print("KONG_CERTIFICATION_PLAN=PASS RUNTIME_CERTIFIED=NO")
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        print("KONG_CERTIFICATION_PLAN=FAIL")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
