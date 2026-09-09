#!/usr/bin/env python3
"""Authenticate a complete staging report from its protected GitHub run/artifact."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import kong_certification as evidence
from tools.verify_release_candidate import api, REPOSITORY
from tools import verify_release_candidate as source_candidate

WORKFLOW = ".github/workflows/runtime-certification.yml"
RECEIPT_SCHEMA = "codestra.kong.staging-receipt.v1"


def validate_run(run: dict, run_id: int, commit: dict, candidate: dict) -> None:
    require = evidence.require
    require(type(run_id) is int and run_id > 0 and run.get("id") == run_id, "wrong_staging_run")
    require(run.get("head_branch") == "staging" and run.get("path") == WORKFLOW and
            run.get("event") == "workflow_dispatch" and run.get("status") == "completed" and
            run.get("conclusion") == "success", "not_completed_runtime_certification")
    for field in ("repository", "head_repository"):
        require(isinstance(run.get(field), dict) and run[field].get("full_name") == REPOSITORY,
                "foreign_staging_repository")
    require(type(run.get("run_attempt")) is int and run["run_attempt"] > 0, "invalid_run_attempt")
    detail = commit.get("commit", {})
    require(commit.get("sha") == run.get("head_sha") and
            detail.get("verification", {}).get("verified") is True and
            detail.get("tree", {}).get("sha") == candidate.get("source_tree"), "unverified_staging_source")


def select_artifact(page: dict, run: dict, source: str) -> dict:
    items = page.get("artifacts")
    evidence.require(isinstance(items, list) and type(page.get("total_count")) is int and
                     len(items) == page["total_count"], "incomplete_staging_artifacts")
    name = f"kong-staging-certification-{source}-{run['run_attempt']}"
    matches = [item for item in items if isinstance(item, dict) and item.get("name") == name]
    evidence.require(len(matches) == 1, "missing_or_ambiguous_staging_artifact")
    item = matches[0]
    evidence.require(type(item.get("id")) is int and item["id"] > 0 and item.get("expired") is False,
                     "invalid_staging_artifact")
    evidence.require(isinstance(item.get("digest"), str) and bool(evidence.DIGEST.fullmatch(item["digest"])) and
                     type(item.get("size_in_bytes")) is int and 0 < item["size_in_bytes"] <= 2 * evidence.MAX_DOCUMENT,
                     "unbounded_or_unhashed_staging_artifact")
    producing = item.get("workflow_run", {})
    evidence.require(producing.get("id") == run["id"] and producing.get("head_sha") == run["head_sha"],
                     "wrong_artifact_run")
    return item


def extract_document(archive: bytes, artifact: dict) -> bytes:
    evidence.require(len(archive) <= 2 * evidence.MAX_DOCUMENT and
                     "sha256:" + hashlib.sha256(archive).hexdigest() == artifact["digest"],
                     "staging_artifact_digest_mismatch")
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        entries = bundle.infolist()
        evidence.require(len(entries) == 1 and entries[0].filename == "certification.json" and
                         not stat.S_ISLNK(entries[0].external_attr >> 16) and
                         not entries[0].flag_bits & 1 and entries[0].file_size <= evidence.MAX_DOCUMENT,
                         "unsafe_staging_archive")
        raw = bundle.read(entries[0])
    return raw


def verified_document(archive: bytes, artifact: dict, candidate_raw: bytes, inventory_raw: bytes, *, rollback_candidate=None, now=None):
    raw = extract_document(archive, artifact)
    document = evidence.validate_bytes(raw, candidate_raw, inventory_raw, rollback_candidate=rollback_candidate, now=now)
    return raw, document


def load_rollback_candidate(source: str, run_id: int) -> tuple[bytes, dict]:
    evidence.require(isinstance(source, str) and bool(evidence.SHA.fullmatch(source)) and
                     type(run_id) is int and run_id > 0, "invalid_rollback_candidate_identity")
    run = evidence.decode(api(f"actions/runs/{run_id}"))
    source_candidate.validate_run(run, source, run_id)
    commit = evidence.decode(api(f"commits/{source}"))
    evidence.require(commit.get("sha") == source and
                     commit.get("commit", {}).get("verification", {}).get("verified") is True,
                     "unsigned_rollback_source")
    artifact = source_candidate.select_artifact(
        evidence.decode(api(f"actions/runs/{run_id}/artifacts?per_page=100")), source)
    raw, _ = source_candidate.verified_manifest(api(f"actions/artifacts/{artifact['id']}/zip"), artifact, source)
    manifest = evidence.decode(raw)
    evidence.require(commit["commit"].get("tree", {}).get("sha") == manifest["source_tree"],
                     "rollback_source_tree_mismatch")
    evidence.require(isinstance(manifest.get("kong_declarative_config_sha256"), str) and
                     bool(evidence.HASH.fullmatch(manifest["kong_declarative_config_sha256"])),
                     "rollback_configuration_hash_missing")
    return raw, {"source_sha": source, "run_id": run_id, "artifact_id": artifact["id"],
        "artifact_digest": artifact["digest"], "manifest_sha256": hashlib.sha256(raw).hexdigest()}


def certification_id(source: str, run_id: int, artifact_id: int) -> str:
    return f"PASS:{source}:github-actions/{run_id}/{artifact_id}"


def validate_receipt(receipt: dict, raw: bytes, candidate_raw: bytes, inventory_raw: bytes, *, now=None) -> dict:
    required = {"schema", "repository", "workflow", "source_sha", "staging_sha", "run_id", "run_attempt",
                "artifact_id", "artifact_digest", "certification_sha256", "certification_id",
                "rollback_manifest_json", "rollback_artifact"}
    evidence.require(isinstance(receipt, dict) and set(receipt) == required and
                     receipt["schema"] == RECEIPT_SCHEMA and receipt["repository"] == REPOSITORY and
                     receipt["workflow"] == WORKFLOW, "invalid_staging_receipt")
    evidence.require(isinstance(receipt["rollback_manifest_json"], str), "rollback_manifest_missing")
    rollback_raw = receipt["rollback_manifest_json"].encode("utf-8")
    document = evidence.validate_bytes(raw, candidate_raw, inventory_raw,
        rollback_candidate=evidence.decode(rollback_raw), now=now)
    proof = receipt["rollback_artifact"]
    evidence.require(isinstance(proof, dict) and set(proof) == {
        "source_sha", "run_id", "artifact_id", "artifact_digest", "manifest_sha256"}, "invalid_rollback_receipt")
    evidence.require(proof["source_sha"] == document["rollback"]["source_sha"] and
                     type(proof["run_id"]) is int and proof["run_id"] == document["rollback"]["candidate_run_id"] and
                     type(proof["artifact_id"]) is int and proof["artifact_id"] > 0 and
                     isinstance(proof["artifact_digest"], str) and bool(evidence.DIGEST.fullmatch(proof["artifact_digest"])) and
                     proof["manifest_sha256"] == hashlib.sha256(rollback_raw).hexdigest(), "rollback_receipt_mismatch")
    source = document["candidate"]["source_sha"]
    evidence.require(receipt["source_sha"] == source and isinstance(receipt["staging_sha"], str) and
                     bool(evidence.SHA.fullmatch(receipt["staging_sha"])), "receipt_source_mismatch")
    for field in ("run_id", "run_attempt", "artifact_id"):
        evidence.require(type(receipt[field]) is int and receipt[field] > 0, "invalid_receipt_identity")
    evidence.require(isinstance(receipt["artifact_digest"], str) and bool(evidence.DIGEST.fullmatch(receipt["artifact_digest"])) and
                     receipt["certification_sha256"] == hashlib.sha256(raw).hexdigest() and
                     receipt["certification_id"] == certification_id(source, receipt["run_id"], receipt["artifact_id"]),
                     "receipt_hash_mismatch")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, default=evidence.ROOT / "config/kong-production-route-inventory.v2.json")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence.require(bool(evidence.SHA.fullmatch(args.source_sha)) and args.run_id > 0, "invalid_staging_identity")
        candidate_raw, inventory_raw = args.candidate_manifest.read_bytes(), args.inventory.read_bytes()
        candidate = evidence.decode(candidate_raw)
        evidence.require(candidate.get("source_sha") == args.source_sha, "wrong_candidate")
        run = evidence.decode(api(f"actions/runs/{args.run_id}"))
        head = run.get("head_sha")
        evidence.require(isinstance(head, str) and bool(evidence.SHA.fullmatch(head)), "invalid_run_source")
        commit = evidence.decode(api(f"commits/{head}"))
        validate_run(run, args.run_id, commit, candidate)
        artifact = select_artifact(evidence.decode(api(f"actions/runs/{args.run_id}/artifacts?per_page=100")), run, args.source_sha)
        raw = extract_document(api(f"actions/artifacts/{artifact['id']}/zip"), artifact)
        provisional = evidence.decode(raw)
        rollback_raw, rollback_artifact = load_rollback_candidate(candidate.get("rollback_source_sha"),
            provisional.get("rollback", {}).get("candidate_run_id"))
        document = evidence.validate_bytes(raw, candidate_raw, inventory_raw,
            rollback_candidate=evidence.decode(rollback_raw))
        evidence.require(evidence.timestamp(document["completed_at"]) <= evidence.timestamp(run["updated_at"]),
                         "observation_after_run")
        receipt = {"schema": RECEIPT_SCHEMA, "repository": REPOSITORY, "workflow": WORKFLOW,
                   "source_sha": args.source_sha, "staging_sha": head, "run_id": args.run_id,
                   "run_attempt": run["run_attempt"], "artifact_id": artifact["id"],
                   "artifact_digest": artifact["digest"], "certification_sha256": hashlib.sha256(raw).hexdigest(),
                   "certification_id": certification_id(args.source_sha, args.run_id, artifact["id"]),
                   "rollback_manifest_json": rollback_raw.decode("utf-8"), "rollback_artifact": rollback_artifact}
        args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        (args.output_dir / "certification.json").write_bytes(raw)
        (args.output_dir / "receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        with args.github_output.open("a") as output:
            output.write("staging_certification=" + receipt["certification_id"] + "\n")
        print("KONG_STAGING_ARTIFACT=PASS")
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, RecursionError,
            zipfile.BadZipFile, subprocess.SubprocessError):
        print("KONG_STAGING_ARTIFACT=FAIL")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
