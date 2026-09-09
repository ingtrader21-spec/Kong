#!/usr/bin/env python3
"""Generate secret-free release evidence for the exact checked-out source."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.kong_certification import decode
from tools.verify_staging_certification import validate_receipt


ROOT = Path(__file__).resolve().parents[1]
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
CERTIFICATION_ID = re.compile(r"^PASS:([0-9a-f]{40}):[A-Za-z0-9._:/-]+$")
VERIFIED_SIGNATURES = {"G", "U", "VERIFIED"}
SOURCE_RELEASE_STAGE = "protected-main-source-candidate"
STAGING_RELEASE_STAGE = "staging-certified"
PRODUCTION_RELEASE_STAGE = "production"
RELEASE_STAGES = {
    SOURCE_RELEASE_STAGE,
    STAGING_RELEASE_STAGE,
    PRODUCTION_RELEASE_STAGE,
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()



def verify_promotion_candidate(document: dict, source: str | None, path: Path | None,
                               expected_hash: str | None, run_id: int | None,
                               artifact_id: int | None) -> dict:
    """Bind original certified source to identical destination bytes and artifacts.

    GitHub run/archive authentication is done by verify_release_candidate.py.
    Neither matching source trees nor a PASS identifier proves live staging tests.
    """
    if (not isinstance(source, str) or not SOURCE_SHA.fullmatch(source) or path is None
            or not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
            or type(run_id) is not int or run_id <= 0 or type(artifact_id) is not int or artifact_id <= 0):
        raise ValueError("missing_candidate_authority")
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError("candidate_manifest_mismatch")
    candidate = json.loads(raw)
    if (candidate["source_sha"] != source or candidate["release_stage"] != SOURCE_RELEASE_STAGE
            or candidate["commit_verification_status"] not in VERIFIED_SIGNATURES
            or candidate["staging_certification"] != "NOT_RUN_SOURCE_CANDIDATE"):
        raise ValueError("wrong_source_candidate")
    if git("rev-parse", source + "^{tree}") != document["source_tree"]:
        raise ValueError("promotion_changes_certified_tree")
    for key in ("source_tree", "kong_version", "kong_image", "kong_image_digest",
                "standby_auth_image", "standby_auth_image_digest", "manifest_generation_id",
                "migration_manifest_json_sha256", "migration_manifest_yaml_sha256",
                "kong_declarative_config_sha256", "rollback_source_sha"):
        if candidate[key] != document[key]:
            raise ValueError("promotion_changes_candidate")
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release-stage", choices=sorted(RELEASE_STAGES), required=True)
    parser.add_argument("--commit-verification-status")
    parser.add_argument("--kong-image-digest", default="UNRESOLVED")
    parser.add_argument("--standby-auth-image-digest", default="UNRESOLVED")
    parser.add_argument("--staging-certification", default="UNRESOLVED")
    parser.add_argument("--rollback-source-sha", default="UNRESOLVED")
    parser.add_argument("--certified-source-sha")
    parser.add_argument("--candidate-manifest", type=Path)
    parser.add_argument("--candidate-manifest-sha256")
    parser.add_argument("--candidate-run-id", type=int)
    parser.add_argument("--candidate-artifact-id", type=int)
    parser.add_argument("--staging-evidence", type=Path)
    parser.add_argument("--staging-receipt", type=Path)
    args = parser.parse_args()

    authority = yaml.safe_load((ROOT / "MIGRATION_MANIFEST.yaml").read_text())
    verification = args.commit_verification_status or git("log", "-1", "--format=%G?")
    source_sha = git("rev-parse", "HEAD")
    promotion_sha = source_sha
    document = {
        "release_stage": args.release_stage,
        "source_sha": source_sha,
        "source_tree": git("rev-parse", "HEAD^{tree}"),
        "commit_verification_status": verification,
        "kong_version": "3.14.0.1",
        "kong_image": "kong/kong-gateway:3.14.0.1-ubuntu",
        "kong_image_digest": args.kong_image_digest,
        "standby_auth_image": "ghcr.io/appolon1908-hue/kong-standby-auth",
        "standby_auth_image_digest": args.standby_auth_image_digest,
        "manifest_generation_id": authority["manifest_generation_id"],
        "migration_manifest_json_sha256": sha256(ROOT / "MIGRATION_MANIFEST.json"),
        "migration_manifest_yaml_sha256": sha256(ROOT / "MIGRATION_MANIFEST.yaml"),
        "kong_declarative_config_sha256": sha256(ROOT / "deploy/kong/control-plane.yml"),
        "staging_certification": args.staging_certification,
        "rollback_source_sha": args.rollback_source_sha,
    }
    if args.release_stage != SOURCE_RELEASE_STAGE:
        try:
            candidate = verify_promotion_candidate(
                document, args.certified_source_sha, args.candidate_manifest,
                args.candidate_manifest_sha256, args.candidate_run_id, args.candidate_artifact_id,
            )
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
            print("RELEASE_MANIFEST=INCOMPLETE\nUNRESOLVED=candidate_authority")
            return 2
        source_sha = args.certified_source_sha
        document.update(source_sha=source_sha, promotion_sha=promotion_sha,
                        promotion_tree=document["source_tree"],
                        candidate_manifest_sha256=args.candidate_manifest_sha256,
                        candidate_run_id=args.candidate_run_id,
                        candidate_artifact_id=args.candidate_artifact_id,
                        source_commit_verification_status=candidate["commit_verification_status"])
        try:
            if args.staging_evidence is None or args.staging_receipt is None:
                raise ValueError("missing_staging_artifact")
            receipt = decode(args.staging_receipt.read_bytes())
            observed = validate_receipt(
                receipt, args.staging_evidence.read_bytes(), args.candidate_manifest.read_bytes(),
                (ROOT / "config/kong-production-route-inventory.v2.json").read_bytes(),
            )
            if args.staging_certification != receipt["certification_id"]:
                raise ValueError("certification_reference_mismatch")
            document.update(
                staging_certification_verification="PROTECTED_RUN_ARTIFACT_VERIFIED",
                staging_certification_run_id=receipt["run_id"],
                staging_certification_artifact_id=receipt["artifact_id"],
                staging_certification_artifact_digest=receipt["artifact_digest"],
                staging_certification_sha256=receipt["certification_sha256"],
                staging_certification_completed_at=observed["completed_at"],
                rollback_image_digest=observed["rollback"]["image_digest"],
                rollback_configuration_sha256=observed["rollback"]["config_sha256"],
                rollback_candidate_run_id=receipt["rollback_artifact"]["run_id"],
                rollback_candidate_artifact_id=receipt["rollback_artifact"]["artifact_id"],
                rollback_candidate_artifact_digest=receipt["rollback_artifact"]["artifact_digest"],
            )
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
            print("RELEASE_MANIFEST=INCOMPLETE\nUNRESOLVED=staging_artifact_authority")
            return 2
    document.update(runtime_apply_authorized=False, external_effects_enabled=False)

    unresolved = {key for key, value in document.items() if value == "UNRESOLVED"}
    if verification not in VERIFIED_SIGNATURES:
        unresolved.add("commit_verification_status")
    if not IMAGE_DIGEST.fullmatch(args.kong_image_digest):
        unresolved.add("kong_image_digest")
    if not IMAGE_DIGEST.fullmatch(args.standby_auth_image_digest):
        unresolved.add("standby_auth_image_digest")
    if not SOURCE_SHA.fullmatch(args.rollback_source_sha):
        unresolved.add("rollback_source_sha")
    if args.release_stage == SOURCE_RELEASE_STAGE:
        if args.staging_certification != "NOT_RUN_SOURCE_CANDIDATE":
            unresolved.add("staging_certification")
    else:
        certification = CERTIFICATION_ID.fullmatch(args.staging_certification)
        if not certification or certification.group(1) != source_sha:
            unresolved.add("staging_certification")

    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print("RELEASE_MANIFEST=PASS" if not unresolved else "RELEASE_MANIFEST=INCOMPLETE")
    print("UNRESOLVED=" + ",".join(sorted(unresolved)))
    return 0 if not unresolved else 2


if __name__ == "__main__":
    raise SystemExit(main())
