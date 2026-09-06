#!/usr/bin/env python3
"""Generate secret-free release evidence for the exact checked-out source."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

import yaml


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release-stage", choices=sorted(RELEASE_STAGES), required=True)
    parser.add_argument("--commit-verification-status")
    parser.add_argument("--kong-image-digest", default="UNRESOLVED")
    parser.add_argument("--standby-auth-image-digest", default="UNRESOLVED")
    parser.add_argument("--staging-certification", default="UNRESOLVED")
    parser.add_argument("--rollback-source-sha", default="UNRESOLVED")
    args = parser.parse_args()

    authority = yaml.safe_load((ROOT / "MIGRATION_MANIFEST.yaml").read_text())
    verification = args.commit_verification_status or git("log", "-1", "--format=%G?")
    source_sha = git("rev-parse", "HEAD")
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
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")

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

    print("RELEASE_MANIFEST=PASS" if not unresolved else "RELEASE_MANIFEST=INCOMPLETE")
    print("UNRESOLVED=" + ",".join(sorted(unresolved)))
    return 0 if not unresolved else 2


if __name__ == "__main__":
    raise SystemExit(main())
