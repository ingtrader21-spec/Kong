#!/usr/bin/env python3
"""Verify a release manifest against ``config/kong-release-evidence-contract.v1.json``.

Runs in the release workflows right after ``generate_release_manifest.py`` and
fails closed on any unbound, unresolved, malformed or unauthorized value. Release
evidence proves that an exact verified commit was built, published by digest and
attested; it never authorizes a runtime apply.

    python3 tools/verify_release_evidence.py --manifest release-manifest.json \
        --expected-source-sha "$GITHUB_SHA" --expected-stage protected-main-source-candidate \
        --sbom standby-sbom.spdx.json --provenance standby-provenance.json \
        --registry-digest "$(cat remote-digest.txt)"
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.release_contract import (  # noqa: E402
    REPOSITORY, REPOSITORY_ID, STANDBY_IMAGE, authoritative_tag, contract_sha256,
    load_evidence_contract, preflight_tag,
)

SHA = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
VERIFIED = {"G", "U", "VERIFIED"}
KONG_IMAGE = "kong/kong-gateway:3.14.0.1-ubuntu"
PREFLIGHT_STAGE = "pull-request-preflight"
SOURCE_STAGE = "protected-main-source-candidate"
MAX_MANIFEST = 1024 * 1024


class EvidenceError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise EvidenceError(reason)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(manifest: dict, *, expected_source_sha: str | None = None, expected_stage: str | None = None,
           sbom: Path | None = None, provenance: Path | None = None, registry_digest: str | None = None,
           evidence_contract: dict | None = None) -> dict:
    contract = evidence_contract or load_evidence_contract()
    stages = contract["stages"]
    bindings = contract["bindings"]
    require(isinstance(manifest, dict), "manifest_not_object")
    for key, rule in bindings.items():
        if rule.get("required"):
            value = manifest.get(key)
            require(value is not None and value != "UNRESOLVED" and value != "", f"unbound:{key}")
    stage = manifest["release_stage"]
    require(stage in stages, f"unknown_stage:{stage}")
    if expected_stage is not None:
        require(stage == expected_stage, f"stage_mismatch:{stage}")
    require(manifest["repository"] == REPOSITORY, "repository_mismatch")
    require(manifest["repository_id"] == REPOSITORY_ID, "repository_id_mismatch")
    source = manifest["source_sha"]
    require(SHA.fullmatch(source) is not None, "source_sha_format")
    if expected_source_sha is not None:
        require(source == expected_source_sha, "source_sha_mismatch")
    require(SHA.fullmatch(manifest["source_tree"]) is not None, "source_tree_format")
    require(SHA.fullmatch(manifest["rollback_source_sha"]) is not None, "rollback_source_sha_format")
    if stage == PREFLIGHT_STAGE:
        require(manifest["commit_verification_status"] in VERIFIED | {"UNVERIFIED_PREFLIGHT_HEAD"}, "commit_status_unknown")
    else:
        require(manifest["commit_verification_status"] in VERIFIED, "commit_not_verified")
    require(manifest["kong_image"] == KONG_IMAGE, "kong_image_authority")
    require(DIGEST.fullmatch(manifest["kong_image_digest"]) is not None, "kong_image_digest_format")
    require(manifest["standby_auth_image"] == STANDBY_IMAGE, "standby_image_authority")
    require(DIGEST.fullmatch(manifest["standby_auth_image_digest"]) is not None, "standby_image_digest_format")
    if registry_digest is not None:
        require(manifest["standby_auth_image_digest"] == registry_digest, "registry_digest_mismatch")
    tag = manifest["standby_auth_image_tag"]
    expected_tag = preflight_tag(source) if stage == PREFLIGHT_STAGE else authoritative_tag(source)
    require(tag == expected_tag, f"tag_policy:{tag}")
    if stages[stage]["promotable"] is False and stage == PREFLIGHT_STAGE:
        require(tag.startswith("preflight-"), "preflight_tag_required")
    for key in ("standby_auth_sbom_sha256", "standby_auth_provenance_sha256", "migration_manifest_json_sha256",
                "migration_manifest_yaml_sha256", "kong_declarative_config_sha256", "middleware_contract_sha256",
                "release_registry_contract_sha256"):
        require(HEX64.fullmatch(str(manifest[key])) is not None, f"digest_format:{key}")
    require(manifest["release_registry_contract_sha256"] == contract_sha256(), "registry_contract_drift")
    if sbom is not None:
        require(sbom.is_file() and sha256_file(sbom) == manifest["standby_auth_sbom_sha256"], "sbom_digest_mismatch")
        document = json.loads(sbom.read_text(encoding="utf-8"))
        require(str(document.get("spdxVersion", "")).startswith("SPDX-"), "sbom_not_spdx")
    if provenance is not None:
        require(provenance.is_file() and sha256_file(provenance) == manifest["standby_auth_provenance_sha256"],
                "provenance_digest_mismatch")
    require(type(manifest["workflow_run_id"]) is int and manifest["workflow_run_id"] > 0, "workflow_run_id")
    require(type(manifest["workflow_run_attempt"]) is int and manifest["workflow_run_attempt"] > 0, "workflow_run_attempt")
    require(str(manifest["workflow_ref"]).startswith(REPOSITORY + "/.github/workflows/"), "workflow_ref_foreign")
    if stage in (PREFLIGHT_STAGE, SOURCE_STAGE):
        require(manifest["staging_certification"] == "NOT_RUN_SOURCE_CANDIDATE", "staging_certification_stage")
    else:
        require(str(manifest["staging_certification"]).startswith(f"PASS:{source}:"), "staging_certification_binding")
    for flag in ("runtime_apply_authorized", "external_effects_enabled", "provider_effects_enabled"):
        require(manifest[flag] is False, f"{flag}_not_false")
    return {"stage": stage, "source_sha": source, "image": f"{STANDBY_IMAGE}@{manifest['standby_auth_image_digest']}",
            "tag": tag, "promotable": stages[stage]["promotable"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-stage")
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--registry-digest")
    args = parser.parse_args()
    try:
        raw = args.manifest.read_bytes()
        require(len(raw) <= MAX_MANIFEST, "manifest_too_large")
        summary = verify(json.loads(raw), expected_source_sha=args.expected_source_sha,
                         expected_stage=args.expected_stage, sbom=args.sbom, provenance=args.provenance,
                         registry_digest=args.registry_digest)
    except (EvidenceError, OSError, ValueError, TypeError, KeyError) as error:
        print(f"RELEASE_EVIDENCE=FAIL {error}")
        return 2
    print("RELEASE_EVIDENCE=PASS")
    for key, value in summary.items():
        print(f"{key.upper()}={value}")
    print("RUNTIME_APPLY_AUTHORIZED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
