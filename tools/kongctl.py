#!/usr/bin/env python3
"""Offline gateway onboarding, preview, drift and release package interface."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.gateway_integrations import (AUTHORITY, ContractError, canonical, compile_integrations,
                                         digest, load_json, validate_set)

MAX_PACKAGE_BYTES = 8 * 1_048_576
MAX_PACKAGE_MEMBER_BYTES = 2 * 1_048_576


def emit(value):
    sys.stdout.buffer.write(canonical(value))


def write_new(path, value):
    with Path(path).open("xb") as handle:
        handle.write(canonical(value))


def package_release(compilation, output, source_sha, image_digest, rollback_sha):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha) or not re.fullmatch(r"[0-9a-f]{40}", rollback_sha):
        raise ContractError("immutable_source_sha_required")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
        raise ContractError("immutable_image_digest_required")
    files = {"compilation.json": canonical(compilation), "kong.json": canonical(compilation["kong"]),
             "test-matrix.json": canonical(compilation["test_matrix"])}
    manifest = {"schema": "codestra.gateway.offline-package.v1", "source_sha": source_sha,
        "kong_image_digest": image_digest, "rollback_source_sha": rollback_sha,
        "source_signature_verified": False, "registry_digest_verified": False,
        "runtime_certified": False, "runtime_apply_authorized": False,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}}
    files["manifest.json"] = canonical(manifest)
    if any(len(data) > MAX_PACKAGE_MEMBER_BYTES for data in files.values()):
        raise ContractError("package_member_too_large")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    package = buffer.getvalue()
    if len(package) > MAX_PACKAGE_BYTES:
        raise ContractError("package_too_large")
    with Path(output).open("xb") as handle:
        handle.write(package)
    return manifest


def verify_package(path):
    if Path(path).stat().st_size > MAX_PACKAGE_BYTES:
        raise ContractError("package_too_large")
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if sorted(names) != ["compilation.json", "kong.json", "manifest.json", "test-matrix.json"]:
                raise ContractError("invalid_package_members")
            for info in archive.infolist():
                if (info.file_size > MAX_PACKAGE_MEMBER_BYTES or info.flag_bits & 1
                        or (info.external_attr >> 16) != 0o100644):
                    raise ContractError("invalid_package_member")
            raw = {name: archive.read(name) for name in names}
        # Compare canonical bytes too: duplicate keys and ambiguous encodings fail.
        values = {name: json.loads(data) for name, data in raw.items()}
        if any(canonical(values[name]) != raw[name] for name in names):
            raise ContractError("noncanonical_package_document")
        manifest, compilation = values["manifest.json"], values["compilation.json"]
        expected = {name: hashlib.sha256(data).hexdigest() for name, data in raw.items() if name != "manifest.json"}
        if manifest.get("files") != expected or manifest.get("schema") != "codestra.gateway.offline-package.v1":
            raise ContractError("package_integrity_mismatch")
        if any(manifest.get(key) is not False for key in ("runtime_certified", "runtime_apply_authorized",
                                                          "source_signature_verified", "registry_digest_verified")):
            raise ContractError("offline_package_cannot_claim_certification")
        if compilation.get("kong") != values["kong.json"] or compilation.get("test_matrix") != values["test-matrix.json"]:
            raise ContractError("package_document_mismatch")
        if digest(values["kong.json"]) != compilation.get("config_sha256"):
            raise ContractError("config_digest_mismatch")
        return manifest
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError("invalid_release_package") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    groups = parser.add_subparsers(dest="group", required=True)
    integration = groups.add_parser("integration").add_subparsers(dest="action", required=True)
    init = integration.add_parser("init", help="create a reviewable contract from the registered Moneybee example")
    init.add_argument("--id", required=True)
    init.add_argument("--owner", required=True)
    init.add_argument("--security-owner", required=True)
    init.add_argument("--output", type=Path, required=True)
    for command in ("validate", "preview", "test", "status", "drift"):
        sub = integration.add_parser(command)
        sub.add_argument("files", nargs="+", type=Path)
        sub.add_argument("--environment", choices=("development", "staging", "production"), default="staging")
        if command in {"status", "drift"}:
            sub.add_argument("--observed-config", type=Path, required=True,
                             help="sanitized, previously captured Kong configuration; never fetched by this command")
    release = groups.add_parser("release").add_subparsers(dest="action", required=True)
    diff = release.add_parser("diff")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    pack = release.add_parser("package")
    pack.add_argument("files", nargs="+", type=Path)
    pack.add_argument("--environment", choices=("development", "staging", "production"), required=True)
    pack.add_argument("--source-sha", required=True)
    pack.add_argument("--image-digest", required=True)
    pack.add_argument("--rollback-sha", required=True)
    pack.add_argument("--output", type=Path, required=True)
    rollback = groups.add_parser("rollback").add_subparsers(dest="action", required=True)
    verify = rollback.add_parser("verify")
    verify.add_argument("package", type=Path)
    verify.add_argument("--expected-source-sha", required=True)
    verify.add_argument("--expected-image-digest", required=True)
    args = parser.parse_args(argv)
    try:
        if args.group == "integration" and args.action == "init":
            document = load_json(AUTHORITY / "examples/moneybee-account-bootstrap.json")
            document["metadata"].update(id=args.id, owner=args.owner, securityOwner=args.security_owner)
            validate_set([document])
            bundle = args.output.with_name(args.output.name + ".onboarding")
            if args.output.exists() or bundle.exists():
                raise ContractError("onboarding_output_already_exists")
            preview = compile_integrations([document], environment=document["metadata"]["environment"])
            bundle.mkdir(mode=0o700)
            created_contract = False
            try:
                write_new(bundle / "test-matrix.json", preview["test_matrix"])
                write_new(bundle / "openapi-stub.json", preview["openapi_stub"])
                write_new(bundle / "rollback-plan.json", {"integration_id": args.id,
                    "maximum_minutes": document["spec"]["operations"]["rollbackMaximumMinutes"],
                    "previous_signed_release": None, "backup_restore_evidence": None,
                    "approval_required": True, "runtime_apply_authorized": False})
                (bundle / "runbook.md").write_text(
                    "# Integration onboarding draft\n\nReview the contract and upstream OpenAPI schemas. "
                    "Record accountable owners, exact previous release, restore proof and runtime test evidence. "
                    "The adjacent test matrix is NOT_RUN and the rollback plan requires completion.\n")
                write_new(args.output, document)
                created_contract = True
            finally:
                if not created_contract:
                    shutil.rmtree(bundle)
            emit({"contract_created": True, "onboarding_bundle_created": True,
                  "review_required": True, "runtime_apply_authorized": False})
        elif args.group == "release" and args.action == "diff":
            before, after = load_json(args.before), load_json(args.after)
            emit({"changed": before != after, "before_sha256": digest(before), "after_sha256": digest(after),
                  "comparison": "local_source_documents", "runtime_observed": False})
        elif args.group == "rollback":
            manifest = verify_package(args.package)
            if manifest["source_sha"] != args.expected_source_sha or manifest["kong_image_digest"] != args.expected_image_digest:
                raise ContractError("rollback_identity_mismatch")
            emit({"package_integrity": "PASS", "rollback_executed": False, "runtime_certified": False,
                  "source_signature_verified": False, "registry_digest_verified": False})
        else:
            documents = [load_json(path) for path in args.files]
            compiled = compile_integrations(documents, environment=args.environment)
            if args.group == "release":
                emit(package_release(compiled, args.output, args.source_sha, args.image_digest, args.rollback_sha))
            elif args.action == "preview":
                emit(compiled)
            elif args.action == "test":
                emit({"source_contracts_valid": True, "runtime_tests_executed": False, "test_matrix": compiled["test_matrix"]})
            elif args.action in {"status", "drift"}:
                observed = load_json(args.observed_config)
                changed = digest(observed) != compiled["config_sha256"]
                emit({"drift": changed, "desired_sha256": compiled["config_sha256"], "observed_sha256": digest(observed),
                      "observation": "user_supplied_local_snapshot", "freshness_verified": False, "runtime_certified": False})
                return 1 if changed else 0
            else:
                emit({"source_contracts_valid": True, "config_sha256": compiled["config_sha256"], "runtime_certified": False})
        return 0
    except (ContractError, OSError) as exc:
        emit({"error": str(exc) if isinstance(exc, ContractError) else "local_file_operation_failed"})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
