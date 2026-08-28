from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import yaml

from generate_migration_manifests import (
    JSON_MANIFEST,
    YAML_MANIFEST,
    approved_paths,
    current_outputs,
    generation_id,
    generator_lock,
    recover_transaction,
    validate_pair,
)

EXPECTED_SCHEMA = "codestra.kong.repository-migration.v1"
PROVENANCE_FIELDS = (
    "schema", "production_state_changed", "generated_at", "source_repository",
    "source_protected_sha", "source_route_pr", "source_route_sha", "source_files",
    "target_repository", "target_head_before_manifest", "target_manifest_updated_at",
    "target_hardening",
)


class ManifestError(AssertionError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def load_document(path: Path, *, yaml_format: bool) -> dict[str, object]:
    require(path.is_file(), f"manifest is absent: {path.name}")
    try:
        document = yaml.safe_load(path.read_text()) if yaml_format else json.loads(path.read_text())
    except (OSError, ValueError, yaml.YAMLError) as error:
        raise ManifestError(f"malformed manifest: {path.name}: {error}") from error
    require(isinstance(document, dict), f"manifest must contain an object: {path.name}")
    return document


def indexed_files(document: dict[str, object], label: str) -> tuple[list[dict[str, object]], dict[str, dict[str, object]]]:
    rows = document.get("files")
    require(isinstance(rows, list), f"{label} files must be a list")
    require(all(isinstance(row, dict) for row in rows), f"{label} file entries must be objects")
    paths = [row.get("path") for row in rows]
    require(all(isinstance(path, str) and path for path in paths), f"{label} contains an invalid path")
    require(len(paths) == len(set(paths)), f"{label} contains duplicate paths")
    require(paths == sorted(paths), f"{label} paths are not deterministically ordered")
    return rows, {row["path"]: row for row in rows}


def verify(root: Path) -> int:
    with generator_lock(root):
        recover_transaction(root)
        return verify_locked(root)


def verify_locked(root: Path) -> int:
    validate_pair(current_outputs(root), root)
    yaml_document = load_document(root / YAML_MANIFEST, yaml_format=True)
    json_document = load_document(root / JSON_MANIFEST, yaml_format=False)
    require(yaml_document.get("schema") == EXPECTED_SCHEMA, "unexpected YAML schema")
    require(json_document.get("schema") == EXPECTED_SCHEMA, "unexpected JSON schema")
    require(yaml_document.get("production_state_changed") is False, "YAML records a production change")
    require(json_document.get("production_state_changed") is False, "JSON records a production change")
    require(set(yaml_document) == set(json_document), "manifest top-level field sets differ")
    require(yaml_document == json_document, "manifest documents are not semantically equivalent")
    identifier = yaml_document.get("manifest_generation_id")
    require(
        isinstance(identifier, str)
        and len(identifier) == 64
        and all(character in "0123456789abcdef" for character in identifier),
        "invalid manifest generation ID",
    )
    require(generation_id(yaml_document) == identifier, "manifest generation ID does not match document")
    for field in PROVENANCE_FIELDS:
        require(field in yaml_document, f"missing required provenance field: {field}")
        require(yaml_document[field] == json_document[field], f"manifest provenance differs: {field}")

    yaml_rows, yaml_by_path = indexed_files(yaml_document, "YAML manifest")
    json_rows, json_by_path = indexed_files(json_document, "JSON manifest")
    require(yaml_rows == json_rows, "manifest file collections differ")
    expected = approved_paths(root)
    require(list(yaml_by_path) == expected, "manifest path set differs from approved authority inventory")
    for relative, row in yaml_by_path.items():
        path = root / relative
        require(path.is_file(), f"declared authority file is missing: {relative}")
        content = path.read_bytes()
        require(row.get("size") == len(content), f"stale byte size: {relative}")
        require(row.get("sha256") == hashlib.sha256(content).hexdigest(), f"stale SHA-256: {relative}")
        require(json_by_path[relative] == row, f"JSON/YAML entry differs: {relative}")
    return len(yaml_rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    count = verify(args.root.resolve())
    print("MIGRATION_MANIFEST_JSON=PASS")
    print("MIGRATION_MANIFEST_YAML=PASS")
    print("MIGRATION_MANIFEST_SEMANTIC_EQUALITY=PASS")
    print(f"MIGRATION_MANIFEST=PASS FILES={count}")

if __name__ == "__main__":
    main()
