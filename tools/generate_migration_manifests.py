#!/usr/bin/env python3
"""Generate the YAML migration manifest and its JSON compatibility projection."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
YAML_MANIFEST = "MIGRATION_MANIFEST.yaml"
JSON_MANIFEST = "MIGRATION_MANIFEST.json"
MANIFEST_INFRASTRUCTURE = {
    YAML_MANIFEST,
    JSON_MANIFEST,
    "tools/generate_migration_manifests.py",
}
AUTHORITY_ROOTS = (
    ".github/workflows", "config", "deploy", "docs", "operations", "scripts", "tests", "tools"
)
AUTHORITY_FILES = {
    ".github/workflows/validate.yml",
    ".gitignore",
    "README.md",
    "SECURITY.md",
    "pytest.ini",
}
EXCLUDED_PARTS = {".git", "__pycache__", ".pytest_cache"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".swp", ".tmp", "~"}


def approved_paths(root: Path = ROOT) -> list[str]:
    paths = set(AUTHORITY_FILES)
    for top in AUTHORITY_ROOTS:
        base = root / top
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            relative = path.relative_to(root).as_posix()
            if not path.is_file() or EXCLUDED_PARTS.intersection(path.parts):
                continue
            if any(relative.endswith(suffix) for suffix in EXCLUDED_SUFFIXES):
                continue
            paths.add(relative)
    paths.difference_update(MANIFEST_INFRASTRUCTURE)
    return sorted(paths)


def inventory(root: Path = ROOT) -> list[dict[str, object]]:
    rows = []
    for relative in approved_paths(root):
        path = root / relative
        if not path.is_file():
            raise FileNotFoundError(f"approved authority file is missing: {relative}")
        content = path.read_bytes()
        rows.append({
            "path": relative,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        })
    return rows


def canonical_document(root: Path = ROOT) -> dict[str, object]:
    path = root / YAML_MANIFEST
    if not path.is_file():
        raise FileNotFoundError(path)
    document = yaml.safe_load(path.read_text())
    if not isinstance(document, dict):
        raise ValueError("YAML manifest must contain an object")
    document = dict(document)
    document["files"] = inventory(root)
    return document


def render(document: dict[str, object]) -> tuple[bytes, bytes]:
    yaml_bytes = yaml.safe_dump(document, sort_keys=True, allow_unicode=True).encode()
    json_bytes = (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
    return yaml_bytes, json_bytes


def atomic_write(path: Path, content: bytes) -> None:
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def generate(root: Path = ROOT) -> None:
    yaml_bytes, json_bytes = render(canonical_document(root))
    atomic_write(root / YAML_MANIFEST, yaml_bytes)
    atomic_write(root / JSON_MANIFEST, json_bytes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    root = args.root.resolve()
    generate(root)
    print(f"MIGRATION_MANIFEST_GENERATION=PASS FILES={len(inventory(root))}")


if __name__ == "__main__":
    main()
