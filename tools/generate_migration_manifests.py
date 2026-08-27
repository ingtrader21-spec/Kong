#!/usr/bin/env python3
"""Generate and transactionally publish both Kong migration manifests."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import yaml

ROOT = Path(__file__).resolve().parents[1]
YAML_MANIFEST = "MIGRATION_MANIFEST.yaml"
JSON_MANIFEST = "MIGRATION_MANIFEST.json"
MANIFEST_ARTIFACTS = {YAML_MANIFEST, JSON_MANIFEST}
AUTHORITY_ROOTS = (
    ".github/workflows", "config", "deploy", "docs", "operations", "scripts", "tests", "tools"
)
AUTHORITY_FILES = {".gitignore", "README.md", "SECURITY.md", "pytest.ini"}
EXCLUDED_PARTS = {".git", "__pycache__", ".pytest_cache"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".swp", ".tmp", "~"}
LOCK_NAME = ".migration-manifests.lock"
JOURNAL_NAME = ".migration-manifests.transaction.json"
RECOVERY_NAMES = {
    YAML_MANIFEST: ".MIGRATION_MANIFEST.yaml.recovery",
    JSON_MANIFEST: ".MIGRATION_MANIFEST.json.recovery",
}
CANDIDATE_NAMES = {
    YAML_MANIFEST: ".MIGRATION_MANIFEST.yaml.candidate",
    JSON_MANIFEST: ".MIGRATION_MANIFEST.json.candidate",
}


class TransactionError(RuntimeError):
    pass


class FileOperations:
    """Injectable transaction seam used by fault-recovery tests."""

    def replace(self, source: Path, destination: Path) -> None:
        os.replace(source, destination)

    def checkpoint(self, name: str) -> None:
        del name


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


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
    paths.difference_update(MANIFEST_ARTIFACTS)
    return sorted(paths)


def inventory(root: Path = ROOT) -> list[dict[str, object]]:
    rows = []
    for relative in approved_paths(root):
        path = root / relative
        if not path.is_file():
            raise FileNotFoundError(f"approved authority file is missing: {relative}")
        content = path.read_bytes()
        rows.append({"path": relative, "sha256": sha256(content), "size": len(content)})
    return rows


def generation_id(document: dict[str, object]) -> str:
    canonical = dict(document)
    canonical.pop("manifest_generation_id", None)
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return sha256(encoded)


def canonical_document(root: Path = ROOT) -> dict[str, object]:
    path = root / YAML_MANIFEST
    if not path.is_file():
        raise FileNotFoundError(path)
    document = yaml.safe_load(path.read_text())
    if not isinstance(document, dict):
        raise ValueError("YAML manifest must contain an object")
    document = dict(document)
    document["files"] = inventory(root)
    document["manifest_generation_id"] = generation_id(document)
    return document


def render(document: dict[str, object]) -> dict[str, bytes]:
    return {
        YAML_MANIFEST: yaml.safe_dump(document, sort_keys=True, allow_unicode=True).encode(),
        JSON_MANIFEST: (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode(),
    }


def parse_pair(outputs: dict[str, bytes]) -> tuple[dict[str, object], dict[str, object]]:
    try:
        yaml_document = yaml.safe_load(outputs[YAML_MANIFEST].decode())
        json_document = json.loads(outputs[JSON_MANIFEST].decode())
    except (UnicodeDecodeError, ValueError, yaml.YAMLError) as error:
        raise TransactionError(f"staged manifest pair is malformed: {error}") from error
    if not isinstance(yaml_document, dict) or not isinstance(json_document, dict):
        raise TransactionError("staged manifest pair must contain objects")
    return yaml_document, json_document


def validate_pair(outputs: dict[str, bytes], root: Path, *, validate_inventory: bool = True) -> int:
    yaml_document, json_document = parse_pair(outputs)
    if yaml_document != json_document:
        raise TransactionError("staged manifest documents differ")
    identifier = yaml_document.get("manifest_generation_id")
    if not isinstance(identifier, str) or len(identifier) != 64 or any(c not in "0123456789abcdef" for c in identifier):
        raise TransactionError("invalid manifest generation ID")
    if generation_id(yaml_document) != identifier:
        raise TransactionError("manifest generation ID does not match canonical document")
    rows = yaml_document.get("files")
    if not isinstance(rows, list):
        raise TransactionError("manifest files must be a list")
    paths = [row.get("path") for row in rows if isinstance(row, dict)]
    if len(paths) != len(rows) or paths != sorted(paths) or len(paths) != len(set(paths)):
        raise TransactionError("manifest paths are invalid, duplicated, or unsorted")
    if validate_inventory:
        expected = approved_paths(root)
        if paths != expected:
            raise TransactionError("manifest paths differ from approved authority inventory")
        for row in rows:
            content = (root / row["path"]).read_bytes()
            if row.get("size") != len(content) or row.get("sha256") != sha256(content):
                raise TransactionError(f"stale authority entry: {row['path']}")
    return len(rows)


def fsync_directory(root: Path) -> None:
    descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_durable(path: Path, content: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def write_journal(root: Path, journal: dict[str, object]) -> None:
    content = (json.dumps(journal, sort_keys=True, indent=2) + "\n").encode()
    temporary = root / f".{JOURNAL_NAME}.{uuid.uuid4().hex}.tmp"
    write_durable(temporary, content, 0o600)
    os.replace(temporary, root / JOURNAL_NAME)
    fsync_directory(root)


def current_outputs(root: Path) -> dict[str, bytes]:
    return {name: (root / name).read_bytes() for name in MANIFEST_ARTIFACTS}


def cleanup_transaction(root: Path) -> None:
    for name in [JOURNAL_NAME, *RECOVERY_NAMES.values(), *CANDIDATE_NAMES.values()]:
        try:
            (root / name).unlink()
        except FileNotFoundError:
            pass
    for path in root.glob(f".{JOURNAL_NAME}.*.tmp"):
        path.unlink(missing_ok=True)
    fsync_directory(root)


def restore_previous_pair(root: Path) -> None:
    recovery = {name: (root / recovery_name).read_bytes() for name, recovery_name in RECOVERY_NAMES.items()}
    validate_pair(recovery, root, validate_inventory=False)
    for name in (YAML_MANIFEST, JSON_MANIFEST):
        temporary = root / f".{name}.restore"
        write_durable(temporary, recovery[name], 0o644)
        os.replace(temporary, root / name)
    for name in (YAML_MANIFEST, JSON_MANIFEST):
        descriptor = os.open(root / name, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    fsync_directory(root)
    validate_pair(current_outputs(root), root, validate_inventory=False)


def recover_transaction(root: Path) -> bool:
    journal_path = root / JOURNAL_NAME
    if not journal_path.exists():
        return False
    try:
        journal = json.loads(journal_path.read_text())
    except (OSError, ValueError) as error:
        raise TransactionError(f"unreadable transaction journal: {error}") from error
    recovery = {name: (root / recovery_name).read_bytes() for name, recovery_name in RECOVERY_NAMES.items()}
    if sha256(recovery[JSON_MANIFEST]) != journal.get("previous_json_sha256"):
        raise TransactionError("JSON recovery copy does not match transaction journal")
    if sha256(recovery[YAML_MANIFEST]) != journal.get("previous_yaml_sha256"):
        raise TransactionError("YAML recovery copy does not match transaction journal")
    if journal.get("state") == "COMMITTED":
        try:
            published = current_outputs(root)
            if sha256(published[JSON_MANIFEST]) != journal.get("candidate_json_sha256"):
                raise TransactionError("published JSON does not match transaction journal")
            if sha256(published[YAML_MANIFEST]) != journal.get("candidate_yaml_sha256"):
                raise TransactionError("published YAML does not match transaction journal")
            validate_pair(published, root, validate_inventory=False)
        except Exception:
            restore_previous_pair(root)
    elif journal.get("state") == "PREPARED":
        restore_previous_pair(root)
    else:
        raise TransactionError("unknown transaction journal state")
    cleanup_transaction(root)
    return True


def open_manifest_lock(path: Path) -> int:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise TransactionError(f"unable to open manifest lock safely: {error}") from error
    try:
        opened = os.fstat(descriptor)
        linked = path.lstat()
        if stat.S_ISLNK(linked.st_mode):
            raise TransactionError("manifest lock must not be a symbolic link")
        if not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(linked.st_mode):
            raise TransactionError("manifest lock must be a regular file")
        if opened.st_uid != os.geteuid() or linked.st_uid != os.geteuid():
            raise TransactionError("manifest lock must be owned by the effective user")
        if stat.S_IMODE(opened.st_mode) != 0o600 or stat.S_IMODE(linked.st_mode) != 0o600:
            raise TransactionError("manifest lock mode must be 0600")
        if opened.st_nlink != 1 or linked.st_nlink != 1:
            raise TransactionError("manifest lock must have exactly one link")
        if (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino):
            raise TransactionError("manifest lock path changed during open")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


@contextmanager
def generator_lock(root: Path) -> Iterator[None]:
    path = root / LOCK_NAME
    descriptor = open_manifest_lock(path)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        linked = path.lstat()
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino):
            raise TransactionError("manifest lock inode changed while locked")
        if stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_uid != os.geteuid():
            raise TransactionError("manifest lock ownership or mode changed while locked")
        if opened.st_nlink != 1 or linked.st_nlink != 1:
            raise TransactionError("manifest lock link count changed while locked")
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def generate(root: Path = ROOT, operations: FileOperations | None = None) -> None:
    operations = operations or FileOperations()
    with generator_lock(root):
        recover_transaction(root)
        outputs = render(canonical_document(root))
        validate_pair(outputs, root)
        previous = current_outputs(root)
        modes = {name: (root / name).stat().st_mode & 0o777 for name in MANIFEST_ARTIFACTS}
        try:
            for name in (YAML_MANIFEST, JSON_MANIFEST):
                write_durable(root / CANDIDATE_NAMES[name], outputs[name], modes[name])
            validate_pair({name: (root / CANDIDATE_NAMES[name]).read_bytes() for name in MANIFEST_ARTIFACTS}, root)
            operations.checkpoint("candidates_staged")
            for name in (YAML_MANIFEST, JSON_MANIFEST):
                write_durable(root / RECOVERY_NAMES[name], previous[name], 0o600)
            journal = {
                "transaction_id": uuid.uuid4().hex,
                "state": "PREPARED",
                "previous_json_sha256": sha256(previous[JSON_MANIFEST]),
                "previous_yaml_sha256": sha256(previous[YAML_MANIFEST]),
                "candidate_json_sha256": sha256(outputs[JSON_MANIFEST]),
                "candidate_yaml_sha256": sha256(outputs[YAML_MANIFEST]),
            }
            write_journal(root, journal)
            operations.checkpoint("prepared")
            operations.replace(root / CANDIDATE_NAMES[YAML_MANIFEST], root / YAML_MANIFEST)
            operations.checkpoint("first_replaced")
            operations.replace(root / CANDIDATE_NAMES[JSON_MANIFEST], root / JSON_MANIFEST)
            operations.checkpoint("second_replaced")
            journal["state"] = "COMMITTED"
            write_journal(root, journal)
            for name in (YAML_MANIFEST, JSON_MANIFEST):
                descriptor = os.open(root / name, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            fsync_directory(root)
            operations.checkpoint("before_final_verification")
            validate_pair(current_outputs(root), root)
            cleanup_transaction(root)
        except Exception:
            if (root / JOURNAL_NAME).exists():
                restore_previous_pair(root)
            cleanup_transaction(root)
            raise


def check(root: Path = ROOT) -> int:
    with generator_lock(root):
        if (root / JOURNAL_NAME).exists():
            raise TransactionError("incomplete manifest transaction requires recovery")
        expected = render(canonical_document(root))
        actual = current_outputs(root)
        validate_pair(actual, root)
        if actual != expected:
            raise TransactionError("committed manifests differ from deterministic generator output")
        return validate_pair(expected, root)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true", help="verify committed output without writing")
    args = parser.parse_args()
    root = args.root.resolve()
    count = check(root) if args.check else (generate(root) or len(inventory(root)))
    action = "CHECK" if args.check else "GENERATION"
    print(f"MIGRATION_MANIFEST_{action}=PASS FILES={count}")


if __name__ == "__main__":
    main()
