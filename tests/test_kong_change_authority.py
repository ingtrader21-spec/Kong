from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import os
import shutil
import stat
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import generate_migration_manifests as manifest_generator
PACKAGE = ROOT / "operations" / "kong-database" / "approvals"
VALIDATOR = ROOT / "operations" / "kong-database" / "validate-change-authority.sh"


def approved_values(tmp_path: Path) -> dict[str, str]:
    now = datetime.now(timezone.utc)
    evidence = {}
    markers = {"restore": "RESTORE_TEST", "pitr": "PITR_REHEARSAL"}
    for name in ("backup", "offhost", "restore", "pitr", "rollback", "telephony"):
        path = tmp_path / f"{name}.evidence"
        path.write_text(f"{markers.get(name, name.upper())}=PASS\n")
        evidence[name] = str(path)
    return {
        "KONG_CHANGE_ID": "CHG-SYNTHETIC-001",
        "KONG_CHANGE_STATUS": "APPROVED",
        "KONG_CHANGE_OWNER": "change-team",
        "KONG_DATABASE_OWNER": "database-team",
        "KONG_PLATFORM_OWNER": "platform-team",
        "KONG_ROLLBACK_OWNER": "rollback-team",
        "KONG_CANARY_OWNER": "application-team",
        "KONG_FAILOVER_OWNER": "database-team",
        "KONG_FENCING_OWNER": "infrastructure-team",
        "KONG_DNS_OWNER": "network-team",
        "KONG_SECRET_OWNER": "security-team",
        "KONG_ROTATION_OWNER": "security-team",
        "KONG_TELEPHONY_OPERATOR_OWNER": "telephony-team",
        "KONG_MAINTENANCE_START": (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "KONG_MAINTENANCE_END": (now + timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "KONG_TIMEZONE": "UTC",
        "KONG_FAILOVER_REHEARSAL_WINDOW": "CHG-SYNTHETIC-FAILOVER",
        "KONG_LOAD_SOAK_WINDOW": "CHG-SYNTHETIC-SOAK",
        "KONG_DB_REPLICA_HOST": "db-replica.example.invalid",
        "KONG_DB_REPLICA_IP": "10.40.0.3",
        "KONG_DB_REPLICA_CIDR": "10.40.0.0/28",
        "KONG_DB_FAILURE_DOMAIN": "independent-host-b",
        "KONG_DB_REPLICA_PROVIDER": "synthetic-provider",
        "KONG_DB_REPLICA_STORAGE": "150GiB-ssd",
        "KONG_DB_REPLICA_TLS_IDENTITY": "db-replica.example.invalid",
        "KONG_DB_STABLE_AUTHORITY": "kong-db.internal.codestra.agency",
        "KONG_DB_DNS_BACKEND": "private-dns",
        "KONG_DB_DNS_OWNER": "network-team",
        "KONG_DB_DNS_TTL_SECONDS": "30",
        "KONG_DB_PROMOTION_MUTATION_OWNER": "ha-workflow",
        "KONG_DB_FENCING_PROVIDER": "synthetic-provider-api",
        "KONG_DB_FENCING_OWNER": "infrastructure-team",
        "KONG_DB_FENCE_ACTION": "provider-fence-workflow",
        "KONG_DB_FENCE_VERIFY_ACTION": "provider-fence-readback",
        "KONG_DB_UNFENCE_ACTION": "provider-reviewed-unfence",
        "KONG_DB_SECRET_AUTHORITY": "protected-secret-backend",
        "KONG_DB_SECRET_OWNER": "security-team",
        "KONG_DB_ROTATION_OWNER": "security-team",
        "KONG_DB_ROTATION_INTERVAL_DAYS": "90",
        "KONG_DB_BREAK_GLASS_POLICY": "SEC-BREAK-GLASS-001",
        "KONG_DB_RPO_SECONDS": "300",
        "KONG_DB_RTO_SECONDS": "900",
        "KONG_DB_WAL_RETENTION_DAYS": "7",
        "KONG_DB_BASE_BACKUP_RETENTION": "2-weekly-3-monthly",
        "KONG_DB_LOGICAL_BACKUP_RETENTION": "14-daily-8-weekly-12-monthly",
        "KONG_TELEPHONY_CANARY_AUTHORITY": "TEL-CANARY-SYNTHETIC-001",
        "KONG_BACKUP_EVIDENCE": evidence["backup"],
        "KONG_OFFHOST_BACKUP_EVIDENCE": evidence["offhost"],
        "KONG_RESTORE_EVIDENCE": evidence["restore"],
        "KONG_PITR_REHEARSAL_EVIDENCE": evidence["pitr"],
        "KONG_ROLLBACK_EVIDENCE": evidence["rollback"],
        "KONG_TELEPHONY_EVIDENCE": evidence["telephony"],
    }


def execute(tmp_path: Path, values: dict[str, str]):
    approved = tmp_path / "approved.env"
    approved.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    approved.chmod(0o600)
    tools = tmp_path / "bin"
    tools.mkdir(exist_ok=True)
    dig = tools / "dig"
    dig.write_text("#!/bin/sh\nexit 0\n")
    dig.chmod(0o755)
    env = os.environ | {"PATH": f"{tools}:{os.environ['PATH']}"}
    return subprocess.run(
        [str(VALIDATOR), str(approved)], text=True, capture_output=True, env=env
    )


@pytest.mark.parametrize(
    "missing",
    [
        "KONG_CHANGE_ID",
        "KONG_CHANGE_OWNER",
        "KONG_DB_REPLICA_HOST",
        "KONG_DB_FENCING_PROVIDER",
        "KONG_DB_SECRET_AUTHORITY",
        "KONG_DB_RPO_SECONDS",
        "KONG_DB_RTO_SECONDS",
        "KONG_TELEPHONY_CANARY_AUTHORITY",
    ],
)
def test_missing_authority_fails_closed(tmp_path, missing):
    values = approved_values(tmp_path)
    values.pop(missing)
    result = execute(tmp_path, values)
    assert result.returncode != 0
    assert "KONG_DB_CUTOVER_GO=NO" in result.stdout
    assert result.stdout.count("BLOCKED_BY=") == 1


def test_placeholder_fails_closed(tmp_path):
    values = approved_values(tmp_path)
    values["KONG_CHANGE_ID"] = "REQUIRED"
    result = execute(tmp_path, values)
    assert result.returncode != 0
    assert "CHANGE_RECORD=FAIL" in result.stdout
    assert "KONG_DB_CUTOVER_GO=NO" in result.stdout


def test_failed_or_unstructured_evidence_fails_closed(tmp_path):
    for content in ("RESTORE_TEST=FAIL\n", "arbitrary text\n"):
        values = approved_values(tmp_path)
        evidence = tmp_path / "restore.evidence"
        evidence.write_text(content)
        result = execute(tmp_path, values)
        assert result.returncode != 0
        assert "RECOVERY_EVIDENCE=FAIL" in result.stdout
        assert "KONG_DB_CUTOVER_GO=NO" in result.stdout


def test_fully_synthetic_approved_fixture_passes_without_mutation(tmp_path):
    result = execute(tmp_path, approved_values(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "KONG_DB_CUTOVER_GO=YES" in result.stdout
    assert result.stdout.count("=PASS") == 10
    assert "BLOCKED_BY=" not in result.stdout


def test_template_is_no_go_and_validator_contains_no_mutation_commands(tmp_path):
    template = PACKAGE / "approved-change.env.example"
    protected = tmp_path / "template.env"
    protected.write_text(template.read_text())
    protected.chmod(0o600)
    result = subprocess.run([str(VALIDATOR), str(protected)], text=True, capture_output=True)
    assert result.returncode != 0
    assert "KONG_DB_CUTOVER_GO=NO" in result.stdout
    source = VALIDATOR.read_text()
    for forbidden in ("docker ", "psql ", "systemctl ", "pg_reload_conf", "curl -X"):
        assert forbidden not in source


def test_approval_packet_has_every_required_document():
    expected = {
        "CHANGE_REQUEST.md",
        "OWNERSHIP_MATRIX.md",
        "MAINTENANCE_WINDOW_REQUEST.md",
        "REPLICA_INFRASTRUCTURE_REQUEST.md",
        "PRIVATE_DNS_REQUEST.md",
        "FENCING_REQUEST.md",
        "SECRET_GOVERNANCE_REQUEST.md",
        "RPO_RTO_POLICY.md",
        "TELEPHONY_CANARY_REQUEST.md",
        "CUTOVER_GO_NO_GO.md",
        "approved-change.env.example",
    }
    assert expected <= {path.name for path in PACKAGE.iterdir()}


def copy_manifest_fixture(tmp_path: Path) -> Path:
    destination = tmp_path / "repository"
    shutil.copytree(
        ROOT,
        destination,
        ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "*.pyc"),
    )
    return destination


def run_manifest_verifier(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(root / "tools/verify_migration_manifest.py"), "--root", str(root)],
        text=True,
        capture_output=True,
    )


def generate_manifests(root: Path) -> None:
    subprocess.run(
        ["python3", str(root / "tools/generate_migration_manifests.py"), "--root", str(root)],
        check=True,
        text=True,
        capture_output=True,
    )


def load_manifests(root: Path) -> tuple[dict, dict]:
    return (
        json.loads((root / "MIGRATION_MANIFEST.json").read_text()),
        yaml.safe_load((root / "MIGRATION_MANIFEST.yaml").read_text()),
    )


def test_dual_manifests_use_same_ordered_authority_inventory(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    json_manifest, yaml_manifest = load_manifests(root)
    assert json_manifest["files"] == yaml_manifest["files"]
    assert len(json_manifest["files"]) == len(manifest_generator.approved_paths(root))
    assert [row["path"] for row in json_manifest["files"]] == sorted(
        row["path"] for row in json_manifest["files"]
    )
    assert run_manifest_verifier(root).returncode == 0


def test_manifest_generation_is_byte_for_byte_deterministic(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    first = tuple((root / name).read_bytes() for name in ("MIGRATION_MANIFEST.json", "MIGRATION_MANIFEST.yaml"))
    generate_manifests(root)
    second = tuple((root / name).read_bytes() for name in ("MIGRATION_MANIFEST.json", "MIGRATION_MANIFEST.yaml"))
    assert first == second


def test_generator_and_verifier_are_inventoried_with_matching_metadata(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    json_manifest, yaml_manifest = load_manifests(root)
    json_rows = {row["path"]: row for row in json_manifest["files"]}
    yaml_rows = {row["path"]: row for row in yaml_manifest["files"]}
    for relative in ("tools/generate_migration_manifests.py", "tools/verify_migration_manifest.py"):
        assert json_rows[relative] == yaml_rows[relative]
        content = (root / relative).read_bytes()
        assert json_rows[relative]["size"] == len(content)
        assert json_rows[relative]["sha256"] == manifest_generator.sha256(content)
    assert manifest_generator.MANIFEST_ARTIFACTS == {
        "MIGRATION_MANIFEST.json", "MIGRATION_MANIFEST.yaml"
    }


@pytest.mark.parametrize(
    "relative",
    ["tools/generate_migration_manifests.py", "tools/verify_migration_manifest.py"],
)
def test_manifest_authority_tool_change_requires_regeneration(tmp_path, relative):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    with (root / relative).open("a") as stream:
        stream.write("\n# stale authority test\n")
    assert run_manifest_verifier(root).returncode != 0


def test_generation_id_matches_across_formats_and_recomputes(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    json_manifest, yaml_manifest = load_manifests(root)
    identifier = json_manifest["manifest_generation_id"]
    assert identifier == yaml_manifest["manifest_generation_id"]
    assert len(identifier) == 64
    assert manifest_generator.generation_id(json_manifest) == identifier


@pytest.mark.parametrize("mutation", ["missing", "malformed", "different", "nonmatching"])
def test_invalid_generation_id_fails(tmp_path, mutation):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    json_manifest, yaml_manifest = load_manifests(root)
    if mutation == "missing":
        json_manifest.pop("manifest_generation_id")
        yaml_manifest.pop("manifest_generation_id")
    elif mutation == "malformed":
        json_manifest["manifest_generation_id"] = "invalid"
        yaml_manifest["manifest_generation_id"] = "invalid"
    elif mutation == "different":
        json_manifest["manifest_generation_id"] = "0" * 64
    else:
        json_manifest["manifest_generation_id"] = "0" * 64
        yaml_manifest["manifest_generation_id"] = "0" * 64
    (root / "MIGRATION_MANIFEST.json").write_text(
        json.dumps(json_manifest, sort_keys=True, indent=2) + "\n"
    )
    (root / "MIGRATION_MANIFEST.yaml").write_text(yaml.safe_dump(yaml_manifest, sort_keys=True))
    assert run_manifest_verifier(root).returncode != 0


def test_mixed_generation_pair_fails(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    old_json = (root / "MIGRATION_MANIFEST.json").read_bytes()
    with (root / "README.md").open("a") as stream:
        stream.write("\nnew generation\n")
    generate_manifests(root)
    (root / "MIGRATION_MANIFEST.json").write_bytes(old_json)
    assert run_manifest_verifier(root).returncode != 0


class CheckpointFailure(manifest_generator.FileOperations):
    def __init__(self, checkpoint: str, error_type=RuntimeError):
        self.target = checkpoint
        self.error_type = error_type

    def checkpoint(self, name: str) -> None:
        if name == self.target:
            raise self.error_type(name)


class ReplacementFailure(manifest_generator.FileOperations):
    def __init__(self, replacement: int):
        self.target = replacement
        self.count = 0

    def replace(self, source: Path, destination: Path) -> None:
        self.count += 1
        if self.count == self.target:
            raise OSError(f"replacement {self.count} failed")
        super().replace(source, destination)


def manifest_bytes(root: Path) -> tuple[bytes, bytes]:
    return tuple((root / name).read_bytes() for name in ("MIGRATION_MANIFEST.json", "MIGRATION_MANIFEST.yaml"))


def transaction_residue(root: Path) -> list[Path]:
    paths = sorted(root.glob(".MIGRATION_MANIFEST.*")) + sorted(root.glob(".migration-manifests.*"))
    return [path for path in paths if path.name != manifest_generator.LOCK_NAME]



@pytest.mark.parametrize(
    "operations",
    [
        CheckpointFailure("prepared"),
        CheckpointFailure("first_replaced"),
        ReplacementFailure(2),
        CheckpointFailure("before_final_verification"),
    ],
)
def test_transaction_failure_restores_complete_old_pair(tmp_path, operations):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    previous = manifest_bytes(root)
    with (root / "README.md").open("a") as stream:
        stream.write("\ntransaction candidate\n")
    with pytest.raises((RuntimeError, OSError)):
        manifest_generator.generate(root, operations)
    assert manifest_bytes(root) == previous
    assert transaction_residue(root) == []


def test_both_candidates_are_complete_before_first_destination_change(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    previous = manifest_bytes(root)

    class InspectCandidates(CheckpointFailure):
        def checkpoint(self, name: str) -> None:
            if name == "candidates_staged":
                staged = {}
                for manifest, prefix in manifest_generator.CANDIDATE_NAMES.items():
                    matches = list(root.glob(f"{prefix}.*"))
                    assert len(matches) == 1
                    staged[manifest] = matches[0].read_bytes()
                manifest_generator.validate_pair(staged, root)
                assert manifest_bytes(root) == previous
            super().checkpoint(name)

    with pytest.raises(RuntimeError):
        manifest_generator.generate(root, InspectCandidates("candidates_staged"))
    assert manifest_bytes(root) == previous
    assert transaction_residue(root) == []


def test_interrupted_transaction_recovers_on_next_invocation(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    with (root / "README.md").open("a") as stream:
        stream.write("\ninterrupted candidate\n")
    with pytest.raises(KeyboardInterrupt):
        manifest_generator.generate(root, CheckpointFailure("first_replaced", KeyboardInterrupt))
    assert (root / manifest_generator.JOURNAL_NAME).is_file()
    manifest_generator.generate(root)
    assert run_manifest_verifier(root).returncode == 0
    assert transaction_residue(root) == []


def test_success_leaves_no_transaction_files(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    assert transaction_residue(root) == []


@pytest.mark.parametrize(
    ("manifest_name", "field"),
    [
        ("MIGRATION_MANIFEST.json", "sha256"),
        ("MIGRATION_MANIFEST.yaml", "sha256"),
        ("MIGRATION_MANIFEST.json", "size"),
    ],
)
def test_stale_manifest_entry_fails(tmp_path, manifest_name, field):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    path = root / manifest_name
    if path.suffix == ".json":
        document = json.loads(path.read_text())
        document["files"][0][field] = "0" * 64 if field == "sha256" else -1
        path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")
    else:
        document = yaml.safe_load(path.read_text())
        document["files"][0][field] = "0" * 64
        path.write_text(yaml.safe_dump(document, sort_keys=True))
    assert run_manifest_verifier(root).returncode != 0


@pytest.mark.parametrize("operation", ["remove", "add"])
def test_json_entry_set_drift_fails(tmp_path, operation):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    path = root / "MIGRATION_MANIFEST.json"
    document = json.loads(path.read_text())
    if operation == "remove":
        document["files"].pop()
    else:
        document["files"].append({"path": "unapproved", "sha256": "0" * 64, "size": 0})
    path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")
    assert run_manifest_verifier(root).returncode != 0


@pytest.mark.parametrize("manifest_name", ["MIGRATION_MANIFEST.json", "MIGRATION_MANIFEST.yaml"])
def test_missing_manifest_fails(tmp_path, manifest_name):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    (root / manifest_name).unlink()
    assert run_manifest_verifier(root).returncode != 0


def test_one_sided_manifest_field_fails(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    path = root / "MIGRATION_MANIFEST.json"
    document = json.loads(path.read_text())
    document["json_only_field"] = True
    path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")
    assert run_manifest_verifier(root).returncode != 0


def test_missing_declared_authority_file_fails(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    (root / "README.md").unlink()
    assert run_manifest_verifier(root).returncode != 0


def test_undeclared_kong_authority_file_fails(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    (root / "scripts/undeclared_authority.py").write_text("raise SystemExit(0)\n")
    assert run_manifest_verifier(root).returncode != 0


def tracked_mode(root: Path, relative: str) -> str:
    result = subprocess.run(
        ["git", "ls-files", "--stage", "--", relative],
        cwd=root,
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.split(maxsplit=1)[0]


def test_canonical_reconciler_is_tracked_executable_and_directly_invocable():
    relative = "scripts/reconcile_kong_canonical_routes.py"
    assert tracked_mode(ROOT, relative) == "100755"
    result = subprocess.run([str(ROOT / relative), "--help"], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


def test_tracked_mode_guard_rejects_removed_executable_bit(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    relative = "scripts/reconcile_kong_canonical_routes.py"
    path = root / relative
    path.parent.mkdir()
    path.write_text("#!/usr/bin/env python3\n")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", relative], cwd=root, check=True)
    subprocess.run(["git", "update-index", "--chmod=-x", relative], cwd=root, check=True)
    assert tracked_mode(root, relative) == "100644"
    assert tracked_mode(root, relative) != "100755"



def _probe_manifest_lock(root: Path) -> int:
    code = (
        "import fcntl\n"
        "import os\n"
        "import sys\n"
        "path = sys.argv[1]\n"
        "flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)\n"
        "fd = os.open(path, flags, 0o600)\n"
        "try:\n"
        "    try:\n"
        "        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
        "    except BlockingIOError:\n"
        "        raise SystemExit(75)\n"
        "    else:\n"
        "        fcntl.flock(fd, fcntl.LOCK_UN)\n"
        "        raise SystemExit(0)\n"
        "finally:\n"
        "    os.close(fd)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(root / manifest_generator.LOCK_NAME)],
        timeout=5,
    )
    return result.returncode


def _wait_for_path(path: Path, process: subprocess.Popen, timeout: float = 5.0) -> None:
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise AssertionError(f"lock holder exited early: {process.returncode}")
        time.sleep(0.01)
    process.kill()
    raise AssertionError(f"timed out waiting for {path}")


def _assert_command_serializes_behind_lock(root: Path, command: list[str]) -> None:
    import time

    ready = root / ".lock-test-ready"
    release = root / ".lock-test-release"
    holder_code = (
        "import sys\n"
        "import time\n"
        "from pathlib import Path\n"
        "root = Path(sys.argv[1])\n"
        "sys.path.insert(0, str(root / 'tools'))\n"
        "import generate_migration_manifests as generator\n"
        "ready = Path(sys.argv[2])\n"
        "release = Path(sys.argv[3])\n"
        "with generator.generator_lock(root):\n"
        "    ready.write_text('ready\\n')\n"
        "    while not release.exists():\n"
        "        time.sleep(0.01)\n"
    )
    holder = subprocess.Popen(
        [sys.executable, "-c", holder_code, str(root), str(ready), str(release)],
        text=True,
    )
    contender = None
    try:
        _wait_for_path(ready, holder)
        contender = subprocess.Popen(command, cwd=root, text=True)
        time.sleep(0.25)
        assert contender.poll() is None, "lock-aware command bypassed an active manifest lock"
        release.write_text("release\n")
        assert holder.wait(timeout=5) == 0
        assert contender.wait(timeout=20) == 0
    finally:
        release.write_text("release\n")
        if holder.poll() is None:
            holder.kill()
        if contender is not None and contender.poll() is None:
            contender.kill()
        ready.unlink(missing_ok=True)
        release.unlink(missing_ok=True)


def test_manifest_lock_inode_is_persistent_and_cross_process_exclusive(tmp_path):
    import stat

    root = copy_manifest_fixture(tmp_path)
    lock_path = root / manifest_generator.LOCK_NAME
    with manifest_generator.generator_lock(root):
        first = lock_path.stat()
        assert _probe_manifest_lock(root) == 75
    assert _probe_manifest_lock(root) == 0
    with manifest_generator.generator_lock(root):
        second = lock_path.stat()
        assert _probe_manifest_lock(root) == 75
    assert (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)
    assert stat.S_ISREG(second.st_mode)
    assert stat.S_IMODE(second.st_mode) == 0o600
    assert second.st_uid == os.geteuid()
    assert second.st_nlink == 1


def test_manifest_lock_rejects_mode_drift_and_symlinks(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    lock_path = root / manifest_generator.LOCK_NAME
    with manifest_generator.generator_lock(root):
        pass
    lock_path.chmod(0o644)
    with pytest.raises(manifest_generator.TransactionError, match="mode"):
        with manifest_generator.generator_lock(root):
            pass
    lock_path.unlink()
    lock_path.symlink_to(root / "README.md")
    with pytest.raises((manifest_generator.TransactionError, OSError)):
        with manifest_generator.generator_lock(root):
            pass


@pytest.mark.parametrize(
    "command_kind",
    ["generate", "check", "verify"],
)
def test_generator_verifier_and_check_serialize_across_processes(tmp_path, command_kind):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    if command_kind == "generate":
        command = [
            sys.executable,
            str(root / "tools/generate_migration_manifests.py"),
            "--root",
            str(root),
        ]
    elif command_kind == "check":
        command = [
            sys.executable,
            str(root / "tools/generate_migration_manifests.py"),
            "--root",
            str(root),
            "--check",
        ]
    else:
        command = [
            sys.executable,
            str(root / "tools/verify_migration_manifest.py"),
            "--root",
            str(root),
        ]
    _assert_command_serializes_behind_lock(root, command)


def test_check_holds_lock_through_expected_and_actual_comparison(tmp_path, monkeypatch):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    original_outputs = manifest_generator.current_outputs
    original_inventory = manifest_generator.inventory

    def guarded_current_outputs(selected_root):
        assert _probe_manifest_lock(selected_root) == 75
        return original_outputs(selected_root)

    def guarded_inventory(selected_root=manifest_generator.ROOT):
        assert _probe_manifest_lock(selected_root) == 75
        return original_inventory(selected_root)

    monkeypatch.setattr(manifest_generator, "current_outputs", guarded_current_outputs)
    monkeypatch.setattr(manifest_generator, "inventory", guarded_inventory)
    assert manifest_generator.check(root) == len(manifest_generator.approved_paths(root))


def test_verifier_holds_lock_through_manifest_and_authority_reads(tmp_path, monkeypatch):
    import importlib

    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    verifier = importlib.import_module("verify_migration_manifest")
    original_load_document = verifier.load_document
    original_approved_paths = verifier.approved_paths

    def guarded_load_document(path, *, yaml_format):
        assert _probe_manifest_lock(root) == 75
        return original_load_document(path, yaml_format=yaml_format)

    def guarded_approved_paths(selected_root):
        assert _probe_manifest_lock(root) == 75
        return original_approved_paths(selected_root)

    monkeypatch.setattr(verifier, "load_document", guarded_load_document)
    monkeypatch.setattr(verifier, "approved_paths", guarded_approved_paths)
    assert verifier.verify(root) == len(manifest_generator.approved_paths(root))


def test_committed_generation_survives_later_authority_drift(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    with (root / "README.md").open("a") as stream:
        stream.write("\ncommitted candidate\n")
    with pytest.raises(KeyboardInterrupt):
        manifest_generator.generate(
            root,
            CheckpointFailure("before_final_verification", KeyboardInterrupt),
        )
    committed = manifest_bytes(root)
    assert (root / manifest_generator.JOURNAL_NAME).is_file()
    with (root / "SECURITY.md").open("a") as stream:
        stream.write("\npost-commit source drift\n")
    with manifest_generator.generator_lock(root):
        assert manifest_generator.recover_transaction(root) is True
    assert manifest_bytes(root) == committed
    assert transaction_residue(root) == []
    assert run_manifest_verifier(root).returncode != 0



def test_secure_staging_write_refuses_existing_symlink(tmp_path):
    target = tmp_path / "protected-target"
    target.write_bytes(b"protected\n")
    target.chmod(0o640)
    staging = tmp_path / ".candidate"
    staging.symlink_to(target)
    before_mode = target.stat().st_mode

    with pytest.raises(manifest_generator.TransactionError, match="create staging file safely"):
        manifest_generator.write_durable(staging, b"overwrite\n", 0o600)

    assert target.read_bytes() == b"protected\n"
    assert target.stat().st_mode == before_mode
    assert staging.is_symlink()


def test_transaction_candidates_use_unpredictable_ids_and_detect_inode_swap(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)
    previous = manifest_bytes(root)
    target = root / "protected-target"
    target.write_bytes(b"protected\n")
    target.chmod(0o640)

    class SwapCandidate(manifest_generator.FileOperations):
        def checkpoint(self, name: str) -> None:
            if name != "candidates_staged":
                return
            prefix = manifest_generator.CANDIDATE_NAMES[manifest_generator.YAML_MANIFEST]
            matches = list(root.glob(f"{prefix}.*"))
            assert len(matches) == 1
            candidate = matches[0]
            transaction_id = candidate.name.rsplit(".", 1)[-1]
            assert len(transaction_id) == 32
            assert all(character in "0123456789abcdef" for character in transaction_id)
            candidate.unlink()
            candidate.symlink_to(target)

    with (root / "README.md").open("a") as stream:
        stream.write("\nsecure staging candidate\n")
    with pytest.raises(manifest_generator.TransactionError, match="staging file"):
        manifest_generator.generate(root, SwapCandidate())

    assert manifest_bytes(root) == previous
    assert target.read_bytes() == b"protected\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert transaction_residue(root) == []


def test_transaction_recovery_files_are_unique_and_non_symlink(tmp_path):
    root = copy_manifest_fixture(tmp_path)
    generate_manifests(root)

    class InspectRecovery(manifest_generator.FileOperations):
        def checkpoint(self, name: str) -> None:
            if name != "prepared":
                return
            journal = json.loads((root / manifest_generator.JOURNAL_NAME).read_text())
            transaction_id = manifest_generator.require_transaction_id(journal["transaction_id"])
            recovery_names = manifest_generator.transaction_names(
                manifest_generator.RECOVERY_NAMES,
                transaction_id,
            )
            for recovery_name in recovery_names.values():
                recovery = root / recovery_name
                metadata = recovery.lstat()
                assert stat.S_ISREG(metadata.st_mode)
                assert not stat.S_ISLNK(metadata.st_mode)
                assert stat.S_IMODE(metadata.st_mode) == 0o600
                assert metadata.st_nlink == 1

    with (root / "README.md").open("a") as stream:
        stream.write("\nunique recovery candidate\n")
    manifest_generator.generate(root, InspectRecovery())
    assert run_manifest_verifier(root).returncode == 0
    assert transaction_residue(root) == []
