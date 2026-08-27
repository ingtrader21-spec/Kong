from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
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
