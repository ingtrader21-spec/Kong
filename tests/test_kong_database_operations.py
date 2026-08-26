from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "operations" / "kong-database"


def test_backup_is_encrypted_checksummed_retained_and_off_host():
    value = (PACKAGE / "kong-database-backup.sh").read_text()
    assert "pg_dump" in value and "--format=custom" in value
    assert "gpg" in value and "--encrypt" in value
    assert "sha256sum -c" in value
    assert "restic_retry backup" in value
    assert "--keep-daily 14" in value
    assert "--keep-weekly 8" in value
    assert "--keep-monthly 12" in value
    assert "POSTGRES_PASSWORD" not in value


def test_restore_is_isolated_and_never_targets_production():
    value = (PACKAGE / "kong-database-restore-rehearsal.sh").read_text()
    assert "docker network create --internal" in value
    assert "PUBLIC_PORTS=0" in value
    assert "codestra-kong_kong_db_data" not in value
    assert "--exit-on-error" in value
    assert "kong health" in value
    for topology in ("services", "routes", "plugins"):
        assert f"restored_{topology}" in value


def test_metrics_and_alerts_cover_production_database_gates():
    metrics = (PACKAGE / "kong-database-metrics.sh").read_text()
    rules = (PACKAGE / "kong-database.rules.yml").read_text()
    for metric in (
        "connections",
        "lock_waits",
        "deadlocks_total",
        "disk_used_percent",
        "backup_age_seconds",
        "migration_up_to_date",
        "replication_lag_seconds",
    ):
        assert f"codestra_kong_db_{metric}" in metrics
        assert f"codestra_kong_db_{metric}" in rules or metric in {
            "deadlocks_total"
        }
    for alert in (
        "KongDatabaseUnavailable",
        "KongDatabaseConnectionsWarning",
        "KongDatabaseConnectionsCritical",
        "KongDatabaseDiskWarning",
        "KongDatabaseDiskCritical",
        "KongDatabaseBackupStale",
        "KongDatabaseBackupJobFailed",
        "KongDatabaseRestoreRehearsalOverdue",
        "KongDatabaseDeadlockDetected",
        "KongDatabaseMigrationMismatch",
        "KongDatabaseReplicationDisconnected",
        "KongDatabaseReplicationLagHigh",
        "KongDatabaseUnexpectedWritableStandby",
        "KongDatabaseReplicationSlotInactive",
        "KongDatabaseWalReceiverDown",
        "KongDatabaseWALArchiveFailure",
    ):
        assert f"alert: {alert}" in rules


def test_units_are_root_controlled_and_persistent():
    service = (PACKAGE / "codestra-kong-database-backup.service").read_text()
    timer = (PACKAGE / "codestra-kong-database-backup.timer").read_text()
    assert "User=root" in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
    assert "Persistent=true" in timer
    assert "OnCalendar=" in timer
    expected = {
        "codestra-kong-database-backup.service": "kong-database-backup.sh",
        "codestra-kong-database-metrics.service": "kong-database-metrics.sh",
        "codestra-kong-database-restore.service": "kong-database-restore-rehearsal.sh",
        "codestra-kong-database-pitr-rehearsal.service": "pitr-rehearsal.sh",
    }
    for unit, script in expected.items():
        assert f"ExecStart=/usr/local/sbin/{script}" in (PACKAGE / unit).read_text()
        assert (PACKAGE / script).is_file()


def test_restore_rehearsal_is_scheduled_and_persistent():
    service = (PACKAGE / "codestra-kong-database-restore.service").read_text()
    timer = (PACKAGE / "codestra-kong-database-restore.timer").read_text()
    assert "kong-database-restore-rehearsal" in service
    assert "NoNewPrivileges=true" in service
    assert "OnCalendar=monthly" in timer
    assert "Persistent=true" in timer
    pitr_service = (PACKAGE / "codestra-kong-database-pitr-rehearsal.service").read_text()
    pitr_timer = (PACKAGE / "codestra-kong-database-pitr-rehearsal.timer").read_text()
    assert "pitr-rehearsal.sh" in pitr_service
    assert "OnCalendar=monthly" in pitr_timer
    assert "Persistent=true" in pitr_timer


def test_hba_and_roles_fail_closed_without_secrets():
    hba = (PACKAGE / "pg_hba.conf").read_text()
    roles_path = PACKAGE / "roles.sql"
    assert roles_path.is_file(), "roles.sql must exist in a clean checkout"
    roles = roles_path.read_text()
    active_hba = [line for line in hba.splitlines() if line and not line.startswith("#")]
    assert all(line.split()[-1] != "trust" for line in active_hba)
    assert "scram-sha-256" in hba
    assert "0.0.0.0/0            reject" in hba
    assert "kong_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE" in roles
    assert "kong_replication LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE" in roles
    assert "kong_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE" in roles
    assert "kong_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE" in roles
    assert "REASSIGN OWNED BY kong TO kong_owner" in roles
    assert "GRANT kong_owner TO kong_migration_admin" in roles
    assert " PASSWORD '" not in roles.upper()


def test_pitr_and_wal_archive_are_off_host_and_encrypted():
    config = (PACKAGE / "postgresql-ha.conf").read_text()
    archive = (PACKAGE / "codestra-kong-wal-archive.sh").read_text()
    rehearsal = (PACKAGE / "pitr-rehearsal.sh").read_text()
    for value in ("archive_mode = 'on'", "wal_level = 'replica'", "max_wal_senders", "max_replication_slots"):
        assert value in config
    assert "gpg" in archive and "restic backup" in archive
    assert "recovery_target_time" in rehearsal
    assert "codestra_pitr_marker" in rehearsal
    assert "KONG_SCHEMA_BOOT=PASS" in rehearsal


def test_least_privilege_rehearsal_proves_runtime_and_migration_separation():
    value = (PACKAGE / "least-privilege-rehearsal.sh").read_text()
    assert "KONG_PG_USER=kong_runtime" in value
    assert "ADMIN_READ_WRITE=PASS" in value
    assert "MIGRATION_PRIVILEGE_ISOLATION=PASS" in value
    assert "create table must_be_denied" in value


def test_replication_metrics_are_live_when_expected():
    value = (PACKAGE / "kong-database-metrics.sh").read_text()
    assert "pg_stat_wal_receiver" in value
    assert "pg_last_xact_replay_timestamp" in value
    assert "replica-monitor.env" in value
    for metric in (
        "codestra_kong_db_replication_lag_seconds $replication_lag",
        "codestra_kong_db_standby_in_recovery $standby_in_recovery",
        "codestra_kong_db_standby_read_only $standby_read_only",
        "codestra_kong_db_wal_receiver_up $wal_receiver_up",
    ):
        assert metric in value
