# Kong database RPO/RTO proposal

These values are proposals and are **not approved** by this document.

```text
PROPOSED_RPO_SECONDS=300
PROPOSED_RTO_SECONDS=900
PROPOSED_WAL_RETENTION=7 days off-host, subject to capacity validation
PROPOSED_BASE_BACKUP_RETENTION=2 weekly and 3 monthly physical backups
LOGICAL_BACKUP_RETENTION=14 daily, 8 weekly, 12 monthly
APPROVAL_OWNER=PENDING
APPROVAL_STATUS=PENDING
```

Evidence: daily encrypted logical backup, independent Restic copy, 14/8/12
retention, 9-second isolated logical restore, and isolated timestamp recovery
already pass. The five-minute RPO requires live WAL archiving and monitored
streaming replication. The fifteen-minute RTO requires stable DNS, fencing and
a rehearsed promotion.

The database owner must explicitly accept data-loss exposure, recovery time,
WAL/base-backup capacity, expiry behavior, and rehearsal frequency. Failure to
approve any value leaves cutover NO-GO.
