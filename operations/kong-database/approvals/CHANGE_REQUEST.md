# Kong PostgreSQL 17.11 Security / PITR / HA Activation

Status: `PENDING_APPROVAL`

Change ID: `PENDING_APPROVAL`

## Current evidence

| Control | Value |
| --- | --- |
| PostgreSQL | 17.6 |
| Target | 17.11 pinned digest in Git |
| Backup | PASS |
| Off-host backup | PASS |
| Restore | PASS, measured RTO 9 seconds |
| PITR rehearsal | PASS (isolated) |
| Unexpected Kong drift | 0 |

## Requested decision and scope

Approve one controlled production change covering the PostgreSQL 17.11 minor
upgrade, separate database roles, runtime credential cutover, SCRAM HBA
hardening, PostgreSQL TLS, encrypted WAL archiving, physical base backup,
cross-host streaming replication, private stable database DNS, fencing,
failover/failback rehearsal, narrow authenticated Kong canary, and load/soak.

Approval accepts only the reviewed sequence and rollback boundaries in this
package. It does not approve unrelated infrastructure or application changes.

**NO USER TRAFFIC ACTIVATION IS IMPLIED BY THIS APPROVAL.** Telephony safety and
the separate canary authority remain mandatory.

## Acceptance and rollback boundary

Accept when all go/no-go gates pass, topology remains 19 services/27 routes/115
plugins, database security and recovery checks pass, and drift remains zero.
Rollback before irreversible authority promotion uses the prior 17.6 image and
preserved volume when catalog-compatible; otherwise restore the fresh encrypted
backup. After promotion, rollback is a fenced recovery/failover operation—never
two writable primaries.

Security constraints: no public PostgreSQL listener, no secrets in Git/logs,
private TLS replication, least-privilege runtime, positive fencing confirmation,
and fail-closed exit on missing evidence or approval.

Post-approval workflow: run `validate-change-authority.sh` against the protected
approved file; proceed only when it returns `KONG_DB_CUTOVER_GO=YES`.
