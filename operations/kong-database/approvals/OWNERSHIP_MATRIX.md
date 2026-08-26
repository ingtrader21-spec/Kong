# Kong database change ownership matrix

Every assignee requires authoritative acceptance. Until then each assignment is
`PENDING_APPROVAL`; role names alone do not grant authority.

| Role | Assignee | Responsibility / required approval | During change | Rollback responsibility | Escalation path |
| --- | --- | --- | --- | --- | --- |
| CHANGE_OWNER | PENDING_APPROVAL | Own scope, window and final go/no-go | Chair checkpoints | Order stop/rollback | Change authority |
| DATABASE_OWNER | PENDING_APPROVAL | Approve PostgreSQL, roles, HBA, TLS, PITR | Validate DB/LSN | Restore/promote DB safely | DBA incident lead |
| PLATFORM_OWNER | PENDING_APPROVAL | Approve hosts, networks and deployment | Execute reviewed release | Restore platform config | Platform incident lead |
| ROLLBACK_OWNER | PENDING_APPROVAL | Accept rollback criteria/artifacts | Track abort thresholds | Direct rollback | Change owner |
| CANARY_OWNER | PENDING_APPROVAL | Approve harmless authenticated canary | Observe runtime evidence | Close bypass immediately | Application owner |
| FAILOVER_OWNER | PENDING_APPROVAL | Approve promotion and rejoin | Control failover sequence | Select authoritative timeline | Database owner |
| FENCING_OWNER | PENDING_APPROVAL | Own enforceable fence | Confirm old primary isolated | Authorize safe unfence | Infrastructure owner |
| DNS_OWNER | PENDING_APPROVAL | Own private zone and TTL | Mutate only after promotion | Restore prior target | Network owner |
| SECRET_OWNER | PENDING_APPROVAL | Approve backend/access | Release role references | Revoke compromised secrets | Security owner |
| ROTATION_OWNER | PENDING_APPROVAL | Own rotation schedule | Record deployed versions | Restore rollback credential | Secret owner |
| TELEPHONY_OPERATOR_OWNER | PENDING_APPROVAL | Certify zero activity safely | Run sanitized readback | Preserve maintenance gate | Telephony incident lead |
