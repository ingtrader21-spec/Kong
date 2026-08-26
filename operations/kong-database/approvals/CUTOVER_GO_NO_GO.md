# Kong database cutover GO/NO-GO contract

The read-only validator is the mandatory entry gate. It authorizes no mutation.

GO requires: assigned approved change ID; every accountable owner; current
approved maintenance window; allocated independent replica; approved private DNS;
enforceable fencing; approved secret backend; approved RPO/RTO and retention;
approved telephony authority; fresh local and off-host backups; restore PASS;
PITR rehearsal PASS; and rollback evidence.

```text
IF any required gate != PASS
THEN
    KONG_DB_CUTOVER_GO=NO
    EXIT WITHOUT DATABASE MUTATION
```

After GO, the workflow executes the reviewed backup, upgrade, role/HBA/TLS/WAL
cutover, base backup, replica bootstrap, parity, stable authority, monitoring,
fenced failover/rejoin, isolated PITR, canary, soak and drift checks. Every phase
has a stop/rollback checkpoint. No promotion is possible without positive fence
confirmation; no canary is possible without telephony safety evidence.

Acceptance: `validate-change-authority.sh <protected-approved-file>` exits zero
and prints every gate PASS plus `KONG_DB_CUTOVER_GO=YES`. Any other result is NO-GO.
