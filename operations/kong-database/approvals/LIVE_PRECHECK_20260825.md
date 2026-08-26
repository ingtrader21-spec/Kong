# Kong database live precheck — 2026-08-25

This is non-secret, read-only evidence for change `CHG-20260826-KONG-DB-HA-01`.
It does not authorize mutation or supersede the fail-closed validator.

## Primary runtime

- Observed: `2026-08-25T22:28:03-04:00`
- Kong gateway image: `kong/kong-gateway:3.14.0.1-ubuntu`
- Gateway: healthy, restart count 0
- PostgreSQL: 17.6, healthy, restart count 0
- PostgreSQL recovery state: false
- PostgreSQL transaction read-only: off
- Connections: 17 of 100
- Waiting locks: 0
- Deadlocks: 0
- Public PostgreSQL listener: none
- `kong health`: PASS
- `kong migrations list`: PASS
- Host storage used: 79%

## Backup and recovery prerequisites

- Latest local encrypted dump: `20260826T003659Z`
- Local SHA-256 verification: PASS
- Latest tagged off-host snapshot: `2026-08-25T20:36:59.554110407-04:00`
- Off-host repository structural/data-subset check: PASS, no errors
- Fresh in-window backup: required again immediately before cutover
- Restore, PITR, and rollback evidence: must be supplied to the protected runtime approval file and pass the validator

## Replica candidate

- Host: `codestra-provider`
- Private address: `10.40.0.4`
- Distinct host identity from primary: PASS
- CPU: 20 logical CPUs
- Available memory: approximately 57.8 GiB
- Root filesystem: approximately 364 GiB free, NVMe
- Current iowait sample: 0.00%
- Private reachability to primary: PASS
- Public PostgreSQL listeners: 0
- Private port 53 currently available: PASS
- PostgreSQL installed: NO
- Mandatory 24-hour CPU average: NOT AVAILABLE

The replica designation remains fail-closed until genuine 24-hour history proves
average CPU below 50% and the workload owner confirms no material degradation.
An instantaneous or since-boot estimate is not substituted for this requirement.

## Remaining live gates

- Current time is outside the approved cutover window beginning
  `2026-08-28T00:00:00-04:00`.
- The dedicated fencing credential path
  `/etc/codestra/secrets/kong-database/fencing_credential` is not installed.
  Existing Hetzner Robot credential files were inspected by metadata only and
  were not copied, printed, or used for a fencing action.
- Dual private CoreDNS authority is not deployed.
- Restricted `codestra-vicidial-operator safety-status` is not installed on the
  telephony host, so the required sanitized canary evidence is unavailable.
- No database role, PostgreSQL configuration, DNS record, replica, gateway
  credential, route, or production traffic was changed during this precheck.

Result: `KONG_DB_CUTOVER_GO=NO`.
