# Kong PostgreSQL operations

This directory is the source authority for Kong database backup, isolated restore
rehearsal, operational metrics, and alerting. Deploy the scripts to
`/usr/local/sbin`, units to `/etc/systemd/system`, and the rule file to the
production Prometheus rule directory through the reviewed platform release.

## Recovery objectives

- Daily encrypted logical backup, RPO 24 hours.
- Retention: 14 daily, 8 weekly, and 12 monthly snapshots.
- Independent encrypted Restic object storage copy on every successful run.
- Monthly isolated restore rehearsal; current measured logical restore RTO is
  recorded in root-only evidence under `/var/lib/codestra-kong-database/evidence`.
- No backup or restore listener is published.

The current single-node PostgreSQL deployment does not provide PITR or HA. Do
not claim those controls until a second failure domain, private TLS replication,
fencing authority, and a tested promotion workflow are approved and deployed.

## Approved target architecture

`kong-db.internal.codestra.agency` is the proposed stable private authority. It
must resolve only inside the production control/database networks and must be
changed exclusively by the HA promotion workflow. The primary and replica must
run on independent physical failure domains. Replication uses TLS, the dedicated
`kong_replication` role, one physical slot, and no public listener.

The committed `postgresql-ha.conf`, `pg_hba.conf`, and `roles.sql` are deployment
inputs, not authorization to restart production. The HBA deployment must render
`${REPLICA_CIDR}` from approved infrastructure inventory, validate it through
`pg_hba_file_rules`, prove an authenticated alternate session, preserve a
root-only rollback copy, then reload. An unresolved placeholder fails release.

Runtime, migration, monitoring, and replication credentials are distinct secret
objects. Runtime Kong uses only `kong_runtime`; migrations temporarily use
`kong_migration_admin`; metrics use `kong_monitor`; streaming uses
`kong_replication`. Secret values are never supplied by this repository.

The WAL archive command encrypts each validated WAL segment and verifies an
independent Restic object-storage snapshot. A physical base-backup workflow and
archive retention policy must be deployed with it before live PITR is enabled.
The isolated rehearsal proves timestamp recovery and Kong schema boot, but does
not make the current production instance PITR-capable.

## Minor upgrade and rollback

Current live DB image: PostgreSQL 17.6 digest
`sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`.
Approved desired image: PostgreSQL 17.11 digest
`sha256:0b657ff48d7f76a1e907f381b1693eb4f2bf54c1d2df4feb6743d7dc601768dd`.
Kong remains `kong/kong-gateway:3.14.0.1-ubuntu`; schema migrations are current.

Before the approved window, require a fresh off-host backup, checksum, successful
17.11 restore rehearsal, current migrations, both local image digests, and a
captured topology count. Recreate only `kong-db` with the 17.11 image and the
existing named volume. Verify PostgreSQL, Kong datastore, migrations, topology,
auth, rate limiting, request IDs, restarts, and logs. Same-major rollback may
recreate the container with the prior 17.6 digest only if PostgreSQL has not
written an incompatible catalog change; otherwise restore the pre-change backup
into an isolated volume and promote through the recovery workflow.

## DR reconstruction

DR inputs are: this Git commit, pinned PostgreSQL/Kong images, off-host logical
backup, off-host encrypted WAL/base backup, protected role secrets, and Kong
desired state. Rebuild an isolated database, perform PITR, start Kong privately,
compare topology and drift, then promote only after fencing and change approval.
Logical restore and isolated PITR have automated rehearsals; cross-host promotion
and stable-authority switching remain mandatory live evidence.

## Failover runbook (approval required)

Owner: production platform on-call and database owner.

Trigger: confirmed primary loss or corruption after application and host checks.

1. Freeze Kong configuration mutations and declare an incident.
2. Fence the failed primary at the compute/network layer. Promotion is forbidden
   until fencing is independently confirmed.
3. Confirm the approved replica is streaming, its replay lag is within the RPO,
   and its last received/replayed LSN is consistent.
4. Promote using the HA manager's reviewed promotion command; never start a
   second independent writable database.
5. Change the stable private database authority (managed endpoint or HA virtual
   name), not individual Kong containers.
6. Verify Kong datastore health, Admin API topology counts, auth, rate limiting,
   request IDs, and proxy traffic.
7. Rebuild the former primary as a replica before it may rejoin.

Rollback means fencing the failed promotion target, selecting the authoritative
timeline, and following the same controlled promotion process. Target RTO is 15
minutes; final RPO depends on the approved synchronous/asynchronous replication
policy. No credentials belong in this runbook.

## Mutation governance

The Admin API remains loopback/private. Normal mutations flow from Git review to
validated reconciliation. Emergency Admin API changes require an incident/change
record and a same-day source reconciliation. Drift detection is read-only and
must never automatically delete an unknown production object.
