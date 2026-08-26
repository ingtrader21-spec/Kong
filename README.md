# Codestra Kong Gateway

This repository is the source authority for Codestra's Kong Gateway configuration,
exact public route and plugin contracts, private standby design, PostgreSQL
operations and recovery, monitoring, reconciliation tooling, and Kong-specific
tests.

## Architecture boundary

```text
Public client
  -> host Caddy (public TLS edge)
  -> Docker upstream-gateway
  -> private Kong proxy
  -> private application services
```

Kong proxy, Kong Admin API, middleware ports, Redis, and PostgreSQL must not be
published to the public Internet. Host Caddy remains outside Docker.

## Repository layout

- `deploy/kong/` — route, service, plugin, and scope-policy authority.
- `deploy/kong-production-standby/` — private standby topology and auth middleware.
- `config/` — canonical route and route-security manifests.
- `scripts/` — dry-run reconciliation, export, validation, standby, and rollback.
- `operations/kong-database/` — PostgreSQL roles, HBA, TLS, backup, PITR, HA,
  monitoring, approvals, and systemd units.
- `operations/runbooks/` — bounded production activation and rollback procedures.
- `tests/` — standalone route and database authority tests.
- `reports/` — Kong-specific historical evidence retained for traceability.

## Activation boundary

Reconciliation is dry-run by default. Live Admin API mutation, database cutover,
DNS promotion, fencing, deployment, or traffic activation requires a separate
reviewed change, exact-head approval, recovery evidence, and an active maintenance
window.
