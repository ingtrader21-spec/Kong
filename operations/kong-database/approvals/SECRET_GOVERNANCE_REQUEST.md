# Kong PostgreSQL secret governance request

Requested decision: approve the backend, owners, access policy and rotation for
five unique credentials: `kong_runtime`, `kong_migration_admin`, `kong_monitor`,
`kong_backup`, and `kong_replication`.

```text
SECRET_BACKEND=PENDING
SECRET_OWNER=PENDING
ROTATION_OWNER=PENDING
ROTATION_INTERVAL=PENDING
BREAK_GLASS_POLICY=PENDING
```

Required policy: one independently generated credential per role; root/service
readability only; mode 0400/0600; no Git, command-line, log, evidence, image, or
Compose interpolation leakage; audited retrieval; versioned rotation metadata;
immediate emergency revoke; and a protected rollback credential valid only for
the approved rollback window.

Migration credentials are mounted only for reviewed migrations. Monitoring,
backup, and replication credentials cannot perform application mutations.
Acceptance requires access tests for each intended service and denial tests for
other identities. Rollback restores the prior protected runtime secret without
reintroducing a superuser gateway role.
