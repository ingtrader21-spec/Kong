# Private database DNS request

Requested authority: `kong-db.internal.codestra.agency`

```text
PRIVATE_ONLY=YES
PUBLIC_A_RECORD=NONE
PUBLIC_AAAA_RECORD=NONE
DNS_BACKEND=PENDING
DNS_OWNER=PENDING
TTL=30_SECONDS_PROPOSED
INITIAL_TARGET=CURRENT_KONG_POSTGRESQL_PRIMARY
PROMOTION_UPDATE_METHOD=PENDING_HA_WORKFLOW
ROLLBACK_UPDATE_METHOD=PENDING_HA_WORKFLOW
```

Only the approved HA promotion workflow may mutate this record. Initial creation
must point to the current primary private address. Promotion mutation occurs only
after positive fencing confirmation. Rollback restores the last authoritative
target only after preventing dual writers.

Acceptance: absent from public recursive DNS; resolvable from Kong, primary and
replica private networks; exact target and TTL read back; mutation credentials
restricted to the DNS owner/HA workflow. This request does not create DNS.
