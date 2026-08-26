# Maintenance window request

Requested decision: approve a database cutover window and separate failover and
load/soak windows. No clock time is approved by this document.

| Sequence | Estimate |
| --- | ---: |
| Freeze and fresh encrypted/off-host backup | 15 min |
| PostgreSQL 17.11 restart and validation | 15 min |
| Role deployment and Kong credential cutover | 20 min |
| HBA/TLS deployment and validation | 20 min |
| WAL activation and physical base backup | 30 min |
| Replica initialization and parity checks | 60 min |
| Stable authority and monitoring validation | 20 min |
| Rollback reserve | 60 min |

`MINIMUM_REQUIRED_WINDOW=180 minutes`

`RECOMMENDED_WINDOW=240 minutes`

`ROLLBACK_RESERVE=60 minutes`

`APPROVED_START=PENDING`

`APPROVED_END=PENDING`

`TIMEZONE=PENDING`

`FAILOVER_REHEARSAL_WINDOW=PENDING`

`LOAD_SOAK_WINDOW=PENDING`

The change owner stops before mutation if the approval validator fails. Abort
criteria include stale backup, restore failure, topology mismatch, HBA/TLS
failure, datastore failure, replication outside RPO, or unavailable rollback.
