# Gateway responsibilities

| Authority | Owns |
| --- | --- |
| GitHub | Reviewed non-secret contracts, policy, source identity and release evidence |
| Caddy | Public HTTP/TLS ingress on 80/443 |
| Kong | Routing, authentication enforcement, claim/scope checks, limits and edge identity |
| Keycloak | Users, clients, issuers, signing keys, tokens, roles and scopes |
| Middleware | Business resource tenancy, durable replay/idempotency, inbox/outbox, providers and reconciliation |
| Control API | Draft/version/preview/approval/job records, tenant membership, audit and command idempotency |
| Deployment agent | Authenticated immutable release admission and authorized private Admin operations |
| Database authority | Dedicated PostgreSQL roles, TLS/HBA, backups, PITR, fencing and rejoin |
| Observability authority | Redacted telemetry, configuration drift, certificate and recovery evidence |

Approval does not grant deployment permission. Source validation does not grant
production activation. A successful status command is not runtime certification.
