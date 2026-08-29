# Caddy API-Edge Source Authority

## Decision

`appolon1908-hue/Kong` is the canonical source repository for **Codestra API-edge policy**, including the Caddy configuration that fronts Kong and enforces the outer TLS/host/network boundary for `api.codestra.co` and related governed API ingress.

This does **not** make Kong a central release-authority repository. Each product/service still releases independently. This repository owns only the gateway/edge policy and artifacts that belong to the Kong ingress boundary.

## Why this decision exists

Stage 0 inventory found no single repository owning the shared Caddy edge. Existing Caddy material is fragmented:

- historical Server A/private VICIdial ingress reconciliation exists in `appolon1908-hue/codestra-production-platform`;
- individual product repositories contain product-specific Caddy examples/templates;
- current Kong source already owns API gateway, route, security, standby/failover and Caddy/Kong validation concerns.

Without an explicit owner, runtime Caddy drift cannot be tied to a reviewed source SHA.

## Authority boundary

```text
Internet / private ingress
        |
        v
Caddy  -- TLS, host, source/network edge
        |
        v
Kong   -- OIDC/JWT, ACL/scope, rate/body/route policy
        |
        v
Middleware -- tenant/actor revalidation, durable command/write authority
```

Keycloak is the identity authority. Caddy must not manufacture trusted identity headers. Kong validates the Keycloak token, and Middleware independently revalidates the service/tenant authorization required for privileged commands.

## Canonical path

New shared API-edge Caddy source should live under:

```text
deploy/caddy/
```

with reviewable host snippets, TLS/network policy, tests and immutable release metadata. Product-site webserver/Caddy configuration that serves a product's own frontend remains in that product repository unless it is part of the shared `api.codestra.co` edge.

## Migration rule

This decision does not move live traffic or overwrite current host files. Existing runtime Caddy configuration remains authoritative for the running host until a separately reviewed migration:

1. inventories the live Caddy config read-only;
2. records its checksum and listener/host map;
3. ports the exact required behavior into `deploy/caddy/`;
4. proves no legacy identity-header trust;
5. validates Caddy -> Kong routes in write-disabled staging;
6. rehearses rollback;
7. deploys an immutable reviewed artifact/config set;
8. verifies live read-back before declaring source convergence.

## Historical repository

`appolon1908-hue/codestra-production-platform` is historical runtime/reconciliation evidence, not the future shared Caddy source authority. Its recorded Server A/private VICIdial Caddy material must be migrated or explicitly retired, not silently copied into production.
