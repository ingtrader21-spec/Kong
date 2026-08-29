# Caddy-to-Kong Authority Boundary

## Decision

`appolon1908-hue/Caddy` is the **principal source repository** for shared Codestra Caddy edge configuration.

`appolon1908-hue/Kong` is the principal source repository for Kong gateway services, routes, plugins, OIDC/JWT policy, rate/body/route enforcement, gateway reconciliation and the compatibility rules the Caddy edge must satisfy when forwarding governed API ingress.

Kong does **not** own Caddy source merely because Caddy forwards traffic to Kong.

## Architecture

```text
Internet / private ingress
        |
        v
Caddy   -- principal repo: appolon1908-hue/Caddy
        |  TLS, canonical host, outer request boundary, reverse proxy, log redaction
        v
Kong    -- principal repo: appolon1908-hue/Kong
        |  Keycloak OIDC/JWT, scopes, rate/body/route policy
        v
Middleware
           tenant/actor revalidation, durable command/write authority
```

Keycloak is the identity authority. Caddy must not manufacture trusted service identity. Kong validates the reviewed Keycloak token/policy for the gateway route, and Middleware independently revalidates the identity/tenant authorization needed for privileged commands.

## Canonical cross-repository contract

The principal machine-readable Caddy-side handoff contract is owned by the Caddy repository:

```text
appolon1908-hue/Caddy
  config/caddy-kong-contract.v1.json
```

Kong must remain compatible with that edge contract without copying Caddy implementation into this repository.

The reviewed Kong source currently exercises its data plane on `127.0.0.1:8000`, and Caddy uses the deployment-provided `CADDY_KONG_UPSTREAM` value for Kong-managed API paths. The listener may change only through reviewed deployment configuration; the ownership boundary does not change.

For Kong host-bound routes, Caddy must preserve `Host: api.codestra.co`. The bearer `Authorization` header must reach Kong unchanged; Caddy may redact it from access logs but must not remove or replace it on the upstream request. Caddy's normal reverse-proxy forwarding must preserve the original HTTPS scheme so Kong's HTTPS-required policy can evaluate the request correctly.

## Trusted identity boundary

Caddy must not create any of these application-trust headers:

```text
X-Authenticated-Client
X-Authenticated-Tenant
X-Authenticated-Role
X-Codestra-Gateway-Secret
```

Kong derives/sets trusted downstream identity only after its own token and scope policy succeeds. Middleware then revalidates privileged authorization. Caller-supplied values must never be allowed to substitute for that gateway decision.

## Historical reference

`appolon1908-hue/codestra-production-platform` is historical runtime/deployment/reconciliation/rollback evidence only.

The reviewed historical baseline:

```text
release/production-activation:operations/caddy/api.codestra.co.caddy
```

was used as the migration reference for `appolon1908-hue/Caddy`. The old copy remains provenance/evidence and is not the place for new Caddy feature development.

## Transitional routes

The historical edge used loopback listeners `18101` and `18102`. The Caddy principal repository retains those only as explicit migration fallbacks for route families whose Kong parity has not yet been proven. They are not alternate gateway authority.

A legacy path may move to Kong only after the Kong repository contains an accepted route/security contract for it and write-disabled staging proves the complete Caddy -> Kong -> Middleware behavior.

## Kong responsibilities for the boundary

Kong source must validate the assumptions it requires from Caddy, including:

- canonical host compatibility for `api.codestra.co`;
- preservation of the bearer token;
- HTTPS forwarded-scheme enforcement;
- route-specific request-size, rate and scope policy;
- no caller-controlled trusted identity-header bypass;
- no public exposure of Kong Admin;
- health/readiness route compatibility for routes Kong actually owns;
- deterministic rejection behavior for invalid/expired/wrong-scope tokens.

Those compatibility tests do not turn Kong into the Caddy source repository.

## Change rule

If a change is primarily a Caddy concern (TLS site block, reverse-proxy target, Caddy request policy, Caddy log redaction, Caddy modules, Caddy validation or Caddy release/reload behavior), change `appolon1908-hue/Caddy`.

If a change is a Kong concern (service/route/plugin/OIDC/scope/rate-limit/gateway reconciliation), change `appolon1908-hue/Kong`.

If both change, use coordinated PRs and versioned compatibility evidence; do not duplicate either implementation in the other repository.

## Runtime migration

Source authority does not itself change live traffic. Before the Caddy repository becomes runtime-authoritative for a host, perform read-only inventory, checksum reconciliation, complete config validation, write-disabled staging Caddy -> Kong -> Middleware tests, invalid-token rejection tests, rollback rehearsal, immutable-source acceptance, controlled reload and post-change read-back.
