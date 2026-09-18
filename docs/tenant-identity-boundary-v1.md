# Tenant & Identity Boundary V1

Machine-readable: `config/kong-access-policy.v1.json` (`identityHeaders`,
`routes[].identityPropagation`, `routes[].tenantPolicy`) and
`config/kong-authentication-profiles.v1.json` (`identityPropagationProfiles`,
`tenantPolicies`).

## Identity header trust

```text
client-supplied identity headers
        ↓  never trusted; stripped or overwritten where the route strips, ignored by Middleware where it does not
Kong authentication (signature, issuer, audience, expiry, scope, azp)
        ↓  only after success
trusted derived identity context  (X-Authenticated-*, X-Codestra-*, X-Consumer-* set by Kong)
        ↓
Middleware re-validates the token and performs tenant/resource authorization
```

Headers that are **never** an authority when supplied by a client
(`identityHeaders.neverTrustedFromClients`): `X-User-ID`, `X-Username`,
`X-Email`, `X-Roles`, `X-Scopes`, `X-Consumer-ID`, `X-Consumer-Username`,
`X-Credential-Identifier`, `X-Anonymous-Consumer`, `X-Authenticated-UserID`,
`X-Authenticated-User`, `X-Authenticated-Client/-Subject/-Tenant/-Campaign/-Role/-Email`,
`X-Codestra-Tenant`, `X-Codestra-Scopes`, `X-Codestra-Gateway-Secret`,
`X-Internal-Service`, `X-Admin`.

| Propagation profile | Strips client identity | Mints | Routes |
| --- | --- | --- | --- |
| `GATEWAY_MINTED_TENANT_ROLE` | yes (`scope-policy.lua` clears first) | `X-Authenticated-Client/-Tenant/-Role`, `X-Codestra-Gateway-Secret` | control plane (7) |
| `GATEWAY_MINTED_SUBJECT_TENANT_CAMPAIGN` | yes (`calling-policy.lua`) | `X-Authenticated-Client/-Subject/-Tenant/-Campaign` | telephony (5) |
| `GATEWAY_MINTED_SUBJECT_EMAIL` | yes (`moneybee-identity-policy.lua`) | `X-Authenticated-Client/-Subject/-Email` | MoneyBee bootstrap |
| `REQUEST_CONTEXT_STRIP_AND_AUTHZ_MINT` | yes (`codestra-request-context` + `codestra-authz`) | `X-Authenticated-Client/-Subject`, `X-Codestra-Tenant/-Scopes` | gateway-platform design |
| `STANDBY_STRIP_LIST` | yes (`request-transformer` remove list) | none | standby (4) |
| `KONG_CONSUMER_HEADERS_ONLY` | **no** — client `X-Authenticated-*` pass through; Kong overwrites `X-Consumer-*` after the signature check | `X-Consumer-ID/-Username`, `X-Credential-Identifier` | callbacks, campaign, n8n, intake, provider control (accepted finding `IDENTITY_HEADERS_NOT_STRIPPED`, mitigation: Middleware ignores them and re-validates the token; REFACTOR after #105) |
| `SESSION_OIDC_UPSTREAM` | no (proposal) | none | n8n editor (n8n native auth stays on) |
| `LEGACY_UNVERIFIED` | no | Kong `X-Consumer-*` on key-auth routes | legacy and blocked routes |
| `STRIP_ALL_PUBLIC` | required target for public routes | none | — (no public route strips today; recorded as the target) |

A guard that mints identity always clears the same header names first, so a
client value can never survive into the upstream request even on an early
exit (tested: `clear_header` precedes `set_header` in every policy).

## Tenant boundary

Kong may propagate an authenticated tenant claim; it never accepts a header as
the tenant authority. `X-Tenant-ID` is a *selector*:

| Tenant policy | Behaviour | Routes |
| --- | --- | --- |
| `HEADER_SELECTOR_CLAIM_AUTHORITY` | optional `X-Tenant-ID`; if present it must equal the token `tenant` (control plane) / `tenant_id` (telephony); mismatch → `403 cross_tenant_denied`; the claim is minted upstream | control plane (7), telephony (5), design integration |
| `HEADER_REQUIRED_CLAIM_AUTHORITY` | `X-Tenant-ID` required (400/403 when missing, `*` refused); must equal `tenant_id` or be one of `tenant_ids` → else `403 tenant_denied` | n8n control plane (2 + 2 staging), intake (2) |
| `CLAIM_FIXED_TENANT_CAMPAIGN` | token `tenant_id` must equal the contract tenant (`COD`) and `campaigns` must contain `TEST_SYN` | callbacks (2) |
| `CLAIM_ONLY_MIDDLEWARE_VALIDATES` | no gateway tenant comparison; Middleware compares any selector against the re-validated token | campaign automation (5 + 4 staging), provider control (6), standby (4), egress proposal |
| `NOT_APPLICABLE_IDENTITY` | bootstrap/session routes with no tenant claim | MoneyBee, n8n editor |
| `NONE_PUBLIC` / `LEGACY_UNVERIFIED` / `DESIGN_UNSPECIFIED` | no gateway tenant context | public, legacy, blocked, design |

`X-Tenant-ID: whatever-i-want` therefore either fails the guard (mismatch with
the claim), is refused (`*`, empty) or is ignored by Middleware; it never
grants access. The validator rejects any tenant policy that would make a
header the authority (`identityHeaderAuthorityAllowed: false`).

## What Middleware still does

Middleware re-validates signature, issuer, audience, scope and tenant on every
governed route and decides resource ownership, campaign membership beyond the
contracted claims, and command authorization. The gateway identity headers
(`X-Authenticated-*`, `X-Codestra-Gateway-Secret`) tell Middleware what Kong
verified and that the request traversed Kong; they are not a substitute for
Middleware's own validation.
