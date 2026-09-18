# Keycloak → Kong Token Contract V1

Machine-readable: `config/kong-authentication-profiles.v1.json`
(`issuerProfiles`, `audienceProfiles`, `tokenCachePolicies`, `failurePolicies`).
Companion to `docs/token-validation-boundary-v1.md` (Mission 1). Kong validates
tokens with the bundled `openid-connect` and `jwt` plugins only; no custom
cryptography exists or is permitted.

## Trusted issuers

| Profile | Environment | Issuer | Discovery | JWKS |
| --- | --- | --- | --- | --- |
| `KEYCLOAK_CODESTRA_PRODUCTION` | production | `https://auth.codestra.co/realms/codestra` | `…/.well-known/openid-configuration` | `…/protocol/openid-connect/certs` |
| `KEYCLOAK_CODESTRA_STAGING` | staging | `https://auth-staging.codestra.co/realms/codestra` | `…/.well-known/openid-configuration` | `…/protocol/openid-connect/certs` |

No other issuer is trusted; no wildcard; a staging source may not bind the
production realm (validator + integration compiler). Development has no
shared realm.

## Discovery and JWKS mechanisms

| Plugin | Key source | Rotation |
| --- | --- | --- |
| `openid-connect` | discovery document → JWKS, cached; rediscovery on unknown `kid` (Kong default 30 s lifetime) | automatic on realm key rotation |
| `jwt` | RS256 public key **snapshot** stored on the consumer credential, provisioned by the reconciler from the live JWKS (`--jwks-url`, optional `--active-kid`; ambiguous signing keys are refused) | manual: re-run the reconciler under change authority; until then tokens signed by a new key fail closed (401) |

## Accepted algorithms

`RS256` only. `jwt` credentials are created with `algorithm: RS256`; the
standby auth middleware requires `alg=RS256` and a `kid`; `HS256` (shared
secret) credentials are never provisioned. The validator rejects any issuer
profile whose algorithm list is not exactly `["RS256"]`.

## Audience requirements

| Audience profile | Audience | Routes |
| --- | --- | --- |
| `CONTROL_PLANE` | `codestra-control-plane` | control-plane candidate (7) |
| `CALLBACK_API` | `codestra-callback-api` | callbacks (2) |
| `CAMPAIGN_MIDDLEWARE` | `codestra-middleware` | campaign automation (5 + 4 staging) |
| `MIDDLEWARE_API` | `middleware-api` | n8n control plane (2 + 2 staging), calling (5), provider control (6), egress proposal, cell design |
| `SDK_INTAKE_CLIENT` | `sdk-intake` (= client id, contractually) | intake (2) |
| `MONEYBEE_API` | `moneybee-api` | MoneyBee bootstrap |
| `STANDBY_CODESTRA_API` | `codestra-api` | standby (4, validated by the auth middleware) |

`aud` may be a string or an array; the route audience must be present. A
token minted for one audience is rejected on every other service. `client_id
== audience` is forbidden except where a contract defines it
(`clientIdIsAudience` + `contractuallyDefinedBy`; today only `sdk-intake`).

## Expiration and clock skew

| Check | `openid-connect` | `jwt` + guard |
| --- | --- | --- |
| `exp` | enforced | `claims_to_verify: [exp]` |
| `nbf` / `iat` | enforced by the plugin; `codestra-authz` also rejects non-finite values | n8n guard: `exp` and `iat` numeric, `exp > iat`, `exp - iat ≤ 300 s`; callback/campaign guards: not bounded (follow-up after #105) |
| leeway | 0 s (no `leeway` configured; validator bound 60 s) | 0 s |
| malformed timestamps | 401 | 401 |

## Scope interpretation

`scope` is a space-separated string; the guard requires the route scope to be
present. Scopes are gateway prerequisites only ([scope contract](gateway-scope-contract-v1.md)).

## `azp` / client relationship

`consumer_claim: [azp]` (`openid-connect`) or `key_claim_name: azp` (`jwt`)
maps the token's authorized party to a registered Kong consumer; the guard
additionally requires `azp` ∈ the parties contracted for the route scope
(callbacks: `codestra-odoo-callback-service`; campaign: per-scope consumer
list plus `environment` claim; n8n: `n8n-automation`; MoneyBee:
`moneybee-borrower`; intake: `sdk-intake`). No consumer credential is in Git.

## Service accounts

Client-credentials tokens are the only accepted form for
`SERVICE_AUTHENTICATED`/`INTERNAL` routes; the n8n guard's 300 s lifetime bound
and the provider-control contract's `maximumTokenLifetimeSeconds: 300` define
the service-token lifetime policy. A service token never qualifies for
`ADMIN_INTERNAL` unless its `azp` is a declared admin party (`ADMIN_PARTIES_UNDECLARED`
is an activation prerequisite today).

## Token cache behaviour

`OIDC_CACHE_V1`: `cache_tokens_salt` is `{vault://env/kong-oidc-cache-tokens-salt}`,
never in Git, stable across nodes and decK synchronizations; `cache_ttl` Kong
default 3600 s (validator bound); rediscovery lifetime 30 s. Rotating the salt
invalidates every cached credential and is a reviewed credential-cache
rotation. `JWT_STATIC_KEY_V1`: no cache; the credential *is* the key.

## Failure behaviour (`FAIL_CLOSED_V1`)

| Condition | Status | Body |
| --- | --- | --- |
| missing / malformed / expired / not-yet-valid credential | 401 | constant error code (`unauthenticated`, `invalid_bearer_token`, `invalid_token_time`) |
| wrong issuer / wrong audience | 401 | `invalid_issuer` / `invalid_audience` |
| missing required scope / unauthorized party / tenant or role denied | 403 | `insufficient_scope` / `service_identity_denied` / `tenant_denied` |
| forwarded scheme not https from the trusted edge | 426 | `https_required` |
| discovery/JWKS unavailable | 401/500 from the plugin — never "allow" | plugin error |
| gateway identity secret unavailable | 503 | `gateway_identity_unavailable` |

No response body echoes a token, claim value, header value or plugin
configuration; the guards' exit bodies are constant tables (tested).
