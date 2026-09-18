# Kong Mission 2 — Identity & Security Audit

Scope: every authentication and identity mechanism declared in this repository
at commit `50dad08` (Mission 1 foundation) on branch
`feature/mission2-identity-access-security`. Source-only; no Kong, Keycloak,
Caddy or Middleware runtime was contacted. Governance dependency: PR #105
(`fb353cb`, Mission 1 reconciliation) is under independent approval and is
**not** treated as merged; see §6.

## 1. Mechanism inventory

| Mechanism | Where | Findings |
| --- | --- | --- |
| `openid-connect` (Enterprise) | `deploy/kong/control-plane.yml` (service plugin, audience `codestra-control-plane`, `scopes_required: [openid]`, `consumer_claim: [azp]`, vault salt); template `kong/plugins/oidc/keycloak.yml` (audience `middleware-api`); intake, calling, MoneyBee and gateway-platform renderers | KEEP. Discovery-based issuer, JWKS with rediscovery, bearer only, no `anonymous`, no `leeway` (0 s), Kong default `cache_ttl` 3600 s bounded. Template is `TEMPLATE_NOT_LOADABLE` (would be a global auth plugin). |
| `jwt` (bundled) | callback, campaign, n8n, intake reconcilers and the readback | KEEP. RS256 credential keyed by `azp`, `claims_to_verify: [exp]`, `anonymous: None`. **The public key is a snapshot** provisioned from the realm JWKS at reconcile time (`active_rsa_key`); rotation needs a reconciler run. `jwt` itself verifies neither `iss` nor `aud` nor `nbf`/`iat` — the guards do. |
| `post-function` claim guards | `scope-policy.lua`, `calling-policy.lua`, `moneybee-identity-policy.lua`, callback/campaign/n8n guard strings, intake guard (live only) | KEEP / REFACTOR (see §2 identity headers). All decode the already-verified token, check `iss` exactly, `aud` (string or array), `azp` where contracted, scope, tenant/campaign/role; n8n bounds lifetime `exp-iat ≤ 300`. |
| `codestra-authz` / `codestra-request-context` / `codestra-webhook-verifier` | gateway-platform topology (`config/integrations`) | KEEP (design). Strip client identity, validate trace context, HMAC webhooks; `nbf`/`iat` finite-time checks. |
| `key-auth` | 13 legacy routes (CRM/email/SMS/DLR/webhooks, website forms, website API, gateway-test, key-auth communication routes) | LEGACY. Shared keys; `cors`+`key-auth` on browser routes (`CORS_WITH_SHARED_KEY`); `newProductionAllowed: false`. |
| `ip-restriction` | 4 private standby routes; private integration policies | KEEP. Source allowlist in front of an RS256-validating auth middleware (leeway 0, `alg=RS256`+`kid` required). |
| consumer mappings | `consumer_claim: [azp]` / `key_claim_name: azp` → registered consumers (`codestra-odoo-callback-service`, `codestra-n8n-campaign-crm-production`, `codestra-odoo-campaign-reader-production`, `codestra-n8n-automation`, `test-syn-*`) | KEEP. Credentials never in Git. |
| consumer groups / ACL / anonymous consumers / hmac-auth / basic-auth / ldap | none | KEEP (absent). Validator forbids `anonymous` on jwt/openid-connect. |
| Admin identities | container-loopback Admin, bounded in-container channel | KEEP (Mission 1 admin boundary). |

## 2. Findings

| ID | Class | Sev | Finding | Disposition |
| --- | --- | --- | --- | --- |
| M2-001 | AUTH_BYPASS (M1-001 carried) | C | `codestra-mail-api` — `/api/v1/mail`, `/api/v1/admin/mail`, no plugins | **Not resolved, not hidden**: access class `ADMIN_INTERNAL`, profile `BLOCKED_NONE_V1`, activation `BLOCKED`, inventory gate; the policy refuses to allowlist it as public. |
| M2-002 | MISSING | H | No machine-readable access classification existed per route (class, issuer, audience, scopes, parties, propagation, tenant policy) | **Implemented**: `config/kong-access-policy.v1.json` (79 routes) + `config/kong-authentication-profiles.v1.json` (14 profiles); validator cross-checks both against the foundation. |
| M2-003 | IDENTITY_CONFUSION | M | jwt-guarded routes (callback ×2, campaign ×5, n8n ×2, intake ×2, provider-control) forward client-supplied `X-Authenticated-*` / `X-Tenant-ID` unchanged; only `X-Consumer-*` are overwritten by Kong | Accepted finding `IDENTITY_HEADERS_NOT_STRIPPED` with recorded mitigation (Middleware derives identity from the re-validated token; Kong overwrites `X-Consumer-*`). REFACTOR: add `clear_header` for the minted names in those guards **after #105** (it rewrites these reconcilers). |
| M2-004 | IDENTITY_CONFUSION | M | Unauthenticated/legacy routes forward any client header (`X-Consumer-ID`, `X-Authenticated-*`) to upstreams (website forms → control plane 8096; blocked routes) | Accepted `IDENTITY_HEADERS_NOT_STRIPPED`; `STRIP_ALL_PUBLIC` is the target profile; MOVE with the legacy host. Upstreams must not consume these headers. |
| M2-005 | SERVICE_IDENTITY_RISK | M | No declared list of clients (`azp`) permitted to hold `platform.admin`; a service token with that scope would be minted `platform_admin` | Accepted `ADMIN_PARTIES_UNDECLARED`; `activationPrerequisites` on `control-plane-system-admin`: declare the admin clients in the Keycloak contract before activation. |
| M2-006 | AUDIENCE_RISK | L | Intake audience equals client id (`sdk-intake`) | Contractually defined (`requiredClientId`, reconciler-verified); audience profile `SDK_INTAKE_CLIENT` with `contractuallyDefinedBy`; validator forbids the pattern anywhere else. KEEP. |
| M2-007 | MISSING | M | Intake claim-guard source is not in this repository (verified live by markers only) | Accepted `GUARD_SOURCE_NOT_IN_REPOSITORY`; REFACTOR: vendor the guard. |
| M2-008 | SCOPE_RISK | L | jwt routes verify `exp` only; `nbf`/`iat` enforced by n8n guard (lifetime ≤ 300 s), openid-connect and `codestra-authz`; callback/campaign guards do not bound lifetime | Documented in the token contract; REFACTOR after #105: add the lifetime bound to callback/campaign guards. |
| M2-009 | SECRET_RISK | — | Pattern scan of 236 tracked files: 0 secrets; only synthetic sentinels in redaction tests | KEEP; scan is now part of the validator (`validate_secret_boundary`). |
| M2-010 | KEEP | — | Token cache: vault-referenced `cache_tokens_salt`, `cache_ttl` default 3600 s, rediscovery 30 s; jwt static key snapshot | Documented rotation and invalidation; validator bounds leeway (≤60 s) and ttl (≤3600 s) and requires the vault reference. |
| M2-011 | LEGACY | M | 13 `key-auth` routes, 7 of them effectively public browser routes | `LEGACY_SHARED_KEY_V1` (strength 1) forbidden on canonical routes; public ones on the allowlist with reasons. |
| M2-012 | TENANT_TRUST_RISK | L | Tenant handling differs per family: control-plane/calling compare an optional `X-Tenant-ID` selector to the claim; n8n/intake require it and compare to `tenant_id`/`tenant_ids`; callbacks fix the tenant; campaign defers to Middleware | Documented in `tenant-identity-boundary-v1.md`; policy forbids any `HEADER_AUTHORITY` tenant policy. KEEP. |
| M2-013 | KEEP | — | CORS only on legacy key-auth routes; origins not captured by the readback; wildcard+credentials forbidden by boundary rules and the integration compiler; callback `run_on_preflight: false` is safe only because those routes declare no `OPTIONS` | `corsPolicy: LEGACY_UNVERIFIED_ORIGINS` on the 7 routes. |
| M2-014 | KEEP | — | Logging: proxy access log `combined` (no headers/bodies), Admin/Status logs off, no log plugins, no `kong.log` in any guard, constant error bodies | Policy `logging.neverPersisted`; validator requires `redactsCredentials` on any future log plugin. |
| M2-015 | M1 dependency | — | n8n control plane and provider-control bind the transitional `appolon-middleware-integration-api:8080` alias; PR #105 retires it | `m1Dependency` markers on 8 routes; strict-xfail guard `test_middleware_8080_alias_is_retired_after_mission1_reconciliation` (M1_DEPENDENCY_PENDING). |

Searched and not found: issuer wildcards; wildcard audiences or scopes;
`anonymous` consumers; HS256; global authentication plugins; shared universal
service credentials (every service family has its own consumer/azp); identity
headers used as an authorization authority; `Access-Control-Allow-Origin: *`
with credentials; tokens or secrets in evidence or templates.

## 3. Route access classes (result)

| Class | Routes | Profiles |
| --- | ---: | --- |
| PUBLIC | 7 | `PUBLIC_V1` (1 probe), `LEGACY_SHARED_KEY_V1` (6 browser routes) — all allowlisted with reasons |
| AUTHENTICATED | 24 | `HUMAN_OIDC_V1`, `HUMAN_SESSION_OIDC_V1`, `LEGACY_SHARED_KEY_V1`, `DESIGN_OIDC_V1`, `BLOCKED_NONE_V1` |
| SERVICE_AUTHENTICATED | 37 | `SERVICE_OIDC_V1`, `SERVICE_JWT_V1`, `SERVICE_OIDC_JWT_V1`, `DESIGN_SERVICE_OIDC_V1`, `HMAC_WEBHOOK_V1`, `BLOCKED_NONE_V1` |
| ADMIN_INTERNAL | 2 | `ADMIN_INTERNAL_V1` (system admin), `BLOCKED_NONE_V1` (mail API, blocked) |
| INTERNAL | 9 | `INTERNAL_SERVICE_V1` (calling ×5), `INTERNAL_STANDBY_V1` (standby ×4) |

## 4. Repairs in this mission

No runtime-facing source changed. Mission 2 adds enforcement and contracts;
the guard-level refactors (M2-003, M2-008) are deliberately deferred because
PR #105 rewrites the same reconcilers and a parallel edit would create a
merge conflict on files under independent review.

## 5. Validation

`python scripts/validate_kong_foundation.py` (now includes access policy,
profiles, token settings, secret boundary), `pytest -q
tests/test_kong_identity_security.py` (58 passed, 1 xfailed = M1 dependency),
`tests/test_kong_foundation.py` (58 passed), full regression: see
`docs/mission2-evidence-matrix.md`.

## 6. Mission 1 dependency

- PR #105 `fb353cb` — 8095 consolidation and middleware authority v2 — CI
  7/7, mergeable, **independent approval required**. Not merged; not assumed.
- Mission 1 foundation `50dad08` on `feature/issue-58-canonical-campaign-routes`
  — also unmerged; Mission 2 builds on it.
- When #105 merges: remove the 8080 alias and `m1Dependency` markers, drop the
  strict xfail, register `config/kong-middleware-authority.v2.json` and the
  `/platform/v1/*` contract, re-run `--write-docs` and the manifests.
