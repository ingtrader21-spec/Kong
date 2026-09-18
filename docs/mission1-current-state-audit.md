# Kong Mission 1 — Current-State Forensic Audit

Part of the [Kong API Gateway Control Plane V1](KONG_GATEWAY_CONTROL_PLANE_V1.md).

## 0. Repository entry gate

| Item | Value |
| --- | --- |
| Remote | `origin` / `newci` → `https://github.com/ingtrader21-spec/Kong.git` (mirror of `appolon1908-hue/Kong` per `REPOSITORY_PROFILE.md`) |
| Branch | `feature/issue-58-canonical-campaign-routes` |
| Audited head | `4723b579e0c3ee9f9f2ccec236865ee91205fc85` |
| Working tree at entry | two tracked files modified (Windows shims in `tools/generate_migration_manifests.py`, `tests/test_kong_change_authority.py`), 13 untracked Mission 1 drafts |
| Identity proof | remote + contents: `deploy/kong/compose.kong.yaml`, `deploy/kong/control-plane.yml`, `kong/plugins/oidc/keycloak.yml`, `config/kong-*.json`, `operations/kong-database/` |
| Other worktrees | `Kong.worktrees/cross-repo-authority-20260916` (`codex/cross-repo-authority-20260916`), `Kong.worktrees/implement-text-pasting-feature`; neither is the authorized branch and neither was modified |

Caddy and Keycloak repositories were not touched. No Kong Admin API, Caddy,
Keycloak, Middleware, Redis or database was contacted; every statement below is
derived from checked-in source and the sanitized 2026-09-06 readback.

## 1. Scope of inspection

All of: `deploy/kong/` (compose, `kong.conf.example`, `runtime.env.example`,
`observability.env.example`, `control-plane.yml`, four Lua policies, three
custom plugins), `deploy/gateway-platform/` (hybrid/traditional topologies,
entrypoint, network boundaries), `deploy/kong-production-standby/`,
`kong/plugins/oidc/keycloak.yml`, every `config/*.json|yaml` contract and
overlay, `config/integrations/` (policies, schemas, upstream registry,
example), `contracts/`, `operations/` (database roles/HBA/backup/PITR/HA,
runbooks, community n8n egress), `scripts/` and `tools/` (reconcilers,
renderers, validators, admin channel, capture, certification, manifests),
`tests/` (31 modules, 596 tests), `.github/workflows/` (9 workflows),
`docs/` and `docs/evidence/`. No database-backed migration files, gRPC, SSE or
WebSocket Kong routes exist; the calling contract explicitly forbids a public
Kong WebSocket route.

## 2. Test baseline (REPRODUCE)

`python -m pytest -q` on this Windows workstation at entry: **538 passed, 56
failed, 4 errors**. Every failure is a POSIX host artifact
(`WinError 193` executing `.py` by executable bit, `python3` shim,
`os.fchmod`, `S_IMODE` mode drift, symlink privilege, 32 KiB environment cap,
CRLF checkout). CI runs on `ubuntu-24.04` and self-hosted Linux runners where
these suites are the security tests for the transactional manifest writer and
the certification packager. Classification: **ENVIRONMENT_BLOCKER**, not a
repository defect; no assertion was weakened and no test was skipped. The
uncommitted Windows shims found in the working tree do not make these pass and
add platform-conditional bypasses to a security-critical writer; they are
preserved as a patch outside the tree and are not part of this baseline
(decision left to the owner).

## 3. Architecture at entry

`deploy/kong/compose.kong.yaml` stands up one database-backed Kong Gateway
3.14 node: immutable digest, PostgreSQL TLS verify, Admin on container
loopback, Manager off, Status on the private observability network, proxy
published on host loopback for Caddy, read-only root, all capabilities dropped,
`trusted_ips` required with no default, Lua sandbox with exactly `cjson.safe`,
env vault, license and database password as file secrets.
`deploy/kong/control-plane.yml` is the OIDC control-plane candidate (7 routes,
audience `codestra-control-plane`, Redis rate limiting fail-closed, correlation,
post-function scope/tenant/identity policy). Production today (readback
2026-09-06, 29 routes → 27-route successor inventory) is a mix of canonical
JWT/claim-guard routes (callbacks, campaign automation, n8n control plane),
key-auth legacy routes on the legacy host, five website form routes, two
provider-direct routes already fail-closed to Middleware, one route with **no
plugins at all**, four private standby routes and a test upstream. Twelve
further contracts describe candidates, proposals, prepared-disabled route
sets, a cell design and a gateway-platform integration model.

## 4. Findings and dispositions

Classification legend — disposition: KEEP / REFACTOR / MOVE / DEPRECATE /
DELETE / MISSING; risk: SECURITY / ROUTING / AUTH / UPSTREAM / PLUGIN /
AVAILABILITY / OBSERVABILITY_GAP / DEPLOYMENT. Severity C/H/M/L. "Fixed here"
means repaired in this baseline with a focused test; otherwise the disposition
is enforced by the foundation validator and listed as follow-up.

| ID | Sev | Risk | Finding (evidence) | Classification | Disposition |
| --- | --- | --- | --- | --- | --- |
| M1-001 | C | AUTH / SECURITY | `codestra-mail-api`: `GET,POST /api/v1/mail` and `/api/v1/admin/mail` on `api.codestra.co`, **plugins `[]`** — public by omission, unbounded body, no rate limit, administrative path, upstream `codestra-mail-api:8098` with no owner (inventory + readback) | SECURITY_RISK, MISSING contract | **Fixed here (gated):** inventory `activationBlockedRoutes` + registry `BLOCKED`, `ADMIN_INTERNAL` required class; `validate_kong_production_inventory.py` and the foundation validator refuse activation. REFACTOR into an owned contract or DELETE. |
| M1-002 | H | ROUTING / AUTH | `breero-production-api-route`: `api.breero.com`, paths `/health` + `/api/v1`, all six methods, no authentication plugin; readback upstream `scraper.internal.codestra.agency:8443` | ROUTING_RISK catch-all, SECURITY_RISK | Inventory already fail-closes the upstream to Middleware 8095; registry `BLOCKED` (`CATCH_ALL_PREFIX`, `ALL_METHODS`, `NO_GATEWAY_AUTHENTICATION`). REFACTOR: route contract with exact paths/methods/audience. |
| M1-003 | H | UPSTREAM | `codestra-website-api-route` readback upstream `10.40.0.3:8443` (hard-coded private IP); key-auth + cors, no rate/body limit, legacy host | SECURITY_RISK | Inventory fail-closes to Middleware 8095; registry `LEGACY`/`PUBLIC` with reason; validator forbids IP literals anywhere. MOVE to a governed website API. |
| M1-004 | H | CONFIG | `deploy/kong/control-plane.yml` references `{vault://env/kong-oidc-cache-tokens-salt}` but `deploy/kong/runtime.env.example` (the only env source of `compose.kong.yaml`) did not declare `KONG_OIDC_CACHE_TOKENS_SALT` → declarative load fails on a node built from the reviewed templates | CONFIGURATION_DEFECT | **Fixed here:** variable declared; validator requires every vault reference to be declared; test `test_missing_runtime_variable_for_a_vault_reference_fails`. |
| M1-005 | H | AVAILABILITY / SECURITY | Implicit retries: `codestra-control-plane` (declarative), `codestra-campaign-automation-api` (contract), `codestra-middleware-intake` (contract), calling and MoneyBee renderers declared no `retries` → Kong default **5** on command APIs | CONFIGURATION_DEFECT | **Fixed here:** explicit `retries: 0` in `control-plane.yml`, campaign (prod+staging) and intake contracts, calling and MoneyBee renderers; `verify_control_plane` now compares `retries`; profile `NONE`; tests updated. |
| M1-006 | H | AVAILABILITY | Implicit timeouts: campaign automation service ran Kong defaults 60/60/60 s (readback) with no contract value; intake contract had none | CONFIGURATION_DEFECT | **Fixed here:** `STANDARD_API` (3/30/30 s) pinned in the campaign (prod+staging) and intake contracts and emitted by the renderer; readback difference recorded as declared drift. |
| M1-007 | H | PLUGIN | `control-plane-reconciliation` accepts `POST` with no `request-size-limiting` (unbounded body on a canonical command route) | CONFIGURATION_DEFECT | **Fixed here:** 1 MB limit with `require_content_length` added; validator forbids `UNBOUNDED_REQUEST_BODY` on canonical routes. |
| M1-008 | H | DEPLOYMENT / AUTH | Environment mixing: `config/integrations/examples/moneybee-account-bootstrap.json` declared `environment: staging` with the **production** issuer because `gateway-integration.schema.json` pinned the issuer as a `const` | CONFIGURATION_DEFECT (root cause in schema) | **Fixed here:** schema enumerates both reviewed realms; compiler enforces `issuer_environment_mismatch`; example bound to the staging realm; foundation validator couples issuer to environment for every source. |
| M1-009 | H | PLUGIN | Live callback routes run their claim guard as `pre-function` (before `jwt`); desired state is `post-function` (readback vs `reconcile_kong_callback_routes.py`) | PLUGIN_DEFECT, runtime drift | Declared in `knownDrift` (HIGH). Not a bypass — `jwt` still gates the signature — but the guard reads unverified claims; the callback reconciler corrects the phase on apply under change authority. |
| M1-010 | H | ROUTING | Route shadowing/ambiguity between the OIDC control-plane candidate and the key-auth communication routes: `/api/v1/control/messages` and `/api/v1/results/messages` (longer) shadow `/api/v1/control` and `/api/v1/results`; `GET /api/v1/messages` is an identical match (ambiguous) | ROUTING_RISK | Declared in `precedence.knownConflicts` (`LEGACY_SHADOWS_SUCCESSOR_UNTIL_RETIRED`, `SUCCESSOR_REPLACES_LEGACY_ON_APPLY`); legacy routes `supersededBy` the candidate; applying the candidate must retire them in the same change. DEPRECATE legacy. |
| M1-011 | H | UPSTREAM | Middleware listener split: 8095 (`codestra-middleware-integration-api-1`), 8080 (`appolon-middleware-integration-api`), 8096 (control plane); the provider-control contract validator pins 8080 | UPSTREAM_RISK | Declared aliases with roles in `boundaryRules.middlewareUpstreamAliases`; every governed service must target a declared alias; new routes target 8095; consolidation of n8n/provider-control to 8095 is a coordinated Middleware change. REFACTOR. |
| M1-012 | H | AUTH | `config/marketing-stage4-routes.yaml`: four routes with no host, no methods, no authentication, `strip_path: true`, implicit timeouts/retries, direct application upstreams | ROUTING_RISK, AUTH_RISK | `DESIGN_ONLY`, not activatable; registry records `authenticationGap`; its own certification workflow (`validate_marketing_routes.py`) only checks a comment-level promotion gate. REFACTOR before any staging apply. |
| M1-013 | H | AUTH | `config/kong-community-n8n-egress.v1.json` proposal carries no authentication plugin (relies on Middleware revalidation) and is a broader prefix of the two canonical n8n routes | AUTH_RISK | `PROPOSED` with `authenticationGap`; validator requires a token prerequisite before it can become a candidate. REFACTOR. |
| M1-014 | M | AUTH | Intake contract uses the client id `sdk-intake` as the OIDC audience; the reconciler verifies exactly that | AUTH_RISK (client_id == audience) | Contractually defined (`requiredClientId`), so accepted as the named finding `AUDIENCE_IS_CLIENT_ID`; not assumed anywhere else. KEEP, document. |
| M1-015 | M | PLUGIN | Legacy shared-key routes (`crm`, `email`, `sms`, `sms/dlr/telnexa`, `webhooks`, website forms, website API, gateway-test): `key-auth` on both hosts, `cors`+`key-auth` on browser routes, legacy adapters `codestra-kong-service-auth-adapter-1`, `codestra-email-reseller-api-1`, `codestra-sms-api-api-1` | AUTH_RISK, UPSTREAM_RISK | `LEGACY`; retirement `BLOCKED_PENDING_CONSUMER_MIGRATION` (provider-control contract); shared keys cannot be promoted; validator forbids `LEGACY_SHARED_KEY`/`LEGACY_UPSTREAM` on canonical routes. DEPRECATE / MOVE. |
| M1-016 | M | UPSTREAM | `gateway-test-route` → `kong-test-upstream:8080` in production on the legacy host | DEPLOYMENT_RISK | **Gated here** (`activationBlockedRoutes`); `RETIRE_CANDIDATE`, DELETE under runtime change authority. |
| M1-017 | M | AUTH | `codestra-token-validation-certification`: no authentication, both hosts, cors | AUTH_RISK (bounded) | `PUBLIC_PROBE`, GET/OPTIONS only, rate limited; `TRANSITIONAL`, DEPRECATE with the legacy host. |
| M1-018 | M | AVAILABILITY | Five website-form routes and the website API accept `POST` with no body limit | AVAILABILITY_RISK | `LEGACY` with `UNBOUNDED_REQUEST_BODY`; forbidden on canonical; MOVE to a governed forms API with `FORM_2MB`. |
| M1-019 | M | ROUTING | `codestra-n8n-editor-ui`: `/` with every method on `automation.codestra.co` → `codestra-n8n-main:5678` | ROUTING_RISK (intentional UI proxy) | `PROPOSED`, `enabled: false`, direct-upstream reason recorded, session OIDC + realm role; KEEP as design. |
| M1-020 | M | DEPLOYMENT | Staging overlays reuse production upstream aliases (`…-1:8095`, `…:8080`); isolation is by issuer + dedicated stack, not by name | DEPLOYMENT_RISK | Declared `sharedUpstreamAliases: true` per overlay; validator proves staging issuer, route subset and identical matches; network isolation is runtime certification evidence. KEEP. |
| M1-021 | M | UPSTREAM | No Kong `upstream` objects: every service is a single DNS target with no active health check | UPSTREAM_RISK / OBSERVABILITY_GAP | `DNS_TARGET_PASSIVE` profile documented; `ACTIVE_HTTP_REQUIRED` mandatory before any second target. MISSING, follow-up. |
| M1-022 | M | PLUGIN | `kong/plugins/oidc/keycloak.yml` is literally a global `openid-connect` (audience `middleware-api`) if loaded as a document | PLUGIN_RISK | Registered `PLUGIN_TEMPLATE` / `TEMPLATE_NOT_LOADABLE`; validator forbids authentication plugins at global scope. KEEP as template. |
| M1-023 | M | PLUGIN | Callback control `POST` service keeps `retries: 1` and does not require `Idempotency-Key` | AVAILABILITY_RISK (bounded) | `TRANSPORT_CONNECT_ONLY_1` is transport-safe (nginx never re-sends a sent POST); requiring `Idempotency-Key` on the callback contract is a follow-up. KEEP. |
| M1-024 | L | OBSERVABILITY_GAP | The sanitized readback records plugin names only and no `retries`; rate/body values of legacy routes are unknown | STALE_EVIDENCE scope | `UNRECORDED_READBACK` profiles; next bounded capture should include `retries` and the two limiter values. |
| M1-025 | L | DEPLOYMENT | Standby routes: applier upserts `protocols [http, https]`, readback shows `https` only; standby rate limiting uses `policy: local` | drift | Declared drift ×4 (LOW); `local` is acceptable on the private single node and documented. |
| M1-026 | L | PLUGIN | `control-plane.yml` comment cites Kong 2.x priorities for `openid-connect`/`jwt` | doc nit | Invariant (post-function after auth) holds on 3.x; noted in plugin governance. |
| M1-027 | L | DEPLOYMENT | Single-node compose has no `pids_limit`/`mem_limit`/`cpus`/`user` (the gateway-platform topologies do) | DEPLOYMENT_RISK | Follow-up; recorded in the admin boundary. |
| M1-028 | L | AUTH | The MoneyBee identity contract routes directly to `moneybee-api:8000` while the gateway-platform example routes the same operation through Middleware over TLS | architecture inconsistency | Direct route has a recorded reason (backend revalidates JWT); the integration model is the target. KEEP both, documented. |
| M1-029 | M | DEPLOYMENT | The 13 Mission 1 draft files found in the working tree described the foundation in ~20-line documents, a 50-line registry with no route/service enumeration, and a validator that did not cross-check sources; the plugin governance draft named `correlation-id` as the only global plugin while the actual global plugin is `prometheus` | STALE_EVIDENCE | Replaced by this baseline; the validator now enumerates and cross-checks every route, service and plugin. |
| M1-030 | H | DEPLOYMENT | No foundation-level enforcement existed across sources: nothing detected undocumented routes, cross-source duplicates/shadowing, unauthenticated routes by omission, implicit transport policy, or environment/issuer mixing | MISSING | **Implemented here:** `config/kong-gateway-foundation.v1.json`, `scripts/validate_kong_foundation.py`, `tests/test_kong_foundation.py` (58 tests incl. 41 mutation cases), CI step in `validate.yml`. |

Searched and **not found** (no finding): TLS verification disabled anywhere;
secrets or private keys in Git; wildcard CORS with credentials; `0.0.0.0/0`
trusted IPs; published Admin/Manager/Status ports; Docker socket mounts;
duplicate route names within a source; direct Odoo or n8n-execution routes;
gRPC; WebSocket/SSE Kong routes; `/v2`, `/platform/v1` or `/v2/automation`
namespaces (do not exist and are not invented).

## 5. Defect log (DETECT → REPRODUCE → CLASSIFY → ROOT CAUSE → FIX → TEST)

| # | Detect | Reproduce | Root cause | Smallest correct fix | Focused test |
| --- | --- | --- | --- | --- | --- |
| M1-004 | grep of `{vault://env/...}` vs `runtime.env.example` | validator `validate_node` fails on the checked-in files | template written for two secrets before the OIDC salt reference was introduced | declare `KONG_OIDC_CACHE_TOKENS_SALT` (name only) | `test_missing_runtime_variable_for_a_vault_reference_fails`, `test_runtime_env_template_declares_every_vault_reference` |
| M1-005 | source dump: `retries=None` on canonical services | validator `IMPLICIT_RETRIES` on canonical | Kong default never overridden | `retries: 0` in `control-plane.yml`, campaign prod/staging, intake; renderers emit `retries: 0`; verifier compares `retries` | `test_control_plane_verifier_rejects_declarative_drift[service.retries]`, campaign renderer test, calling renderer test, `test_implicit_retries_or_kong_default_timeouts_on_a_canonical_service_fail` |
| M1-006 | readback 60/60/60 s on campaign service; contract silent | validator `KONG_DEFAULT_TIMEOUTS` / profile mismatch | contract carried only name/host/port/protocol | pin `STANDARD_API` in campaign prod+staging and intake; renderer passes through | `test_renderer_emits_exact_routes_plugins_and_consumers`, `test_intake_authority_is_service_only_and_fail_closed`, edge-contract validator (staging == production service) |
| M1-007 | validator `UNBOUNDED_REQUEST_BODY` on `control-plane-reconciliation` | same | route added without the limiter the sibling POST routes carry | add `request-size-limiting` 1 MB | `test_mutation_route_without_body_limit_on_a_canonical_route_fails`; `deck file validate` passes |
| M1-008 | validator: staging source binds production issuer | same | schema `const` issuer | schema `enum` of both realms; compiler `issuer_environment_mismatch`; example → staging realm | `test_invalid_policy_rejected_without_value_disclosure[issuer_environment_mismatch]`, `test_method_and_environment_namespaces`, `test_staging_overlay_cannot_bind_the_production_issuer_or_drift_from_base` |
| M1-001 / M1-016 | inventory route with `plugins: []`; test upstream | `validate_kong_production_inventory.py` had no gate | readback candidate recorded what runs without an activation posture | `activationBlockedRoutes` in the inventory + validator + registry gate | `test_unowned_or_unauthenticated_routes_are_activation_blocked`, `test_activation_gate_rejects_authorization_or_unknown_routes`, `test_inventory_activation_gate_and_registry_must_agree` |
| M1-030 | no cross-source validation | — | foundation missing | registry + validator + tests + CI | `tests/test_kong_foundation.py` (58) |

Full regression after the fixes: see the freeze document.

## 6. Confirmed controls (unchanged, KEEP)

- Node: Admin `127.0.0.1:8001` container loopback and unpublished, Manager off,
  Status private, proxy on host loopback only, `trusted_ips` required,
  `real_ip` from `X-Forwarded-For`, Lua sandbox + `cjson.safe`, env vault,
  headers off, PostgreSQL TLS verify, immutable digest, read-only root, no
  capabilities, no-new-privileges, healthcheck, file secrets only.
- Control plane: OIDC bearer with exact audience, Redis rate limiting
  fail-closed, correlation, post-function scope/tenant/identity policy that
  denies unknown paths before minting headers and clears caller identity
  headers first.
- Canonical Middleware routes: exact host/path/method, anchored regex path
  parameters equal to Middleware's `PUBLIC_ID`, `jwt` RS256 keyed by `azp`,
  claim guards (issuer → audience → party+environment → scope), Redis
  fail-closed limits, 1 MB bodies, Middleware contract pinned by sha256.
- Management: bounded in-container Admin channel, read-only capture,
  exact-head manifests, immutable promotion, no runtime apply from source.

## 7. Residual blockers (honest scope)

- Runtime certification of Caddy → Kong (`KONG_TRUSTED_IPS`, `426`, header
  stripping, peer-network Admin denial), Keycloak token matrices and the
  Middleware hops is not claimed by this baseline.
- Legacy shared-key routes and the legacy host cannot be deleted from source
  without runtime consumer evidence; they are `LEGACY`, non-promotable and
  their retirement conditions are recorded.
- Applying the OIDC control-plane candidate, the campaign transport policy and
  the callback guard phase to production are reviewed runtime changes under
  `operations/runbooks/`; the registry records them as declared drift, not as
  done.
- Windows host cannot run the POSIX security suites; CI on Linux is the
  authority for those.
- `main` has moved past this branch's base (PR #104, `/platform/v1/*` read
  routes). The foundation's source discovery will refuse that contract until
  it is registered; see the rebase note in the freeze document.
- A parallel worktree `Kong.worktrees/mission1-foundation-20260918`
  (branch `mission/kong-mission1-foundation-20260918`, cut from the newer
  `main`) appeared during this session and was not created, read or modified
  by this baseline; whichever branch lands second must reconcile with the
  registry.
