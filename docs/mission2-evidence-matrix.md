# Kong Mission 2 — Evidence Matrix

Branch `feature/mission2-identity-access-security` (from Mission 1 foundation
`50dad08`). Source-only; `runtimeApplyAuthorized: false` in every artifact.
Windows workstation evidence; Linux CI (`validate.yml`) is the authority for
the POSIX-only suites.

## Freeze gate

| Gate | Evidence | Result |
| --- | --- | --- |
| Route access classification | 79/79 routes carry an access class; `ACCESS_CLASSES=ADMIN_INTERNAL:2,AUTHENTICATED:24,INTERNAL:9,PUBLIC:7,SERVICE_AUTHENTICATED:37`; validator cross-checks class ↔ foundation; `test_unclassified_route_fails` | GREEN |
| Public-route allowlist | 7 public routes = 7 allowlist entries with reasons; mutation-only public routes are legacy; `codestra-mail-api` stays `BLOCKED`, not public; `test_public_route_not_allowlisted_fails`, `test_route_cannot_be_reclassified_public_by_policy_alone` | GREEN |
| Authentication profiles | 14 profiles (`config/kong-authentication-profiles.v1.json`); every route bound; class/mechanism/lifecycle/activation constraints; strength floors | GREEN |
| Issuer contract | two realms, RS256 only, skew 0 s, no wildcard; source issuer ↔ environment ↔ profile; `test_wrong_issuer_in_a_source_fails`, catalogue mutations | GREEN |
| Audience contract | 7 audience profiles, no wildcard, `clientIdIsAudience` only with contract (`sdk-intake`); policy audience ↔ foundation audience; mutations (missing, wrong, wildcard, uncontracted client-id) | GREEN |
| Scope prerequisites | policy scopes == foundation scopes; no wildcard; `platform.admin` required on admin; `docs/gateway-scope-contract-v1.md`; mutations | GREEN |
| Service identities | explicit `authorizedParties` per service family or `consumer-mapped`; source client must be listed; no shared universal credential; `docs/service-authentication-contract-v1.md` | GREEN |
| Human / service separation | principal classes per route; HUMAN never on service/internal/admin; SERVICE never on admin; ADMIN-only admin route; `test_human_service_admin_and_internal_identities_are_separated` | GREEN |
| Identity-header trust | `headerAuthorityAllowed: false`; 22 never-trusted headers; strip-before-mint proven on every policy; unstripped routes carry the explicit finding + mitigation | GREEN (M2-003 refactor deferred behind #105) |
| Tenant boundary | 8 tenant policies, none header-authority; validator rejects `HEADER_AUTHORITY`; `docs/tenant-identity-boundary-v1.md` | GREEN |
| Fail-closed identity behaviour | `FAIL_CLOSED_V1` on every canonical protected route; `downgradeToPublic: false`; openid-connect `anonymous` forbidden; discovery unavailable → plugin error, never allow | GREEN |
| Token-cache secret boundary | vault salt required, ttl ≤ 3600 s, leeway ≤ 60 s; `KONG_OIDC_CACHE_TOKENS_SALT` declared by name only; jwt static-key rotation documented | GREEN |
| Admin isolation | Mission 1 node checks unchanged; `test_logging_policy_and_admin_isolation_are_preserved` | GREEN |
| Logging redaction | no log plugins; guards never log; constant error bodies; `neverPersisted` list; validator requires `redactsCredentials` on any future log plugin; secret scan 0 hits over 236 tracked files (sentinels only in tests) | GREEN |
| Canonical validator | `python scripts/validate_kong_foundation.py` → `KONG_GATEWAY_FOUNDATION=PASS … SECRET_HITS=0 M1_DEPENDENCY=M1_DEPENDENCY_PENDING` | GREEN |
| Focused M2 tests | `pytest -q tests/test_kong_identity_security.py` → 58 passed, 1 xfailed (strict M1 guard) | GREEN |
| Mission 1 tests | `pytest -q tests/test_kong_foundation.py` → 58 passed | GREEN |
| Full regression | `pytest -q --ignore=tests/test_kong_change_authority.py` → 655 passed, 1 xfailed, 4 failed + 4 errors (all pre-existing Windows host artifacts in the certification packager: symlink privilege, umask, 32 KiB env cap); 0 new failures vs. the entry baseline; `test_kong_change_authority.py` needs `fcntl` (Linux CI) | GREEN (CI-owned residue) |
| Source validators | community n8n egress, calling policy (+self-test), production inventory, middleware edge contract, foundation, marketing, provider control, cells, standby: PASS; `compileall` PASS; JSON/YAML parse PASS; migration manifests regenerated (235 files) and verified in an LF worktree | GREEN |
| luac / shellcheck | not installed on this workstation; no Lua or shell file changed in Mission 2 | CI-owned |

## Mission 1 preservation

| Invariant | State |
| --- | --- |
| canonical Middleware = `:8095` | preserved (`canonicalPublicApiListener: 8095`) |
| `:8080` = 0 after #105 | **M1_DEPENDENCY_PENDING** — one transitional alias (`appolon-middleware-integration-api:8080`, n8n control plane + prepared provider control); strict xfail guard flips to a failure when #105 lands |
| direct provider routes = 0 | preserved (validator blocks markers and IP literals) |
| direct command bypass = 0 | preserved |
| explicit methods / no wildcard fallback | preserved on every canonical route |
| Caddy → Kong / Kong → Middleware boundaries | unchanged |
| Admin isolation | unchanged |

## Dependency statement

```text
KONG MISSION 2:
IMPLEMENTATION COMPLETE — FOUNDATION DEPENDENCY PENDING

DEPENDENCY:
KONG PR #105 / MISSION 1 INDEPENDENT APPROVAL
(also: Mission 1 foundation commit 50dad08 on feature/issue-58-canonical-campaign-routes, unmerged)

PRODUCTION EFFECTS:
0
```

Mission 3 does not start until the dependency closes.
