# Kong Mission 2 — Evidence Matrix (post-#105 reconciliation)

Branch `feature/mission2-identity-access-security` = Mission 1 foundation
(`50dad08`) + Mission 2 (`8d4ac7b`) + `main` at `6afd0bd` (PR #103, #104,
#105) + the reconciliation commit. Source-only; `runtimeApplyAuthorized:
false` and `providerEffectsEnabled: false` in every artifact; no runtime,
Caddy, Keycloak, Middleware or provider was touched. Windows workstation
evidence; Linux CI (`validate.yml`, `kong-config.yml`) is the authority for the
POSIX-only suites.

## Freeze gate

| Gate | Evidence | Result |
| --- | --- | --- |
| PR #105 dependency | merged into `main` as `6afd0bd` (2026-09-18T17:43:57Z) after independent approval; `main` merged into this branch; `M1_DEPENDENCY=MERGED`; no `m1Dependency` marker, no xfail, no "awaiting #105" statement remains | CLOSED |
| Middleware `:8095` authority | `middlewareUpstreamAliases[0]` = `middleware-integration-api:8095` `CANONICAL_PUBLIC_API`; v2 authority, both generated manifests, campaign and (retired) n8n contracts bind it; `canonicalPublicApiListener: 8095` | GREEN |
| Middleware `:8080` active alias | `TRANSITIONAL_8080_ALIASES=0`; alias role `RETIRED_DENIED_PR105`; `RETIRED_UPSTREAM_ALIAS` accepted only on `provider-control-middleware` (+6 routes, `PREPARED_DISABLED`) and the two live n8n routes (`RETIRE_CANDIDATE`, `knownDrift` 8080 → 8095); no `8080` literal in the generated manifests; `test_retired_middleware_8080_alias_has_no_activatable_route` | ZERO |
| v2 authority registered | 4 new sources (`middleware-authority-v2`, 2 × `kong-declarative`, `platform-api-read-contract`); `SOURCES=24`; source discovery refuses any unregistered `config/kong-*` file (`test_unknown_source_and_unknown_route_fail`) | GREEN |
| 80 shared-edge routes | 80 `middleware-*` production routes bound to canonical + manifest + authority, 80 staging twins bound to the staging manifest; every one carries routeId, serviceId, environment, bindings, traffic class, access class, profile, issuer, audience, scope, `contractExpectedAzp`, rate and size profile, lifecycle, activation, disposition — all derived from the authority (`test_v2_shared_edge_routes_are_governed_from_the_authority`) | GOVERNED |
| 10 denied aliases | 10 production + 10 staging `DENIED_ALIAS` routes: `serviceId: null`, `request-termination` 404 only, no upstream, no provider/8080/wildcard fallback; `validate_denied_aliases`; `test_denied_aliases_are_fail_closed_404_terminations`; mutations (upstream added, status ≠ 404, extra plugin) fail | FAIL-CLOSED |
| Platform API routes (PR #104) | 20 routes + `codestra-platform-api` registered as `TRANSITIONAL`, each `supersededBy` its v2 twin; v2 regex wins deterministically; overlaps declared; contradiction (`serviceTokenOnly` vs v2 `browser-session`) recorded as M2-016 | RECONCILED |
| Route access classification | 279/279 routes classified: `ADMIN_INTERNAL:2 AUTHENTICATED:142 INTERNAL:9 PUBLIC:27 SERVICE_AUTHENTICATED:99`; `test_unclassified_route_fails`, `test_v2_route_without_access_class_or_profile_fails` | GREEN |
| Public-route allowlist | 27 public routes = 27 allowlist entries with reasons (7 legacy/probe + 20 gateway-terminated aliases); `codestra-mail-api` stays `BLOCKED`, never public | GREEN |
| Authentication profiles | 16 profiles (`HUMAN_OR_SERVICE_OIDC_V1` and `DENIED_TERMINATION_V1` added, `CAMPAIGN_MIDDLEWARE` audience retired with the source); strength floors; class/mechanism/lifecycle/activation constraints | GREEN |
| Issuer enforcement | production `https://auth.codestra.co/realms/codestra`, staging `https://auth-staging.codestra.co/realms/codestra`, never collapsed (`test_environments_are_not_collapsed`); RS256 only, skew 0, no wildcard; wrong production/staging/foreign issuer in a manifest fails | GREEN |
| Audience enforcement | every openid-connect block pins one non-wildcard audience; authority ↔ manifest ↔ registry ↔ policy agree; wrong/wildcard audience mutations fail | GREEN |
| Scope enforcement | one explicit `scopes_required` per deployable openid-connect block (validator rule); policy scopes == foundation scopes == authority scope; missing/wildcard scope fails | GREEN |
| Authorized-party enforcement | `consumer_claim: [azp]` on every v2 route; `contractExpectedAzp` (policy) == authority `azp` == the value the generated guard forwards; wrong client in the guard or the policy fails; explicit party lists preserved on the jwt routes | GREEN |
| Identity-header boundary | generated post-function clears 18 client-asserted identity headers before minting (`OIDC_STRIP_AND_CONTRACT_METADATA`, 160 routes); `X-Codestra-*` metadata headers never trusted from clients; `headerAuthorityAllowed: false`; `test_generated_guard_strips_identity_before_minting_and_never_logs` | GREEN |
| Tenant boundary | no `HEADER_AUTHORITY` tenant policy; v2 routes `CLAIM_ONLY_MIDDLEWARE_VALIDATES` (Middleware authorizes tenant/resource; `X-Tenant-ID` is a selector) | GREEN |
| Route precedence | 60 declared overlaps in the post-#105 universe; every v2-vs-old and v2-vs-#104 pair won by the v2 route (`SUCCESSOR_REPLACES_LEGACY_ON_APPLY` / `DETERMINISTIC_SPECIFICITY`); one pre-existing declared ambiguity (M1, key-auth vs OIDC control plane, never co-applied); the generator's `regex_priority` removed the `/tenants/authorized` vs `/tenants/{id}` tie; undeclared overlap and duplicate authority mutations fail | GREEN |
| Source discovery | 24 registered + 8 reasoned exclusions; unregistered file fails | GREEN |
| Secret scan | `SECRET_HITS=0` over the authority roots (sentinels only in tests); gitleaks 8.30.1 (`security.yml`) on PR #107 reported 4 findings, all `"authenticationProfile": "INTERNAL_STANDBY_V1"` (profile identifier, entropy 3.68, `generic-api-key` heuristic, commit `8d4ac7b`); `.gitleaks.toml` extends the default rules and exempts exactly that one JSON key, whose values the foundation validator restricts to catalogue names — verified with the pinned binary that a private-key block beside the exempted line is still reported | GREEN |
| Foundation validator | `python scripts/validate_kong_foundation.py` → `KONG_GATEWAY_FOUNDATION=PASS SOURCES=24 SERVICES=37 ROUTES=279 PLUGINS=19 OVERLAPS=60 KNOWN_DRIFT=22 … M1_DEPENDENCY=MERGED TRANSITIONAL_8080_ALIASES=0 RETIRED_ALIAS_RESIDUE=1+8 RUNTIME_APPLY_AUTHORIZED=NO`; generated docs current | GREEN |
| Source validators | production inventory, middleware edge contract, calling policy (+ `--self-test`), community n8n egress, provider control, cells, standby, marketing: all `PASS` / rc 0 | GREEN |
| Mission 1 tests | `pytest -q tests/test_kong_foundation.py` → 58 passed (two fixtures retargeted: the n8n 8080 → 8095 drift is now declared, the public-mutation rule names gateway-terminated routes) | GREEN |
| Mission 2 tests | `pytest -q tests/test_kong_identity_security.py` → 92 passed, 0 xfail (former strict M1 guard is now `test_retired_middleware_8080_alias_has_no_activatable_route`) | GREEN |
| v2 Middleware tests | `tests/test_kong_middleware_contract_v2.py` + `tests/test_kong_route_authority_hardening.py` → 46 passed after regeneration; `tests/test_kong_canonical_route_contract.py`, `tests/test_oidc_auth.py` green | GREEN |
| Full regression | `pytest -q --ignore=tests/test_kong_change_authority.py` → 694 passed, 4 failed + 4 errors, 16 subtests passed (16:47 on this workstation); the residue is the pre-existing Windows host-artifact set (certification packager: symlink privilege, umask, 32 KiB env cap), identical on a detached checkout of `origin/main` `6afd0bd`; `tests/test_kong_change_authority.py` needs `fcntl` (Linux CI) | GREEN (CI-owned residue) |
| Migration manifests | regenerated from the LF-normalized tree: `MIGRATION_MANIFEST_GENERATION=PASS FILES=244`, `MIGRATION_MANIFEST_CHECK=PASS`, `MIGRATION_MANIFEST=PASS` (semantic equality); conflicts resolved by regeneration only | GREEN |
| Linux-equivalent gates | `compileall` PASS; JSON/YAML parse PASS; `deck file validate` PASS on both generated manifests and the control plane (local decK 1.55; CI pins its own); 160 generated Lua chunks compile (`lupa`); `luac -p` / `shellcheck`: no Lua or shell file changed, CI-owned | GREEN / CI-owned |
| Line endings | repository content LF; `core.autocrlf=false`; every modified file written LF; no `.gitattributes` added | GREEN |
| Production safety | `RUNTIME_APPLY_AUTHORIZED=NO`, `provider_effects_enabled: false`, no deck sync / Admin API / deploy / provider / Caddy / Keycloak / Middleware change | 0 effects |

## Mission 1 preservation

| Invariant | State |
| --- | --- |
| canonical Middleware = `:8095` | preserved and consolidated (`middleware-integration-api:8095`) |
| `:8080` = 0 after #105 | **0 activatable**: retired alias, residue declared (M2-017 prepared contract, M2-019 live readback) |
| direct provider routes = 0 | preserved (validator blocks markers and IP literals) |
| direct command bypass = 0 | preserved; retired aliases answer 404 at the gateway |
| explicit methods / no wildcard fallback | preserved on every canonical route (`test_wildcard_route_in_the_canonical_contract_fails`) |
| Caddy → Kong / Kong → Middleware boundaries | unchanged |
| Admin isolation | unchanged (`test_logging_policy_and_admin_isolation_are_preserved`) |

## Residue for the owners (not blocking, not hidden)

1. `config/kong-provider-control-routes.v1.json` + its validator still pin the
   retired 8080 alias (`PREPARED_DISABLED`; cross-repository re-pin before
   activation).
2. PR #104 `config/kong-platform-api-read-routes.v1.json` duplicates 20 v2
   operations and contradicts the v2 principal model on session context; fold
   into the generator or retire.
3. The live n8n control-plane routes on 8080 must be deleted in the reviewed
   apply that activates the generated deny manifest.
4. `codestra-mail-api` (M2-001 / M1-001) remains `BLOCKED`, unowned and
   unresolved.

## Freeze statement

```text
KONG MISSION 2 — IDENTITY, AUTHENTICATION & API ACCESS SECURITY
POST-#105 RECONCILIATION COMPLETE

MISSION 1 DEPENDENCY: CLOSED
CANONICAL MIDDLEWARE: middleware-integration-api:8095
ACTIVE MIDDLEWARE :8080 ALIASES: 0
RUNTIME APPLY AUTHORIZED: NO
PROVIDER EFFECTS: 0
```

Mission 3 does not start in this change.
