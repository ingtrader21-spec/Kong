# Kong Mission 3 — Release Supply Chain Audit

Scope: every workflow, script, contract and deployment file that produces,
verifies, publishes or consumes Kong release evidence, audited on `main`
`873ee31` (Mission 2 frozen) on 2026-09-18. Source-only: no image was built or
published from this workstation, no registry or runtime was mutated,
`runtimeApplyAuthorized: false` and `providerEffectsEnabled: false` everywhere.

## 1. Root cause of the observed GHCR failure

Every push to `main` since at least `942ef1c` (2026-09-17) failed in
`release.yml` → `Build and publish exact standby auth image`:

```text
failed to push ghcr.io/appolon1908-hue/kong-standby-auth:sha-<sha>:
denied: permission_denied: The requested installation does not exist.
```

| Fact | Value | Evidence |
| --- | --- | --- |
| CURRENT_REPOSITORY_OWNER | `ingtrader21-spec` (user) | `GET /repos/ingtrader21-spec/Kong` → `owner.login`, `owner.type = User`, id `1347790742` |
| CURRENT_REGISTRY_NAMESPACE (workflow) | `appolon1908-hue` | `release.yml` `STANDBY_IMAGE_REPOSITORY: ghcr.io/appolon1908-hue/kong-standby-auth` (hard-coded) |
| EXPECTED_PACKAGE_OWNER | `ingtrader21-spec` | the only namespace a repository-scoped `GITHUB_TOKEN` can write |
| Repository history | transferred | `GET /repos/appolon1908-hue/Kong` → HTTP 301 → `/repositories/1347790742` (`full_name: ingtrader21-spec/Kong`); the sibling repositories `Middleware-`, `Caddy`, `Keycloak` redirect the same way |
| WORKFLOW_TOKEN_ACTOR | `${GITHUB_ACTOR}` with `github.token` | `docker login ghcr.io --username "${GITHUB_ACTOR}" --password-stdin` — step 7 succeeded, so authentication is not the defect |
| PACKAGES_WRITE_PERMISSION | present | top-level `permissions: packages: write` |
| PACKAGE_EXISTS (`ingtrader21-spec/kong-standby-auth`) | not readable anonymously (HTTP 403 on `/v2/…/tags/list`); created and linked by the first publication from the repository workflow | registry probe; GHCR package semantics |
| PACKAGE_VISIBILITY | private (inherits the private repository on first publication) | GHCR semantics |
| REPOSITORY_PACKAGE_LINK | established by the first publication from `ingtrader21-spec/Kong` | GHCR semantics |
| TOKEN_CAN_PUSH to `appolon1908-hue/*` | no — `permission_denied: The requested installation does not exist` | run 35406310562 and every earlier `main` run |

Root cause classification: **STALE_REGISTRY_OWNER** (primary) manifesting as
**INSTALLATION_PERMISSION** (the token's app installation exists only for the
current owner). Not `MISSING_PACKAGES_WRITE`, not `WRONG_TOKEN`, not
`WRONG_PACKAGE_POLICY`.

The same stale owner was baked into three more production-authority places,
so "changing the string" in the workflow alone would not have repaired the
release path:

- `tools/generate_release_manifest.py` — `standby_auth_image` literal;
- `tools/verify_release_candidate.py` — `REPOSITORY = 'appolon1908-hue/Kong'`;
  its `foreign_repository` check compares against the API's `full_name`
  (`ingtrader21-spec/Kong`), so every staging/production promotion would also
  have failed;
- `deploy/kong-production-standby/compose.standby.yaml` — image reference.

## 2. Inventory and classification

| Item | Where | Finding | Class |
| --- | --- | --- | --- |
| Workflow trigger | `release.yml` `on: push` to `main`/`staging`/`production`, `workflow_dispatch` | correct; environment branches only, refuses others | KEEP |
| Permissions | `actions: read`, `contents: read`, `packages: write` | least privilege; no `id-token` needed (BuildKit attestations, not GitHub OIDC attestations) | KEEP |
| Registry host / namespace / package | `ghcr.io` / `appolon1908-hue` (stale) / `kong-standby-auth` | namespace must be the repository owner | REPAIR → `config/kong-release-registry-contract.v1.json` |
| Authentication source | `github.token` as `GITHUB_ACTOR` | correct; no PAT, no shared credential | KEEP |
| GITHUB_TOKEN permissions | repository-scoped installation token | can write only `ghcr.io/ingtrader21-spec/*` | PERMISSION_DEFECT (of the target, not of the token) |
| Artifact upload | `kong-release-<sha>`, 90 days, `if-no-files-found: error` | correct | KEEP |
| Image tags | `sha-<40 hex>` only; no `latest` | immutable | KEEP (now contract-enforced, `preflight-sha-<sha>` added for pull requests) |
| Digest capture | buildx `--metadata-file` → `containerimage.digest`, regex-checked | correct but never re-read from the registry | REPAIR: registry re-read + `LOCAL == REMOTE` |
| SBOM | `--sbom=true` (BuildKit SPDX attestation on the index) — attached but never extracted or bound | MISSING (binding) → extracted, sha256 bound in the manifest |
| Provenance | `--provenance=mode=max` — attached but never verified | MISSING (binding) → extracted, revision-checked, sha256 bound |
| Build ↔ publish separation | single `--push` build; an unverifiable image could be published | SUPPLY_CHAIN_RISK → `--load` build + `tools/verify_standby_image.py` before any push |
| Release evidence | `tools/generate_release_manifest.py` (repository, workflow identity, contract digests absent) | REPAIR → evidence contract + `tools/verify_release_evidence.py` |
| Promotion authority | `tools/verify_release_candidate.py` (exact run/artifact/digest reuse) | design correct; stale repository literal | REPAIR (contract-derived) |
| Runtime topology gate | `runtime-topology` job on `[self-hosted, linux, kong-runtime]` for staging/production | unchanged; runtime boundary | RUNTIME_BOUNDARY |
| Candidate certification | `runtime-certification.yml`, `tools/package_staging_certification.py`, `tools/verify_staging_certification.py` | derive `REPOSITORY` transitively from the contract | KEEP |
| Runtime mutation authority | none in any release path; `runtime_apply_authorized: false`, `external_effects_enabled: false` | preserved; `provider_effects_enabled: false` added | KEEP |
| Standby compose image | `ghcr.io/appolon1908-hue/…@${KONG_STANDBY_AUTH_IMAGE_DIGEST:?}` | digest-only consumption correct; namespace stale | REPAIR |
| Standby Dockerfile | `python:3.12-alpine@sha256:d09d15e…`, pinned requirements, `USER 65532:65532`, no network fetch | correct | KEEP (now validator-enforced) |
| Former-owner references elsewhere | `appolon1908-hue/{Caddy,Keycloak,Middleware-,N8N,Odoo}` in contracts/docs; `appolon1908-hue/Kong` issue links | cross-repository authorities also redirect (transferred together); documentary; not release authority | LEGACY (documentary; no runtime effect) |

## 3. Canonical registry contract (summary)

`config/kong-release-registry-contract.v1.json` — see
`docs/kong-release-registry-contract-v1.md`:

```text
registry     ghcr.io
namespace    ingtrader21-spec        (= lower(repository owner); never a literal in a workflow or tool)
package      kong-standby-auth
image        ghcr.io/ingtrader21-spec/kong-standby-auth
writer       GITHUB_TOKEN of release.yml (push to main) and release-preflight.yml (same-repo PRs)
reader       GITHUB_TOKEN of promotion/certification workflows; deploy identity pulls by digest
tags         sha-<sha> (authoritative), preflight-sha-<sha> (never promotable); mutable tags forbidden
digest       OCI index digest, re-read from the registry, consumed only as image@sha256:…
```

`tools/release_contract.py` is the single loader; every workflow proves
`GITHUB_REPOSITORY == contract.repository` and
`lower(GITHUB_REPOSITORY_OWNER) == contract.namespace` before it authenticates
to the registry, so a further transfer fails closed instead of publishing to a
stale namespace.

## 4. Repairs

| Area | Change |
| --- | --- |
| `release.yml` | contract binding step before login; BUILD (`--load`) → VERIFY (`tools/verify_standby_image.py`: non-root 65532, expected labels, no secret-like env, expected cmd, platform, bounded layers, contained import smoke) → PUBLISH (`--push --provenance=mode=max --sbom=true`, tag `sha-<sha>`) → REGISTRY VERIFY (`imagetools inspect`, `remote == local`) → attestation extraction (`tools/extract_image_attestations.py`) → manifest generation → `tools/verify_release_evidence.py`; builder torn down in the always-step; no `continue-on-error` |
| `release-preflight.yml` (new) | same chain on the exact pull-request head for same-repository PRs, publishing only `preflight-sha-<sha>`; proves GHCR permission, digest, SBOM and provenance before merge |
| `tools/generate_release_manifest.py` | image from the contract; new bindings (repository, id, tag, SBOM/provenance sha256, Middleware contract digest, registry contract digest, workflow identity, `provider_effects_enabled`); `pull-request-preflight` stage that is never promotable |
| `tools/verify_release_candidate.py` | repository and image from the contract; refuses any non-authoritative tag |
| `tools/verify_release_evidence.py` (new) | enforces `config/kong-release-evidence-contract.v1.json` |
| `scripts/validate_release_supply_chain.py` (new) | static gate in `validate.yml`: permissions, no stale owner, no mutable tag, no `continue-on-error`, contract bound before login, exact source proven, digest captured and re-read, attestations extracted, evidence verified, compose/Dockerfile/requirements pinned |
| `deploy/kong-production-standby/compose.standby.yaml` | contract namespace, digest-only unchanged |
| `tests/test_release_supply_chain.py` (new) | positive proofs and the negative matrix (stale owner, missing `packages: write`, mutable tag, source SHA mismatch, missing/mismatched digest, missing SBOM, evidence without exact SHA, flags true, `continue-on-error`, fork PR, unpinned base/requirements) |

## 5. What remains runtime work (not done here, by design)

- The first authoritative publication of `ghcr.io/ingtrader21-spec/kong-standby-auth:sha-<main sha>` happens on the next push to `main` after this change merges; the pull-request preflight proves the same path on the PR head first.
- `runtime-topology` (self-hosted `kong-runtime` runner) and the staging certification remain live-runtime gates; nothing in Mission 3 executes them.
- Documentary references to `appolon1908-hue/*` sibling repositories are left as they are: those repositories were transferred together and redirect; rewriting them is not a release concern.
