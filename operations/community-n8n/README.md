# Community n8n gateway and egress gate

This source is `SUPERSEDED_NOT_APPLIED`. The canonical Middleware edge contract
(`config/middleware-public-api-route-contract.v1.json`, pinned by
`config/middleware-public-api-route-contract.sha256`) classifies every
`/v1/integrations/n8n/*` alias as `denied`, so the public endpoint this proposal
targeted no longer exists as a shared-edge route. The only shared-edge upstream
is `middleware-integration-api:8095`, generated into
`config/kong-middleware-routes.production.yml` and
`config/staging/kong-middleware-routes.staging.yml`. Middleware continues to
revalidate the original `n8n-automation` token on the canonical
`/v2/automation/*` and result submit/read routes.

## Decision R6-2026-09-16-canonical-middleware-upstream

Kong PR #30 collected read-only runtime evidence showing that, at that time,
the generic `middleware-integration-api` Docker alias resolved to a different,
legacy runtime and that `appolon-middleware-integration-api:8080` was the
unique runtime serving the `/v1/integrations/n8n` routes. Two authorities then
disagreed: that evidence bound the route authority to the legacy host, while the
Middleware repository's own public route contract names the service
`middleware-integration-api` listening on `8095`.

The contract wins. The route authority in
`config/kong-n8n-control-plane-routes.json` is retired deny-only, its service is
disabled, and it is bound to `middleware-integration-api:8095`. The legacy host
and port are recorded under `retired_legacy_runtime` and listed in
`ambiguous_aliases_denied`; no Kong route may target them. This decision is
source-only: it is not permission to reconcile Kong, change the deployed
runtime, or apply a firewall, and `runtime_apply_authorized` stays `false`.

## Required topology evidence

Before any runtime reconciliation toward the canonical upstream can be
authorized, run the read-only collector from an exact, clean checkout of the
reviewed Kong SHA:

```bash
python3 operations/community-n8n/collect_topology_evidence.py \
  --source-sha <exact-40-character-reviewed-sha> \
  --tls-host <private-middleware-tls-dns-name> \
  --output /secure/evidence/community-n8n-topology.json
```

The collector checks both `git rev-parse HEAD` and `git status --porcelain`; it
refuses a mismatched SHA, modified tracked file, staged change, or untracked
file. It then:

- identifies exactly one running Kong gateway and hashes its canonical Docker ID
  rather than a caller-supplied name or abbreviated ID;
- applies the same Kong identity verification when `--kong-container` is used,
  rejecting an unrelated or stopped container;
- resolves the canonical `middleware-integration-api` runtime, the retired
  `appolon-middleware-integration-api` host, and the proposed TLS hostname from
  inside that verified Kong network namespace, proving the canonical alias is
  unique and the retired host is not that runtime;
- requires every resolved TLS address and every Docker alias candidate to map
  exclusively to the verified Appolon Middleware runtime; one matching address
  cannot hide another legacy or unrelated target;
- maps only Docker network aliases, IPs, configured image references, image IDs,
  network names, and hashed container IDs;
- verifies the TLS certificate and requested DNS hostname when `openssl` is
  available inside the Kong container;
- sends one anonymous read-only operation probe when `curl` is available and
  accepts only `401`, `403`, or domain-level `404` as fail-closed evidence;
- emits no environment dump, credentials, request/response body, logs, or secret
  values;
- performs no container, network, route, configuration, service, or firewall
  mutation.

When `--output` is used, the explicitly requested evidence artifact is the only
file written. The schema therefore records
`runtime_mutations_performed=false`, rather than making the inaccurate claim
that no evidence file was created.

The emitted document must validate against
`topology-evidence.schema.json`, its source SHA and clean checkout must be
verified, every promotion result must be true, and an independent reviewer must
confirm that every proposed TLS target represents the same signed Middleware
runtime from every active Kong network. A rollback rehearsal and exact-head CI
are also mandatory.

## Egress enforcement

`enforce-docker-egress.sh check` validates explicit IPv4 destination CIDRs,
finds all active Kong container-network addresses, and requires every
non-internal Kong network to carry the `codestra.egress.scope=kong` label. Rules
match stable Docker bridge interfaces rather than ephemeral container addresses,
allow established replies, and reject IPv6-enabled governed networks.
`apply` installs one managed `DOCKER-USER` chain; `remove` deterministically
removes it. Never supply a default route. Resolve and review allowed DNS
destinations immediately before a maintenance window, record their CIDRs,
verify staging first, and keep external effects disabled.
