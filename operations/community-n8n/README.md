# Community n8n gateway and egress gate

This source remains `PROPOSED_NOT_APPLIED`. The public n8n Middleware authority
is fixed at `https://api.codestra.co/v1/integrations/n8n`; the proposed future
Kong-to-Middleware hop requires a DNS upstream on HTTPS/443 with certificate and
hostname verification. Middleware continues to revalidate the original
`n8n-automation` token.

## Current production authority stays unchanged

The currently reviewed production route remains:

```text
appolon-middleware-integration-api:8080
```

That unique Docker DNS name was selected after read-only runtime evidence proved
that the generic `middleware-integration-api` alias resolved to a different,
legacy runtime. The generic alias is therefore explicitly denied by the source
contract. The proposed HTTPS design is not permission to change the current
route, reconcile Kong, or apply a firewall.

## Required topology evidence

Before `PROPOSED_NOT_APPLIED` can change, run the read-only collector from an
exact checkout of the reviewed Kong SHA:

```bash
python3 operations/community-n8n/collect_topology_evidence.py \
  --source-sha <exact-40-character-reviewed-sha> \
  --tls-host <private-middleware-tls-dns-name> \
  --output /secure/evidence/community-n8n-topology.json
```

The collector first checks `git rev-parse HEAD` and refuses a supplied SHA that
does not match the checkout. It then:

- identifies exactly one running Kong container and hashes its canonical Docker
  ID rather than a caller-supplied name or abbreviated ID;
- resolves the unique current runtime, denied generic alias, and proposed TLS
  hostname from inside that Kong network namespace;
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
`topology-evidence.schema.json`, its source SHA must be verified, every promotion
result must be true, and an independent reviewer must confirm that the proposed
TLS hostname represents the same signed Middleware runtime from every active
Kong network. A rollback rehearsal and exact-head CI are also mandatory.

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
