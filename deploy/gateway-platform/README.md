# Gateway topology source

These mutually exclusive Compose authorities describe the hybrid and traditional
topologies. They have no published ports and no automatic default profile. They
do not install networks, initialize PostgreSQL, create trust material, run database
migrations or activate traffic. Existing source authorities own dedicated PostgreSQL,
Redis, backup, Caddy and the private upstream gateway. The external networks must
exist under their exact designated names and be verified `Internal=true` before
admission. A similarly named public network is not acceptable.

Use exactly one topology in an approved environment. Enterprise hybrid runs a
private CP plus two DPs. Only the CP joins the database network or receives database
credentials. CP/DP identity uses separate PKI certificates, a trusted CA and exact
CP SNI. Both DPs use durable, pre-provisioned private prefix volumes; protect these
volumes as configuration secrets and verify recovery after a CP outage.

The traditional topology runs two proxy nodes plus an isolated management node.
Only the management node enables Admin, bound to container loopback. Administrative
access uses the existing authorized namespace channel. No Docker socket is mounted
in any service. Proxy nodes expose only private TLS proxy listeners. The canonical
OIDC/mTLS candidate requires its Enterprise capabilities; an OSS fallback image
needs a separately reviewed supported authentication candidate, never removal of
authentication plugins from a generated document to make it start.

Select the exact reviewed image repository and `sha256:` digest. The image must
contain all three versioned plugins at `kong/plugins/<name>/` and the executable
`codestra-kong-entrypoint.sh` at `/usr/local/bin/codestra-kong-entrypoint`. Preserve
the official `/docker-entrypoint.sh`. The wrapper loads the env Vault rate-limit
reference from an explicit secret file without printing it. No secret is baked
into the image. CP, DP and management nodes use the identical image digest/plugin
versions; the source test checks this invariant. Runtime version/plugin read-back
still belongs to protected staging certification.

Provision secret files and cache volumes for UID/GID 1000 with minimum permissions;
include trusted upstream/database CA roots, proxy TLS identity, cluster PKI and the
runtime-only PostgreSQL credential. Kong migrations use the separate existing
migrator authority, never this runtime credential. Run the pinned offline decK
schema check against the selected image and verify certificate SNI/expiry, private
network memberships, limits, read-only roots, backup/restore and rollback before
starting an approved runtime. The source tests do not attest live network isolation.

No secret, certificate, cache volume or runtime output belongs in Git. See
`network-boundaries.yaml` and the architecture documents for the ownership model.

Every node mounts the separately provisioned `kong_license` file and uses
`KONG_LICENSE_PATH`; generated OIDC/mTLS candidates require a valid Enterprise
license. A traditional OSS fallback must use a separately reviewed compatible
candidate and image. Declaring a license path does not add Enterprise plugins to
an OSS image. The env Vault provider is explicitly enabled on all nodes.

Proxy nodes require `KONG_TRUSTED_IPS` with the exact reviewed Caddy/upstream-gateway
source CIDRs and use recursive `X-Forwarded-For` handling. Do not trust a default
route or arbitrary client networks. The upstream gateway must preserve the
authenticated forwarding chain so per-IP Redis quotas identify callers correctly.
Status listens on private container interfaces at 8100 with no host publication;
Prometheus reaches it through the designated observability network. Generated
configuration explicitly enables its global Prometheus metrics plugin.

The `oidc_cache_tokens_salt` secret is stable across CP/DP nodes and configuration
synchronizations. The entrypoint exports `KONG_OIDC_CACHE_TOKENS_SALT` for the
established env Vault reference; no generated salt or secret value is committed.
Public health templates require optional caller correlation IDs. Route contracts
reject trailing slashes other than `/`, so compilation cannot silently change a
reviewed path.
