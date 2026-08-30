# Community n8n gateway and egress gate

This change is source-only and `PROPOSED_NOT_APPLIED`. It fixes the public n8n
Middleware authority at `https://api.codestra.co/v1/integrations/n8n`, requires
an HTTPS/443 DNS upstream with certificate verification, and retains Middleware
token revalidation.

The service subject is the existing Keycloak-managed `n8n-automation` client;
this source must not introduce a parallel `n8n-runtime` identity.

`enforce-docker-egress.sh check` validates explicit IPv4 destination CIDRs,
finds all active Kong container-network addresses, and requires every
non-internal Kong network to carry the `codestra.egress.scope=kong` label. Rules
match stable Docker bridge interfaces rather than ephemeral container addresses,
allow established replies, and reject IPv6-enabled governed networks.
`apply` installs one managed `DOCKER-USER` chain; `remove` deterministically
removes it. Never supply a default route. Resolve and review allowed DNS
destinations immediately before a maintenance window, record their CIDRs,
verify staging first, and keep external effects disabled.
