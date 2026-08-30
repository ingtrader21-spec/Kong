# Community n8n gateway and egress gate

This change is source-only and `PROPOSED_NOT_APPLIED`. It fixes the public n8n
Middleware authority at `https://api.codestra.co/v1/integrations/n8n`, requires
an HTTPS/443 DNS upstream with certificate verification, and retains Middleware
token revalidation.

`enforce-docker-egress.sh check` validates explicit destination CIDRs and finds
all active Kong container-network addresses. `apply` installs one managed
`DOCKER-USER` chain; `remove` deterministically removes it. Never supply a
default route. Resolve and review allowed DNS destinations immediately before a
maintenance window, record their CIDRs, verify staging first, and keep external
effects disabled.
