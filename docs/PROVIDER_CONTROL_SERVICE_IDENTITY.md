# Provider-control service identity

`config/kong-provider-control-routes.v1.json` is the disabled-by-default Kong
side of the reviewed application → Kong → Middleware provider-control
boundary. It binds each route to one Keycloak client, the `middleware-api`
audience and one exact operation scope. Kong preserves the bearer token and
Middleware independently revalidates identity, tenant and operation authority.

n8n is intentionally not represented by a generic route here. Its existing
v1 compatibility surface remains separately governed while the accepted
workflow-family `/v2/automation/*` contract is implemented and certified.

This source contract does not authorize reconciliation, workflow activation,
provider traffic or production writes. Its Middleware and Keycloak pull-request
dependencies must merge first. Runtime application then requires a separate
reviewed Kong reconciliation change, pre-change export and rollback evidence.

The five existing shared-key paths remain explicitly inventoried as blockers.
They may not be deleted merely to make source validation green: consumer usage
must be proven zero and each replacement must have reviewed ownership first.
