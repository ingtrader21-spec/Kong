# Integration contracts

`platform-control-plane.v1.json` defines this repository's side of the coordinated N8N, Kong, Middleware, and Odoo integration.

Kong owns ingress and gateway security. Middleware remains the durable cross-system write authority and independently revalidates the originating N8N service identity and tenant claims.

The N8N control-plane route authority is prepared but not approved for live reconciliation. Source validation, migration-authority manifests, and a compatible exact reconciler must all be green before any apply operation is considered.
