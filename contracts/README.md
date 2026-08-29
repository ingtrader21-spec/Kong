# Integration contracts

`platform-control-plane.v1.json` defines this repository's side of the coordinated N8N, Kong, Middleware, and Odoo integration.

Kong owns ingress and gateway security. Middleware remains the durable cross-system write authority and independently revalidates the originating N8N service identity and tenant claims.

The N8N control-plane route authority is prepared but not approved for live reconciliation. `scripts/reconcile_kong_n8n_control_plane.py` is the exact fail-closed reconciler for this boundary, and the canonical route reconciler dispatches N8N authority verification through it. Source validation and migration-authority manifests must remain green before any apply operation is considered. `PREPARED_DISABLED` plus `reconciliation_apply=false` prevents live reconciliation from this source branch.
