# Gateway Scope Contract V1

Machine-readable: `config/kong-access-policy.v1.json` → `routes[].requiredScopes`
(equal, by validation, to the foundation's `requiredScopes` / `scopeAuthority`).

## Meaning of a scope at the gateway

Possession of a route's required scope means exactly one thing:

```text
this principal may reach this API class
```

It never means the business command is authorized. Middleware remains the
final command authority for every route: it re-validates the token and
decides whether *this* principal may execute *this* command on *this*
resource in *this* tenant and environment.

## Scopes by route family

| Family | Scope(s) | Enforced by |
| --- | --- | --- |
| control plane (`/api/v1/control/*`) | `communications.message.create`, `communications.message.dispatch`, `campaign.write`, `agent.write`, `sync.execute`, `mapping.read`, `mapping.read.minimum` — chosen per path/method by `deploy/kong/scope-policy.lua` | post-function after `openid-connect` |
| control plane reads/results/reconciliation | `communications.message.read`, `communications.message.events.read`, `sync.result.write`, `communications.result.write`, `communications.reconciliation.read`, `communications.reconciliation.execute` | scope-policy |
| control plane `/api/v1/events`, `/api/v1/health` | none (`application_auth_only`: audience + tenant claim) | scope-policy |
| `/v1/admin/system` | `platform.admin` (ADMIN_INTERNAL) | scope-policy |
| callbacks | `callbacks.write`, `callbacks.read` | callback guard |
| campaign automation | `n8n.policy.check`, `n8n.results.submit`, `n8n.results.read`, `odoo.campaigns.read`; forbidden for every consumer: `odoo.campaign.control.write` | campaign guard |
| intake | `leads.write`, `surveys.write` | openid-connect `scopes_required` + intake guard |
| n8n control plane | `middleware.request.forward`, `middleware.status.read` | n8n guard |
| telephony (private host) | `telephony:command`, `telephony:status`, `realtime:session:create` | calling-policy |
| provider control (prepared) | `ai.inference.request`, `communication.email.request`, `communication.sms.request`, `marketing.campaign.request`, `odoo.events.publish`, `social.publish.request` | guard (prepared) |
| standby | `sms.send`, `email.send`, `webhooks.sms.ingest`, `webhooks.email.ingest` | standby auth middleware |
| MoneyBee bootstrap | none (claims: `azp`, `email_verified`) | moneybee-identity-policy |
| design integration example | `moneybee.account.bootstrap` | codestra-authz |

Unknown paths under a guarded family are denied (`403 route_scope_undefined`)
before any identity header is minted. A scope is a literal string: wildcards
(`*`, `prefix.*`) are rejected by the validator, and `fullScopeAllowed`/
`wildcardScopesAllowed` are `false` in the provider-control contract.

## What Kong does not do with scopes

- It does not map scopes to business roles beyond the fixed
  `platform_admin`/`tenant_admin` role header the control plane mints for
  Middleware's convenience (Middleware re-derives authority from the token).
- It does not evaluate resource ownership, campaign membership beyond the
  contracted claim checks, quotas or workflow state.
- It does not grant access because a scope *sounds* sufficient; only the
  route's declared scope counts.

## Change rule

A new route declares its scope in its contract and in the access policy in the
same change; the validator rejects a drift between the two, an empty scope on
an `ADMIN_INTERNAL` route, and any wildcard.
