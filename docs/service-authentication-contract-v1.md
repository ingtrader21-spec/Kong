# Service Authentication Contract V1

Machine-readable: `config/kong-authentication-profiles.v1.json`
(`SERVICE_OIDC_V1`, `SERVICE_JWT_V1`, `SERVICE_OIDC_JWT_V1`, `INTERNAL_SERVICE_V1`,
`INTERNAL_STANDBY_V1`) and `config/kong-access-policy.v1.json`
(`authorizedParties`, `principalClasses`).

## Principle

Every service has its own Keycloak client (`azp`) and its own Kong consumer;
there is no shared universal service credential, no shared key on any
canonical route, and no consumer can present a token for another service's
audience. A service token qualifies only for the route families whose
authorized parties list its `azp` (or, for `consumer-mapped` profiles, whose
consumer the `azp` resolves to) and whose audience the token carries.

## Service identities

| Principal | `azp` / consumer | Grant | Audience | Routes | Profile |
| --- | --- | --- | --- | --- | --- |
| Odoo integration (callbacks) | `codestra-odoo-callback-service` | client_credentials, realm role `service`, tenant `COD`, campaign `TEST_SYN` | `codestra-callback-api` | `/api/v1/callbacks`, `/api/v1/control/callbacks` | `SERVICE_JWT_V1` |
| n8n campaign CRM | `codestra-n8n-campaign-crm-production` | client_credentials + `environment` claim | `codestra-middleware` | policy-check, n8n results submit/read | `SERVICE_JWT_V1` |
| Odoo campaign reader | `codestra-odoo-campaign-reader-production` | client_credentials + `environment` claim | `codestra-middleware` | Odoo campaign reads | `SERVICE_JWT_V1` |
| n8n automation (control plane) | `n8n-automation` / consumer `codestra-n8n-automation` | client_credentials, lifetime ≤ 300 s, `X-Tenant-ID` ∈ token tenants | `middleware-api` | `/v1/integrations/n8n/commands`, `/operations` | `SERVICE_JWT_V1` |
| SDK intake | `sdk-intake` | client_credentials; audience = client id by contract | `sdk-intake` | `/v1/intake/*` | `SERVICE_OIDC_JWT_V1` |
| Communication control-plane clients | consumer-mapped by `azp` | client_credentials with the control-plane scopes and `tenant` claim | `codestra-control-plane` | `/api/v1/control/*`, events, results, reconciliation, messages, health | `SERVICE_OIDC_V1` |
| Telephony workloads (private VLAN) | consumer-mapped by `azp`; `tenant_id`, `campaign_ids`, `sub` claims | client_credentials | `middleware-api` | `/v1/telephony/*`, `/api/v1/realtime/sessions` | `INTERNAL_SERVICE_V1` |
| Provider-control clients (prepared, disabled) | `codestra-ai`, `codestra-communication`, `codestra-marketing`, `odoo-integration`, `codestra-social` | client_credentials, lifetime ≤ 300 s, required claims incl. `jti` | `middleware-api` | `/api/v1/control/{ai,communications,marketing,social}/…`, `/api/v1/odoo/events` | `SERVICE_JWT_V1` |
| Standby rehearsal workloads | validated by the standby auth middleware | RS256 bearer, audience `codestra-api`, per-service scope | `codestra-api` | standby routes (IP-restricted) | `INTERNAL_STANDBY_V1` |
| Staging certification identities | `test-syn-n8n-submit`, `test-syn-n8n-read`, `test-syn-odoo-reader`, `test-syn-wrong-tenant`, `test-syn-wrong-audience` | staging realm only | `codestra-middleware` | staging campaign overlay | `SERVICE_JWT_V1` |
| Middleware worker | not a Kong caller: Middleware reaches Odoo/n8n/providers outbound; Kong never authenticates Middleware | — | — | — | — |

## Human vs service vs workload vs admin

| Principal class | Profiles | May reach | May not reach |
| --- | --- | --- | --- |
| HUMAN | `HUMAN_OIDC_V1`, `HUMAN_SESSION_OIDC_V1` | `AUTHENTICATED` routes (MoneyBee bootstrap, n8n editor UI) | `SERVICE_AUTHENTICATED`, `INTERNAL`, `ADMIN_INTERNAL` |
| SERVICE | `SERVICE_*` | `SERVICE_AUTHENTICATED` routes whose parties/audience match | `ADMIN_INTERNAL` (no service profile serves it) |
| WORKLOAD | `INTERNAL_SERVICE_V1`, `INTERNAL_STANDBY_V1` | `INTERNAL` routes (private VLAN, IP-restricted) | public/browser routes |
| ADMIN | `ADMIN_INTERNAL_V1` | `/v1/admin/system` with `platform.admin` | — ; parties must be declared before activation (`ADMIN_PARTIES_UNDECLARED`) |

The validator refuses a HUMAN principal on service/internal classes, a
SERVICE profile on `ADMIN_INTERNAL`, and an admin route without `platform.admin`.

## How a service authenticates through Kong

1. Obtain a client-credentials token from the environment's realm (never a
   password or browser flow; `auth_methods: [bearer]` only).
2. Send `Authorization: Bearer <token>` plus the contracted headers
   (`X-Correlation-ID`, `X-Tenant-ID` where required, `Idempotency-Key` on
   command routes).
3. Kong verifies signature (`openid-connect` discovery or `jwt` RS256
   credential), then the guard checks issuer, audience, `azp`/environment,
   scope, lifetime and tenant; failures are 401/403 with constant bodies.
4. Kong forwards to the declared Middleware alias; Middleware re-validates the
   token and authorizes the command.

## Credentials and rotation

No client secret, key or token is in Git. `jwt` consumer credentials are
provisioned from the realm JWKS by the reconcilers under change authority and
must be re-provisioned after a realm key rotation. Client secrets live in
Keycloak and the calling service; Kong never sees them.
