# Kong Route Registry V1

Part of the [Kong API Gateway Control Plane V1](KONG_GATEWAY_CONTROL_PLANE_V1.md).
Machine-readable authority: `config/kong-gateway-foundation.v1.json` (`routes[]`,
`precedence`, `knownDrift`). Validator: `python3 scripts/validate_kong_foundation.py`.

## Canonical gateway pipeline

```text
Request from Caddy (trusted source, X-Forwarded-* honoured only from KONG_TRUSTED_IPS)
  → gateway listener 0.0.0.0:8000 (published 127.0.0.1:8000 for host Caddy only)
  → host match      (explicit host; no wildcard; api.codestra.co canonical, api.codestra.agency legacy)
  → path match      (explicit prefix or anchored regex; no catch-all)
  → method match    (explicit list; no all-methods routes outside the n8n editor proposal)
  → route identity  (one registered routeId, bound to its reviewed source)
  → gateway security prerequisites (authentication class + mechanism, audience, scope/tenant claim guard)
  → rate and request controls (rate-limit profile, request-size profile, correlation)
  → approved service → approved upstream (declared Middleware alias or reasoned direct application)
  → Middleware / governed backend decides the business authorization
```

No business authorization happens in Kong. A request that matches no route is
answered by Kong's `404 no Route matched`; a matched route whose prerequisites
fail is answered 401/403/413/429 by the plugin that failed; an unreachable
upstream is answered 502/503/504. There is no fallback route on any host.

## What every route must declare

Route entries bind to the reviewed source(s) that declare them (`bindings[]`;
`DESIRED` for contracts/declarative candidates, `OBSERVED` for the production
readback) and the validator materializes hosts, paths, methods, protocols,
strip/preserve flags, upstream and plugin set from those sources. Each entry
adds the gateway policy the source cannot express uniformly:

| Field | Meaning |
| --- | --- |
| `routeId`, `serviceId`, `environment` | identity; the environment must equal the bound sources' environment |
| `trafficClass` | see the [service registry](service-registry-v1.md) |
| `authentication` | required class: `PUBLIC`, `AUTHENTICATED`, `SERVICE_AUTHENTICATED`, `ADMIN_INTERNAL`, `INTERNAL` |
| `mechanism` | observed mechanism: `OIDC_BEARER`, `OIDC_BEARER_CLAIM_GUARD`, `JWT_RS256_CLAIM_GUARD`, `OIDC_AND_JWT_CLAIM_GUARD`, `SESSION_OIDC`, `KEY_AUTH_SHARED`, `IP_RESTRICTION`, `HMAC_WEBHOOK`, `MTLS_OIDC`, `NONE` |
| `audience`, `requiredScopes`, `scopeAuthority` | token prerequisites ([token validation boundary](token-validation-boundary-v1.md)) |
| `rateLimitProfile`, `requestSizeProfile` | profiles in `profiles.rateLimit` / `profiles.requestSize`; cross-checked against the source value when the source declares one |
| `lifecycle`, `activation`, `disposition` | `CANONICAL`/`TRANSITIONAL`/`LEGACY`/`STANDBY`/`RETIRE_CANDIDATE`/`PREPARED_DISABLED`/`PROPOSED`/`DESIGN_ONLY`; `RUNTIME_OBSERVED`/`SOURCE_CANDIDATE`/`BLOCKED`/`PREPARED_DISABLED`/`PROPOSED`/`DESIGN_ONLY`; `KEEP`/`REFACTOR`/`MOVE`/`DEPRECATE`/`DELETE` |
| `acceptedFindings` | exactly the debt findings detected on the effective route |
| `publicReason` / `blockedReason` / `retirement` / `supersededBy` / `authenticationGap` | required by the classification rules below |

Classification rules the validator enforces:

- a route with no authentication plugin (`NO_GATEWAY_AUTHENTICATION`) is either
  `PUBLIC` with a `publicReason`, or `BLOCKED`, or a non-activatable design with
  an `authenticationGap`; it can never be a live authenticated route;
- a `PUBLIC` route with a mutation method must be `LEGACY`/`RETIRE_CANDIDATE`
  or `BLOCKED` (the five website forms and the website API are the legacy cases);
- `KEY_AUTH_SHARED` is only valid on `LEGACY`/`RETIRE_CANDIDATE` routes;
- token mechanisms require an `audience`; `ADMIN_INTERNAL` requires scopes;
- a path with an administrative segment (`ADMIN_PATH`) requires
  `ADMIN_INTERNAL` or `BLOCKED`;
- `CANONICAL` routes may carry none of `debtRules.forbiddenOnCanonical`
  (wildcards, missing methods, catch-alls, no authentication, shared keys,
  unbounded bodies, no rate limit, legacy host/upstream, provider/IP upstream,
  implicit or default transport, unresolved upstream, unspecified plugin set);
- a route on an RFC 2606 `.invalid` placeholder host cannot be `RUNTIME_OBSERVED`;
- a route reaching a provider or IP-literal upstream must be `BLOCKED`.

## API versioning

Known namespaces on `api.codestra.co` and their owners:

| Namespace | Owner service(s) | Treatment |
| --- | --- | --- |
| `/api/v1/control`, `/api/v1/events`, `/api/v1/results`, `/api/v1/reconciliation`, `/api/v1/messages`, `/api/v1/health` | `codestra-control-plane` (successor of the key-auth communication routes) | explicit routes |
| `/api/v1/callbacks`, `/api/v1/control/callbacks` | `codestra-callback-api` | explicit routes |
| `/api/v1/automation/policy-check`, `/api/v1/integrations/n8n/results[/{event_id}]`, `/api/v1/integrations/odoo/campaigns/{id}[/desired-state]` | `codestra-campaign-automation-api` | explicit + anchored regex |
| `/v1/intake/*` | `codestra-middleware-intake` | explicit routes |
| `/v1/integrations/n8n/commands`, `/v1/integrations/n8n/operations` | `codestra-middleware-n8n-control-plane` | explicit routes |
| `/v1/admin/system` | `codestra-control-plane` (`ADMIN_INTERNAL`) | explicit route |
| `/v1/crm`, `/v1/email`, `/v1/sms`, `/v1/sms/dlr/telnexa`, `/v1/webhooks` | legacy shared-key services | `LEGACY`, retirement blocked pending consumer migration |
| `/v1/identity-token-certification` | `codestra-token-validator` | `PUBLIC_PROBE`, transitional |
| `/api/v1/mail`, `/api/v1/admin/mail` | `codestra-mail-control-plane` | `BLOCKED` |
| `/healthz`, `/readyz`, `/version` | edge-owned (Caddy → websocket gateway), no Kong route | excluded from Kong by the canary contract |
| `/platform/v1/*` | not on this branch; `main` (PR #104) adds `config/kong-platform-api-read-routes.v1.json` (20 read-side routes, `codestra-platform-api` → `…-1:8095`, audience `middleware-api`) | must be registered on rebase — the calling-contract loader reads its shape unchanged and `sourceDiscovery` refuses the unregistered file |
| `/v2/*`, `/v2/automation/*` | none | do not exist; a request gets Kong's controlled 404, never a legacy service |

An unknown version is not routed anywhere: there is no route whose path is
`/api`, `/api/v1`, `/v1` or `/` on `api.codestra.co`, and the validator flags
such a prefix as `CATCH_ALL_PREFIX`. The single catch-all in the reviewed
sources (`breero-production-api-route`, `/api/v1` with every method on
`api.breero.com`) is `BLOCKED`.

## Precedence

Kong Gateway 3.x (`traditional_compatible` router) orders candidate routes by:

1. number of matched criteria (a route with host + path + method beats one with
   only a path, so a hostless or methodless fragment never wins over an explicit route);
2. plain hosts before wildcard hosts;
3. regex paths before prefix paths, by `regex_priority`;
4. longer prefix paths before shorter ones;
5. equal priority with an overlapping match is **ambiguous** (Kong picks by
   entity order) and is never allowed between two routes deployed together.

`scripts/validate_kong_foundation.py` computes every overlapping pair inside an
environment and requires it to be declared in `precedence.knownConflicts` with
the winner the router would pick. The mission's four cases are unit-tested in
`tests/test_kong_foundation.py` (specific host > generic host, specific path >
broad path, specific method > methodless, regex/current version > legacy
prefix). Today's declared overlaps:

<!-- BEGIN GENERATED: conflicts -->
| Route A | Route B | Router winner | Resolution | Note |
| --- | --- | --- | --- | --- |
| `codestra-callback-control` | `control-plane-control` | `codestra-callback-control` | DETERMINISTIC_SPECIFICITY | /api/v1/control/callbacks is longer than /api/v1/control; the callback route keeps its own audience and guard. |
| `codestra-communication-canonical-write` | `control-plane-control` | `codestra-communication-canonical-write` | LEGACY_SHADOWS_SUCCESSOR_UNTIL_RETIRED | The key-auth /api/v1/control/messages route is longer and shadows the OIDC control-plane successor for messages until it is retired. |
| `codestra-communication-canonical-write` | `control-plane-results` | `codestra-communication-canonical-write` | LEGACY_SHADOWS_SUCCESSOR_UNTIL_RETIRED | /api/v1/results/messages shadows /api/v1/results for message results until retired. |
| `codestra-communication-canonical-read` | `communication-message-read` | `AMBIGUOUS` | SUCCESSOR_REPLACES_LEGACY_ON_APPLY | Identical host, path and method; applying deploy/kong/control-plane.yml must retire the key-auth route in the same change. |
| `sms-dlr-telnexa-route` | `sms-route` | `sms-dlr-telnexa-route` | DETERMINISTIC_SPECIFICITY | Longer prefix wins on both hosts. |
<!-- END GENERATED: conflicts -->

The three conflicts involving `codestra-communication-canonical-*` are the
migration from the key-auth communication routes to the OIDC control-plane
candidate: as long as the legacy routes exist they shadow (longer path) or tie
(identical match) the successor, so `deploy/kong/control-plane.yml` must be
applied in the same change that retires them. Nothing works "because it
appears first in YAML".

## Method posture

Every route lists its methods explicitly; the validator rejects a missing
method list on anything but the design-only marketing fragment (accepted
finding `METHODS_UNSPECIFIED`, not activatable). `OPTIONS` appears only on
routes that carry `cors`. The n8n editor proposal is the only route with all
methods, by design of a browser UI proxy, and it is `PROPOSED` with
`enabled: false`.

## Declared runtime drift

The production readback (`docs/evidence/PRODUCTION_ROUTE_READBACK_20260906.json`,
27-route successor in `config/kong-production-route-inventory.v2.json`) is bound
as `OBSERVED`. Every field on which it differs from the desired contracts must
be declared here; an undeclared or stale difference fails validation.

<!-- BEGIN GENERATED: drift -->
| Kind | Subject | Field | Observed (readback 2026-09-06) | Desired (contract) | Severity | Resolution |
| --- | --- | --- | --- | --- | --- | --- |
| service | `codestra-campaign-automation-api` | `connect_timeout` | `60000` | `3000` | MEDIUM | apply the campaign reconciler under change authority; dry-run reports the field |
| service | `codestra-campaign-automation-api` | `read_timeout` | `60000` | `30000` | MEDIUM | apply the campaign reconciler under change authority |
| service | `codestra-campaign-automation-api` | `write_timeout` | `60000` | `30000` | MEDIUM | apply the campaign reconciler under change authority |
| route | `codestra-callback-control` | `protocols` | `["https"]` | `["http"]` | LOW | the callback reconciler verifies protocols == [http]; https-only matching also works behind trusted_ips but the desired state is http + 426 policy |
| route | `codestra-callback-control` | `plugins` | `["correlation-id", "jwt", "pre-function", "rate-limiting", "request-size-limiting"]` | `["correlation-id", "jwt", "post-function", "rate-limiting", "request-size-limiting"]` | HIGH | the live claim guard runs as pre-function (before jwt); the reconciler moves it to post-function; jwt still gates the signature so this is an ordering drift, not a bypass |
| route | `codestra-callback-read` | `protocols` | `["https"]` | `["http"]` | LOW | as codestra-callback-control |
| route | `codestra-callback-read` | `plugins` | `["correlation-id", "jwt", "pre-function", "rate-limiting", "request-size-limiting"]` | `["correlation-id", "jwt", "post-function", "rate-limiting", "request-size-limiting"]` | HIGH | as codestra-callback-control |
| route | `codestra-campaign-policy-check` | `protocols` | `["https"]` | `["http"]` | LOW | campaign reconciler applies protocols [http] |
| route | `codestra-campaign-result-submit` | `protocols` | `["https"]` | `["http"]` | LOW | campaign reconciler applies protocols [http] |
| route | `codestra-sms-standby-route` | `protocols` | `["https"]` | `["http", "https"]` | LOW | scripts/apply_kong_standby.py upserts protocols [http, https]; the private standby node currently matches https only; re-apply under the standby acceptance runbook |
| route | `codestra-email-standby-route` | `protocols` | `["https"]` | `["http", "https"]` | LOW | scripts/apply_kong_standby.py upserts protocols [http, https]; the private standby node currently matches https only; re-apply under the standby acceptance runbook |
| route | `codestra-sms-webhook-standby-route` | `protocols` | `["https"]` | `["http", "https"]` | LOW | scripts/apply_kong_standby.py upserts protocols [http, https]; the private standby node currently matches https only; re-apply under the standby acceptance runbook |
| route | `codestra-email-webhook-standby-route` | `protocols` | `["https"]` | `["http", "https"]` | LOW | scripts/apply_kong_standby.py upserts protocols [http, https]; the private standby node currently matches https only; re-apply under the standby acceptance runbook |
<!-- END GENERATED: drift -->

## Registry

Generated by `scripts/validate_kong_foundation.py --write-docs`; CI fails if stale.

<!-- BEGIN GENERATED: routes -->
| Route | Service | Env | Hosts | Paths | Methods | Strip | Preserve | Auth | Mechanism | Audience | Scopes | Rate | Size | Class | Lifecycle | Activation | Disposition | Findings |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `automation-private` | `codestra-design-cell-upstreams` | production | `middleware.internal.invalid` | `/internal/v1/automation` | `GET`, `POST` | *unspecified* | *unspecified* | SERVICE_AUTHENTICATED | OIDC_BEARER | `middleware-api` | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLACEHOLDER_HOST, PLUGIN_SET_UNSPECIFIED |
| `beyvra-automation-private` | `codestra-design-cell-upstreams` | production | `middleware-beyvra.internal.invalid` | `/v1/beyvra/automation` | `GET`, `POST` | *unspecified* | *unspecified* | SERVICE_AUTHENTICATED | OIDC_BEARER | `middleware-api` | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLACEHOLDER_HOST, PLUGIN_SET_UNSPECIFIED |
| `beyvra-public` | `codestra-design-cell-upstreams` | production | `api.beyvra.com` | `/v1` | `GET`, `POST`, `PATCH`, `DELETE` | *unspecified* | *unspecified* | AUTHENTICATED | OIDC_BEARER | `middleware-api` | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | KEEP | CATCH_ALL_PREFIX, PLUGIN_SET_UNSPECIFIED |
| `breero-production-api-route` | `breero-production-api` | production | `api.breero.com` | `/health`, `/api/v1` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS` | false | false | AUTHENTICATED | NONE | *unspecified* | *unspecified* | UNRECORDED_READBACK | UNRECORDED_READBACK | TENANT_PRODUCT_API | TRANSITIONAL | BLOCKED | REFACTOR | ALL_METHODS, CATCH_ALL_PREFIX, NO_GATEWAY_AUTHENTICATION |
| `codestra-ai-inference-request` | `provider-control-middleware` | production | *unspecified* | `/api/v1/control/ai/inference-requests` | `POST` | *unspecified* | *unspecified* | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `middleware-api` | `ai.inference.request` | UNSPECIFIED_CONTRACT | UNSPECIFIED_CONTRACT | COMMAND_API | PREPARED_DISABLED | PREPARED_DISABLED | KEEP | HOST_UNSPECIFIED, PLUGIN_SET_UNSPECIFIED |
| `codestra-callback-control` | `codestra-callback-api` | production | `api.codestra.co` | `/api/v1/control/callbacks` | `POST` | false | true | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `codestra-callback-api` | `callbacks.write` | SERVICE_COMMAND_60 | STANDARD_API_1MB | COMMAND_API | CANONICAL | RUNTIME_OBSERVED | KEEP | — |
| `codestra-callback-read` | `codestra-callback-api` | production | `api.codestra.co` | `/api/v1/callbacks` | `GET` | false | true | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `codestra-callback-api` | `callbacks.read` | SERVICE_STANDARD_120 | STANDARD_API_1MB | READ_API | CANONICAL | RUNTIME_OBSERVED | KEEP | — |
| `codestra-calling-command-submit` | `codestra-calling-api` | production | `telephony.internal.invalid` | `/v1/telephony/commands` | `POST` | false | true | INTERNAL | OIDC_BEARER_CLAIM_GUARD | `middleware-api` | `telephony:command` | SERVICE_COMMAND_60 | STANDARD_API_1MB | COMMAND_API | CANONICAL | SOURCE_CANDIDATE | KEEP | PLACEHOLDER_HOST |
| `codestra-calling-operation-cancel` | `codestra-calling-api` | production | `telephony.internal.invalid` | `~^/v1/telephony/operations/[0-9a-fA-F-]{36}/cancel$` | `POST` | false | true | INTERNAL | OIDC_BEARER_CLAIM_GUARD | `middleware-api` | `telephony:command` | SERVICE_COMMAND_60 | STANDARD_API_1MB | COMMAND_API | CANONICAL | SOURCE_CANDIDATE | KEEP | PLACEHOLDER_HOST |
| `codestra-calling-operation-read` | `codestra-calling-api` | production | `telephony.internal.invalid` | `~^/v1/telephony/operations/[0-9a-fA-F-]{36}$` | `GET` | false | true | INTERNAL | OIDC_BEARER_CLAIM_GUARD | `middleware-api` | `telephony:status` | AUTHENTICATED_READ_240 | STANDARD_API_1MB | READ_API | CANONICAL | SOURCE_CANDIDATE | KEEP | PLACEHOLDER_HOST |
| `codestra-calling-operation-reconcile` | `codestra-calling-api` | production | `telephony.internal.invalid` | `~^/v1/telephony/operations/[0-9a-fA-F-]{36}/reconcile$` | `POST` | false | true | INTERNAL | OIDC_BEARER_CLAIM_GUARD | `middleware-api` | `telephony:status` | SERVICE_RECONCILE_30 | STANDARD_API_1MB | COMMAND_API | CANONICAL | SOURCE_CANDIDATE | KEEP | PLACEHOLDER_HOST |
| `codestra-campaign-policy-check` | `codestra-campaign-automation-api` | production | `api.codestra.co` | `/api/v1/automation/policy-check` | `POST` | false | false | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `codestra-middleware` | `n8n.policy.check` | SERVICE_STANDARD_120 | STANDARD_API_1MB | COMMAND_API | CANONICAL | RUNTIME_OBSERVED | KEEP | — |
| `codestra-campaign-result-read` | `codestra-campaign-automation-api` | production | `api.codestra.co` | `~/api/v1/integrations/n8n/results/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | `GET` | false | false | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `codestra-middleware` | `n8n.results.read` | SERVICE_STANDARD_120 | STANDARD_API_1MB | READ_API | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `codestra-campaign-result-submit` | `codestra-campaign-automation-api` | production | `api.codestra.co` | `/api/v1/integrations/n8n/results` | `POST` | false | false | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `codestra-middleware` | `n8n.results.submit` | SERVICE_STANDARD_120 | STANDARD_API_1MB | COMMAND_API | CANONICAL | RUNTIME_OBSERVED | KEEP | — |
| `codestra-communication-canonical-read` | `codestra-communication-control-plane` | production | `api.codestra.co` | `/api/v1/messages` | `GET` | false | true | AUTHENTICATED | KEY_AUTH_SHARED | *unspecified* | *unspecified* | UNRECORDED_READBACK | NONE_READ_ONLY | READ_API | LEGACY | RUNTIME_OBSERVED | DEPRECATE | LEGACY_SHARED_KEY |
| `codestra-communication-canonical-write` | `codestra-communication-control-plane` | production | `api.codestra.co` | `/api/v1/control/messages`, `/api/v1/results/messages` | `POST` | false | true | AUTHENTICATED | KEY_AUTH_SHARED | *unspecified* | *unspecified* | UNRECORDED_READBACK | UNRECORDED_READBACK | COMMAND_API | LEGACY | RUNTIME_OBSERVED | DEPRECATE | LEGACY_SHARED_KEY |
| `codestra-communication-email-request` | `provider-control-middleware` | production | *unspecified* | `/api/v1/control/communications/email` | `POST` | *unspecified* | *unspecified* | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `middleware-api` | `communication.email.request` | UNSPECIFIED_CONTRACT | UNSPECIFIED_CONTRACT | COMMAND_API | PREPARED_DISABLED | PREPARED_DISABLED | KEEP | HOST_UNSPECIFIED, PLUGIN_SET_UNSPECIFIED |
| `codestra-communication-sms-request` | `provider-control-middleware` | production | *unspecified* | `/api/v1/control/communications/sms` | `POST` | *unspecified* | *unspecified* | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `middleware-api` | `communication.sms.request` | UNSPECIFIED_CONTRACT | UNSPECIFIED_CONTRACT | COMMAND_API | PREPARED_DISABLED | PREPARED_DISABLED | KEEP | HOST_UNSPECIFIED, PLUGIN_SET_UNSPECIFIED |
| `codestra-community-n8n-middleware-route` | `codestra-community-n8n-middleware` | production | `api.codestra.co` | `/v1/integrations/n8n` | `GET`, `POST` | false | *unspecified* | SERVICE_AUTHENTICATED | NONE | `middleware-api` | *unspecified* | UNSPECIFIED_CONTRACT | UNSPECIFIED_CONTRACT | COMMAND_API | PROPOSED | PROPOSED | REFACTOR | NO_GATEWAY_AUTHENTICATION, UPSTREAM_HOST_UNRESOLVED |
| `codestra-email-standby-route` | `codestra-email-standby` | production | `kong-standby.internal.codestra.agency` | `/v1/email` | `POST` | false | false | INTERNAL | IP_RESTRICTION | `codestra-api` | `email.send` | STANDBY_EMAIL_5 | STANDBY_128KB | STANDBY_REHEARSAL | STANDBY | RUNTIME_OBSERVED | KEEP | — |
| `codestra-email-webhook-standby-route` | `codestra-email-webhook-standby` | production | `kong-standby.internal.codestra.agency` | `/v1/webhooks/email` | `POST` | false | false | INTERNAL | IP_RESTRICTION | `codestra-api` | `webhooks.email.ingest` | STANDBY_WEBHOOK_60 | STANDBY_128KB | STANDBY_REHEARSAL | STANDBY | RUNTIME_OBSERVED | KEEP | — |
| `codestra-intake-leads` | `codestra-middleware-intake` | production | `api.codestra.co` | `/v1/intake/leads` | `POST` | false | true | SERVICE_AUTHENTICATED | OIDC_AND_JWT_CLAIM_GUARD | `sdk-intake` | `leads.write` | SERVICE_STANDARD_120 | STANDARD_API_1MB | COMMAND_API | CANONICAL | SOURCE_CANDIDATE | KEEP | AUDIENCE_IS_CLIENT_ID |
| `codestra-intake-survey-responses` | `codestra-middleware-intake` | production | `api.codestra.co` | `/v1/intake/surveys/responses` | `POST` | false | true | SERVICE_AUTHENTICATED | OIDC_AND_JWT_CLAIM_GUARD | `sdk-intake` | `surveys.write` | SERVICE_STANDARD_120 | STANDARD_API_1MB | COMMAND_API | CANONICAL | SOURCE_CANDIDATE | KEEP | AUDIENCE_IS_CLIENT_ID |
| `codestra-mail-api` | `codestra-mail-control-plane` | production | `api.codestra.co` | `/api/v1/mail`, `/api/v1/admin/mail` | `GET`, `POST` | false | true | ADMIN_INTERNAL | NONE | *unspecified* | *unspecified* | NONE | UNBOUNDED | COMMAND_API | TRANSITIONAL | BLOCKED | REFACTOR | ADMIN_PATH, DIRECT_APPLICATION_UPSTREAM, NO_GATEWAY_AUTHENTICATION, NO_RATE_LIMIT, UNBOUNDED_REQUEST_BODY |
| `codestra-marketing-campaign-request` | `provider-control-middleware` | production | *unspecified* | `/api/v1/control/marketing/campaigns` | `POST` | *unspecified* | *unspecified* | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `middleware-api` | `marketing.campaign.request` | UNSPECIFIED_CONTRACT | UNSPECIFIED_CONTRACT | COMMAND_API | PREPARED_DISABLED | PREPARED_DISABLED | KEEP | HOST_UNSPECIFIED, PLUGIN_SET_UNSPECIFIED |
| `codestra-n8n-command-read` | `codestra-middleware-n8n-control-plane` | production | `api.codestra.co` | `/v1/integrations/n8n/operations` | `GET` | false | false | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `middleware-api` | `middleware.status.read` | AUTHENTICATED_READ_240 | STANDARD_API_1MB | READ_API | CANONICAL | RUNTIME_OBSERVED | KEEP | — |
| `codestra-n8n-command-submit` | `codestra-middleware-n8n-control-plane` | production | `api.codestra.co` | `/v1/integrations/n8n/commands` | `POST` | false | false | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `middleware-api` | `middleware.request.forward` | SERVICE_STANDARD_120 | STANDARD_API_1MB | COMMAND_API | CANONICAL | RUNTIME_OBSERVED | KEEP | — |
| `codestra-n8n-editor-ui` | `codestra-n8n-editor` | production | `automation.codestra.co` | `/` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS` | false | true | AUTHENTICATED | SESSION_OIDC | *unspecified* | *unspecified* | EDITOR_SESSION_600 | EDITOR_4MB | EDITOR_UI | PROPOSED | PROPOSED | KEEP | ALL_METHODS, CATCH_ALL_PATH, DIRECT_APPLICATION_UPSTREAM, PLUGIN_SET_UNSPECIFIED |
| `codestra-odoo-campaign-desired-state-read` | `codestra-campaign-automation-api` | production | `api.codestra.co` | `~/api/v1/integrations/odoo/campaigns/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/desired-state$` | `GET` | false | false | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `codestra-middleware` | `odoo.campaigns.read` | SERVICE_STANDARD_120 | STANDARD_API_1MB | READ_API | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `codestra-odoo-campaign-read` | `codestra-campaign-automation-api` | production | `api.codestra.co` | `~/api/v1/integrations/odoo/campaigns/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | `GET` | false | false | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `codestra-middleware` | `odoo.campaigns.read` | SERVICE_STANDARD_120 | STANDARD_API_1MB | READ_API | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `codestra-odoo-event-publish` | `provider-control-middleware` | production | *unspecified* | `/api/v1/odoo/events` | `POST` | *unspecified* | *unspecified* | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `middleware-api` | `odoo.events.publish` | UNSPECIFIED_CONTRACT | UNSPECIFIED_CONTRACT | COMMAND_API | PREPARED_DISABLED | PREPARED_DISABLED | KEEP | HOST_UNSPECIFIED, PLUGIN_SET_UNSPECIFIED |
| `codestra-realtime-session-create` | `codestra-calling-api` | production | `telephony.internal.invalid` | `/api/v1/realtime/sessions` | `POST` | false | true | INTERNAL | OIDC_BEARER_CLAIM_GUARD | `middleware-api` | `realtime:session:create` | SERVICE_RECONCILE_30 | STANDARD_API_1MB | COMMAND_API | CANONICAL | SOURCE_CANDIDATE | KEEP | PLACEHOLDER_HOST |
| `codestra-sms-standby-route` | `codestra-sms-standby` | production | `kong-standby.internal.codestra.agency` | `/v1/sms` | `POST` | false | false | INTERNAL | IP_RESTRICTION | `codestra-api` | `sms.send` | STANDBY_SMS_10 | IDENTITY_BOOTSTRAP_64KB | STANDBY_REHEARSAL | STANDBY | RUNTIME_OBSERVED | KEEP | — |
| `codestra-sms-webhook-standby-route` | `codestra-sms-webhook-standby` | production | `kong-standby.internal.codestra.agency` | `/v1/webhooks/sms` | `POST` | false | false | INTERNAL | IP_RESTRICTION | `codestra-api` | `webhooks.sms.ingest` | STANDBY_WEBHOOK_60 | IDENTITY_BOOTSTRAP_64KB | STANDBY_REHEARSAL | STANDBY | RUNTIME_OBSERVED | KEEP | — |
| `codestra-social-publication-request` | `provider-control-middleware` | production | *unspecified* | `/api/v1/control/social/publications` | `POST` | *unspecified* | *unspecified* | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `middleware-api` | `social.publish.request` | UNSPECIFIED_CONTRACT | UNSPECIFIED_CONTRACT | COMMAND_API | PREPARED_DISABLED | PREPARED_DISABLED | KEEP | HOST_UNSPECIFIED, PLUGIN_SET_UNSPECIFIED |
| `codestra-token-validation-certification` | `codestra-token-validator` | production | `api.codestra.co`, `api.codestra.agency` | `/v1/identity-token-certification` | `GET`, `OPTIONS` | false | false | PUBLIC | NONE | *unspecified* | *unspecified* | UNRECORDED_READBACK | NONE_READ_ONLY | PUBLIC_PROBE | TRANSITIONAL | RUNTIME_OBSERVED | DEPRECATE | LEGACY_HOST, NO_GATEWAY_AUTHENTICATION |
| `codestra-website-api-route` | `codestra-website-api` | production | `api.codestra.agency` | `/api/v1/demo-requests`, `/api/v1/contact-requests`, `/api/v1/pricing-requests`, `/api/v1/analytics/events`, `/api/v1/localization/country`, `/api/v1/localization/preference` | `GET`, `POST`, `OPTIONS` | false | false | PUBLIC | KEY_AUTH_SHARED | *unspecified* | *unspecified* | NONE | UNBOUNDED | PUBLIC_FORM | LEGACY | RUNTIME_OBSERVED | MOVE | CORS_WITH_SHARED_KEY, LEGACY_HOST, LEGACY_SHARED_KEY, NO_RATE_LIMIT, UNBOUNDED_REQUEST_BODY |
| `communication-message-read` | `codestra-control-plane` | production | `api.codestra.co` | `/api/v1/messages` | `GET` | false | false | SERVICE_AUTHENTICATED | OIDC_BEARER_CLAIM_GUARD | `codestra-control-plane` | `communications.message.read`, `communications.message.events.read` | AUTHENTICATED_STANDARD_120 | NONE_READ_ONLY | READ_API | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `control-plane-control` | `codestra-control-plane` | production | `api.codestra.co` | `/api/v1/control` | `POST`, `PATCH` | false | false | SERVICE_AUTHENTICATED | OIDC_BEARER_CLAIM_GUARD | `codestra-control-plane` | `communications.message.create`, `communications.message.dispatch`, `campaign.write`, `agent.write`, `sync.execute`, `mapping.read`, `mapping.read.minimum` | AUTHENTICATED_STANDARD_120 | STANDARD_API_1MB | COMMAND_API | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `control-plane-events` | `codestra-control-plane` | production | `api.codestra.co` | `/api/v1/events` | `POST` | false | false | SERVICE_AUTHENTICATED | OIDC_BEARER_CLAIM_GUARD | `codestra-control-plane` | *unspecified* | AUTHENTICATED_STANDARD_120 | STANDARD_API_1MB | EVENT_INGEST | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `control-plane-health` | `codestra-control-plane` | production | `api.codestra.co` | `/api/v1/health` | `GET` | false | false | SERVICE_AUTHENTICATED | OIDC_BEARER_CLAIM_GUARD | `codestra-control-plane` | *unspecified* | AUTHENTICATED_STANDARD_120 | NONE_READ_ONLY | HEALTH | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `control-plane-reconciliation` | `codestra-control-plane` | production | `api.codestra.co` | `/api/v1/reconciliation` | `GET`, `POST` | false | false | SERVICE_AUTHENTICATED | OIDC_BEARER_CLAIM_GUARD | `codestra-control-plane` | `communications.reconciliation.read`, `communications.reconciliation.execute` | AUTHENTICATED_STANDARD_120 | STANDARD_API_1MB | COMMAND_API | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `control-plane-results` | `codestra-control-plane` | production | `api.codestra.co` | `/api/v1/results` | `POST` | false | false | SERVICE_AUTHENTICATED | OIDC_BEARER_CLAIM_GUARD | `codestra-control-plane` | `sync.result.write`, `communications.result.write` | AUTHENTICATED_STANDARD_120 | STANDARD_API_1MB | COMMAND_API | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `control-plane-system-admin` | `codestra-control-plane` | production | `api.codestra.co` | `/v1/admin/system` | `GET` | false | false | ADMIN_INTERNAL | OIDC_BEARER_CLAIM_GUARD | `codestra-control-plane` | `platform.admin` | AUTHENTICATED_STANDARD_120 | NONE_READ_ONLY | ADMIN | CANONICAL | SOURCE_CANDIDATE | KEEP | ADMIN_PATH |
| `crawler-api` | `codestra-design-cell-upstreams` | production | `api.codestra.co` | `/v1/crawler` | `GET`, `POST`, `PATCH` | *unspecified* | *unspecified* | AUTHENTICATED | OIDC_BEARER | `middleware-api` | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLUGIN_SET_UNSPECIFIED |
| `crm-api` | `codestra-design-cell-upstreams` | production | `api.codestra.co` | `/v1/crm` | `GET`, `POST`, `PATCH` | *unspecified* | *unspecified* | AUTHENTICATED | OIDC_BEARER | `middleware-api` | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLUGIN_SET_UNSPECIFIED |
| `crm-route` | `codestra-crm-api` | production | `api.codestra.agency`, `api.codestra.co` | `/v1/crm` | `GET`, `POST`, `PATCH`, `OPTIONS` | true | false | AUTHENTICATED | KEY_AUTH_SHARED | *unspecified* | *unspecified* | LEGACY_SHARED_KEY_120 | FORM_2MB | LEGACY_SHARED_KEY | LEGACY | RUNTIME_OBSERVED | DEPRECATE | CORS_WITH_SHARED_KEY, LEGACY_HOST, LEGACY_SHARED_KEY, LEGACY_UPSTREAM |
| `email-api` | `codestra-design-cell-upstreams` | production | `api.codestra.co` | `/v1/email` | `GET`, `POST`, `PATCH`, `DELETE` | *unspecified* | *unspecified* | AUTHENTICATED | OIDC_BEARER | `middleware-api` | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLUGIN_SET_UNSPECIFIED |
| `email-route` | `codestra-email-api` | production | `api.codestra.agency`, `api.codestra.co` | `/v1/email` | `GET`, `POST` | true | false | AUTHENTICATED | KEY_AUTH_SHARED | *unspecified* | *unspecified* | LEGACY_SHARED_KEY_60 | UPLOAD_10MB | LEGACY_SHARED_KEY | LEGACY | RUNTIME_OBSERVED | DEPRECATE | LEGACY_HOST, LEGACY_SHARED_KEY, LEGACY_UPSTREAM |
| `email-webhook` | `codestra-design-cell-upstreams` | production | `api.codestra.co` | `/v1/webhooks/email` | `POST` | *unspecified* | *unspecified* | SERVICE_AUTHENTICATED | HMAC_WEBHOOK | *unspecified* | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | WEBHOOK_INGEST | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLUGIN_SET_UNSPECIFIED |
| `forms-api` | `codestra-design-cell-upstreams` | production | `api.codestra.co` | `/v1/forms` | `GET`, `POST` | *unspecified* | *unspecified* | AUTHENTICATED | OIDC_BEARER | `middleware-api` | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLUGIN_SET_UNSPECIFIED |
| `gateway-test-route` | `codestra-gateway-test` | production | `api.codestra.agency` | `/v1/test` | `GET` | true | false | AUTHENTICATED | KEY_AUTH_SHARED | *unspecified* | *unspecified* | NONE | NONE_READ_ONLY | TEST | RETIRE_CANDIDATE | BLOCKED | DELETE | LEGACY_HOST, LEGACY_SHARED_KEY, NO_RATE_LIMIT, TEST_UPSTREAM |
| `moneybee-account-bootstrap` | `moneybee-api` | production | `api.moneybeeloan.com` | `/api/v2/account/bootstrap` | `POST` | *unspecified* | *unspecified* | AUTHENTICATED | OIDC_BEARER_CLAIM_GUARD | `moneybee-api` | *unspecified* | IDENTITY_BOOTSTRAP_10 | IDENTITY_BOOTSTRAP_64KB | IDENTITY | CANONICAL | SOURCE_CANDIDATE | KEEP | DIRECT_APPLICATION_UPSTREAM |
| `platform-api` | `codestra-design-cell-upstreams` | production | `api.codestra.co` | `/v1/platform` | `GET`, `POST`, `PATCH` | *unspecified* | *unspecified* | AUTHENTICATED | OIDC_BEARER | `middleware-api` | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLUGIN_SET_UNSPECIFIED |
| `sms-api` | `codestra-design-cell-upstreams` | production | `api.codestra.co` | `/v1/sms` | `GET`, `POST`, `PATCH`, `DELETE` | *unspecified* | *unspecified* | AUTHENTICATED | OIDC_BEARER | `middleware-api` | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLUGIN_SET_UNSPECIFIED |
| `sms-dlr-telnexa-route` | `codestra-sms-dlr` | production | `api.codestra.agency`, `api.codestra.co` | `/v1/sms/dlr/telnexa` | `POST` | true | false | AUTHENTICATED | KEY_AUTH_SHARED | *unspecified* | *unspecified* | LEGACY_SHARED_KEY_240 | STANDARD_API_1MB | WEBHOOK_INGEST | LEGACY | RUNTIME_OBSERVED | DEPRECATE | LEGACY_HOST, LEGACY_SHARED_KEY, LEGACY_UPSTREAM |
| `sms-route` | `codestra-sms-api` | production | `api.codestra.agency`, `api.codestra.co` | `/v1/sms` | `GET`, `POST` | true | false | AUTHENTICATED | KEY_AUTH_SHARED | *unspecified* | *unspecified* | LEGACY_SHARED_KEY_60 | STANDARD_API_1MB | LEGACY_SHARED_KEY | LEGACY | RUNTIME_OBSERVED | DEPRECATE | LEGACY_HOST, LEGACY_SHARED_KEY, LEGACY_UPSTREAM |
| `sms-webhook` | `codestra-design-cell-upstreams` | production | `api.codestra.co` | `/v1/webhooks/sms` | `POST` | *unspecified* | *unspecified* | SERVICE_AUTHENTICATED | HMAC_WEBHOOK | *unspecified* | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | WEBHOOK_INGEST | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLUGIN_SET_UNSPECIFIED |
| `social-api` | `codestra-design-cell-upstreams` | production | `api.codestra.co` | `/v1/social` | `GET`, `POST`, `PATCH`, `DELETE` | *unspecified* | *unspecified* | AUTHENTICATED | OIDC_BEARER | `middleware-api` | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLUGIN_SET_UNSPECIFIED |
| `social-webhook` | `codestra-design-cell-upstreams` | production | `api.codestra.co` | `/v1/webhooks/social` | `POST` | *unspecified* | *unspecified* | SERVICE_AUTHENTICATED | HMAC_WEBHOOK | *unspecified* | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | WEBHOOK_INGEST | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLUGIN_SET_UNSPECIFIED |
| `telephony-private` | `codestra-design-cell-upstreams` | production | `telephony.internal.invalid` | `/v1/telephony` | `GET`, `POST` | *unspecified* | *unspecified* | SERVICE_AUTHENTICATED | OIDC_BEARER | `middleware-api` | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLACEHOLDER_HOST, PLUGIN_SET_UNSPECIFIED |
| `telephony-webhook-private` | `codestra-design-cell-upstreams` | production | `telephony.internal.invalid` | `/v1/webhooks/telephony` | `POST` | *unspecified* | *unspecified* | SERVICE_AUTHENTICATED | HMAC_WEBHOOK | *unspecified* | *unspecified* | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | WEBHOOK_INGEST | DESIGN_ONLY | DESIGN_ONLY | KEEP | PLACEHOLDER_HOST, PLUGIN_SET_UNSPECIFIED |
| `webhooks-route` | `codestra-webhooks` | production | `api.codestra.agency`, `api.codestra.co` | `/v1/webhooks` | `POST` | false | false | AUTHENTICATED | KEY_AUTH_SHARED | *unspecified* | *unspecified* | LEGACY_SHARED_KEY_120 | FORM_2MB | WEBHOOK_INGEST | LEGACY | RUNTIME_OBSERVED | DEPRECATE | LEGACY_HOST, LEGACY_SHARED_KEY |
| `website-form-demo-request` | `codestra-website-forms` | production | `api.codestra.agency` | `/v1/forms/demo-request` | `POST`, `OPTIONS` | false | false | PUBLIC | KEY_AUTH_SHARED | *unspecified* | *unspecified* | UNRECORDED_READBACK | UNBOUNDED | PUBLIC_FORM | LEGACY | RUNTIME_OBSERVED | MOVE | CORS_WITH_SHARED_KEY, LEGACY_HOST, LEGACY_SHARED_KEY, UNBOUNDED_REQUEST_BODY |
| `website-form-electronic-billing` | `codestra-website-forms` | production | `api.codestra.agency` | `/v1/forms/electronic-billing-application` | `POST`, `OPTIONS` | false | false | PUBLIC | KEY_AUTH_SHARED | *unspecified* | *unspecified* | UNRECORDED_READBACK | UNBOUNDED | PUBLIC_FORM | LEGACY | RUNTIME_OBSERVED | MOVE | CORS_WITH_SHARED_KEY, LEGACY_HOST, LEGACY_SHARED_KEY, UNBOUNDED_REQUEST_BODY |
| `website-form-electronic-billing-registration` | `codestra-website-forms` | production | `api.codestra.agency` | `/v1/forms/electronic-billing-registration` | `POST`, `OPTIONS` | false | false | PUBLIC | KEY_AUTH_SHARED | *unspecified* | *unspecified* | UNRECORDED_READBACK | UNBOUNDED | PUBLIC_FORM | LEGACY | RUNTIME_OBSERVED | MOVE | CORS_WITH_SHARED_KEY, LEGACY_HOST, LEGACY_SHARED_KEY, UNBOUNDED_REQUEST_BODY |
| `website-form-pricing-request` | `codestra-website-forms` | production | `api.codestra.agency` | `/v1/forms/pricing-request` | `POST`, `OPTIONS` | false | false | PUBLIC | KEY_AUTH_SHARED | *unspecified* | *unspecified* | UNRECORDED_READBACK | UNBOUNDED | PUBLIC_FORM | LEGACY | RUNTIME_OBSERVED | MOVE | CORS_WITH_SHARED_KEY, LEGACY_HOST, LEGACY_SHARED_KEY, UNBOUNDED_REQUEST_BODY |
| `website-form-sales-contact` | `codestra-website-forms` | production | `api.codestra.agency` | `/v1/forms/sales-contact` | `POST`, `OPTIONS` | false | false | PUBLIC | KEY_AUTH_SHARED | *unspecified* | *unspecified* | UNRECORDED_READBACK | UNBOUNDED | PUBLIC_FORM | LEGACY | RUNTIME_OBSERVED | MOVE | CORS_WITH_SHARED_KEY, LEGACY_HOST, LEGACY_SHARED_KEY, UNBOUNDED_REQUEST_BODY |
| `ai-v1` | `codestra-ai` | staging | *unspecified* | `/v1/ai` | *unspecified* | true | *unspecified* | AUTHENTICATED | NONE | *unspecified* | *unspecified* | NONE | UNBOUNDED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | REFACTOR | DIRECT_APPLICATION_UPSTREAM, HOST_UNSPECIFIED, METHODS_UNSPECIFIED, NO_GATEWAY_AUTHENTICATION, NO_RATE_LIMIT |
| `codestra-campaign-result-read@staging` | `codestra-campaign-automation-api@staging` | staging | `api.codestra.co` | `~/api/v1/integrations/n8n/results/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | `GET` | false | false | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `codestra-middleware` | `n8n.results.read` | SERVICE_STANDARD_120 | STANDARD_API_1MB | READ_API | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `codestra-campaign-result-submit@staging` | `codestra-campaign-automation-api@staging` | staging | `api.codestra.co` | `/api/v1/integrations/n8n/results` | `POST` | false | false | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `codestra-middleware` | `n8n.results.submit` | SERVICE_STANDARD_120 | STANDARD_API_1MB | COMMAND_API | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `codestra-n8n-command-read@staging` | `codestra-middleware-n8n-control-plane@staging` | staging | `api.codestra.co` | `/v1/integrations/n8n/operations` | `GET` | false | false | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `middleware-api` | `middleware.status.read` | AUTHENTICATED_READ_240 | STANDARD_API_1MB | READ_API | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `codestra-n8n-command-submit@staging` | `codestra-middleware-n8n-control-plane@staging` | staging | `api.codestra.co` | `/v1/integrations/n8n/commands` | `POST` | false | false | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `middleware-api` | `middleware.request.forward` | SERVICE_STANDARD_120 | STANDARD_API_1MB | COMMAND_API | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `codestra-odoo-campaign-desired-state-read@staging` | `codestra-campaign-automation-api@staging` | staging | `api.codestra.co` | `~/api/v1/integrations/odoo/campaigns/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/desired-state$` | `GET` | false | false | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `codestra-middleware` | `odoo.campaigns.read` | SERVICE_STANDARD_120 | STANDARD_API_1MB | READ_API | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `codestra-odoo-campaign-read@staging` | `codestra-campaign-automation-api@staging` | staging | `api.codestra.co` | `~/api/v1/integrations/odoo/campaigns/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | `GET` | false | false | SERVICE_AUTHENTICATED | JWT_RS256_CLAIM_GUARD | `codestra-middleware` | `odoo.campaigns.read` | SERVICE_STANDARD_120 | STANDARD_API_1MB | READ_API | CANONICAL | SOURCE_CANDIDATE | KEEP | — |
| `communications-v1` | `codestra-communication` | staging | *unspecified* | `/v1/communications` | *unspecified* | true | *unspecified* | AUTHENTICATED | NONE | *unspecified* | *unspecified* | NONE | UNBOUNDED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | REFACTOR | DIRECT_APPLICATION_UPSTREAM, HOST_UNSPECIFIED, METHODS_UNSPECIFIED, NO_GATEWAY_AUTHENTICATION, NO_RATE_LIMIT |
| `marketing-v1` | `codestra-marketing` | staging | *unspecified* | `/v1/marketing` | *unspecified* | true | *unspecified* | AUTHENTICATED | NONE | *unspecified* | *unspecified* | NONE | FORM_2MB | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | REFACTOR | DIRECT_APPLICATION_UPSTREAM, HOST_UNSPECIFIED, METHODS_UNSPECIFIED, NO_GATEWAY_AUTHENTICATION, NO_RATE_LIMIT |
| `moneybee-account-bootstrap:bootstrap` | `moneybee-bootstrap` | staging | `api.moneybeeloan.com` | `/api/v2/account/bootstrap` | `POST` | *unspecified* | *unspecified* | AUTHENTICATED | OIDC_BEARER_CLAIM_GUARD | `moneybee-api` | `moneybee.account.bootstrap` | IDENTITY_BOOTSTRAP_10 | IDENTITY_BOOTSTRAP_64KB | IDENTITY | DESIGN_ONLY | DESIGN_ONLY | KEEP | — |
| `social-v1` | `codestra-social` | staging | *unspecified* | `/v1/social` | *unspecified* | true | *unspecified* | AUTHENTICATED | NONE | *unspecified* | *unspecified* | NONE | UNBOUNDED | COMMAND_API | DESIGN_ONLY | DESIGN_ONLY | REFACTOR | DIRECT_APPLICATION_UPSTREAM, HOST_UNSPECIFIED, METHODS_UNSPECIFIED, NO_GATEWAY_AUTHENTICATION, NO_RATE_LIMIT |
<!-- END GENERATED: routes -->
