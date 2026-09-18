# Kong Timeout Profiles V1

Part of the [Kong API Gateway Control Plane V1](KONG_GATEWAY_CONTROL_PLANE_V1.md).
Machine-readable: `config/kong-gateway-foundation.v1.json` → `profiles.timeout`.
Every service selects exactly one profile; the validator cross-checks the
profile against the timeouts the bound source declares and rejects a canonical
service that leaves timeouts implicit or on the Kong 60 s defaults.

| Profile | Connect | Read | Write | Use | Services today |
| --- | ---: | ---: | ---: | --- | --- |
| `STANDARD_API` | 3 s | 30 s | 30 s | ordinary request/response APIs | control plane, campaign automation (+staging), intake, calling, MoneyBee bootstrap |
| `FAST_SERVICE_API` | 3 s | 10 s | 10 s | service-to-service APIs with bounded work | callbacks, n8n control plane (+staging), website API (legacy), sms-api (legacy), gateway-platform example |
| `LONG_RUNNING_API` | 3 s | 60 s | 60 s | reviewed long-running operations and browser UIs | n8n editor proposal |
| `HEALTH` | 1 s | 5 s | 5 s | health endpoints | none yet (edge probes are Caddy-owned) |
| `INTERNAL` | 3 s | 30 s | 30 s | private service APIs | none yet |
| `WEBSOCKET` | 3 s | 3600 s | 3600 s | long-lived upgrade transports; request/response buffering off; no retry | none — the calling contract forbids a public Kong WebSocket route (`/ws/agent` is Caddy → websocket gateway) |
| `SSE` | 3 s | 900 s | 900 s | server-sent event streams; response buffering off; no retry | none |
| `STANDBY_FAST` | 3 s | 5 s | 5 s | private standby rehearsal | four standby services |
| `LEGACY_CONNECT_5S` | 5 s | 30 s | 30 s | observed legacy services | breero, mail API |
| `LEGACY_FAST_5S` | 5 s | 5 s | 5 s | observed legacy services | crm-api |
| `KONG_DEFAULT_60S` | 60 s | 60 s | 60 s | Kong defaults observed on legacy services; **forbidden for canonical services** | communication control plane (key-auth), email-api, sms-dlr, webhooks, website forms, gateway-test, token-validator |
| `KONG_DEFAULT_IMPLICIT` | 60 s | 60 s | 60 s | no timeout declared at all; design-only | marketing stage-4 fragment |

`profiles.limits.maxTimeoutMs` caps every profile at one hour.

## Why these values

* **Connect 3 s.** Every governed upstream is a container alias on a private
  network; a connect that takes longer than 3 s is an outage, and surfacing it
  as `502`/`504` quickly is the circuit behaviour the gateway wants. The
  observed 60 s connect timeout on the campaign automation service (Kong
  default) meant a dead Middleware would hold every n8n result submission for
  a minute; the contract now pins 3 s and the readback difference is declared
  drift until the reconciler applies it.
* **Read/write 10 s vs 30 s.** Callback and n8n control-plane operations are
  bounded Middleware work and keep the reviewed 10 s; control-plane commands,
  campaign automation (which may fan out to Odoo/n8n inside Middleware) and
  intake use 30 s. Nothing canonical uses 60 s.
* **Health 1 s / 5 s.** A health probe that needs more than that is a failure.
* **WebSocket / SSE.** Idle timeouts long enough for a session, with buffering
  and retries disabled; these are contract profiles for future routes — no
  reviewed route uses them and none is invented here.

## Buffering

Canonical routes set `request_buffering: true` and `response_buffering: true`
(control plane, calling) so body limits apply before the upstream is touched.
Streaming routes must disable response buffering explicitly and select `SSE`
or `WEBSOCKET`; the validator does not accept a streaming route under
`STANDARD_API`.

## Failure semantics

| Event | Result |
| --- | --- |
| connect timeout | `504` after the profile's connect timeout; no other upstream is tried unless the service's [retry profile](retry-policy-v1.md) allows a connect-phase re-attempt |
| read timeout | `504`; the request is never re-sent |
| write timeout | `504` |
| DNS failure / connection refused | `502`/`503` immediately |

No timeout ever triggers a fallback route.
