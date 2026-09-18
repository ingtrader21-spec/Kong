# Kong Retry Policy V1

Part of the [Kong API Gateway Control Plane V1](KONG_GATEWAY_CONTROL_PLANE_V1.md).
Machine-readable: `config/kong-gateway-foundation.v1.json` → `profiles.retry`.

Kong's service `retries` defaults to **5**. A service that does not declare
`retries` therefore re-attempts failed proxying up to five times without anyone
having decided that. The foundation makes every canonical service declare its
profile, and the validator rejects a canonical service whose bound source
leaves retries implicit (`IMPLICIT_RETRIES`) or whose value disagrees with its
profile.

| Profile | `retries` | Transport-safe | Use | Services today |
| --- | ---: | --- | --- | --- |
| `NONE` | 0 | yes | commands, mutations, identity, standby, editor: surface the failure to the caller | control plane, campaign automation (+staging), intake, calling (renderer), MoneyBee (renderer), n8n editor, standby, gateway-platform example |
| `TRANSPORT_CONNECT_ONLY_1` | 1 | yes | one re-attempt for connect-phase failures only | callbacks, n8n control plane (+staging) |
| `KONG_DEFAULT_IMPLICIT` | 5 | no | nothing declared; design-only | marketing stage-4 fragment |
| `UNRECORDED_READBACK` | 5 (assumed) | no | the sanitized readback does not capture `retries`; assume the Kong default until captured | every observed-only legacy service |

`profiles.limits.maxRetries` is 5; no profile may exceed it.

## Why `TRANSPORT_CONNECT_ONLY_1` is safe on POST

Kong proxies through nginx `proxy_next_upstream`. Without the `non_idempotent`
flag (Kong does not set it), nginx never re-sends a request with a
non-idempotent method (`POST`, `PATCH`, `LOCK`) once any bytes have reached
the upstream; only a failure to *connect* is retried. A callback `POST` or an
n8n command `POST` therefore cannot be duplicated by the gateway: either the
connection failed before the request was sent (safe to retry once) or the
request was sent and the failure is returned to the caller. Because every
governed service has a single DNS target, the re-attempt goes to the same
host and only masks a transient connect failure. This is the sole case where a
value above `0` is marked transport-safe, and only canonical services with a
transport-safe profile pass validation.

## Where retries are forbidden

| Operation | Profile | Reason |
| --- | --- | --- |
| command submission (`/api/v1/control/*`, `/v1/telephony/commands`, `/v1/integrations/n8n/commands` — the latter keeps the reviewed connect-only `1`) | `NONE` (`TRANSPORT_CONNECT_ONLY_1` for n8n) | duplicate side effects are Middleware's ledger problem; the gateway must not add attempts |
| result submission, policy check (`/api/v1/integrations/n8n/results`, `/api/v1/automation/policy-check`) | `NONE` | was Kong default 5 before this baseline |
| intake writes | `NONE` | writes carry `Idempotency-Key`; only the caller may replay |
| identity bootstrap | `NONE` | account creation |
| webhooks | `NONE` (successor policy) | replay denial is Middleware's |
| payment-like or provider mutations | `NONE` | none exist on Kong today; provider control is prepared/disabled |

## Idempotency boundary

`Idempotency-Key` is propagated unchanged and required on the intake, n8n
command and calling command routes; Middleware owns the ledger, conflict
detection and retention. Kong is never the authoritative command-idempotency
store, and a `NONE` profile guarantees the only replay source is the caller
with the same key. The callback control route does not yet require the header
(audit follow-up).

## Failure behaviour (circuit)

| Condition | Gateway behaviour |
| --- | --- |
| DNS failure | `503`; no retry to another name |
| connection refused | `502`/`503`; `TRANSPORT_CONNECT_ONLY_1` services re-attempt once |
| connect/read/write timeout | `504` per the [timeout profile](timeout-profiles-v1.md); reads are never re-sent |
| upstream 5xx | returned as-is; never retried (no `proxy_next_upstream http_5xx`) |
| all targets unavailable | there is one target per service; the service is down and every route answers `502`/`503` |
| rate-limit Redis unreachable | `500` (fail closed), never "unlimited" |

None of these conditions selects an older service, a different listener, a
provider or a legacy route.

## Drift and readback

The 2026-09-06 readback does not capture `retries`, so observed-only legacy
services carry `UNRECORDED_READBACK` and the accepted finding
`RETRIES_UNRECORDED`; capturing `retries` in the next bounded readback closes
that gap. The campaign automation service's readback shows Kong-default
timeouts while the contract now pins `STANDARD_API`/`NONE`; that difference is
declared in `knownDrift` until the reconciler is applied under change
authority.
