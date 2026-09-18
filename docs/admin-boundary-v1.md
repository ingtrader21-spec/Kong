# Kong Administrative Boundary V1

Part of the [Kong API Gateway Control Plane V1](KONG_GATEWAY_CONTROL_PLANE_V1.md).
Companion to `docs/KONG_RELEASE_AND_ADMIN_BOUNDARIES.md` (management channel and
promotion) and `docs/observability/prometheus.md` (metrics).

## Interfaces

| Interface | Binding | Published | Reachable from | Enforced by |
| --- | --- | --- | --- | --- |
| Proxy (data plane) | `0.0.0.0:8000` in the container | `127.0.0.1:8000` on the host, for Caddy only | host Caddy; edge network alias `codestra-kong` | `validate_node`: every published port binds host loopback |
| Admin API | `127.0.0.1:8001` — **container** loopback | never | only a process inside the `kong-gateway` container namespace (`scripts/kong_admin_channel.py`, `tools/capture_kong_server_baseline.py` via bounded in-container `curl`) | `validate_node`: `KONG_ADMIN_LISTEN` must be `127.0.0.1:8001`; no `:8001` publication; `admin_access_log off` |
| Kong Manager (GUI) | `off` | never | nobody | `validate_node`: `KONG_ADMIN_GUI_LISTEN=off`; no `:8002` publication |
| Status API / `/metrics` | `0.0.0.0:8100` in the container | never | the external `codestra-observability` network only (alias `kong`), scraped by the Prometheus authority | `validate_node`: `KONG_STATUS_LISTEN=0.0.0.0:8100`, no `:8100` publication, `status_access_log off`; `tests/test_kong_observability.py`: no proxy route exposes `/metrics` |

A host-loopback publication of Admin would still be reachable by peers on a
shared Docker bridge, which is why Admin binds the container loopback and is
not published at all. Read-only captures record `peerNetworkDenialVerified=false`
until a live peer-network denial test is performed; that remains runtime
certification evidence.

## Allowed networks and access

| Network | Members | Purpose |
| --- | --- | --- |
| `codestra_edge` (external) | Caddy-facing edge, `codestra-kong` alias | proxy traffic only |
| `codestra_backend` (external) | Middleware listeners, Redis (`codestra-redis`), PostgreSQL stable endpoint | upstream, rate-limit counters, datastore |
| `codestra-observability` (external) | Prometheus authority | Status API scrape of `http://kong:8100/metrics` |
| `codestra_kong_admin` (gateway-platform topology) | management node only | Admin on the traditional topology's isolated management node; proxy nodes run Admin `off` |

Administrative change runs through the private channel described in
`docs/KONG_RELEASE_AND_ADMIN_BOUNDARIES.md`: bounded `GET/POST/PATCH/DELETE`
against checked Admin paths inside the verified container, request bodies on
stdin, no shell, no redirects, non-2xx fail closed, container identity
re-verified before a client reports success. Nothing in this repository grants
Docker socket, sudo or SSH access, and no public route may target Admin,
Manager or Status: the validator flags any route path with an `admin` segment
(`ADMIN_PATH`) and requires it to be `ADMIN_INTERNAL` with a mechanism and
scopes (`/v1/admin/system`, `platform.admin`) or `BLOCKED` (`/api/v1/admin/mail`).

## Application admin vs gateway admin

`GET /v1/admin/system` is an *application* administration route on the control
plane, classified `ADMIN_INTERNAL`: OIDC audience `codestra-control-plane`,
scope `platform.admin`, tenant claim required, `X-Authenticated-Role:
platform_admin` minted by the guard. It is not the Kong Admin API and it is
rate-limited by the service-level 120/min counter today (`ADMIN_STRICT_30` is
the recorded target once a route-level limiter is added).

## Datastore and secrets

The node uses the least-privilege `kong_runtime` role over TLS with
certificate verification (`KONG_PG_SSL=on`, `KONG_PG_SSL_VERIFY=on`,
`lua_ssl_trusted_certificate=system`); migrations use the separate
`kong_migration_admin` authority under `operations/kong-database/`. Secrets
reach the node only as root-owned host files mounted as Docker secrets
(`kong_license`, `kong_database_runtime_password`) or as environment variables
from the root-owned runtime env file resolved through the `env` vault
(`KONG_CONTROL_PLANE_GATEWAY_SECRET`, `KONG_RATE_LIMIT_REDIS_PASSWORD`,
`KONG_OIDC_CACHE_TOKENS_SALT`). No Admin credential, database password, client
secret, JWT secret, private key, API key or provider secret exists in Git; the
validator requires every `{vault://env/...}` reference in the deployed
candidate to be declared in `deploy/kong/runtime.env.example` by name only. The
env vault is the seam a future OpenBao vault replaces without changing any
route contract.

## Container least privilege

`read_only: true` root with `tmpfs` for `/tmp` and the Kong prefix,
`cap_drop: [ALL]`, `no-new-privileges`, no `privileged`, no host networking,
no Docker socket, an immutable image digest (`kong/kong-gateway@sha256:…` from
the protected release workflow), a `kong health` healthcheck and
`restart: unless-stopped`. The gateway-platform topologies additionally pin
`user: 1000:1000`, `pids_limit`, memory and CPU limits; adopting the same
resource limits on the single-node compose is a recorded follow-up.

## Logging

Proxy access and error logs go to the container streams (`/dev/stdout`,
`/dev/stderr`) at `notice`; Admin and Status access logs are off. The proxy
access log carries timestamp, client (from `X-Forwarded-For` via the trusted
edge), method, path, status, latency, service and route, and the correlation
id; identity headers and tokens are never logged by Kong. `KONG_HEADERS=off`
suppresses server and version headers.
