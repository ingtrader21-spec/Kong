# Codestra Kong Cell Platform v1

## Status

Source architecture and validation contract only. This branch does not apply Kong, Caddy, DNS, firewall, database, certificate, route, plugin, consumer, credential, container, or production changes.

## Objective

Kong is the traffic-policy layer between Caddy and Codestra Middleware. It does not own business logic, tenant truth, workflow state, provider credentials, CRM records, financial records, or delivery truth.

The production target is three isolated gateway cells:

1. **core-communications** — Codestra public APIs, Odoo facade, Klyrow email, Telnexa SMS, Postly social, Kyqra crawler, forms, support, and provisioning.
2. **beyvra-financial** — a separate control plane, database, rate-limit namespace, certificates, configuration release, and data plane for Beyvra. n8n is limited to the non-financial automation facade.
3. **telephony-private** — private VLAN-only routes for the restricted VICIdial/Asterisk adapter. No public listener and no generic telephony administration surface.

## Request path

```text
Internet -> Caddy -> Kong data plane -> Middleware -> authorized adapter/service
```

Internal automation uses:

```text
n8n cell -> private Kong listener -> Middleware automation API -> authorized adapter/service
```

Provider callbacks use:

```text
provider -> Caddy -> Kong webhook route -> Middleware durable signed inbox
```

n8n is never a public webhook target and never receives provider, Odoo, database, Keycloak-admin, Kong-admin, VICIdial, Postal, Jasmin, social-provider, crawler-provider, broker, wallet, custody, or payment credentials.

## Responsibility boundary

### Caddy

Caddy owns public TLS, exact host allowlisting, HTTP-to-HTTPS redirection, basic edge headers, and forwarding to the selected Kong cell. It contains no product routing or tenant policy.

### Kong

Kong owns exact host/path/method routing, authentication enforcement, request and response policy, request-size limits, rate limits, upstream health, timeouts, trace propagation, and API metrics. Kong removes spoofable internal identity headers before forwarding.

### Middleware

Middleware owns authoritative tenant resolution, authorization, contract validation, idempotency, replay protection, consent and suppression, capability gates, signed webhook verification, durable inbox/outbox, command state, provider adapters, audit, and reconciliation.

## Isolation requirements

Each cell has a separate:

- control-plane PostgreSQL database;
- data-plane certificate trust set;
- Redis rate-limit namespace;
- declarative configuration bundle and checksum;
- release manifest and rollback bundle;
- network policy;
- monitoring labels and alerts;
- machine clients and scopes.

A route, plugin, consumer, or certificate mistake in one cell must not grant access to another cell.

## Listener policy

Public exposure is limited to Caddy on ports 80 and 443. Kong Admin API, Kong Manager, control-plane clustering ports, and status APIs remain loopback or private-management only. Telephony proxy routes remain private VLAN-only.

## Authentication

Human applications use Keycloak Authorization Code with PKCE through their BFF or approved browser boundary. Machine integrations use short-lived Client Credentials tokens with explicit audience and granular scopes. Middleware repeats all critical authorization checks even where Kong validates the token.

## Standard policy chains

- **global**: correlation ID, trace propagation, request-size limit, spoofed-header removal, metrics, redacted logs, standardized errors.
- **browser**: exact CORS origin, OIDC/BFF policy, audience, scopes, tenant-aware rate limit, upstream TLS.
- **service**: private source policy, Client Credentials, audience, granular scope, command-prefix restriction, upstream mTLS.
- **webhook**: exact POST route, no CORS, strict body limit, provider rate limit, Middleware durable inbox target, no direct n8n.

## Route rules

- Every route declares cell, host, path, methods, policy chain, upstream service, and risk class.
- Every public route targets Middleware, never a provider or product database.
- A client-provided tenant header is never authoritative.
- Unsafe automatic retries are disabled for mutating routes. Middleware owns idempotent retry and unknown-outcome reconciliation.
- CORS is route-specific and disabled for service and webhook routes.

## GitOps release

The repository is the source of truth. Normal production changes follow:

```text
OpenAPI lint -> JSON/YAML validation -> route collision tests -> policy allowlist -> secret scan -> decK validate -> decK diff -> independent review -> staging sync -> read-back -> canary -> production sync -> read-back -> rollback proof
```

Kong Manager is not an authoritative editor. Emergency changes must be exported, reconciled, reviewed, and restored to Git before the incident is closed.

## Capability state

All external effects remain disabled in source:

```text
EMAIL_DELIVERY=false
SMS_DELIVERY=false
SOCIAL_PUBLISH=false
CRAWLER_EXECUTION=false
CRAWLER_WRITEBACK=false
ODOO_WRITE=false
CALLBACK_DISPATCH=false
PRODUCTION_DIALING=false
BEYVRA_FINANCIAL_WRITE=false
DEAD_LETTER_REPLAY=false
```

## Branch program

- `architecture/kong-cell-platform-v1` — this binding architecture.
- `config/kong-core-communications-v1` — core route and plugin implementation.
- `config/kong-beyvra-isolated-v1` — isolated Beyvra route implementation.
- `config/kong-telephony-private-v1` — private telephony route implementation.
- `ci/kong-gitops-security-gates-v1` — decK, collision, policy, and exact-head gates.
- `test/kong-route-contracts-v1` — positive and negative gateway tests.

No child branch may deploy directly. Protected merged SHAs produce immutable, reviewed configuration bundles.
