# Gateway trust boundaries

Keycloak authenticates bearer tokens. The generated OIDC configuration accepts
headers only and maps the authorized party to a registered consumer. The authz
plugin then checks issuer, audience, party, time bounds, scopes and tenant identity.
The request-context plugin removes supplied identity headers before authentication;
only sanitized authenticated identity reaches Middleware. Middleware still checks
tenant ownership of every referenced business resource.

Upstream names, scopes and Redis hosts come from reviewed registries. Contracts
cannot authorize arbitrary provider URLs, raw Admin payloads or public listeners.
TLS certificate validation remains enabled; private upstream trust material is
provisioned separately. Kong and Middleware preserve signed webhook bytes and
headers. The HMAC plugin verifies identity/time/body; durable replay denial remains
Middleware-owned and must be tested across process restarts.

The deployment agent is the only component with approved private Admin reachability.
OpenAPI deployment requests carry an approval ID, environment and immutable release
identity. Their boolean defaults never enable runtime execution. The API must
authenticate the exact release artifact before admitting a job; a caller-provided
SHA is an identifier, not signature verification. Administrative approval and
deployment permission are separate, and authors cannot approve their own drafts.

Source archives contain integrity hashes and explicitly unverified runtime state.
Protected release workflows must authenticate signatures, artifacts, registry
digests and fresh staging observations. Local integrity checks cannot replace them.
