# Marketing Edge Contract

Kong is the authenticated API edge for the marketing platform.

## Route families
- /v1/marketing/* -> Codestra Marketing
- /v1/ai/* -> Codestra AI
- /v1/communications/* -> Codestra Communication
- /v1/social/* -> Codestra Social

## Mandatory controls
OIDC/JWT validation, service-to-service identity, request correlation, rate limits, body-size limits, timeout policy, request-id propagation, audit metadata, and explicit environment separation.

## Promotion rule
No production route may be promoted until its upstream health endpoint, auth policy, staging contract test, and rollback path pass. Gateway configuration must not make disabled provider writes reachable.
