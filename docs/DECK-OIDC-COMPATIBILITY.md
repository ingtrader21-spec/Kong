# decK and OpenID Connect compatibility

The repository validates declarative configuration with decK 1.66.0. Starting
with decK 1.59, OpenID Connect synchronization requires a stable
`cache_tokens_salt`; regenerating it during synchronization can invalidate
cached session credentials.

All OpenID Connect authorities therefore reference
`{vault://env/kong-oidc-cache-tokens-salt}`. The protected runtime must provide
one high-entropy value through Kong's environment vault. The value must never be
committed, printed in CI, regenerated during promotion, or changed independently
of an explicitly reviewed credential-cache rotation. Bearer validation behavior,
issuer, audience, scopes, and consumer mapping are otherwise unchanged.

Offline validation does not contact a Kong Admin API and does not resolve or
expose the runtime salt.
