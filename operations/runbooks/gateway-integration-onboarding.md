# Gateway integration onboarding

Install `tools/gateway-requirements.txt` in an isolated Python environment. Run
`python3 tools/kongctl.py integration init --id example-integration --owner platform-team --security-owner security-team --output integration.json`.
The initial contract deliberately uses the existing registered Moneybee example;
review its host, upstream, scopes, methods, environment and owners before submitting.
It is a source document, not an enrollment or an activation.

Validate one or more contracts together with `integration validate integration.json`.
Use `integration preview integration.json` to produce the deterministic desired Kong
document and `integration test integration.json` to obtain the required test matrix.
The latter validates source and lists runtime cases; it does not send requests or
mark unexecuted tests as passing. Add new upstream DNS names, Redis hosts, scopes and
policy changes to their reviewed repository registries before referencing them.

`integration status` and `integration drift` require `--observed-config snapshot.json`.
They compare exact local JSON documents. They neither fetch an Admin API nor attest
that the supplied snapshot is current. Capture and sanitize live state through the
existing private Admin read-only capture workflow when authorized. A raw Admin
response with generated IDs is not a normalized declarative snapshot and will show
drift; do not discard unrecognized fields merely to make that comparison pass.

`release diff before.json after.json` compares source documents. `release package`
requires full source and rollback SHAs, a Kong image digest, environment and output
path. Archives are deterministic, bounded, contain no credentials, and always say
that signatures, registry access and runtime acceptance remain unverified.
`rollback verify package.zip --expected-source-sha <sha> --expected-image-digest <digest>`
checks local archive integrity and exact identity. It does not restore anything.
Use the protected release workflow to authenticate source, registry and staging
evidence. Do not substitute this offline package for a certified release manifest.

Generated Kong configuration requires the reviewed custom plugins, Kong's
`openid-connect` and `mtls-auth` capabilities where selected, TLS trust anchors,
Vault environment references and private Redis connectivity. Load plugin files at
`kong/plugins/<name>/` in the pinned gateway image and explicitly enable their names.
The bearer-only OIDC plugin must run before `codestra-authz`; no anonymous, cookie,
query-token or alternative authentication fallback is permitted on those routes.
Run schema/decK validation against that exact gateway image before runtime admission.
The compiler does not imply compatibility with an arbitrary OSS image.

For signed webhooks, retain the original raw body and the four `X-Webhook-*` headers.
Signature syntax is `v1=<lowercase HMAC-SHA256 hex>` over UTF-8 bytes formed by
`v1\n<key-id>\n<unix-seconds>\n<event-id>\n` followed by the raw request body.
Use a secret of at least 32 bytes. Middleware owns durable replay rejection and
idempotency, including across gateway processes and restarts. A valid signature
alone never authorizes provider delivery. Test bad signatures, timestamps, key IDs,
body size, durable replay, unavailable Redis, upstream loss and previous digest
rollback in isolated staging before protected admission.

This foundation does not replace the canonical 27-route inventory. It provides a
reviewed way to author future integrations. The durable approval/control API and
deployment worker are separate program components; no command here enables them.
