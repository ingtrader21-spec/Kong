# Kong production activation

Activation is prohibited by this standby release. A later protected change may
attach the package only after exact-head independent approval, passing CI,
validated Keycloak issuer/audience/scope registration, tenant-isolation tests,
mock-only security/load tests, and a fresh rollback backup.

The activation change must replace the staging hostname with the reviewed
public hostname, replace the no-delivery fixture only with authenticated
middleware—not a provider—and verify all live-delivery kill switches remain
false before and after reload. Scraper and telephony remain absent unless their
independent gates pass.

Before any staging or production mutation, run the secret-free topology gate:

```bash
python3 scripts/verify_runtime_integration.py
```

It requires healthy Caddy, Kong, Middleware, and Redis containers and shared
networks for every required hop, including Kong to Redis. Any failure prohibits
config application and traffic promotion.

Before selecting a candidate, follow [immutable promotion and Admin isolation](../../docs/KONG_RELEASE_AND_ADMIN_BOUNDARIES.md).
The Admin capture path is container-loopback, not a published host port.
Keep the certified source SHA and destination promotion SHA distinct, verify
identical trees and the original candidate artifact, and never rebuild during
staging/production promotion. Configuration evidence is not a peer-denial proof.
