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

The Middleware command plane uses preserved product tokens. Kong must validate
the product JWT from `https://auth.codestra.co/realms/codestra`, require
`aud=middleware-api`, require the registered product command scope, reject
cross-tenant requests, and forward the original bearer token plus
`X-Codestra-Consumer-Id` to Middleware. Token exchange to `kong-gateway` is not
part of this route contract.
