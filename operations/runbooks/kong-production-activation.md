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
