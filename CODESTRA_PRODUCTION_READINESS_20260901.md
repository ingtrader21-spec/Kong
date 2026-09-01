# Codestra Production Readiness Gate — Kong

Status: NOT PRODUCTION CERTIFIED

Governed by `Infustruction-repo/CODESTRA_PRODUCTION_READINESS_WAVE_20260901.md`.

Required: exact-head source validation; Critical=0; High=0; no shared provider keys; no wildcard/full scopes; no direct-provider routes; exact Keycloak identities/audiences/scopes; Middleware-only provider effect path; legacy shared-key route retirement plan; immutable manifest/source identity; staging apply/read-back; rollback; production read-only canary.

Do not enable runtime apply or business/provider writes before the umbrella gates pass. Do not modify SSH access.
