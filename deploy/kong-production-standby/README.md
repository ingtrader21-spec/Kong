# Kong production standby

This directory is the authoritative, secret-free package for the Codestra API
standby release. It never attaches a route to `api.codestra.co`.

The only routable hostname in the staging manifest is
`kong-standby.internal.codestra.agency`. SMS, email, and webhook requests end
at the no-delivery middleware fixture. Scraper and telephony routes are absent
until their independent gates pass.

Production activation is a separate reviewed change. See
`operations/runbooks/kong-production-activation.md` and
`operations/runbooks/kong-production-rollback.md`.
