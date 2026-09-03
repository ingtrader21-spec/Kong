# Kong branch and release governance

The only routine authority flow is `feature/*` or `fix/*` to `main`, `main` to
`staging`, and `staging` to `production`, each through a current, reviewed pull
request. `main` is reviewed source authority, `staging` is the exact production
candidate, and `production` is approved release source. Neither environment
branch accepts feature development or direct developer pushes.

All three branches require validation, approval, conversation resolution, a
current base, and protection from force-push and deletion. Production promotion
also requires completed staging acceptance, security evidence, reviewed server
drift, resolved unverified routes, rollback certification, and release evidence.

Administrator bypass is emergency-only. Every use requires an incident or
change record explaining necessity, scope, authorizer, exact SHA, validation,
and follow-up reconciliation. It is never a routine repair or release path.

Release-producing commits must be GitHub-verified or cryptographically signed.
Each release record contains source commit and tree SHAs, commit verification,
authority generation ID and hashes, declarative Kong configuration hash, exact
Kong image digest, staging certification reference, and rollback source SHA.

Server capture is read-only. It must not mutate Kong, Caddy, PostgreSQL, Redis,
DNS, firewall, containers, routes, plugins, providers, or public traffic, and it
must pass secret review before publication.
