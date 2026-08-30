# Intake Gateway Release Evidence

This branch carries the reviewed unified intake gateway policy for the canonical path:

`site -> SDK/BFF -> Caddy -> Kong -> Middleware -> Odoo`

This documentation-only marker exists to bind a fresh exact-head pull-request validation to the release branch. It does not alter Kong runtime routes, plugins, credentials, deployment state, or production traffic.

Required release properties remain:
- `sdk-intake` identity only for intake service access;
- `leads.write` for lead intake;
- `surveys.write` for survey responses;
- tenant, correlation, and idempotency headers preserved;
- rate/body/security controls enforced;
- no Kong -> Odoo bypass;
- no public Caddy -> Middleware bypass;
- no runtime apply authorized by this file.
