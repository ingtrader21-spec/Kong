# Automated Production Gates

This repository is intended to support automated promotion without mandatory human pull-request approval, while preserving deterministic production safety gates.

## Merge policy
- Required approving reviews: 0.
- Required Code Owner reviews: off.
- Required status checks: on.
- Strict/up-to-date branch requirement: on.
- Conversation resolution: on.
- Force pushes and protected-branch deletion: blocked.
- Auto-merge: enabled.
- Administrator bypass is not part of the normal release path.

## Release policy
A merge does not authorize external effects. Production promotion still requires source authority, immutable digest pinning, declarative route validation, security checks, rollback evidence, staging/synthetic certification, and a production read-only canary.

For server `65.109.65.169`, preserve reconciliation of all 29 live routes, auth/rate-limit/timeout/header boundaries, private Admin API exposure rules, source SHA, digest, and rollback evidence. SSH access controls must not be changed.
