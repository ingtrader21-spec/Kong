# Gateway source release

Validate all contracts as a set, inspect the generated configuration and test
matrix, and package the exact source/image/rollback identities with `kongctl`.
Run full source tests, Lua/schema checks and both migration manifest verifiers.
Publish a signed source PR and complete normal protected review and merge gates.
Regenerate on the merged source rather than treating a local synthetic commit as
the protected identity.

Promote the exact protected-main tree through staging. Authenticate the image
digest and release artifacts using the existing release tooling. Execute the
isolated staging matrix under its approved runtime authority and retain observation
evidence; submit fresh authenticated certification for release admission. An offline
package explicitly states that signatures, registry and runtime remain unverified.
No command in the onboarding CLI applies Kong or changes traffic.
