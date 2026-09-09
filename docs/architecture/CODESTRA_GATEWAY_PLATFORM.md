# Codestra gateway platform

Traffic follows host Caddy → private upstream gateway → private Kong proxy →
Middleware or an explicitly registered private application. Provider delivery,
financial actions and tenant business correctness remain in Middleware. The
gateway integration contract, compiler and policy registries own desired source;
the current canonical 27-route inventory remains the deployed-candidate authority.

Management consists of GitHub review, deterministic compilation, protected release
evidence and the private deployment agent. The private Control API provides draft,
preview, approval and job interfaces. Its complete OpenAPI contract is source here;
the durable service is a separate implementation step after foundation review.
The public API has no Admin credential or direct deployment capability.

Hybrid CP/DP and traditional topology descriptions are mutually exclusive. Reuse
the existing PostgreSQL resilience, monitoring, backup and read-only capture
packages. Custom plugins are included alongside the compiler because a generated
configuration referencing absent plugins is not a usable source deliverable.
The small offline CLI shares the compiler instead of duplicating its authority.
This independent source PR has no dependency on the release-evidence PR; both
must pass their own protected merge gates and regenerate combined manifests.

Source validation, runtime testing, approval and deployment are distinct states.
No compiler result, offline archive, OpenAPI response or local test can assert
that a production deployment occurred or that staging accepted the candidate.
