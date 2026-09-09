# Authenticated runtime certification

Issues #58, #52 and #49 require completed runtime observations bound to one
immutable candidate. A protected variable containing `PASS:<sha>:...` is no
longer sufficient to create a staging-certified or production release manifest.
The source portion of #6 uses the same route inventory and certification matrix.

## Executable source contract

Generate the deterministic test matrix before the authorized isolated rehearsal:

```sh
python3 tools/kong_certification.py --output /tmp/kong-certification-plan.json
```

This command has no network or container access. It derives the route set from
`config/kong-production-route-inventory.v2.json`, including the 27-route successor
of the historical 29-route inventory. JWT/OIDC routes additionally require wrong
issuer, audience, authorized party, scope and tenant cases. The plan is explicitly
uncertified; it contains no fabricated observations or PASS report.

The runtime report format is `codestra.kong.runtime-certification.v1`, defined by
`tools/kong_certification.py`. Every route and every required global check must
be present, pass, and name the SHA-256 of its retained observation. Unknown
routes, extra fields, duplicate JSON keys, absent checks and truthy substitutes
for booleans fail validation. Reports contain hashes and bounded structured
results only, never tokens, response bodies, headers or logs.

Reports bind the original protected-main candidate SHA/tree, both immutable
image digests, declarative config hash, candidate-manifest hash and route-inventory
hash. They include the exact rollback source and prior image/config identity,
backup and restore observation hashes, GET/HEAD-only isolated canary observations
at no more than 100 basis points, and all nine effect counters before and after.
Both counter sets must be complete integer zeros: a reset or nonzero baseline
cannot pass as "no new effects." Public traffic must remain zero during isolated
staging. Evidence expires after 24 hours; it cannot be future dated or span more
than 24 hours. A production canary and full activation remain separately governed.

## Observation producer and trust boundary

The authorized runtime harness/operator must retain the measured observations
under the hashes in the report. This repository's packager validates the report;
it does **not** execute these tests or independently reconstruct a measurement
from a hash. Test fixtures are synthetic and never publishable evidence.

After the real isolated rehearsal, an authorized operator places the sanitized
report at `/var/lib/codestra/kong-certification/<original-source-sha>/certification.json`.
It must be a regular, single-link, root-owned file with no group/world write
permission. The protected `staging` environment records:

- `KONG_CERTIFIED_SOURCE_SHA`: original protected-main candidate SHA;
- `KONG_CANDIDATE_RUN_ID`: successful canonical main release run;
- `KONG_STAGING_OBSERVATION_SHA256`: reviewed SHA-256 of the complete observation file.

Run **Authenticate isolated staging observations** on the protected `staging`
branch. It verifies the signed staging commit and exact source tree, retrieves
the authenticated original candidate, validates the hash-approved local report,
and publishes one attempt-specific artifact. It makes no Admin requests, starts
no probes, performs no deployment and changes no environment variables.

The protected release environment then supplies `KONG_STAGING_CERTIFICATION_RUN_ID`
for that successful run. Release generation retrieves its latest-attempt artifact,
verifies the GitHub run's repository, branch, workflow, event, completion, signature
and tree, and checks the archive against GitHub's artifact digest. Expired,
ambiguous, foreign, oversized, redirected-source or malformed archives cannot pass.
Only the expected `certification.json` member is accepted; archive content is never
executed. The report is revalidated for freshness, completeness and candidate hashes.

The verifier produces the certification identifier and a receipt automatically.
`generate_release_manifest.py` requires both the exact report and its matching
receipt; a manually entered legacy `STAGING_CERTIFICATION` string is not consumed
by the release workflow. Receipts are meaningful only when emitted by this
authenticated workflow step, just as candidate receipts rely on their downloader.
Do not treat locally constructed JSON receipts as independent attestations.

GitHub's [artifact API](https://docs.github.com/en/rest/actions/artifacts) and
[workflow-run API](https://docs.github.com/en/rest/actions/workflow-runs) supply
the archive digest and producer metadata used by the verifier.

## Standby acceptance scope

`scripts/run_kong_standby_acceptance.py` now requires
`--execute-isolated-staging` before reading credentials or making requests.
Requests refuse redirects and inherited proxies and bound response size. Success
responses must explicitly identify the mock adapter and disabled external action.
Errors do not print remote response bodies. A standalone run reports external
effect counters as **not measured**, and cannot produce a full certification.
It is one input to the isolated rehearsal, not proof of all 27 routes or a real
zero-effect counter observation.

Rollback observations must include `rollback.candidate_run_id`, identifying the
successful canonical protected-main release run for `candidate.rollback_source_sha`.
Both the protected observation packager and the consuming staging verifier recover
that run's retained, digest-bound candidate artifact and require a GitHub-verified
source commit with the same source tree. The reported rollback image digest and
configuration SHA-256 must exactly equal that authenticated candidate. Format-only
hashes, an arbitrary local manifest and a self-asserted rollback record cannot pass.
The prior release artifact must remain available for the rollback retention period.

The staging receipt carries the authenticated rollback manifest bytes and its run,
artifact, digest and manifest-hash references. Offline manifest generation checks
these bindings again. As with the rest of the receipt, this local consistency check
is not standalone provenance: protected release admission first executes the live
GitHub run/artifact verifier. No rollback or runtime probe is executed by these
verification tools.
