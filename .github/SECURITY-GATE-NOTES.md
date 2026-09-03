# Security gate execution notes

This private repository runs the pinned GitHub CodeQL engine with SARIF upload
disabled when GitHub code-scanning storage is not enabled. The workflow retains
the full local analysis: it requires SARIF output, fails on CodeQL error-level
or security-severity 7.0+ findings, and uploads the SARIF as an Actions artifact
for inspection. This avoids treating an unavailable GitHub upload endpoint as a
successful scan while preserving Gitleaks, dependency audit, Trivy, and SBOM
gates.

The local transport grants only `actions: read` plus `contents: read`, writes
SARIF below the checked-out workspace, and uploads only that bounded evidence.
It does not grant code, release, package, deployment, environment, or runtime
write permission.

This file is operational documentation only. It is outside the Kong migration
authority inventory and does not change routes, plugins, services, consumers,
upstreams, images, runtime state, or traffic.
