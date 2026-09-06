# Kong cell branch map

Branches are review workstreams, not deployment environments.

```text
fix/kong-source-authority-signed-replacement-20260827
  -> architecture/kong-cell-platform-v1
       -> config/kong-core-communications-v1
       -> config/kong-beyvra-isolated-v1
       -> config/kong-telephony-private-v1
       -> ci/kong-gitops-security-gates-v1
       -> test/kong-route-contracts-v1
```

## Merge order

1. Source-authority PR #3.
2. Cell architecture and machine-readable invariants.
3. Core communications cell.
4. Isolated Beyvra cell.
5. Private telephony cell.
6. GitOps and negative-security gates.
7. Route-contract tests.
8. Staging read-only diff and no-effect verification.
9. Separate approved configuration canary.

## Cleanup policy

Do not delete or force-update historical branches. A branch is a deletion candidate only after its commits are reachable from the protected canonical branch, every PR dependency is closed, release/tag references are checked, and a separate cleanup change is approved.
