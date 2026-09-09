# Gateway rollback source verification

Identify the previously certified source SHA, image digest, configuration hash and
backup/restore evidence. Use `kongctl rollback verify` to check the retained local
package's integrity and exact expected identity. This check does not authenticate
the GitHub signature or registry and does not execute a rollback.

Use the existing protected rollback workflow and private deployment agent under
the recorded rollback authority. Require fresh authenticated release evidence,
pre-change backup, restored configuration/digest read-back, private health probes,
zero unexpected route/plugin drift and the approved traffic policy. Escalate a
failed restoration through the existing recovery/fencing runbook. Do not substitute
an arbitrary Admin payload, clear failed units or overwrite evidence to declare
success. Retain the actual attempt and outcome in immutable audit history.
