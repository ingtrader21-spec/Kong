# Kong production standby rollback

1. Keep public activation disabled.
2. Remove only entities tagged with the exact standby release identifier.
3. Verify the prechange Kong database backup checksum.
4. If entity rollback is insufficient, restore the prechange Kong dump during
   an approved maintenance window.
5. Validate Kong health, Admin loopback binding, public authentication denial,
   and unrelated existing routes.
6. Confirm no provider action, Odoo record, n8n workflow, call, SMS, email, or
   scraper job was triggered.
