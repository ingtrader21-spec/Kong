-- Synthetic certification principal only. No customer identity is modified.
UPDATE oidc_tenant_registry
SET allowed_scopes = ARRAY(
  SELECT DISTINCT value
  FROM unnest(allowed_scopes || ARRAY['sms.send','email.send']::text[]) AS value
  ORDER BY value
)
WHERE client_id = 'codestra-cert-machine'
  AND tenant_key = 'cert-customer-a'
  AND status = 'active';
