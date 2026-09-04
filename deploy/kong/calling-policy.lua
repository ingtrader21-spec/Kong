-- Codestra calling API identity, scope, tenant, campaign and header policy.
-- Attach as a Kong post-function only after openid-connect has authenticated
-- the request. This source does not enable runtime application or calling.

local cjson = require("cjson.safe")

local identity_headers = {
  "X-Authenticated-Client",
  "X-Authenticated-Subject",
  "X-Authenticated-Tenant",
  "X-Authenticated-Campaign",
  "X-Authenticated-Role",
}
for _, name in ipairs(identity_headers) do
  kong.service.request.clear_header(name)
end

local path = kong.request.get_path()
local method = kong.request.get_method()

-- These boundaries are never public Kong routes. Fail closed even if this
-- guard is accidentally attached to a broader route in a future change.
if path == "/ws/agent" or path:find("^/internal/?") then
  return kong.response.exit(404, { error = "route_not_public_kong_authority" })
end

if kong.request.get_forwarded_scheme() ~= "https" then
  return kong.response.exit(426, { error = "https_required" })
end

-- Proof that an authentication plugin has already accepted the request.
if not kong.client.get_credential() and not kong.client.get_consumer() then
  return kong.response.exit(401, { error = "unauthenticated" })
end

local function verified_claims()
  local shared = kong.ctx.shared.authenticated_jwt_token
  if type(shared) == "table" and type(shared.claims) == "table" then
    return shared.claims
  end

  -- openid-connect does not expose a stable claims table. The token is decoded
  -- only after the credential/consumer proof above, so this fallback cannot
  -- turn an unverified bearer token into authority.
  local header = kong.request.get_header("authorization") or ""
  local token = header:match("[Bb]earer%s+(.+)") or ""
  local segment = token:match("^[^.]+%.([^.]+)%.") or ""
  if segment == "" then
    return nil
  end
  segment = segment:gsub("-", "+"):gsub("_", "/")
  segment = segment .. string.rep("=", (4 - #segment % 4) % 4)
  local raw = ngx.decode_base64(segment)
  local decoded = raw and cjson.decode(raw) or nil
  if type(decoded) ~= "table" then
    return nil
  end
  return decoded
end

local claims = verified_claims()
if type(claims) ~= "table" then
  return kong.response.exit(503, { error = "verified_identity_unavailable" })
end

local required_scope
local idempotency_required = false
local command_body = false
local realtime_body = false

if method == "POST" and path == "/v1/telephony/commands" then
  required_scope = "telephony:command"
  idempotency_required = true
  command_body = true
elseif method == "GET" and path:match("^/v1/telephony/operations/[0-9a-fA-F%-]+$") then
  required_scope = "telephony:status"
elseif method == "POST" and path:match("^/v1/telephony/operations/[0-9a-fA-F%-]+/cancel$") then
  required_scope = "telephony:command"
  idempotency_required = true
elseif method == "POST" and path:match("^/v1/telephony/operations/[0-9a-fA-F%-]+/reconcile$") then
  required_scope = "telephony:status"
  idempotency_required = true
elseif method == "POST" and path == "/api/v1/realtime/sessions" then
  required_scope = "realtime:session:create"
  idempotency_required = true
  realtime_body = true
else
  return kong.response.exit(403, { error = "calling_route_scope_undefined" })
end

local scopes = {}
for value in string.gmatch(claims.scope or "", "%S+") do
  scopes[value] = true
end
if not scopes[required_scope] then
  return kong.response.exit(403, {
    error = "insufficient_scope",
    required_scope = required_scope,
  })
end

local correlation_id = kong.request.get_header("X-Correlation-ID")
if type(correlation_id) ~= "string" or correlation_id == "" then
  return kong.response.exit(400, { error = "correlation_id_required" })
end

if idempotency_required then
  local idempotency_key = kong.request.get_header("Idempotency-Key")
  if type(idempotency_key) ~= "string" or idempotency_key == "" then
    return kong.response.exit(400, { error = "idempotency_key_required" })
  end
end

local tenant_id = claims.tenant_id
if type(tenant_id) ~= "string" or tenant_id == "" then
  return kong.response.exit(403, { error = "tenant_claim_required" })
end

local requested_tenant = kong.request.get_header("X-Tenant-ID")
if requested_tenant and requested_tenant ~= tenant_id then
  return kong.response.exit(403, { error = "cross_tenant_denied" })
end

local function campaign_allowed(campaign_id)
  if type(campaign_id) ~= "string" or campaign_id == "" then
    return false
  end
  local memberships = claims.campaign_ids
  if type(memberships) == "table" then
    for _, value in ipairs(memberships) do
      if value == campaign_id then
        return true
      end
    end
    return false
  end
  if type(memberships) == "string" then
    for value in string.gmatch(memberships, "%S+") do
      if value == campaign_id then
        return true
      end
    end
  end
  return false
end

local authorized_campaign
if command_body or realtime_body then
  local body = kong.request.get_body()
  if type(body) ~= "table" then
    return kong.response.exit(400, { error = "json_body_required" })
  end

  if command_body then
    if type(body.tenant_id) ~= "string" or body.tenant_id ~= tenant_id then
      return kong.response.exit(403, { error = "cross_tenant_denied" })
    end
    if type(body.correlation_id) ~= "string" or body.correlation_id ~= correlation_id then
      return kong.response.exit(400, { error = "correlation_id_mismatch" })
    end
  end

  authorized_campaign = body.campaign_id
  if not campaign_allowed(authorized_campaign) then
    return kong.response.exit(403, { error = "campaign_membership_required" })
  end
end

kong.service.request.set_header("X-Authenticated-Client", claims.azp or "unknown")
kong.service.request.set_header("X-Authenticated-Subject", claims.sub or "unknown")
kong.service.request.set_header("X-Authenticated-Tenant", tenant_id)
if authorized_campaign then
  kong.service.request.set_header("X-Authenticated-Campaign", authorized_campaign)
end
