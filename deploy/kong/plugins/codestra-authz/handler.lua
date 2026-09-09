-- Executes after bearer-only openid-connect (priority 1050). Authentication is
-- mandatory; this plugin adds route authorization and never verifies signatures.
local cjson = require "cjson.safe"
local Handler = { PRIORITY = 900, VERSION = "1.0.0" }
local function contains(values, expected)
  if type(values) == "string" then return values == expected end
  if type(values) ~= "table" then return false end
  for _, value in ipairs(values) do if value == expected then return true end end
  return false
end
local function safe(value)
  return type(value) == "string" and #value > 0 and #value <= 128
    and value:match("^[A-Za-z0-9][A-Za-z0-9._:@-]*$") ~= nil
end
local function finite(value)
  return type(value) == "number" and value == value and value ~= math.huge and value ~= -math.huge
end
function Handler:access(conf)
  for _, name in ipairs({"X-Authenticated-Client", "X-Authenticated-Subject", "X-Authenticated-Email",
                         "X-Tenant-ID", "X-Codestra-Tenant", "X-Codestra-Scopes"}) do
    kong.service.request.clear_header(name)
  end
  if not kong.client.get_credential() and not kong.client.get_consumer() then
    return kong.response.exit(401, { error = "authentication_required" })
  end
  local authorization = kong.request.get_header("authorization")
  if type(authorization) ~= "string" or #authorization > 16384 then
    return kong.response.exit(401, { error = "invalid_bearer_token" })
  end
  local segment = authorization:match("^[Bb][Ee][Aa][Rr][Ee][Rr] ([A-Za-z0-9_-]+%.[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+)$")
  segment = segment and segment:match("^[^.]+%.([^.]+)%.")
  if not segment then return kong.response.exit(401, { error = "invalid_bearer_token" }) end
  segment = segment:gsub("-", "+"):gsub("_", "/")
  local raw = ngx.decode_base64(segment .. string.rep("=", (4 - #segment % 4) % 4))
  local claims = raw and cjson.decode(raw)
  if type(claims) ~= "table" or claims.iss ~= conf.issuer or not contains(claims.aud, conf.audience) then
    return kong.response.exit(401, { error = "invalid_token_identity" })
  end
  local now = ngx.time()
  if not finite(claims.exp) or claims.exp <= now
    or not finite(claims.nbf) or claims.nbf > now
    or not finite(claims.iat) or claims.iat > now then
    return kong.response.exit(401, { error = "invalid_token_time" })
  end
  local tenant = claims[conf.tenant_claim]
  if not safe(tenant) or not safe(claims.sub) or not contains(conf.authorized_parties, claims.azp) then
    return kong.response.exit(403, { error = "unauthorized_identity" })
  end
  local selected = kong.ctx.shared.codestra_requested_tenant
  if selected and selected ~= tenant then
    return kong.response.exit(403, { error = "tenant_mismatch" })
  end
  local scopes = {}
  if type(claims.scope) == "string" then
    for scope in claims.scope:gmatch("%S+") do scopes[scope] = true end
  end
  for _, scope in ipairs(conf.scopes) do
    if not scopes[scope] then return kong.response.exit(403, { error = "insufficient_scope" }) end
  end
  local roles = type(claims.realm_access) == "table" and claims.realm_access.roles
  for _, role in ipairs(conf.roles) do
    if not contains(roles, role) then return kong.response.exit(403, { error = "insufficient_role" }) end
  end
  kong.service.request.set_header("X-Authenticated-Client", claims.azp)
  kong.service.request.set_header("X-Authenticated-Subject", claims.sub)
  kong.service.request.set_header("X-Codestra-Tenant", tenant)
  kong.service.request.set_header("X-Codestra-Scopes", table.concat(conf.scopes, " "))
end
return Handler
