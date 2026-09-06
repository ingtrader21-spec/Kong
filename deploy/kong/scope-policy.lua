-- Codestra control-plane scope, tenant and gateway-identity policy.
--
-- This MUST be attached as `post-function`, never `pre-function`.
-- pre-function has plugin priority 1000000 and therefore executes before every
-- authentication plugin (openid-connect is 1000, jwt is 1005). A policy placed
-- there observes no verified credential and no claims, so every request would
-- be rejected at the tenant check. post-function has priority -1000 and is the
-- only serverless phase that observes the result of authentication.
--
-- Required kong.conf settings (see kong.conf.example):
--   untrusted_lua                  = sandbox
--   untrusted_lua_sandbox_requires = cjson.safe
--   trusted_ips                    = <the Caddy edge>  -- get_forwarded_scheme
--   vaults                         = env               -- gateway secret
local cjson = require("cjson.safe")

-- Identity headers are minted here and nowhere else. Clearing them first means
-- a client-supplied value can never survive into the upstream request, even on
-- a path that exits early below.
local minted = {
  "X-Authenticated-Client",
  "X-Authenticated-Tenant",
  "X-Authenticated-Role",
  "X-Codestra-Gateway-Secret",
}
for _, name in ipairs(minted) do
  kong.service.request.clear_header(name)
end

local scheme = kong.request.get_forwarded_scheme()
if scheme ~= "https" then return kong.response.exit(426,{error="https_required"}) end

-- Proof that an authentication plugin actually ran and accepted this request.
-- The claims below are read from the token body; without this gate a caller
-- could present an unsigned token and choose their own scopes.
if not kong.client.get_credential() and not kong.client.get_consumer() then
  return kong.response.exit(401,{error="unauthenticated"})
end

-- Claims from the already-verified token. The jwt plugin publishes them on
-- kong.ctx.shared; openid-connect does not, and its internals are not a stable
-- contract, so fall back to decoding the token Kong has already validated.
local function verified_claims()
  local shared = kong.ctx.shared.authenticated_jwt_token
  if type(shared) == "table" and type(shared.claims) == "table" then
    return shared.claims
  end
  local header = kong.request.get_header("authorization") or ""
  local token = header:match("[Bb]earer%s+(.+)") or ""
  local segment = token:match("^[^.]+%.([^.]+)%.") or ""
  if segment == "" then return {} end
  segment = segment:gsub("-", "+"):gsub("_", "/")
  segment = segment .. string.rep("=", (4 - #segment % 4) % 4)
  local raw = ngx.decode_base64(segment)
  local decoded = raw and cjson.decode(raw) or nil
  if type(decoded) ~= "table" then return {} end
  return decoded
end

local path = kong.request.get_path()
local method = kong.request.get_method()
local claims = verified_claims()
local scopes = {}
for value in string.gmatch(claims.scope or "", "%S+") do scopes[value] = true end
local required
local application_auth_only = false
if path == "/v1/admin/system" or path:find("^/v1/admin/system/") then
  required = "platform.admin"
elseif path:find("^/api/v1/results/messages/") then
  required = "communications.result.write"
elseif path:find("^/api/v1/control/messages/.+/dispatch$") then
  required = "communications.message.dispatch"
elseif path == "/api/v1/control/messages" then
  required = "communications.message.create"
elseif path:find("^/api/v1/messages/.+/events$") then
  required = "communications.message.events.read"
elseif path == "/api/v1/messages" or path:find("^/api/v1/messages/") then
  required = "communications.message.read"
elseif path:find("^/api/v1/reconciliation/") and method == "POST" then
  required = "communications.reconciliation.execute"
elseif path:find("^/api/v1/reconciliation/") then
  required = "communications.reconciliation.read"
elseif path:find("^/api/v1/results/") then
  required = "sync.result.write"
elseif path:find("^/api/v1/control/campaigns") then
  required = method == "GET" and "mapping.read" or "campaign.write"
elseif path:find("^/api/v1/control/agents") then
  required = method == "GET" and "mapping.read" or "agent.write"
elseif path:find("^/api/v1/control/memberships") then
  required = method == "GET" and "mapping.read.minimum" or "sync.execute"
elseif path:find("^/api/v1/control/adapters") then
  required = "sync.execute"
elseif path == "/api/v1/health" then
  application_auth_only = true
elseif path:find("^/api/v1/events/") then
  application_auth_only = true
else
  return kong.response.exit(403,{error="route_scope_undefined"})
end
if required and not scopes[required] then
  return kong.response.exit(403,{error="insufficient_scope",required_scope=required})
end
if not required and not application_auth_only then
  return kong.response.exit(403,{error="route_scope_undefined"})
end
local tenant = kong.request.get_header("X-Tenant-ID")
if not claims.tenant or claims.tenant == "" then
  return kong.response.exit(403,{error="tenant_claim_required"})
end
if tenant and tenant ~= claims.tenant then
  return kong.response.exit(403,{error="cross_tenant_denied"})
end
kong.service.request.set_header("X-Authenticated-Client", claims.azp or "unknown")
kong.service.request.set_header("X-Authenticated-Tenant", claims.tenant)
if required == "platform.admin" then
  kong.service.request.set_header("X-Authenticated-Role", "platform_admin")
else
  kong.service.request.set_header("X-Authenticated-Role", "tenant_admin")
end
-- Resolved through the env vault rather than os.getenv: the Kong Lua sandbox
-- exposes only os.clock, os.date, os.difftime and os.time, so os.getenv raises
-- at request time. {vault://env/kong-control-plane-gateway-secret} reads the
-- KONG_CONTROL_PLANE_GATEWAY_SECRET environment variable.
local gateway_secret = kong.vault.get("{vault://env/kong-control-plane-gateway-secret}")
if not gateway_secret or gateway_secret == "" then
  return kong.response.exit(503,{error="gateway_identity_unavailable"})
end
kong.service.request.set_header("X-Codestra-Gateway-Secret",gateway_secret)
