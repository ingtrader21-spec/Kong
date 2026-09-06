-- MoneyBee borrower bootstrap claim enforcement.
-- Attach only as post-function, after openid-connect has authenticated.
local cjson = require("cjson.safe")

for _, name in ipairs({
  "X-Authenticated-Client", "X-Authenticated-Subject", "X-Authenticated-Email"
}) do
  kong.service.request.clear_header(name)
end

if kong.request.get_forwarded_scheme() ~= "https" then
  return kong.response.exit(426, { error = "https_required" })
end
if not kong.client.get_credential() and not kong.client.get_consumer() then
  return kong.response.exit(401, { error = "unauthenticated" })
end

local header = kong.request.get_header("authorization") or ""
local token = header:match("[Bb]earer%s+(.+)") or ""
local segment = token:match("^[^.]+%.([^.]+)%.") or ""
segment = segment:gsub("-", "+"):gsub("_", "/")
segment = segment .. string.rep("=", (4 - #segment % 4) % 4)
local raw = ngx.decode_base64(segment)
local claims = raw and cjson.decode(raw) or nil
if type(claims) ~= "table" then
  return kong.response.exit(503, { error = "verified_identity_unavailable" })
end

local required = { "iss", "sub", "aud", "azp", "exp", "iat", "nbf", "email", "email_verified" }
for _, claim in ipairs(required) do
  if claims[claim] == nil then
    return kong.response.exit(403, { error = "required_claim_missing", claim = claim })
  end
end
if claims.iss ~= "https://auth.codestra.co/realms/codestra" then
  return kong.response.exit(401, { error = "invalid_issuer" })
end
local audience_ok = claims.aud == "moneybee-api"
if type(claims.aud) == "table" then
  for _, value in ipairs(claims.aud) do
    if value == "moneybee-api" then audience_ok = true end
  end
end
if not audience_ok then return kong.response.exit(401, { error = "invalid_audience" }) end
if claims.azp ~= "moneybee-borrower" then
  return kong.response.exit(403, { error = "invalid_authorized_party" })
end
if claims.email_verified ~= true then
  return kong.response.exit(403, { error = "email_not_verified" })
end

kong.service.request.set_header("X-Authenticated-Client", claims.azp)
kong.service.request.set_header("X-Authenticated-Subject", claims.sub)
kong.service.request.set_header("X-Authenticated-Email", claims.email)
