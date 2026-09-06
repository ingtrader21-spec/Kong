-- Preserve the distinction between a caller-supplied correlation identifier
-- and one generated later by Kong's correlation-id plugin. This pre-function
-- validates only raw request metadata; authentication and claims authorization
-- remain exclusively in the post-function policy.
local correlation_id = kong.request.get_header("X-Correlation-ID")
if type(correlation_id) ~= "string" or correlation_id == "" then
  return kong.response.exit(400, { error = "correlation_id_required" })
end
