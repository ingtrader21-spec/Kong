return { name = "codestra-request-context", fields = {
  { config = { type = "record", fields = {
    { require_correlation_id = { type = "boolean", required = true, default = true } },
    { not_after = { type = "integer", required = false, gt = 0 } }
  } } }
} }
