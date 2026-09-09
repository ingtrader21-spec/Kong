return { name = "codestra-webhook-verifier", fields = {
  { config = { type = "record", fields = {
    { secret = { type = "string", required = true, referenceable = true, encrypted = true } },
    { key_id = { type = "string", required = true, len_min = 1, len_max = 63 } },
    { maximum_body_bytes = { type = "integer", required = true, between = {1, 1048576} } },
    { clock_skew_seconds = { type = "integer", required = true, between = {1, 300} } }
  } } }
} }
