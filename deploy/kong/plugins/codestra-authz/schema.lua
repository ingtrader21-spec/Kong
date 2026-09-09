local text = { type = "string", required = true, len_min = 1, len_max = 256 }
return { name = "codestra-authz", fields = {
  { config = { type = "record", fields = {
    { issuer = text }, { audience = text },
    { authorized_parties = { type = "array", required = true, len_min = 1, elements = text } },
    { scopes = { type = "array", required = true, len_min = 1, elements = text } },
    { roles = { type = "array", required = true, len_min = 1, elements = text } },
    { tenant_claim = { type = "string", required = true, one_of = {"tenant_id", "tenant", "org_id"} } }
  } } }
} }
