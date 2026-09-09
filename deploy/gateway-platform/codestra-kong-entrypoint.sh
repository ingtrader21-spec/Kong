#!/bin/sh
set -eu
# The env Vault provider reads this process variable. It is not a kong.conf
# option, so the upstream Kong entrypoint's generic *_FILE support cannot load it.
sx_redis_file=/run/secrets/redis_password
if [ ! -r "$sx_redis_file" ] || [ ! -s "$sx_redis_file" ]; then
  echo 'Required gateway rate-limit credential is unavailable' >&2
  exit 1
fi
KONG_RATE_LIMIT_REDIS_PASSWORD=$(cat "$sx_redis_file")
export KONG_RATE_LIMIT_REDIS_PASSWORD
sx_oidc_salt_file=/run/secrets/oidc_cache_tokens_salt
if [ ! -r "$sx_oidc_salt_file" ] || [ ! -s "$sx_oidc_salt_file" ]; then
  echo 'Required stable OIDC cache salt is unavailable' >&2
  exit 1
fi
KONG_OIDC_CACHE_TOKENS_SALT=$(cat "$sx_oidc_salt_file")
export KONG_OIDC_CACHE_TOKENS_SALT
sx_webhook_secret_file=/run/secrets/webhook_signing_secret
if [ ! -r "$sx_webhook_secret_file" ] || [ ! -s "$sx_webhook_secret_file" ]; then
  echo 'Required gateway webhook signing credential is unavailable' >&2
  exit 1
fi
KONG_WEBHOOK_SIGNING_SECRET=$(cat "$sx_webhook_secret_file")
export KONG_WEBHOOK_SIGNING_SECRET
exec /docker-entrypoint.sh "$@"
