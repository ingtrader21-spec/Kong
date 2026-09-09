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
exec /docker-entrypoint.sh "$@"
