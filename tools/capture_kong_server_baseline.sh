#!/usr/bin/env bash
set -Eeuo pipefail

admin_url="${KONG_ADMIN_READ_ONLY_URL:-http://127.0.0.1:8001}"
output="${1:-${RUNNER_TEMP:-/tmp}/kong-production-readback.json}"
case "$admin_url" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo "refusing non-loopback Kong Admin URL" >&2; exit 2 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
curl --fail --silent --show-error "$admin_url/status" > "$work/status.json"
curl --fail --silent --show-error "$admin_url/routes?size=1000" > "$work/routes.json"
curl --fail --silent --show-error "$admin_url/services?size=1000" > "$work/services.json"

plugins="$work/plugins.jsonl"
: > "$plugins"
while IFS=$'\t' read -r id name; do
  curl --fail --silent --show-error "$admin_url/routes/$id/plugins?size=1000" \
    | jq -c --arg name "$name" '{name:$name,plugins:([.data[]|select(.enabled==true)|.name]|sort)}' \
    >> "$plugins"
done < <(jq -r '.data[] | [.id,.name] | @tsv' "$work/routes.json")

jq -n \
  --slurpfile status "$work/status.json" \
  --slurpfile routes "$work/routes.json" \
  --slurpfile services "$work/services.json" \
  --slurpfile plugins "$plugins" \
  --arg captured_at "$(date --iso-8601=seconds)" '
  {
    schema:"codestra.kong.production-route-readback.v1",
    capturedAt:$captured_at,
    captureMode:"READ_ONLY_ADMIN_GET_SANITIZED",
    adminExposure:"LOOPBACK_ONLY",
    databaseReachable:($status[0].database.reachable == true),
    expectedRouteCount:29,
    actualRouteCount:($routes[0].data|length),
    secretsCaptured:false,
    runtimeMutated:false,
    routes:([$routes[0].data[] | . as $route |
      ($services[0].data[] | select(.id == $route.service.id)) as $service |
      ($plugins[] | select(.name == $route.name)) as $route_plugins |
      {name:$route.name,hosts:($route.hosts//[]),paths:($route.paths//[]),methods:($route.methods//[]),
       protocols:($route.protocols//[]),strip_path:$route.strip_path,preserve_host:$route.preserve_host,
       service:{name:$service.name,protocol:$service.protocol,host:$service.host,port:$service.port,
                connect_timeout:$service.connect_timeout,read_timeout:$service.read_timeout,
                write_timeout:$service.write_timeout},plugins:$route_plugins.plugins}]|sort_by(.name))
  }' > "$output"

jq -e '.actualRouteCount == .expectedRouteCount and .databaseReachable == true and
       .secretsCaptured == false and .runtimeMutated == false' "$output" >/dev/null
printf 'KONG_READ_ONLY_BASELINE=PASS ROUTES=%s OUTPUT=%s\n' "$(jq -r .actualRouteCount "$output")" "$output"
