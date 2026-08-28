#!/usr/bin/env bash
set -euo pipefail
umask 077

backup_root=/opt/codestra/backups/kong-database
evidence_root=/var/lib/codestra-kong-database/evidence
stamp="$(cat "$backup_root/LAST_SUCCESS")"
source_dir="$backup_root/$stamp"
start_epoch="$(date +%s)"
suffix="$(date -u +%Y%m%d%H%M%S)-$$"
db_name="kong-restore-db-$suffix"
gateway_name="kong-restore-gateway-$suffix"
network_name="kong-restore-net-$suffix"
network_subnet=10.254.45.0/28
volume_name="kong-restore-data-$suffix"
mkdir -p /var/lib/codestra-kong-database "$evidence_root"
chmod 0700 /var/lib/codestra-kong-database "$evidence_root"
work_dir="$(mktemp -d /var/lib/codestra-kong-database/.restore.XXXXXX)"
evidence_dir="$evidence_root/$suffix"

cleanup() {
  docker rm -f "$gateway_name" "$db_name" >/dev/null 2>&1 || true
  docker volume rm "$volume_name" >/dev/null 2>&1 || true
  docker network rm "$network_name" >/dev/null 2>&1 || true
  find "$work_dir" -type f -delete 2>/dev/null || true
  rmdir "$work_dir" 2>/dev/null || true
}
trap cleanup EXIT

test "$(id -u)" -eq 0
test -f "$source_dir/kong.dump.gpg"
test -f "$source_dir/SHA256SUMS"
(cd "$source_dir" && sha256sum -c SHA256SUMS >/dev/null)
gpg --homedir /etc/codestra/backup-gpg --batch --quiet \
  --decrypt "$source_dir/kong.dump.gpg" >"$work_dir/kong.dump"
docker exec -i codestra-kong-kong-db-1 pg_restore --list \
  <"$work_dir/kong.dump" >/dev/null

mkdir -p "$evidence_dir"
chmod 0700 "$evidence_root" "$evidence_dir"
docker network create --internal --subnet "$network_subnet" "$network_name" >/dev/null
docker volume create "$volume_name" >/dev/null
docker run -d --name "$db_name" --network "$network_name" \
  --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec \
  --tmpfs /var/run/postgresql:rw,nosuid,nodev,noexec,uid=999,gid=999 \
  --security-opt no-new-privileges --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --cap-add SETGID --cap-add SETUID \
  -e POSTGRES_DB=kong -e POSTGRES_USER=kong \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -v "$volume_name:/var/lib/postgresql/data" \
  postgres@sha256:0b657ff48d7f76a1e907f381b1693eb4f2bf54c1d2df4feb6743d7dc601768dd \
  >/dev/null
for _ in $(seq 1 30); do
  docker exec "$db_name" pg_isready -U kong -d kong >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$db_name" pg_isready -U kong -d kong >/dev/null
docker exec -i "$db_name" pg_restore -U kong -d kong \
  --exit-on-error --no-owner --no-acl <"$work_dir/kong.dump"

kong_inventory() {
  local origin="$1" collection="$2" next page records
  next="$origin/$collection?size=1000"
  records="$(mktemp "$work_dir/.${collection}.XXXXXX")"
  while [[ -n "$next" ]]; do
    case "$next" in
      "$origin"/*) ;;
      /*) next="$origin$next" ;;
      *) echo "unsafe Kong pagination URL: $next" >&2; return 1 ;;
    esac
    page="$(curl -fsS "$next")"
    jq -c '.data[] | {id, name}' <<<"$page" >>"$records"
    next="$(jq -r '.next // empty' <<<"$page")"
  done
  printf '%s|%s\n' \
    "$(wc -l <"$records")" \
    "$(LC_ALL=C sort "$records" | sha256sum | awk '{print $1}')"
}

live_services_inventory="$(kong_inventory http://127.0.0.1:8001 services)"
live_routes_inventory="$(kong_inventory http://127.0.0.1:8001 routes)"
live_plugins_inventory="$(kong_inventory http://127.0.0.1:8001 plugins)"

docker run -d --name "$gateway_name" --network "$network_name" \
  --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec \
  --security-opt no-new-privileges --cap-drop ALL \
  -e KONG_DATABASE=postgres -e KONG_PG_HOST="$db_name" \
  -e KONG_PREFIX=/tmp/kong \
  -e KONG_PG_PORT=5432 -e KONG_PG_DATABASE=kong -e KONG_PG_USER=kong \
  -e KONG_PG_PASSWORD=isolated-restore-only \
  -e KONG_PLUGINS=bundled,codestra-gateway-identity \
  -e KONG_PROXY_LISTEN=off -e KONG_ADMIN_LISTEN=0.0.0.0:8001 \
  -e KONG_STATUS_LISTEN=0.0.0.0:8100 \
  -v /opt/codestra/kong/plugins/codestra-gateway-identity:/usr/local/share/lua/5.1/kong/plugins/codestra-gateway-identity:ro \
  kong/kong-gateway:3.14.0.1-ubuntu >/dev/null
restore_ip="$(docker inspect "$gateway_name" --format "{{(index .NetworkSettings.Networks \"$network_name\").IPAddress}}")"
for _ in $(seq 1 60); do
  curl -fsS "http://$restore_ip:8001/status" >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$gateway_name" kong health >/dev/null
restored_services_inventory="$(kong_inventory "http://$restore_ip:8001" services)"
restored_routes_inventory="$(kong_inventory "http://$restore_ip:8001" routes)"
restored_plugins_inventory="$(kong_inventory "http://$restore_ip:8001" plugins)"
test "$restored_services_inventory" = "$live_services_inventory"
test "$restored_routes_inventory" = "$live_routes_inventory"
test "$restored_plugins_inventory" = "$live_plugins_inventory"
restored_services="${restored_services_inventory%%|*}"
restored_routes="${restored_routes_inventory%%|*}"
restored_plugins="${restored_plugins_inventory%%|*}"

rto_seconds="$(( $(date +%s) - start_epoch ))"
cat >"$evidence_dir/result.txt" <<EOF
RESTORE_TEST=PASS
RESTORE_BACKUP_TIMESTAMP=$stamp
RESTORE_RTO_SECONDS=$rto_seconds
SERVICES=$restored_services
ROUTES=$restored_routes
PLUGINS=$restored_plugins
ISOLATED_NETWORK=YES
PUBLIC_PORTS=0
EOF
printf '%s\n' "$suffix" >/var/lib/codestra-kong-database/LAST_RESTORE_SUCCESS
echo "KONG_DATABASE_RESTORE_CERTIFICATION=PASS"
echo "RESTORE_BACKUP_TIMESTAMP=$stamp"
echo "RESTORE_RTO_SECONDS=$rto_seconds"
echo "RESTORE_EVIDENCE=$evidence_dir/result.txt"
