#!/usr/bin/env bash
set -euo pipefail
umask 077

backup_root=/opt/codestra/backups/kong-database
stamp="$(cat "$backup_root/LAST_SUCCESS")"
dump="$backup_root/$stamp/kong.dump.gpg"
suffix="$(date -u +%Y%m%d%H%M%S)-$$"
network="kong-lp-net-$suffix"
volume="kong-lp-data-$suffix"
db="kong-lp-db-$suffix"
gateway="kong-lp-gateway-$suffix"
subnet=10.254.46.0/28
admin_password="$(openssl rand -hex 24)"
runtime_password="$(openssl rand -hex 24)"
work="$(mktemp -d /var/lib/codestra-kong-database/.lp.XXXXXX)"

cleanup() {
  docker rm -f "$gateway" "$db" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  find "$work" -type f -delete 2>/dev/null || true
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT

gpg --homedir /etc/codestra/backup-gpg --batch --quiet --decrypt "$dump" >"$work/kong.dump"
docker network create --internal --subnet "$subnet" "$network" >/dev/null
docker volume create "$volume" >/dev/null
docker run -d --name "$db" --network "$network" --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec \
  --tmpfs /var/run/postgresql:rw,nosuid,nodev,noexec,uid=999,gid=999 \
  --security-opt no-new-privileges --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETGID --cap-add SETUID \
  -e POSTGRES_DB=kong -e POSTGRES_USER=kong_migration_admin \
  -e POSTGRES_PASSWORD="$admin_password" \
  -v "$volume:/var/lib/postgresql/data" \
  postgres@sha256:0b657ff48d7f76a1e907f381b1693eb4f2bf54c1d2df4feb6743d7dc601768dd >/dev/null
for _ in $(seq 1 30); do
  docker exec "$db" pg_isready -U kong_migration_admin -d kong >/dev/null 2>&1 && break
  sleep 1
done
docker exec -i "$db" pg_restore -U kong_migration_admin -d kong \
  --exit-on-error --no-owner --no-acl <"$work/kong.dump"
docker exec -i -e PGPASSWORD="$admin_password" "$db" psql -h 127.0.0.1 \
  -U kong_migration_admin -d kong -v ON_ERROR_STOP=1 \
  <operations/kong-database/roles.sql >/dev/null
docker exec -e PGPASSWORD="$admin_password" "$db" psql -h 127.0.0.1 \
  -U kong_migration_admin -d kong -v ON_ERROR_STOP=1 \
  -c "ALTER ROLE kong_runtime PASSWORD '$runtime_password'" >/dev/null

docker run -d --name "$gateway" --network "$network" --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec --security-opt no-new-privileges --cap-drop ALL \
  -e KONG_DATABASE=postgres -e KONG_PG_HOST="$db" -e KONG_PG_DATABASE=kong \
  -e KONG_PG_USER=kong_runtime -e KONG_PG_PASSWORD="$runtime_password" \
  -e KONG_PREFIX=/tmp/kong -e KONG_PLUGINS=bundled,codestra-gateway-identity \
  -e KONG_PROXY_LISTEN=0.0.0.0:8000 -e KONG_ADMIN_LISTEN=0.0.0.0:8001 \
  -v /opt/codestra/kong/plugins/codestra-gateway-identity:/usr/local/share/lua/5.1/kong/plugins/codestra-gateway-identity:ro \
  kong/kong-gateway:3.14.0.1-ubuntu >/dev/null
for _ in $(seq 1 60); do
  docker exec "$gateway" kong health >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$gateway" kong health >/dev/null
gateway_ip="$(docker inspect "$gateway" --format "{{(index .NetworkSettings.Networks \"$network\").IPAddress}}")"
curl -fsS "http://$gateway_ip:8001/services?size=1" | jq -e '.data|type=="array"' >/dev/null
curl -fsS "http://$gateway_ip:8001/plugins?size=1" | jq -e '.data|type=="array"' >/dev/null
curl -fsS -X POST "http://$gateway_ip:8001/services" \
  --data name=least-privilege-rehearsal --data url=http://127.0.0.1:9 >/dev/null
curl -fsS -X DELETE "http://$gateway_ip:8001/services/least-privilege-rehearsal" >/dev/null
docker exec -e PGPASSWORD="$runtime_password" "$db" psql -h 127.0.0.1 \
  -U kong_runtime -d kong -v ON_ERROR_STOP=1 -c 'select count(*) from services' >/dev/null
if docker exec -e PGPASSWORD="$runtime_password" "$db" psql -h 127.0.0.1 \
  -U kong_runtime -d kong -v ON_ERROR_STOP=1 -c 'create table must_be_denied(id int)' >/dev/null 2>&1; then
  echo 'MIGRATION_PRIVILEGE_ISOLATION=FAIL' >&2
  exit 1
fi
echo 'KONG_DB_LEAST_PRIVILEGE_REHEARSAL=PASS'
echo 'RUNTIME_ROLE_SUPERUSER=NO'
echo 'ADMIN_READ_WRITE=PASS'
echo 'MIGRATION_PRIVILEGE_ISOLATION=PASS'
