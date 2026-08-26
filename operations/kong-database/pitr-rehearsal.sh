#!/usr/bin/env bash
set -euo pipefail
umask 077

backup_root=/opt/codestra/backups/kong-database
stamp="$(cat "$backup_root/LAST_SUCCESS")"
dump="$backup_root/$stamp/kong.dump.gpg"
suffix="$(date -u +%Y%m%d%H%M%S)-$$"
network="kong-pitr-net-$suffix"
primary="kong-pitr-primary-$suffix"
recovery="kong-pitr-recovery-$suffix"
gateway="kong-pitr-gateway-$suffix"
subnet=10.254.47.0/28
work="$(mktemp -d /var/lib/codestra-kong-database/.pitr.XXXXXX)"
base="$work/base"
archive="$work/archive"
mkdir -p "$base" "$archive"
chown 999:999 "$base" "$archive"

cleanup() {
  docker rm -f "$gateway" "$recovery" "$primary" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  find "$work" -type f -delete 2>/dev/null || true
  find "$work" -depth -type d -empty -delete 2>/dev/null || true
}
trap cleanup EXIT

gpg --homedir /etc/codestra/backup-gpg --batch --quiet --decrypt "$dump" >"$work/kong.dump"
docker network create --internal --subnet "$subnet" "$network" >/dev/null
docker run -d --name "$primary" --network "$network" --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec \
  --tmpfs /var/run/postgresql:rw,nosuid,nodev,noexec,uid=999,gid=999 \
  --security-opt no-new-privileges --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETGID --cap-add SETUID \
  -e POSTGRES_DB=kong -e POSTGRES_USER=kong -e POSTGRES_HOST_AUTH_METHOD=trust \
  -v "$archive:/archive" -v "$base:/base" \
  postgres@sha256:0b657ff48d7f76a1e907f381b1693eb4f2bf54c1d2df4feb6743d7dc601768dd \
  -c wal_level=replica -c archive_mode=on \
  -c "archive_command=test ! -f /archive/%f && cp %p /archive/%f" \
  -c archive_timeout=5s >/dev/null
for _ in $(seq 1 30); do
  docker exec "$primary" pg_isready -U kong -d kong >/dev/null 2>&1 && break
  sleep 1
done
docker exec -i "$primary" pg_restore -U kong -d kong --exit-on-error --no-owner --no-acl \
  <"$work/kong.dump"
docker exec "$primary" psql -U kong -d kong -v ON_ERROR_STOP=1 -c \
  'create table codestra_pitr_marker(id integer primary key); insert into codestra_pitr_marker values (1); checkpoint;' >/dev/null
docker exec "$primary" pg_basebackup -U kong -D /base -Fp -X stream \
  -c fast -l codestra-kong-pitr-rehearsal >/dev/null
target_time="$(docker exec "$primary" psql -U kong -d kong -XAt -c 'select clock_timestamp()')"
sleep 1
docker exec "$primary" psql -U kong -d kong -v ON_ERROR_STOP=1 -c \
  'insert into codestra_pitr_marker values (2); select pg_switch_wal();' >/dev/null
for _ in $(seq 1 30); do
  archived="$(docker exec "$primary" psql -U kong -d kong -XAt -c \
    "select archived_count from pg_stat_archiver")"
  [[ "$archived" -gt 0 ]] && break
  sleep 1
done
test "$archived" -gt 0
docker stop -t 30 "$primary" >/dev/null

touch "$base/recovery.signal"
cat >>"$base/postgresql.auto.conf" <<EOF
restore_command = 'cp /archive/%f %p'
recovery_target_time = '$target_time'
recovery_target_action = 'promote'
EOF
chown 999:999 "$base/recovery.signal" "$base/postgresql.auto.conf"
docker run -d --name "$recovery" --network "$network" --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec \
  --tmpfs /var/run/postgresql:rw,nosuid,nodev,noexec,uid=999,gid=999 \
  --security-opt no-new-privileges --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETGID --cap-add SETUID \
  -v "$base:/var/lib/postgresql/data" -v "$archive:/archive:ro" \
  postgres@sha256:0b657ff48d7f76a1e907f381b1693eb4f2bf54c1d2df4feb6743d7dc601768dd >/dev/null
for _ in $(seq 1 60); do
  docker exec "$recovery" pg_isready -U kong -d kong >/dev/null 2>&1 && break
  sleep 1
done
test "$(docker exec "$recovery" psql -U kong -d kong -XAt -c \
  'select count(*) from codestra_pitr_marker')" -eq 1
for _ in $(seq 1 30); do
  [[ "$(docker exec "$recovery" psql -U kong -d kong -XAt -c \
    'select pg_is_in_recovery()')" == f ]] && break
  sleep 1
done
test "$(docker exec "$recovery" psql -U kong -d kong -XAt -c \
  'select pg_is_in_recovery()')" = f
docker exec "$recovery" psql -U kong -d kong -XAt -c \
  'drop table codestra_pitr_marker' >/dev/null

docker run -d --name "$gateway" --network "$network" --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec --security-opt no-new-privileges --cap-drop ALL \
  -e KONG_DATABASE=postgres -e KONG_PG_HOST="$recovery" -e KONG_PG_DATABASE=kong \
  -e KONG_PG_USER=kong -e KONG_PREFIX=/tmp/kong \
  -e KONG_PLUGINS=bundled,codestra-gateway-identity \
  -e KONG_PROXY_LISTEN=off -e KONG_ADMIN_LISTEN=0.0.0.0:8001 \
  -v /opt/codestra/kong/plugins/codestra-gateway-identity:/usr/local/share/lua/5.1/kong/plugins/codestra-gateway-identity:ro \
  kong/kong-gateway:3.14.0.1-ubuntu >/dev/null
for _ in $(seq 1 60); do
  docker exec "$gateway" kong health >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$gateway" kong health >/dev/null
evidence_dir="/var/lib/codestra-kong-database/evidence/pitr/$suffix"
mkdir -p "$evidence_dir"
chmod 0700 "$evidence_dir"
cat >"$evidence_dir/result.txt" <<EOF
WAL_ARCHIVE_REHEARSAL=PASS
PITR_REHEARSAL=PASS
BACKUP_TIMESTAMP=$stamp
ARCHIVED_SEGMENTS=$archived
RECOVERED_MARKER_ROWS=1
KONG_SCHEMA_BOOT=PASS
PUBLIC_PORTS=0
EOF
printf '%s\n' "$suffix" >/var/lib/codestra-kong-database/LAST_PITR_SUCCESS
echo 'WAL_ARCHIVE_REHEARSAL=PASS'
echo 'PITR_REHEARSAL=PASS'
echo "ARCHIVED_SEGMENTS=$archived"
echo 'RECOVERED_MARKER_ROWS=1'
echo 'KONG_SCHEMA_BOOT=PASS'
echo "PITR_EVIDENCE=$evidence_dir/result.txt"
