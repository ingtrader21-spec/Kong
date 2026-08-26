#!/usr/bin/env bash
set -euo pipefail
umask 077

db_container=codestra-kong-kong-db-1
backup_root=/opt/codestra/backups/kong-database
recipient='Codestra Backup Recipient'
restic_repository_file=/etc/codestra/backup/restic-repository
restic_password_file=/etc/codestra/backup/restic-password
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
final_dir="$backup_root/$stamp"
mkdir -p "$backup_root"
chmod 0700 "$backup_root"
work_dir="$(mktemp -d "$backup_root/.work.XXXXXX")"

cleanup() {
  find "$work_dir" -type f -delete 2>/dev/null || true
  rmdir "$work_dir" 2>/dev/null || true
}
trap cleanup EXIT

test "$(id -u)" -eq 0
for path in "$restic_repository_file" "$restic_password_file" \
  /etc/codestra/backup/b2-access-key-id \
  /etc/codestra/backup/b2-secret-access-key \
  /etc/codestra/backup/b2-region; do
  test -r "$path"
  test ! -L "$path"
done
gpg --homedir /etc/codestra/backup-gpg --batch --list-keys "$recipient" >/dev/null
docker inspect "$db_container" >/dev/null
mkdir -p "$final_dir"
chmod 0700 "$final_dir"

docker exec "$db_container" pg_dump \
  -U kong -d kong --format=custom --no-owner --no-acl \
  | gpg --homedir /etc/codestra/backup-gpg --batch --yes \
      --trust-model always --recipient "$recipient" --encrypt \
      --output "$final_dir/kong.dump.gpg"

gpg --homedir /etc/codestra/backup-gpg --batch --quiet \
  --decrypt "$final_dir/kong.dump.gpg" \
  | docker exec -i "$db_container" pg_restore --list >/dev/null

(
  cd "$final_dir"
  sha256sum kong.dump.gpg > SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
)
cat >"$final_dir/MANIFEST" <<EOF
BACKUP_TIMESTAMP=$stamp
DATABASE=kong
ENGINE=PostgreSQL
FORMAT=pg_dump_custom_gpg
SOURCE_CONTAINER=$db_container
EOF

RESTIC_REPOSITORY="$(cat "$restic_repository_file")"
AWS_ACCESS_KEY_ID="$(cat /etc/codestra/backup/b2-access-key-id)"
AWS_SECRET_ACCESS_KEY="$(cat /etc/codestra/backup/b2-secret-access-key)"
AWS_DEFAULT_REGION="$(cat /etc/codestra/backup/b2-region)"
export RESTIC_REPOSITORY AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
export RESTIC_PASSWORD_FILE="$restic_password_file"
export RESTIC_CACHE_DIR="$backup_root/.restic-cache"
restic_retry() {
  local attempt
  for attempt in 1 2 3; do
    if restic "$@"; then
      return 0
    fi
    sleep "$((attempt * 5))"
  done
  return 1
}
echo 'BACKUP_PHASE=OFFHOST_UPLOAD'
restic_retry backup --quiet --tag kong-database "$final_dir"
echo 'BACKUP_PHASE=RETENTION'
restic_retry forget --quiet --tag kong-database \
  --keep-daily 14 --keep-weekly 8 --keep-monthly 12
echo 'BACKUP_PHASE=OFFHOST_VERIFY'
restic_retry snapshots --json --latest 1 --tag kong-database \
  | jq -e 'length >= 1' >/dev/null
unset RESTIC_REPOSITORY RESTIC_PASSWORD_FILE RESTIC_CACHE_DIR AWS_ACCESS_KEY_ID \
  AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION

printf '%s\n' "$stamp" >"$backup_root/LAST_SUCCESS"
chmod 0600 "$backup_root/LAST_SUCCESS"
echo "KONG_BACKUP_AUTOMATED=PASS"
echo "KONG_BACKUP_CHECKSUM=PASS"
echo "KONG_OFFHOST_BACKUP=PASS"
echo "KONG_BACKUP_TIMESTAMP=$stamp"
