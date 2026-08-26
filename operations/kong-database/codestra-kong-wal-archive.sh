#!/usr/bin/env bash
set -euo pipefail
umask 077

test "$(id -u)" -eq 0
source_path="$1"
wal_name="$2"
[[ "$wal_name" =~ ^([0-9A-F]{24}(\.[0-9A-F]{8}\.backup)?|[0-9A-F]{8}\.history)$ ]]
[[ "$source_path" != *..* && -f "$source_path" ]]

spool=/opt/codestra/backups/kong-database/wal
recipient='Codestra Backup Recipient'
artifact="$spool/$wal_name.gpg"
mkdir -p "$spool"
chmod 0700 "$spool"
if [[ ! -s "$artifact" ]]; then
  temporary="$(mktemp "$spool/.${wal_name}.XXXXXX")"
  trap 'rm -f "$temporary"' EXIT
  gpg --homedir /etc/codestra/backup-gpg --batch --yes --trust-model always \
    --recipient "$recipient" --encrypt --output "$temporary" "$source_path"
  mv "$temporary" "$artifact"
  sha256sum "$artifact" >"$artifact.sha256"
fi

RESTIC_REPOSITORY="$(cat /etc/codestra/backup/restic-repository)"
AWS_ACCESS_KEY_ID="$(cat /etc/codestra/backup/b2-access-key-id)"
AWS_SECRET_ACCESS_KEY="$(cat /etc/codestra/backup/b2-secret-access-key)"
AWS_DEFAULT_REGION="$(cat /etc/codestra/backup/b2-region)"
export RESTIC_REPOSITORY AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
export RESTIC_PASSWORD_FILE=/etc/codestra/backup/restic-password
export RESTIC_CACHE_DIR=/opt/codestra/backups/kong-database/.restic-cache
restic backup --quiet --tag kong-database-wal "$artifact" "$artifact.sha256"
touch "$spool/LAST_OFFHOST_SUCCESS"
