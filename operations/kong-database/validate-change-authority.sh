#!/usr/bin/env bash
set -uo pipefail

file="${1:-}"
declare -A cfg=()
parse_ok=1

if [[ -z "$file" || ! -f "$file" || -L "$file" ]]; then
  parse_ok=0
else
  mode="$(stat -c '%a' "$file" 2>/dev/null || true)"
  [[ "$mode" == 400 || "$mode" == 600 ]] || parse_ok=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    if [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      value="${BASH_REMATCH[2]}"
      [[ -v "cfg[$key]" ]] && parse_ok=0
      cfg["$key"]="$value"
    else
      parse_ok=0
    fi
  done <"$file"
fi

valid_value() {
  local value="${cfg[$1]:-}"
  [[ -n "$value" ]] || return 1
  [[ ! "$value" =~ (^|_)(REQUIRED|PENDING|UNKNOWN|UNASSIGNED|NOT_ASSIGNED|NOT_APPROVED|NOT_CONFIGURED)($|_) ]]
}

all_values() {
  local key
  for key in "$@"; do valid_value "$key" || return 1; done
}

gate_change=FAIL
if [[ "$parse_ok" -eq 1 ]] && all_values KONG_CHANGE_ID KONG_CHANGE_STATUS \
  && [[ "${cfg[KONG_CHANGE_STATUS]}" == APPROVED ]]; then gate_change=PASS; fi

owner_keys=(KONG_CHANGE_OWNER KONG_DATABASE_OWNER KONG_PLATFORM_OWNER
  KONG_ROLLBACK_OWNER KONG_CANARY_OWNER KONG_FAILOVER_OWNER KONG_FENCING_OWNER
  KONG_DNS_OWNER KONG_SECRET_OWNER KONG_ROTATION_OWNER KONG_TELEPHONY_OPERATOR_OWNER)
gate_owners=FAIL
all_values "${owner_keys[@]}" && gate_owners=PASS

gate_window=FAIL
if all_values KONG_MAINTENANCE_START KONG_MAINTENANCE_END KONG_TIMEZONE \
    KONG_FAILOVER_REHEARSAL_WINDOW KONG_LOAD_SOAK_WINDOW \
  && [[ -e "/usr/share/zoneinfo/${cfg[KONG_TIMEZONE]}" ]] \
  && [[ "${cfg[KONG_MAINTENANCE_START]}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})$ ]] \
  && [[ "${cfg[KONG_MAINTENANCE_END]}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})$ ]]; then
  start_epoch="$(date -d "${cfg[KONG_MAINTENANCE_START]}" +%s 2>/dev/null || true)"
  end_epoch="$(date -d "${cfg[KONG_MAINTENANCE_END]}" +%s 2>/dev/null || true)"
  now_epoch="$(date +%s)"
  if [[ "$start_epoch" =~ ^[0-9]+$ && "$end_epoch" =~ ^[0-9]+$ ]] \
    && (( start_epoch < end_epoch && now_epoch >= start_epoch && now_epoch <= end_epoch )); then
    gate_window=PASS
  fi
fi

gate_replica=FAIL
if all_values KONG_DB_REPLICA_HOST KONG_DB_REPLICA_IP KONG_DB_REPLICA_CIDR \
    KONG_DB_FAILURE_DOMAIN KONG_DB_REPLICA_PROVIDER KONG_DB_REPLICA_STORAGE \
    KONG_DB_REPLICA_TLS_IDENTITY \
  && python3 - "${cfg[KONG_DB_REPLICA_IP]}" "${cfg[KONG_DB_REPLICA_CIDR]}" <<'PY'
import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
network = ipaddress.ip_network(sys.argv[2], strict=False)
raise SystemExit(0 if address.is_private and address in network else 1)
PY
then gate_replica=PASS; fi

gate_dns=FAIL
if all_values KONG_DB_STABLE_AUTHORITY KONG_DB_DNS_BACKEND KONG_DB_DNS_OWNER \
    KONG_DB_DNS_TTL_SECONDS KONG_DB_PROMOTION_MUTATION_OWNER \
  && [[ "${cfg[KONG_DB_STABLE_AUTHORITY]}" == kong-db.internal.codestra.agency ]] \
  && [[ "${cfg[KONG_DB_DNS_TTL_SECONDS]}" =~ ^[1-9][0-9]*$ ]] \
  && command -v dig >/dev/null 2>&1; then
  public_a="$(dig +time=3 +tries=1 +short A "${cfg[KONG_DB_STABLE_AUTHORITY]}" @1.1.1.1 2>/dev/null)"; a_status=$?
  public_aaaa="$(dig +time=3 +tries=1 +short AAAA "${cfg[KONG_DB_STABLE_AUTHORITY]}" @1.1.1.1 2>/dev/null)"; aaaa_status=$?
  if [[ "$a_status" -eq 0 && "$aaaa_status" -eq 0 && -z "$public_a" && -z "$public_aaaa" ]]; then
    gate_dns=PASS
  fi
fi

gate_fencing=FAIL
all_values KONG_DB_FENCING_PROVIDER KONG_DB_FENCING_OWNER KONG_DB_FENCE_ACTION \
  KONG_DB_FENCE_VERIFY_ACTION KONG_DB_UNFENCE_ACTION && gate_fencing=PASS

gate_secrets=FAIL
if all_values KONG_DB_SECRET_AUTHORITY KONG_DB_SECRET_OWNER KONG_DB_ROTATION_OWNER \
    KONG_DB_ROTATION_INTERVAL_DAYS KONG_DB_BREAK_GLASS_POLICY \
  && [[ "${cfg[KONG_DB_ROTATION_INTERVAL_DAYS]}" =~ ^[1-9][0-9]*$ ]]; then gate_secrets=PASS; fi

gate_rpo=FAIL
if all_values KONG_DB_RPO_SECONDS KONG_DB_RTO_SECONDS KONG_DB_WAL_RETENTION_DAYS \
    KONG_DB_BASE_BACKUP_RETENTION KONG_DB_LOGICAL_BACKUP_RETENTION \
  && [[ "${cfg[KONG_DB_RPO_SECONDS]}" =~ ^[1-9][0-9]*$ ]] \
  && [[ "${cfg[KONG_DB_RTO_SECONDS]}" =~ ^[1-9][0-9]*$ ]] \
  && [[ "${cfg[KONG_DB_WAL_RETENTION_DAYS]}" =~ ^[1-9][0-9]*$ ]]; then gate_rpo=PASS; fi

evidence_file() {
  valid_value "$1" || return 1
  local key="$1" path="${cfg[$1]}" expected
  [[ -s "$path" && ! -L "$path" ]] || return 1
  case "$key" in
    KONG_BACKUP_EVIDENCE) expected=BACKUP ;;
    KONG_OFFHOST_BACKUP_EVIDENCE) expected=OFFHOST ;;
    KONG_RESTORE_EVIDENCE) expected=RESTORE_TEST ;;
    KONG_PITR_REHEARSAL_EVIDENCE) expected=PITR_REHEARSAL ;;
    KONG_ROLLBACK_EVIDENCE) expected=ROLLBACK ;;
    KONG_TELEPHONY_EVIDENCE) expected=TELEPHONY ;;
    *) return 1 ;;
  esac
  grep -Fxq "${expected}=PASS" "$path"
}
fresh_evidence() {
  evidence_file "$1" || return 1
  local modified now
  modified="$(stat -c %Y "${cfg[$1]}")"; now="$(date +%s)"
  (( now - modified < 86400 ))
}

gate_canary=FAIL
if all_values KONG_TELEPHONY_CANARY_AUTHORITY \
  && evidence_file KONG_TELEPHONY_EVIDENCE; then gate_canary=PASS; fi

gate_evidence=FAIL
if fresh_evidence KONG_BACKUP_EVIDENCE && fresh_evidence KONG_OFFHOST_BACKUP_EVIDENCE \
  && evidence_file KONG_RESTORE_EVIDENCE && evidence_file KONG_PITR_REHEARSAL_EVIDENCE \
  && evidence_file KONG_ROLLBACK_EVIDENCE; then gate_evidence=PASS; fi

printf 'CHANGE_RECORD=%s\n' "$gate_change"
printf 'OWNERSHIP=%s\n' "$gate_owners"
printf 'MAINTENANCE_WINDOW=%s\n' "$gate_window"
printf 'REPLICA_INFRASTRUCTURE=%s\n' "$gate_replica"
printf 'STABLE_AUTHORITY=%s\n' "$gate_dns"
printf 'FENCING=%s\n' "$gate_fencing"
printf 'SECRET_GOVERNANCE=%s\n' "$gate_secrets"
printf 'RPO_RTO_POLICY=%s\n' "$gate_rpo"
printf 'CANARY_AUTHORITY=%s\n' "$gate_canary"
printf 'RECOVERY_EVIDENCE=%s\n' "$gate_evidence"

if [[ "$parse_ok" -eq 1 && "$gate_change" == PASS && "$gate_owners" == PASS \
  && "$gate_window" == PASS && "$gate_replica" == PASS && "$gate_dns" == PASS \
  && "$gate_fencing" == PASS && "$gate_secrets" == PASS && "$gate_rpo" == PASS \
  && "$gate_canary" == PASS && "$gate_evidence" == PASS ]]; then
  echo 'KONG_DB_CUTOVER_GO=YES'
  exit 0
fi
echo 'KONG_DB_CUTOVER_GO=NO'
for gate in CHANGE_RECORD OWNERSHIP MAINTENANCE_WINDOW REPLICA_INFRASTRUCTURE \
  STABLE_AUTHORITY FENCING SECRET_GOVERNANCE RPO_RTO_POLICY CANARY_AUTHORITY \
  RECOVERY_EVIDENCE; do
  case "$gate" in
    CHANGE_RECORD) value="$gate_change" ;;
    OWNERSHIP) value="$gate_owners" ;;
    MAINTENANCE_WINDOW) value="$gate_window" ;;
    REPLICA_INFRASTRUCTURE) value="$gate_replica" ;;
    STABLE_AUTHORITY) value="$gate_dns" ;;
    FENCING) value="$gate_fencing" ;;
    SECRET_GOVERNANCE) value="$gate_secrets" ;;
    RPO_RTO_POLICY) value="$gate_rpo" ;;
    CANARY_AUTHORITY) value="$gate_canary" ;;
    RECOVERY_EVIDENCE) value="$gate_evidence" ;;
  esac
  if [[ "$value" != PASS ]]; then
    printf 'BLOCKED_BY=%s\n' "$gate"
    break
  fi
done
exit 1
