#!/usr/bin/env bash
set -euo pipefail

chain=CODESTRA_KONG_EGRESS
mode=${1:-check}

case "$mode" in check|apply|remove) ;; *) echo "usage: $0 check|apply|remove" >&2; exit 2 ;; esac

if [[ "$mode" == remove ]]; then
  while iptables -C DOCKER-USER -j "$chain" 2>/dev/null; do iptables -D DOCKER-USER -j "$chain"; done
  iptables -F "$chain" 2>/dev/null || true
  iptables -X "$chain" 2>/dev/null || true
  exit 0
fi

: "${KONG_CONTAINER_LABEL:=com.docker.compose.service=kong-gateway}"
: "${KONG_EGRESS_TLS_CIDRS:?comma-separated approved TLS destination CIDRs required}"
: "${KONG_INTERNAL_CIDRS:?comma-separated approved internal destination CIDRs required}"

validate_cidrs() {
  local value=$1 cidr
  IFS=, read -ra entries <<<"$value"
  for cidr in "${entries[@]}"; do
    [[ "$cidr" != "0.0.0.0/0" && "$cidr" != "::/0" ]] || { echo "unrestricted destination rejected" >&2; exit 1; }
    python3 -c 'import ipaddress,sys; ipaddress.ip_network(sys.argv[1], strict=False)' "$cidr"
  done
}
validate_cidrs "$KONG_EGRESS_TLS_CIDRS"
validate_cidrs "$KONG_INTERNAL_CIDRS"

mapfile -t sources < <(docker ps --filter "label=$KONG_CONTAINER_LABEL" -q | xargs -r docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{"\n"}}{{end}}' | sed '/^$/d' | sort -u)
((${#sources[@]} > 0)) || { echo "no active Kong source addresses detected" >&2; exit 1; }

if [[ "$mode" == check ]]; then
  printf 'KONG_SOURCES=%s\n' "${sources[*]}"
  printf 'KONG_EGRESS_POLICY=VALID\n'
  exit 0
fi

iptables -N "$chain" 2>/dev/null || true
iptables -F "$chain"
for source in "${sources[@]}"; do
  IFS=, read -ra internal <<<"$KONG_INTERNAL_CIDRS"
  for cidr in "${internal[@]}"; do iptables -A "$chain" -s "$source" -d "$cidr" -j RETURN; done
  IFS=, read -ra tls <<<"$KONG_EGRESS_TLS_CIDRS"
  for cidr in "${tls[@]}"; do iptables -A "$chain" -s "$source" -d "$cidr" -p tcp --dport 443 -j RETURN; done
  iptables -A "$chain" -s "$source" -j REJECT
done
iptables -C DOCKER-USER -j "$chain" 2>/dev/null || iptables -I DOCKER-USER 1 -j "$chain"
