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
: "${KONG_EGRESS_NETWORK_LABEL:=codestra.egress.scope=kong}"
: "${KONG_EGRESS_TLS_CIDRS:?comma-separated approved TLS destination CIDRs required}"
: "${KONG_INTERNAL_CIDRS:?comma-separated approved internal destination CIDRs required}"

validate_cidrs() {
  local value=$1 cidr
  IFS=, read -ra entries <<<"$value"
  for cidr in "${entries[@]}"; do
    python3 -c 'import ipaddress,sys
n=ipaddress.ip_network(sys.argv[1], strict=False)
assert n.version == 4, "IPv6 policy is not supported; disable IPv6 on governed networks"
assert n.prefixlen != 0, "unrestricted destination rejected"
' "$cidr"
  done
}
validate_cidrs "$KONG_EGRESS_TLS_CIDRS"
validate_cidrs "$KONG_INTERNAL_CIDRS"

mapfile -t containers < <(docker ps --filter "label=$KONG_CONTAINER_LABEL" -q)
((${#containers[@]} > 0)) || { echo "no active Kong containers detected" >&2; exit 1; }
mapfile -t attached_networks < <(docker inspect "${containers[@]}" --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{"\n"}}{{end}}' | sed '/^$/d' | sort -u)
mapfile -t governed_networks < <(docker network ls --filter "label=$KONG_EGRESS_NETWORK_LABEL" -q)
((${#governed_networks[@]} > 0)) || { echo "no governed Kong egress networks detected" >&2; exit 1; }

declare -a interfaces=()
for network_name in "${attached_networks[@]}"; do
  network_json=$(docker network inspect "$network_name")
  internal=$(jq -r '.[0].Internal' <<<"$network_json")
  [[ "$internal" == true ]] && continue
  network_id=$(jq -r '.[0].Id' <<<"$network_json")
  labels=$(jq -r '.[0].Labels // {} | to_entries[] | "\(.key)=\(.value)"' <<<"$network_json")
  grep -Fxq "$KONG_EGRESS_NETWORK_LABEL" <<<"$labels" || {
    echo "non-internal Kong network lacks governance label: $network_name" >&2
    exit 1
  }
  [[ $(jq -r '.[0].Driver' <<<"$network_json") == bridge ]] || { echo "governed network must use bridge driver" >&2; exit 1; }
  [[ $(jq -r '.[0].EnableIPv6' <<<"$network_json") == false ]] || { echo "IPv6 must be disabled on governed network" >&2; exit 1; }
  bridge=$(jq -r '.[0].Options["com.docker.network.bridge.name"] // empty' <<<"$network_json")
  [[ -n "$bridge" ]] || bridge="br-${network_id:0:12}"
  interfaces+=("$bridge")
done
((${#interfaces[@]} > 0)) || { echo "no governed external Kong interfaces detected" >&2; exit 1; }

mapfile -t sources < <(docker inspect "${containers[@]}" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{"\n"}}{{end}}' | sed '/^$/d' | sort -u)
((${#sources[@]} > 0)) || { echo "no active Kong source addresses detected" >&2; exit 1; }

if [[ "$mode" == check ]]; then
  printf 'KONG_SOURCES=%s\n' "${sources[*]}"
  printf 'KONG_GOVERNED_INTERFACES=%s\n' "${interfaces[*]}"
  printf 'KONG_EGRESS_POLICY=VALID\n'
  exit 0
fi

iptables -N "$chain" 2>/dev/null || true
iptables -F "$chain"
for interface in "${interfaces[@]}"; do
  ip link show "$interface" >/dev/null
  iptables -A "$chain" -i "$interface" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  IFS=, read -ra internal <<<"$KONG_INTERNAL_CIDRS"
  for cidr in "${internal[@]}"; do iptables -A "$chain" -i "$interface" -d "$cidr" -j RETURN; done
  IFS=, read -ra tls <<<"$KONG_EGRESS_TLS_CIDRS"
  for cidr in "${tls[@]}"; do iptables -A "$chain" -i "$interface" -d "$cidr" -p tcp --dport 443 -j RETURN; done
  iptables -A "$chain" -i "$interface" -j REJECT
done
iptables -C DOCKER-USER -j "$chain" 2>/dev/null || iptables -I DOCKER-USER 1 -j "$chain"
