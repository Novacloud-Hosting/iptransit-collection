#!/usr/bin/env bash

# Exit on error, undefined variable, or pipe failure
set -euo pipefail

# Error handler: reports line number and exit code
error_handler() {
    local exit_code=$?
    echo "Error on line $1: exit code ${exit_code}" >&2
    exit "${exit_code}"
}
trap 'error_handler $LINENO' ERR

# Usage message
usage() {
    echo "Usage: $0 <config_file> <up|down>"
    exit 1
}

preprocess_address() {
    ipv4_addrs=(); ipv6_addrs=()
    if declare -p ADDRESSES >/dev/null 2>&1; then
        for addr in "${ADDRESSES[@]}"; do
            [[ "$addr" == *:* ]] && ipv6_addrs+=("$addr") || ipv4_addrs+=("$addr")
        done
    fi
}

# Process: create or delete tunnel
process_tunnel() {
    if [[ "$action" == "up" ]]; then
        # Create tunnel
        [[ -n "${TUNNEL_TYPE:-}" && -n "${GATEWAY_IPV4:-}" && -n "${GATEWAY_IPV6:-}" && -n "${ADDRESSES:-}" ]] || { echo "Error: TUNNEL_TYPE, GATEWAY_IPV4, GATEWAY_IPV6 or ADDRESSES not set" >&2; exit 1; }
        case "$TUNNEL_TYPE" in
            gre|gretap)
                [[ -n "${ENDPOINT_REMOTE:-}" && -n "${ENDPOINT_LOCAL:-}" ]] || { echo "Error: ENDPOINT_REMOTE or ENDPOINT_LOCAL not set" >&2; exit 1; }
                is_ipv6=false; [[ "${ENDPOINT_REMOTE}" == *:* ]] && is_ipv6=true
                if [[ "${is_ipv6}" == true ]]; then type_name="ip6${TUNNEL_TYPE}"; else type_name="$TUNNEL_TYPE"; fi
                args=(name "$TUNNEL_IF" type "$type_name" remote "$ENDPOINT_REMOTE" local "$ENDPOINT_LOCAL")
                [[ -n "${GRE_KEY:-}" ]] && args+=(key "${GRE_KEY}")
                if ! ip link show dev "$TUNNEL_IF" >/dev/null 2>&1; then
                    ip link add "${args[@]}" || { echo "Failed to create $type_name" >&2; exit 1; }
                    ip link set dev "$TUNNEL_IF" up || { echo "Failed to set $TUNNEL_IF up" >&2; exit 1; }
                    echo "$type_name tunnel created"
                else
                    echo "Warning: $TUNNEL_IF already exists. Is it already up?"
                fi
                ;;
            vxlan)
                [[ -n "${VXLAN_VNI:-}" && -n "${VXLAN_PORT:-}" && -n "${ENDPOINT_REMOTE:-}" && -n "${ENDPOINT_LOCAL:-}" ]] || { echo "Error: VXLAN_VNI, VXLAN_PORT, ENDPOINT_REMOTE, or ENDPOINT_LOCAL not set" >&2; exit 1; }
                type_name="vxlan"
                args=(name "$TUNNEL_IF" type "$type_name" id "$VXLAN_VNI" dstport "$VXLAN_PORT" remote "$ENDPOINT_REMOTE" local "$ENDPOINT_LOCAL")
                if ! ip link show dev "$TUNNEL_IF" >/dev/null 2>&1; then
                    ip link add "${args[@]}" || { echo "Failed to create $type_name" >&2; exit 1; }
                    ip link set dev "$TUNNEL_IF" up || { echo "Failed to set $TUNNEL_IF up" >&2; exit 1; }
                    echo "$type_name tunnel created"
                else
                    echo "Warning: $TUNNEL_IF already exists. Is it already up?"
                fi
                ;;
            wireguard)
                # Up: WireGuard setup
                [[ -n "${WG_PK:-}" && -n "${WG_PUBK:-}" && -n "${ENDPOINT_REMOTE:-}" && -n "${WG_PORT:-}" ]] || { echo "Error: WG_PK, WG_PUBK, ENDPOINT_REMOTE, or WG_PORT not set" >&2; exit 1; }
                endpoint_ip="${ENDPOINT_REMOTE}"
                if ! ip link show dev "$TUNNEL_IF" >/dev/null 2>&1; then
                    ip link add dev "$TUNNEL_IF" type wireguard || { echo "Failed to create WireGuard interface" >&2; exit 1; }
                else
                    echo "Warning: $TUNNEL_IF already exists. Is it already up?"
                fi
                wg set "$TUNNEL_IF" private-key <(echo "$WG_PK") fwmark "${WG_FWMARK:-0}" || { echo "Failed to set WireGuard private-key" >&2; exit 1; }
                wg set "$TUNNEL_IF" peer "$WG_PUBK" endpoint "${endpoint_ip}:${WG_PORT}" persistent-keepalive "${WG_KEEPALIVE:-25}" allowed-ips "${WG_ALLOWED_IPS:-0.0.0.0/0,::/0}" || { echo "Failed to configure WireGuard peer" >&2; exit 1; }
                ip link set dev "$TUNNEL_IF" up || { echo "Failed to bring $TUNNEL_IF up" >&2; exit 1; }
                echo "WireGuard interface $TUNNEL_IF configured and up"
                ;;
            *) echo "Error: Unsupported TUNNEL_TYPE $TUNNEL_TYPE" >&2; exit 1;;
        esac
    elif [[ "$action" == "down" ]]; then
        echo ""
    fi
}

# Process: assign or remove addresses
process_addresses() {
    if [[ "$action" == "up" ]]; then
        for addr in "${ipv4_addrs[@]}"; do
            ip addr add "$addr" dev "$TUNNEL_IF" || { echo "Failed to add IPv4 $addr" >&2; exit 1; }
        done
        for addr in "${ipv6_addrs[@]}"; do
            ip addr add "$addr" dev "$TUNNEL_IF" || { echo "Failed to add IPv6 $addr" >&2; exit 1; }
        done
        echo "Assigned ${#ipv4_addrs[@]} IPv4 and ${#ipv6_addrs[@]} IPv6 addresses"
    elif [[ "$action" == "down" ]]; then
        echo ""
    fi
}

# Process: default-route or cleanup (updated checks to ensure 'default' is present)
process_default_route() {
    if [[ "${AS_DEFAULT_ROUTE:-no}" == "yes" ]]; then
    sleep 0.1
    endpoint_is_ipv6=false; [[ "${ENDPOINT_REMOTE}" == *:* ]] && endpoint_is_ipv6=true
    
        if [[ "$action" == "up" ]]; then
            echo "AS_DEFAULT_ROUTE up handling"

            if [[ ${#ipv4_addrs[@]} -gt 0 ]]; then
                # IPv4 default-route check on main
                if ip -4 route show table main | grep -q '^default '; then
                    echo "IPv4 default route exists on main"
                    if [[ "$endpoint_is_ipv6" == false ]]; then
                        ip -4 route add $(ip -4 route show table main default | sed "s/^default/${ENDPOINT_REMOTE}/") table main
                    fi
                    ip -4 route add $(ip -4 route show table main default) table $ROUTE_TABLE
                    pkill dhclient || echo "DHCP client not running."
                    for address in $(ip -4 addr show dev $(ip -4 route show table $ROUTE_TABLE default | sed -n 's/.* dev \([^ ]*\).*/\1/p') | sed -n 's/.*inet \([0-9]\{1,3\}\(\.[0-9]\{1,3\}\)\{3\}\).*/\1/p'); do
                        ip -4 rule add from ${address} table $ROUTE_TABLE
                        ip -4 addr change ${address} dev $(ip -4 route show table $ROUTE_TABLE default | sed -n 's/.* dev \([^ ]*\).*/\1/p') # Fuck DHCP
                    done
                else
                    echo "No IPv4 default route on main"
                    if [[ "$endpoint_is_ipv6" == false ]]; then
                        echo "Error: endpoint ${ENDPOINT_REMOTE} requires an IPv4 default route on main." >&2
                        exit 1
                    fi
                fi
                ip -4 route change default via $GATEWAY_IPV4 dev $TUNNEL_IF table main || ip -4 route change default via $GATEWAY_IPV4 dev $TUNNEL_IF table main onlink
            fi

            if [[ ${#ipv6_addrs[@]} -gt 0 ]]; then
                # IPv6 default-route check on main
                if ip -6 route show table main | grep -q '^default '; then
                    echo "IPv6 default route exists on main"
                    if [[ "$endpoint_is_ipv6" == true ]]; then
                        ip -6 route add $(ip -6 route show table main default | sed "s/^default/${ENDPOINT_REMOTE}/") table main
                    fi
                    ip -6 route add $(ip -6 route show table main default) table $ROUTE_TABLE
                    pkill dhclient || echo "DHCP client not running."
                    for address in $(ip -6 addr show dev $(ip -6 route show table $ROUTE_TABLE default | sed -n 's/.* dev \([^ ]*\).*/\1/p') | sed -n 's/.*inet6 \([0-9a-fA-F:]+\).*/\1/p'); do
                        ip -6 rule add from ${address} table $ROUTE_TABLE
                        ip -6 addr change ${address} dev $(ip -4 route show table $ROUTE_TABLE default | sed -n 's/.* dev \([^ ]*\).*/\1/p') # Fuck DHCP
                    done
                else
                    echo "No IPv6 default route on main"
                    if [[ "$endpoint_is_ipv6" == true ]]; then
                        echo "Error: endpoint ${ENDPOINT_REMOTE} requires an IPv6 default route on main." >&2
                        exit 1
                    fi
                fi
                ip -6 route change default via $GATEWAY_IPV6 dev $TUNNEL_IF table main || ip -6 route change default via $GATEWAY_IPV6 dev $TUNNEL_IF table main onlink
            fi

        elif [[ "$action" == "down" ]]; then
            echo "AS_DEFAULT_ROUTE down cleanup"
            # IPv4 default-route cleanup
            if ip -4 route show table "$ROUTE_TABLE" | grep -q '^default '; then
                echo "IPv4 default route exists in table $ROUTE_TABLE"
                ip -4 route change $(ip -4 route show table $ROUTE_TABLE default) table main || echo "Error: Cannot restore original default ipv4 route, possibly the table is in an unclean state."
            else
                echo "No IPv4 default route in table $ROUTE_TABLE"
            fi
            if [[ "$endpoint_is_ipv6" == false ]]; then
                ip -4 route del ${ENDPOINT_REMOTE} table main || echo "Removing route for $ENDPOINT_REMOTE failed."
            fi
            # IPv6 default-route cleanup
            if ip -6 route show table "$ROUTE_TABLE" | grep -q '^default '; then
                echo "IPv6 default route exists in table $ROUTE_TABLE"
                ip -6 route change $(ip -6 route show table $ROUTE_TABLE default) table main || echo "Error: Cannot restore original default ipv6 route, possibly the table is in an unclean state."
            else
                echo "No IPv6 default route in table $ROUTE_TABLE"
            fi
            if [[ "$endpoint_is_ipv6" == true ]]; then
                ip -6 route del ${ENDPOINT_REMOTE} table main || echo "Removing route for $ENDPOINT_REMOTE failed."
            fi
        fi
    fi
}

# Process: general routing (after default-route)
process_route() {
    if [[ "$action" == "up" ]]; then
        if [[ "${AS_DEFAULT_ROUTE:-no}" != "yes" ]]; then
            echo "General route up handling"
            if [[ ${#ipv4_addrs[@]} -gt 0 ]]; then
                ip -4 route add default via $GATEWAY_IPV4 dev $TUNNEL_IF table $ROUTE_TABLE onlink || ip -4 route add default via $GATEWAY_IPV4 dev $TUNNEL_IF table $ROUTE_TABLE
                for address in "${ipv4_addrs[@]}"; do
                    ip -4 rule add from ${address} table ${ROUTE_TABLE}
                done
            fi
            if [[ ${#ipv6_addrs[@]} -gt 0 ]]; then
                ip -6 route add default via $GATEWAY_IPV6 dev $TUNNEL_IF table $ROUTE_TABLE onlink || ip -6 route add default via $GATEWAY_IPV4 dev $TUNNEL_IF table $ROUTE_TABLE
                for address in "${ipv6_addrs[@]}"; do
                    ip -6 rule add from ${address} table ${ROUTE_TABLE}
                done
            fi
        fi
    elif [[ "$action" == "down" ]]; then
        echo "General route down cleanup"
        ip -4 rule flush table "$ROUTE_TABLE" || echo "Warning: flush IPv4 rules" >&2
        ip -6 rule flush table "$ROUTE_TABLE" || echo "Warning: flush IPv6 rules" >&2
        ip -4 route flush table "$ROUTE_TABLE" || echo "Warning: flush IPv4 routes" >&2
        ip -6 route flush table "$ROUTE_TABLE" || echo "Warning: flush IPv6 routes" >&2
        ip link del $TUNNEL_IF
    fi
}

# Main
[[ $# -eq 2 ]] || usage
config_file=$1; [[ -f "$config_file" ]] || { echo "Error: Config $config_file not found" >&2; exit 1; }
# Load env
# shellcheck disable=SC1090
source "$config_file"
TUNNEL_IF="novacloud_da"

# Run processes in order
preprocess_address
process_tunnel
process_addresses
process_default_route
process_route
