#!/bin/bash

# Shared with the isolated network regression tests. The optional directory
# argument lets tests exercise forwarding without touching real sysctls.
function ip_forward {
    local sysctl_dir="${1:-/proc/sys/net/ipv4}"
    local setting value
    for setting in ip_dynaddr ip_forward; do
        if ! value=$(cat "${sysctl_dir}/${setting}"); then
            echo "[ERROR] Cannot read IPv4 ${setting}" >&2
            return 1
        fi
        if [ "$value" = "1" ]; then
            echo "[INFO] ${setting} already 1"
        else
            echo "[INFO] Enabling ${setting}"
            if ! printf '1\n' > "${sysctl_dir}/${setting}"; then
                echo "[ERROR] Cannot enable IPv4 ${setting}" >&2
                return 1
            fi
        fi
    done
}

function validate_nat {
    case "$NAT" in
        true|false) ;;
        *) echo "[ERROR] NAT must be true or false" >&2; return 1 ;;
    esac
}

function nat_setup {
    validate_nat || return 1
    # Match the existing package rule exactly, including rules from old images.
    # Never flush a chain or change rules for other subnets/targets.
    local -a rule=(POSTROUTING -s "${SUBNET}/24" ! -d "${SUBNET}/24" -j MASQUERADE)
    local status
    while true; do
        if iptables -w 5 -t nat -C "${rule[@]}" 2>/dev/null; then
            status=0
        else
            status=$?
        fi
        case "$status" in
            0)
                if [ "$NAT" = true ]; then
                    return 0
                fi
                # Remove all copies left by older, non-idempotent startups.
                iptables -w 5 -t nat -D "${rule[@]}" || return 1
                ;;
            1)
                if [ "$NAT" = true ]; then
                    iptables -w 5 -t nat -A "${rule[@]}" || return 1
                fi
                return 0
                ;;
            *)
                echo "[ERROR] Cannot inspect WiFi NAT rule (iptables status ${status})" >&2
                return 1
                ;;
        esac
    done
}
