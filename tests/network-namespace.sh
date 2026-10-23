#!/bin/bash
# Run only in a disposable --network none container, never on a live Dappnode.
set -euo pipefail
if [ "$(ls /sys/class/net)" != lo ]; then
    echo "This test requires an isolated network namespace with only loopback." >&2
    exit 1
fi
source /usr/bin/network.sh
export SUBNET=10.20.12.0 NAT=true
rule=(POSTROUTING -s "${SUBNET}/24" ! -d "${SUBNET}/24" -j MASQUERADE)
unrelated=(POSTROUTING -s 192.0.2.0/24 -j MASQUERADE)
rule_count() { iptables -t nat -S POSTROUTING | grep -c '^-A ' || true; }

printf '0\n' > /proc/sys/net/ipv4/ip_dynaddr
printf '0\n' > /proc/sys/net/ipv4/ip_forward
ip_forward
test "$(cat /proc/sys/net/ipv4/ip_dynaddr)" = 1
test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1
ip_forward
echo 'PASS: real namespace sysctls 0 -> 1 and repeated setup'

iptables -t nat -A "${unrelated[@]}"
nat_setup
nat_setup
iptables -t nat -C "${rule[@]}"
test "$(rule_count)" = 2
echo 'PASS: NAT enabled without duplicate rules'

# Reproduce duplicate rules left by older entrypoints before changing modes.
iptables -t nat -A "${rule[@]}"
iptables -t nat -A "${rule[@]}"
NAT=false
nat_setup
nat_setup
test "$(rule_count)" = 1
iptables -t nat -C "${unrelated[@]}"
test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1
echo 'PASS: NAT disabled; legacy duplicates removed; unrelated rule and forwarding retained'

NAT=true
nat_setup
test "$(rule_count)" = 2
iptables -t nat -C "${unrelated[@]}"
echo 'PASS: transition back to NAT enabled'

if NAT=invalid /usr/bin/entrypoint.sh > /tmp/invalid-nat.log 2>&1; then
    echo 'Invalid NAT unexpectedly started the package' >&2
    exit 1
fi
grep -q 'NAT must be true or false' /tmp/invalid-nat.log
test "$(rule_count)" = 2
echo 'PASS: packaged entrypoint rejects invalid NAT before changing networking'
bash -n /usr/bin/entrypoint.sh /usr/bin/network.sh
dnsmasq --test
echo 'PASS: packaged shell and dnsmasq configuration checks'
