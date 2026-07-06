#!/bin/bash
set -euo pipefail
mkdir -p /logs/firewall
# NFLOG listener uses libpcap through tcpdump, not host kernel log access.
python3 /opt/lab/firewall/logger.py &
logger=$!
nft -f /opt/lab/firewall/policy.nft
nft 'add chain inet lab ingress { type filter hook prerouting priority -160; policy accept; }'
for vlan in 10 20 30 40 50 60; do
    iface=$(ip -o -4 addr show | awk -v address="10.77.$vlan.254/24" '$4 == address { print $2 }')
    [[ -n "$iface" ]] || { echo "Missing VLAN $vlan interface" >&2; exit 1; }
    nft add rule inet lab ingress iifname "$iface" ip saddr != "10.77.$vlan.0/24" log prefix '"F01 deny "' group 5 counter drop comment '"F01"'
done
nft --stateless list ruleset > /run/firewall-policy.snapshot
touch /run/firewall-ready
trap 'kill "$logger"; wait "$logger" || true' TERM INT
wait "$logger"
