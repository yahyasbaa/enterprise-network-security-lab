#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p reports
# Bounded, local-only capture, including traffic before firewall decisions.
docker compose exec -T firewall timeout 15 tcpdump -U -i any -nn -w - 'net 10.77.0.0/16' > reports/lab.pcap || [[ $? == 124 ]]
echo 'Capture saved to reports/lab.pcap (open in Wireshark or tcpdump -r).'
