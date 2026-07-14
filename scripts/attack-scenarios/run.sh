#!/bin/bash
set -euo pipefail
token=${2:-manual}
[[ "$token" =~ ^[a-zA-Z0-9-]{1,64}$ ]] || { echo 'Invalid correlation token' >&2; exit 2; }
# Commands accept scenario names, never arbitrary targets. All targets are local.
case "${1:-all}" in
    port-scan) nmap -sT -Pn -n --max-retries 0 --min-rate 40 --initial-rtt-timeout 200ms --max-rtt-timeout 500ms --host-timeout 12s -p 20-40,80,443 10.77.50.10 ;;
    ssh-bruteforce)
        for i in {1..7}; do
            sshpass -p wrong-lab-password ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 -o NumberOfPasswordPrompts=1 labadmin@10.77.30.20 true 2>/dev/null || true
        done ;;
    http-recon) curl --noproxy '*' -s -o /dev/null -w '%{http_code}\n' "http://10.77.50.10/.env?run=$token" ;;
    auth-failures)
        for i in {1..7}; do curl --noproxy '*' -s -u wrong:wrong -o /dev/null -w '%{http_code}\n' "http://10.77.50.10/private?run=$token"; done ;;
    http-payload) curl --noproxy '*' --path-as-is -s -o /dev/null -w '%{http_code}\n' "http://10.77.50.10/../../etc/passwd?run=$token" ;;
    unauthorized) curl --noproxy '*' --connect-timeout 2 --max-time 3 telnet://10.77.20.10:5432 || [[ $? == 28 ]] ;;
    dmz-management|users-management) curl --noproxy '*' --connect-timeout 2 --max-time 3 telnet://10.77.30.20:22 || [[ $? == 28 ]] ;;
    icmp-scan) ping -n -c 8 -i 0.1 -W 1 10.77.50.10 || true ;;
    malware-marker)
        status=0
        curl --noproxy '*' --max-time 3 "http://10.77.50.10/ENS-LAB-MALWARE?run=$token" || status=$?
        [[ "$status" == 28 ]] || { echo "IPS must cause timeout, got curl exit $status" >&2; exit 1; }
        ;;
    *) echo 'Choose a documented scenario name; use make attack-tests to run all.' >&2; exit 2 ;;
esac
