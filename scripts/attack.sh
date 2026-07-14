#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
scenario=${1:?Pass a scenario name from docs/attack-scenarios.md}
case "$scenario" in
    ssh-bruteforce) source=security ;;
    unauthorized|users-management|icmp-scan) source=users ;;
    dmz-management) source=web ;;
    port-scan|http-recon|auth-failures|http-payload|malware-marker) source=internet ;;
    *) echo 'Unknown lab scenario' >&2; exit 2 ;;
esac
docker compose exec -T "$source" /opt/lab/scripts/attack-scenarios/run.sh "$scenario"
