#!/bin/bash
set -euo pipefail
role=${1:?service role required}
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1\n' > /etc/resolv.conf
if [[ "$role" != firewall && "$role" != suricata ]]; then
    # No public route. Only the five other lab subnets go through the firewall.
    ip route del default 2>/dev/null || true
    for subnet in 10 20 30 40 50 60; do
        if [[ "$subnet" != "$VLAN" ]]; then
            ip route replace "10.77.$subnet.0/24" via "10.77.$VLAN.254"
        fi
    done
    # Block Docker's embedded DNS forwarding (literal local addresses are used).
    printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1\n' > /etc/resolv.conf
    nft -f /opt/lab/firewall/endpoint.nft
    nft --stateless list table inet endpoint > /run/endpoint-policy.snapshot
fi
case "$role" in
    firewall) exec /opt/lab/firewall/start.sh ;;
    suricata) exec suricata -c /opt/lab/suricata/suricata.yaml -q 0 --runmode workers ;;
    client) exec setpriv --bounding-set=-net_admin,-net_raw sleep infinity ;;
    web)
        mkdir -p /logs/web
        cp /opt/lab/services/web/nginx.conf /etc/nginx/nginx.conf
        exec setpriv --bounding-set=-net_admin,-net_raw nginx -g 'daemon off;'
        ;;
    internet)
        exec setpriv --bounding-set=-net_admin,-net_raw python3 -m http.server 80 --directory /opt/lab/services/web/public
        ;;
    ssh)
        mkdir -p /run/sshd /logs/ssh
        ssh-keygen -A
        echo "labadmin:$(cat /run/secrets/ssh_password)" | chpasswd
        install -d -m 700 -o labadmin -g labadmin /home/labadmin/.ssh
        install -m 600 -o labadmin -g labadmin /run/secrets/admin_key.pub /home/labadmin/.ssh/authorized_keys
        exec setpriv --bounding-set=-net_admin,-net_raw /usr/sbin/sshd -D -E /logs/ssh/auth.log -f /opt/lab/services/management/sshd_config
        ;;
    database) exec setpriv --bounding-set=-net_admin,-net_raw /opt/lab/services/internal/start.sh ;;
    collector) exec setpriv --bounding-set=-net_admin,-net_raw python3 /opt/lab/monitoring/collector.py ;;
    *) echo "Unknown role: $role" >&2; exit 2 ;;
esac
