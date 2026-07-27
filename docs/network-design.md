# Network design

| VLAN | Role | Subnet | Members | Router |
|---|---|---|---|---|
| 10 | USERS | 10.77.10.0/24 | users .10 | .254 |
| 20 | SERVERS | 10.77.20.0/24 | database .10 | .254 |
| 30 | MANAGEMENT | 10.77.30.0/24 | admin .10, ssh .20 | .254 |
| 40 | SECURITY | 10.77.40.0/24 | collector .10, security .20 | .254 |
| 50 | DMZ | 10.77.50.0/24 | web .10 | .254 |
| 60 | UNTRUSTED simulation | 10.77.60.0/24 | internet .10 | .254 |

Each subnet is an `internal: true` bridge with IPv6 disabled. Docker reserves .1
in IPAM but `inhibit_ipv4=true` prevents assigning the bridge an IPv4 gateway.
Only the router has interfaces in multiple segments. Endpoints have explicit
routes to the other five /24 networks via their local .254 and **no default
route**. Their output ACL permits loopback and the six lab subnets only. DNS is
pointed at unused localhost rather than Docker's upstream resolver; no names are
needed for the fixed simulation targets. Tests inspect external-route absence
without sending any packets outside the lab.

Suricata shares the router network namespace but has its own process and logging
mount. It does not need a second packet mirror or privileged host access.
Nftables queues ingress IPv4 at prerouting priority -150; an earlier chain checks
source subnet/interface consistency. Suricata returns accept/drop, after which the
router's input/forward policies still apply. There is no masquerading or DNAT.

The management workstation and SSH endpoint share a bridge: their traffic is
switched, not routed. SSH's local input ACL admits only administrator .30.10 and
security analyst .40.20. The routed security client is used for the SSH detection
exercise. The monitoring collector and analyst similarly communicate locally on
VLAN 40. Neither bridge membership nor a sensor container label changes this
visibility boundary.

The only host listener provided by the project is the optional Python dashboard
proxy on 127.0.0.1:8080. It is not a published Docker port. Root on the host can
attach interfaces/containers or enter any namespace and is outside this model.
