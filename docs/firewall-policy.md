# Firewall policy

Router rules live in `firewall/policy.nft`; interface-specific anti-spoofing is
installed by `firewall/start.sh`. Ports below are destination ports. All addresses
are lab IPv4. Only new flows need the service allowlist; F04 admits their replies.
The inspection queue precedes both the input and forward chains.

| ID | Source | Destination | Protocol | Port | Action | Reason |
|---|---|---|---|---|---|---|
| F01 | Source outside ingress interface's /24 | Any | IPv4 | Any | Log/drop | Cross-interface source spoofing |
| Q00 | Any lab ingress | Any | IPv4 | Any | Queue 0 | Fail-closed inline IDS/IPS before firewall |
| F02 | Any | Router itself | Any | Any | Log/drop | No router management listeners; loopback and established replies excepted |
| F03 | Invalid conntrack state | Any routed destination | Any | Any | Drop | Reject invalid packets |
| F04 | Established/related flow | Any routed destination | Any | Any | Accept | Stateful response traffic |
| F10 | USERS .10.10 | DMZ .50.10 | TCP | 80 | Log/accept | Approved user web service |
| F11 | USERS .10.10 | UNTRUSTED .60.10 | TCP | 80 | Log/accept | Local Internet simulation |
| F12 | UNTRUSTED .60.10 | DMZ .50.10 | TCP | 80 | Log/accept | Public-facing lab HTTP service |
| F13 | DMZ .50.10 | SERVERS .20.10 | TCP | 5432 | Log/accept | Application identity database query |
| F14 | ADMIN .30.10 | SERVERS .20.10 | TCP | 5432 | Log/accept | Database administration |
| F15 | ADMIN .30.10 | DMZ .50.10 | TCP | 80 | Log/accept | Web operations |
| F16 | ADMIN .30.10 | SECURITY .40.10 | TCP | 8080 | Log/accept | Security dashboard/API |
| F17 | SECURITY .40.20 | DMZ .50.10 | TCP | 80 | Log/accept | HTTP monitoring |
| F18 | SECURITY .40.20 | SERVERS .20.10 | TCP | 5432 | Log/accept | Database readiness monitoring |
| F19 | SECURITY .40.20 | MANAGEMENT .30.20 | TCP | 22 | Log/accept | SSH monitoring and controlled auth test |
| F20 | SECURITY .40.20 | .20.10, .50.10, .60.10 | ICMP echo | N/A | Log/accept | Restricted reachability monitoring |
| F99 | Any unmatched source | Any routed destination | Any | Any | Log/drop | Default deny, including Users/DMZ to Management |
| R-IN-LO | Loopback | Router | Any | Any | Accept | Local router processes |
| R-IN-EST | Established/related | Router | Any | Any | Accept | Replies to router-local flows |
| R-OUT-LO | Router | Loopback | Any | Any | Accept | Local router processes |
| R-OUT-EST | Router | Established/related peer | Any | Any | Accept | Router-generated replies |
| R-OUT | Router-originated traffic | Any | Any | Any | Drop | No router egress; loopback and established replies excepted |
| E-OUT-LO | Endpoint | Loopback | Any | Any | Accept | Local service traffic |
| E-OUT | Endpoint | Six lab subnets | IPv4 | Any | Accept | Constrain endpoint egress |
| E-OUT-DENY | Endpoint | All other destinations | Any | Any | Drop | Default output policy |
| E-EST | Established/related or loopback | Endpoint | Any | Any | Accept | Replies and local health checks |
| E-SSH | .30.10 or .40.20 | SSH .30.20 | TCP | 22 | Accept | Also enforce management control on switched traffic |
| E-MGMT | Any other traffic | SSH .30.20 | Any | Any | Drop | Defense in depth on management endpoint |
| E-IN | Six lab subnets | Other endpoints | IPv4 | Any | Accept | Forward policy enforces inter-VLAN service access |
| E-IN-DENY | All unmatched sources | Endpoint | Any | Any | Drop | Default input policy |

Address abbreviations `.30.10` mean `10.77.30.10`. IPv6 is disabled. Router and
endpoint chain default policies are DROP except the inspection/source-validation
hooks whose accepted packets continue through subsequent policies. Loopback
exceptions do not expose a routed service. Router invalid-state drops are counted
without logging; F99 logging is limited to 100 packets/sec, router-input denies to
20/sec. Sampling limits logs, never the DROP decision. Established packets are
counted but not logged per packet.

## Examples

- Users -> Nginx: HTTP 200, F10 accept, Nginx access event.
- Users -> local Internet: HTTP 200, F11 accept.
- DMZ -> PostgreSQL: authenticated SELECT succeeds, F13 accept.
- Users -> PostgreSQL: TCP timeout, F99 deny, SID 1000007.
- Users -> SSH: TCP timeout, F99 deny, SID 1000009.
- DMZ -> SSH: TCP timeout, F99 deny, SID 1000008.
- Untrusted -> DMZ port 443: timeout; HTTPS is deliberately not exposed.
- Admin -> SSH: key authentication succeeds through E-SSH on the same bridge;
  there is no router NFLOG/Suricata event for this switched flow.
- Security -> SSH: routed F19 accept; SSH failures are logged at the endpoint.
- Marker URI -> Nginx: handshake allowed under F12, payload dropped by Suricata;
  EVE action is `blocked`, and there is no Nginx access entry for that request.

The snapshot audit detects runtime nftables mutations. Tests exercise positive
controls and denied flows independently of the policy text. Application accounts
and `pg_hba.conf` add authentication after network authorization.
