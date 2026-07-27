# Controlled attack scenarios

Run `./scripts/attack.sh NAME` from the host. The wrapper chooses the source
container and calls `scripts/attack-scenarios/run.sh` there. Targets are fixed;
there is no arbitrary-host argument. Run `make attack-tests` to execute all ten
and assert fresh Suricata and corresponding service/firewall events.

| Name / source | Actual technique and target | Expected Suricata alert | Expected log | Firewall / service behavior |
|---|---|---|---|---|
| `port-scan` / internet | `nmap -sT -Pn -n --max-retries 0 --min-rate 40 --initial-rtt-timeout 200ms --max-rtt-timeout 500ms --host-timeout 12s -p 20-40,80,443 10.77.50.10` | 1000001, TCP SYN burst | F99 denied probes; F12 for 80 | 80 open; others filtered |
| `ssh-bruteforce` / security | Seven `sshpass -p wrong-lab-password ssh` attempts to `labadmin@10.77.30.20`, one password prompt each | 1000002, possible SSH brute force | SSH `Failed password`; F19 accepts | Network allowed for monitoring; failed passwords and OpenSSH source penalties reject logins |
| `http-recon` / internet | `curl http://10.77.50.10/.env` | 1000003, sensitive path | Nginx access status 404 | F12 allows; no .env file served |
| `auth-failures` / internet | Seven `curl -u wrong:wrong http://10.77.50.10/private` requests | 1000004, repeated HTTP 401 | Nginx access 401 and auth error records | F12 allows HTTP; Basic Auth rejects credentials |
| `http-payload` / internet | `curl --path-as-is http://10.77.50.10/../../etc/passwd` | 1000010, traversal pattern | Nginx access status 400 | F12 allows; Nginx rejects malformed traversal |
| `unauthorized` / users | `curl --connect-timeout 2 --max-time 3 telnet://10.77.20.10:5432` | 1000007, unauthorized DB connection | F99 deny | SYN dropped; database sees no connection |
| `dmz-management` / web | `curl --connect-timeout 2 --max-time 3 telnet://10.77.30.20:22` | 1000008, DMZ boundary violation | F99 deny | SYN dropped; SSH sees no attempt |
| `users-management` / users | Same SSH probe from Users VLAN | 1000009, Users boundary violation | F99 deny | SYN dropped; SSH sees no attempt |
| `icmp-scan` / users | `ping -n -c 8 -i 0.1 -W 1 10.77.50.10` | 1000005, ICMP sweep/burst | F99 ICMP deny | All echo requests dropped |
| `malware-marker` / internet | `curl --max-time 3 http://10.77.50.10/ENS-LAB-MALWARE` | 1000006, action **blocked** | EVE alert/drop; initial F12 accept; **no** Nginx request | TCP handshake allowed; payload dropped inline |

SSH options in the script disable host-key persistence only for failed-login
simulation and bound connection time. OpenSSH may penalize the source after several failures, so later attempts can be throttled before password exchange. The test requires a fresh failed password from this source, as well as the connection-burst alert. It never guesses the generated secret;
the password is deliberately wrong. This demonstrates detection of repeated
failures without a password-cracking tool or wordlist. A separate test proves a
legitimate key login works.

Thresholds: >8 SYN packets/10 sec, >4 SSH SYNs/30 sec, >4 HTTP 401 responses/30 sec,
and >4 ICMP echo requests/10 sec. Bursts are indicators, not proof of compromise;
legitimate tests can trigger them too. The ICMP case deliberately exercises a
burst to one host, not host enumeration of a public subnet. The marker is a
project-defined benign detection string, not malware or a claim of signature-feed
coverage.

The source wrapper exits successfully when an expected timeout occurs. It does
not by itself certify detection; only `make attack-tests` checks event presence,
fields, source identity, event time, firewall evidence and IPS origin non-delivery.
Suricata `action=allowed` means its inspection permitted a packet to continue;
nftables can subsequently deny that same packet. Do not interpret it as end-to-end
access. Run tests serially to avoid mixing threshold windows.
