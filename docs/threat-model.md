# Threat model

## Assets and trust

Protect the internal database, management SSH endpoint, monitoring evidence and
administration credentials from an untrusted client, a Users VLAN client, and a
compromised DMZ application. The Docker host, Docker API, operator, image build
sources and security-management accounts are trusted. Clients model untrusted
network traffic; they are not containers intended to contain a malicious root
operator or kernel exploit.

## Boundaries and mitigations

- Six separate bridges enforce Layer-2 separation; routes force inter-segment
  traffic into the stateful router. Exact service allowlists constrain movement.
- Ingress validation rejects source addresses from another interface's subnet.
  It is not a defense against same-subnet ARP spoofing or a privileged host.
- Suricata sees denied scans as well as allowed sessions and can drop a controlled
  HTTP pattern before the destination receives it. Sensor failure blocks transit.
- Management input policy also covers same-bridge traffic. Root login, SSH
  forwarding, agent forwarding and tunneling are disabled.
- Nginx exposes static files and real authentication; PostgreSQL requires SCRAM
  from only permitted addresses. The labapp account has SELECT on inventory.
- Endpoint processes lose network administration/raw packet capabilities after
  bootstrap. Docker exec remains an administrator facility with configured caps.
- No default route, host gateway address, published Docker port or upstream DNS
  is provided. Endpoint output filters deny destinations beyond the six subnets.
- Source logs are readable but not writable in the collector container. Raw files
  plus durable SQLite ingestion offsets support investigation and restart.

## Deliberate tradeoffs

The DMZ has a database password to model an application identity. Compromising it
permits whatever that account can do over F13; network rules do not prevent SQL
abuse over an authorized connection. The admin client holds administrative lab
secrets. The collector's read-only log mounts are privileged visibility but do
not provide log integrity against a compromised originating service or host.

Basic Auth and HTTP are intentionally cleartext within this isolated lab so the
HTTP IDS rules are observable. Do not transplant this exposure model onto a real
network. SSH's encrypted failures require host logs; only connection-frequency
heuristics are visible to Suricata. The sensor does not monitor switched
same-subnet traffic, loopback health checks, or Docker's control plane.

Small thresholds favor deterministic tests and would produce false positives in
production. There is no rate-based account lockout, TLS PKI, external reputation
feed, HA, automated containment or production-scale log search. The custom benign
marker validates the prevention path; it does not certify general malware
prevention. No intentionally vulnerable software is installed.

SQLite keeps 100,001 recent records; source files remain append-only until the
operator archives/removes them. High-volume traffic may exceed NFQUEUE/NFLOG
capacity or rate-limited firewall logging. Test traffic is bounded and modest.
A stopped sensor is availability loss by design. Production use requires sizing,
load tests, retention/rotation, authenticated dashboard access, TLS, stronger
secret lifecycle and an independently administered security boundary.
