# Executed verification

This project was built and exercised on a native Linux amd64 host with Docker
Engine 29.3.1, Compose 5.1.1, and Python 3.12.3 on 2026-10-02 and 2026-10-03.
The initial workspace was empty. Project containers, networks, database/index
volumes and generated runtime state were reset during development, followed by
fresh setup and startup. No host OS reinstall or separate clean VM was performed.

## Verified controls

- All ten containers healthy; six internally isolated bridges; exact endpoint
  addresses and memberships; no published Docker ports or privileged containers.
- Stateful default-deny routing, service allowlists, source/interface validation,
  endpoint SSH ACL and output restrictions. No default route or external DNS.
- Allowed paths tested using real sockets and HTTP, authenticated SSH key login,
  HTTP Basic Auth, and an authenticated PostgreSQL inventory query.
- Forbidden paths timed out while independent allowed-source probes proved the
  same destination listeners were working. Connection refusal does not count as
  a successful isolation test.
- All ten IDS signatures loaded with zero failed rules. Every attack produced
  fresh alerts with expected endpoints, timestamps and required fields.
- The IPS marker timed out, produced an EVE `blocked` alert, and was absent from
  the origin's source log after a later benign request proved ingestion had
  caught up. HTTP scenarios use unique request tokens; SSH uses fresh source-file
  ranges and matching connection messages.
- Firewall events, native Suricata alerts, Nginx access/errors and SSH events were
  observed in original source files and the central SQLite index.
- Collector restart preserved offsets without duplicate events and resumed
  ingestion. Unit checks verified incomplete-line buffering, truncation recovery,
  and continued collection from other sources after one malformed source.
- The localhost dashboard's page, health endpoint and filtered event API were
  requested successfully. No claim of a cross-browser visual test is made.
- A 15-second capture recorded 106 packets with zero kernel capture drops. It
  showed an allowed HTTP handshake/request and repeated denied Users-to-database
  SYNs without forwarding. Routed packets appear on both ingress and egress in
  the `any` capture.

## Tests of broken controls

`make control-checks` executed successfully on 2026-10-02:

1. Inserted a Users-to-database allow rule: the runtime audit failed, and the
   forbidden-connectivity pytest failed because it observed an open connection
   (`0`) instead of the required timeout (`10`).
2. Deleted the SSH endpoint firewall: the runtime audit failed.
3. Stopped Suricata: an otherwise allowed Users-to-Nginx connection timed out.
4. Restored the policies and sensor, verified allowed/denied paths, and passed
   the runtime audit again.

The deliberate pytest failure is saved in `reports/mutation-firewall-test.log`;
it is expected evidence that the suite detects a broken control.

## Recorded results

| Execution | Result | Evidence |
|---|---|---|
| Build/setup from reset project state | Exit 0 | `reports/final-setup.log` |
| Full test suite, October 2 | 61 passed, 96.03 s | `reports/verified-tests.log` |
| Runtime audit plus suite, October 2 | Exit 0; 61 passed, 99.00 s | `reports/verified-audit.log` |
| Standalone attack suite, October 2 | 10 passed, 36.43 s | `reports/verified-attacks.log` |
| Deliberate control failures/restoration | All checks passed | `reports/control-checks.log` |
| Rebuild/setup, October 3 | Exit 0 | `reports/restart-setup.log` |
| Complete down/up cycle, October 3 | All ten services healthy | `reports/restart-down.log`, `reports/restart-up.log` |
| Full suite after restart, October 3 | 61 passed, 76.54 s | `reports/restart-tests.log` |
| Audit plus suite after restart, October 3 | Exit 0; 61 passed, 75.80 s | `reports/restart-audit.log` |
| Standalone attacks after restart, October 3 | 10 passed, 30.10 s | `reports/restart-attacks.log` |
| Final teardown, October 3 | Exit 0; no lab containers or networks remain | `reports/final-down.log` |

JUnit XML is written by Make to `reports/tests.xml`, `reports/audit-tests.xml`
and `reports/attacks.xml`; each command refreshes its corresponding file. The
collector snapshot is `reports/log-evidence.json`, a native alert example is
`reports/alert-example.json`, and capture evidence is `reports/lab.pcap` plus
`reports/packet-analysis.txt`. Reports and runtime data are deliberately ignored
by version control and excluded from the image build context.

## Actual normalized alert example

The following record was read from the collector after the October 3 restart:

```json
{
  "timestamp": "2026-10-03T16:38:40.202715+0000",
  "src_ip": "10.77.60.10",
  "dest_ip": "10.77.50.10",
  "proto": "TCP",
  "signature": "LAB IPS harmless malware test marker blocked",
  "severity": 1,
  "category": "A Network Trojan was detected",
  "action": "blocked"
}
```

The category comes from Suricata's classification vocabulary. This record was
caused by a benign project test marker, not actual malware.

## Versions and review

Tested packages: nftables 1.1.3, Suricata 7.0.10, Nginx 1.26.3, OpenSSH 10.0p1,
PostgreSQL 17.11, pytest 8.3.5. Full Debian revisions are in `reports/versions.txt`.
The Debian base image is pinned by digest; apt packages follow the Trixie
repositories. Reproduction is functional rather than bit-for-bit historical.

An independent read-only code review identified evidence-correlation, asynchronous
log-ingestion and runtime-audit coverage gaps. Those were corrected and exercised
by the final suites. Per-source ingestion error handling was also fixed and
verified with real temporary log files. The reviewer did not independently rerun
the live tests; the execution records above come from the implementation session.

Native Linux/rootful Docker was validated. Other host platforms, production
traffic load, real 802.1Q trunks and hostile Docker/host administrators are outside
the verified scope. Original logs grow until archived or cleaned; SQLite and
Docker stdout retention are bounded. See the threat model for the trust boundary.

Final state: the lab is stopped. Database/index volumes, secrets, source logs and
reports are retained. Run `make up` to resume, or follow the full README sequence
to rebuild. Local documentation links and shell-script syntax were also checked.
