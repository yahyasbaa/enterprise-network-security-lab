# IDS/IPS and traffic analysis

The complete local ruleset is `suricata/rules/lab.rules` (SIDs 1000001–1000010).
`suricata/suricata.yaml` enables EVE alerts, drops, HTTP transactions, flows and
five-second engine statistics. Each alert carries native timestamp, src_ip,
dest_ip, proto and alert.signature/severity/category. The collector promotes the
alert fields to a common top-level schema while preserving the native record.

```bash
# Confirm all ten signatures are loaded, zero failures
 docker compose exec suricata suricatasc -c ruleset-stats /run/suricata-command.socket
# Review recent native alerts
 docker compose exec collector sh -c 'tail -20 /logs/suricata/fast.log'
# Read normalized malicious-marker alerts
 docker compose exec collector curl -s 'http://127.0.0.1:8080/api/events?source=suricata&sid=1000006'
# Engine capture/IPS counters
 docker compose exec suricata suricatasc -c dump-counters /run/suricata-command.socket
```

NFQUEUE is inline, at ingress before nftables forward decisions. This avoids
counting one routed packet twice from an `any` capture and includes probes later
denied by the firewall. Only the marker rule uses `drop`; the others alert.
`fail-open: no` and absence of queue bypass make sensor loss fail closed. A healthy
sensor plus loaded rules is necessary, but the live traffic tests prove detection.

The firewall logs actual NFLOG packet attributes, not reconstructed test outcomes.
Allow rules log new connections, F99 logs denied packets with a 100/sec limit.
Log timestamp is the libpcap packet timestamp. SSH/Nginx text events receive an
ingestion timestamp in the normalized schema; original messages are retained,
including Nginx's source timestamp. Suricata/JSON access/firewall timestamps come
from the producing component. All containers share the host clock and use UTC.

## Capture exercise

In terminal 1 run `./scripts/capture.sh` (15 seconds). In terminal 2 run:

```bash
./scripts/attack.sh http-recon
./scripts/attack.sh unauthorized
```

Then inspect:

```bash
docker compose cp reports/lab.pcap firewall:/tmp/lab.pcap
docker compose exec firewall tcpdump -nn -r /tmp/lab.pcap 'tcp port 80 or tcp port 5432'
```

Or open `reports/lab.pcap` in Wireshark. Useful display filters:

- `ip.src == 10.77.60.10 && http.request`: inspect method, Host and URI.
- `ip.dst == 10.77.20.10 && tcp.port == 5432`: denied SYNs without SYN-ACK.
- `tcp.flags.syn == 1 && tcp.flags.ack == 0`: connection attempts.
- `http.response.code == 401`: repeated failed HTTP authentication.
- `icmp.type == 8`: echo requests.

Compare an allowed three-way TCP handshake and HTTP response with repeated denied
SYNs. The capture uses `any` so a routed accepted packet may appear at ingress and
egress; do not interpret those duplicates as separate attacks. Packet captures
may include Basic Auth headers and application data; keep them local. They are
not committed to source control.

Rule threshold semantics are documented by [Suricata](https://docs.suricata.io/en/suricata-7.0.10/rules/thresholding.html).
