# Incident response exercise

1. **Triage.** Open `make dashboard` and filter by Suricata or firewall. Record
   event timestamp, signature/SID, severity, source, destination, protocol and
   action. Check `/api/events?source=suricata&sid=1000008` for a DMZ pivot example.
2. **Correlate.** Match addresses and time to firewall rule IDs and service logs.
   For SSH, pair SID 1000002 with `Failed password` records from .40.20. For denied
   pivots, expect F99 and no SSH endpoint event. For the IPS marker, verify
   `action=blocked` and no Nginx request. Suricata `allowed` alone does not mean the
   firewall allowed the connection.
3. **Preserve.** Stop generating test traffic. Copy `runtime/logs/` and the current
   test reports into an incident directory. To snapshot the collector consistently:

   ```bash
   mkdir -p reports/incident
   docker compose exec -T collector python3 -c 'import sqlite3; s=sqlite3.connect("/data/events.sqlite"); d=sqlite3.connect("/tmp/incident.sqlite"); s.backup(d); d.close(); s.close()'
   docker compose cp collector:/tmp/incident.sqlite reports/incident/events.sqlite
   docker compose cp collector:/logs reports/incident/source-logs
   sha256sum reports/incident/events.sqlite > reports/incident/SHA256SUMS
   ```

   Raw source files copied while services run can include writes during copying;
   stop the relevant source container first for a fixed forensic sample. Keep
   generated secrets and packet captures private.
4. **Contain locally.** `docker compose stop web` contains the DMZ service; use
   `docker compose stop users` for the Users client. Do not edit the host firewall
   or scan a suspected external address. This lab contains only local roles.
5. **Investigate.** Review the scenario command and correlate EVE flow IDs,
   request URI/status, SSH username and firewall destination ports. Use
   `./scripts/capture.sh` for a bounded local capture during a repeat exercise.
   A signature is an indicator, not proof that an exploit succeeded.
6. **Recover.** Restore trusted configuration, rotate affected generated lab
   credentials together with their service configuration, and rebuild/recreate.
   To reset all lab database state, `make clean && make setup && make up`.
   Secret deletion also requires database-volume reset before regeneration.
7. **Validate.** Run `make security-audit` and `make attack-tests`. Record which
   prevention rule stopped the attempt, which evidence confirmed it, and any
   visibility gap. A sensor outage should remain fail closed until restored.

No alert triggers automatic deletion, external notification or outbound scanning.
