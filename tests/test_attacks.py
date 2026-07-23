import pytest
import json
import uuid
from datetime import datetime, timezone
from .lab import execute, watermark, wait_events, probe, source_offset, source_after

SCENARIOS = [
    ('port-scan','internet',1000001,'firewall'),
    ('ssh-bruteforce','security',1000002,'ssh'),
    ('http-recon','internet',1000003,'nginx_access'),
    ('auth-failures','internet',1000004,'nginx_error'),
    ('icmp-scan','users',1000005,'firewall'),
    ('malware-marker','internet',1000006,'suricata'),
    ('unauthorized','users',1000007,'firewall'),
    ('dmz-management','web',1000008,'firewall'),
    ('users-management','users',1000009,'firewall'),
    ('http-payload','internet',1000010,'nginx_access'),
]


@pytest.mark.parametrize('scenario,source,sid,log', SCENARIOS)
def test_attack_detection(scenario, source, sid, log):
    after = watermark()
    token = uuid.uuid4().hex
    offset = source_offset(log if log != 'suricata' else 'nginx_access')
    started = datetime.now(timezone.utc)
    execute(source, '/opt/lab/scripts/attack-scenarios/run.sh', scenario, token)
    source_ip = {'internet':'10.77.60.10','security':'10.77.40.20','users':'10.77.10.10','web':'10.77.50.10'}[source]
    # Response-side HTTP failure alerts have the client as their destination.
    endpoint = 'dest_ip' if scenario == 'auth-failures' else 'src_ip'
    events = wait_events(after, 'suricata', lambda e: e['signature_id'] == sid
                         and e[endpoint] == source_ip and datetime.fromisoformat(e['timestamp']) >= started)
    for event in events:
        assert all(event[k] is not None for k in ('timestamp','src_ip','dest_ip','proto','signature','severity','category'))
        assert event['severity'] in (1,2,3,4)
    if log == 'firewall':
        destination = '10.77.20.10' if scenario == 'unauthorized' else '10.77.30.20' if scenario.endswith('management') else '10.77.50.10'
        protocol = 'ICMP' if scenario == 'icmp-scan' else 'TCP'
        match = lambda e: e['action'] == 'deny' and e['src_ip'] == source_ip and e['dest_ip'] == destination and e['proto'] == protocol and e['raw']['rule_id'] == 'F99' and datetime.fromisoformat(e['timestamp']) >= started
        wait_events(after, log, match)
        raw = [json.loads(line) for line in source_after(log, offset)]
        assert any(e['action'] == 'deny' and e['src_ip'] == source_ip and e['dest_ip'] == destination for e in raw)
    elif log == 'ssh':
        raw = source_after(log, offset)
        fresh = [line for line in raw if 'Failed password' in line and f'from {source_ip} port ' in line]
        assert fresh, "At least one real failed password must reach sshd; later attempts may be throttled"
        wait_events(after, log, lambda e: e['category'] == 'authentication-failure' and e['raw']['message'] in fresh)
    elif log == 'nginx_error':
        wait_events(after, log, lambda e: e['category'] == 'authentication-failure' and e['src_ip'] == source_ip and token in e['raw']['message'])
        assert any(token in line for line in source_after(log, offset))
    elif log == 'nginx_access':
        wait_events(after, log, lambda e: e['src_ip'] == source_ip and token in e['raw'].get('request', e['raw']['uri']) and e['raw']['status'] == (400 if scenario == 'http-payload' else 404))
        assert any(token in line for line in source_after(log, offset))
    elif scenario == 'malware-marker':
        assert any(e['action'] == 'blocked' for e in events)
        # Same service is reachable immediately after malicious flow is dropped.
        assert probe('internet','10.77.50.10',80) == 0
        # Drain the origin log through a subsequent unique request before checking absence.
        execute(source,'curl','-fsS','http://10.77.50.10/?barrier=' + token)
        wait_events(after,'nginx_access',lambda e: e['raw'].get('uri') == '/?barrier=' + token)
        assert not any('ENS-LAB-MALWARE' in line and token in line for line in source_after('nginx_access', offset))
        from .lab import api
        access = api(f'/api/events?source=nginx_access&after={after}&limit=1000')
        assert not any('ENS-LAB-MALWARE' in e['raw'].get('uri','') for e in access)
