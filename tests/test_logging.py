from .lab import api, execute, watermark, wait_events


def test_firewall_allowed_event_fields():
    after = watermark()
    execute('users','curl','-fsS','http://10.77.60.10/')
    rows = wait_events(after,'firewall',lambda e: e['raw'].get('rule_id') == 'F11')
    event = rows[0]
    assert event['action'] == 'allow'
    assert event['src_ip'] == '10.77.10.10'
    assert event['dest_ip'] == '10.77.60.10'
    assert event['raw']['dest_port'] == 80


def test_collector_health_and_all_sources():
    assert api('/health')['healthy'] is True
    sources = api('/api/summary')['sources']
    assert set(sources) == {'suricata','firewall','nginx_access','nginx_error','ssh'}
    assert all(n > 0 for n in sources.values())


def test_suricata_has_all_ten_rules_loaded():
    result = execute('suricata','suricatasc','-c','ruleset-stats','/run/suricata-command.socket').stdout
    import json
    stats = json.loads(result)
    assert stats['return'] == 'OK'
    assert sum(item['rules_loaded'] for item in stats['message']) == 10
    assert sum(item['rules_failed'] for item in stats['message']) == 0


def test_collector_restart_resumes_without_duplicate_events():
    import time
    import uuid
    from .lab import compose
    marker = '/resume-' + uuid.uuid4().hex
    after = watermark()
    execute('users','curl','-s','-o','/dev/null','http://10.77.50.10' + marker)
    original = wait_events(after,'nginx_access',lambda e: e['raw'].get('uri') == marker)
    assert len(original) == 1
    compose('restart','collector')
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            if api('/health')['healthy']:
                break
        except (AssertionError, ValueError):
            pass
        time.sleep(0.5)
    else:
        raise AssertionError('Collector did not recover after restart')
    rows = api(f'/api/events?after={after}&source=nginx_access&limit=1000')
    assert [e['id'] for e in rows if e['raw'].get('uri') == marker] == [original[0]['id']]
    execute('users','curl','-s','-o','/dev/null','http://10.77.50.10' + marker + '-after')
    wait_events(original[0]['id'],'nginx_access',lambda e: e['raw'].get('uri') == marker + '-after')
