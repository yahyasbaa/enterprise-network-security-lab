"""Bounded local fault injection. Always restore controls before returning."""
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.lab import compose, execute, probe


def audit():
    return subprocess.run([sys.executable, 'scripts/audit.py'], cwd=ROOT, capture_output=True, text=True)


def healthy(service):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        cid = compose('ps','-q',service).stdout.strip()
        if cid:
            data = json.loads(subprocess.check_output(['docker','inspect',cid]))[0]
            if data['State'].get('Health',{}).get('Status') == 'healthy':
                return
        time.sleep(0.5)
    raise AssertionError(f'{service} did not become healthy')


assert audit().returncode == 0, 'Start from a healthy, unmodified lab'
try:
    execute('firewall','nft','insert','rule','inet','lab','forward','ip','saddr','10.77.10.10',
            'ip','daddr','10.77.20.10','tcp','dport','5432','accept')
    assert audit().returncode != 0, 'Audit failed to detect changed router policy'
    result = subprocess.run([str(ROOT/'.venv/bin/pytest'),'-v',
        'tests/test_network.py::test_forbidden_connections_timeout_not_closed[users-10.77.20.10-5432-admin]'],
        cwd=ROOT,capture_output=True,text=True)
    (ROOT/'reports/mutation-firewall-test.log').write_text(result.stdout+result.stderr)
    assert result.returncode == 1 and 'assert 0 == 10' in result.stdout, result.stdout+result.stderr
    print('PASS: deliberately allowed Users -> database is detected by audit and connectivity test',flush=True)
finally:
    execute('firewall','sh','-c', "{ printf 'flush ruleset\\n'; cat /run/firewall-policy.snapshot; } | nft -f -")

try:
    execute('ssh','nft','delete','table','inet','endpoint')
    assert audit().returncode != 0, 'Audit missed deleted SSH endpoint firewall'
    print('PASS: removed endpoint firewall is detected',flush=True)
finally:
    execute('ssh','nft','-f','/run/endpoint-policy.snapshot')

try:
    compose('stop','suricata')
    assert probe('users','10.77.50.10',80) == 10, 'Transit remained open without sensor'
    print('PASS: stopped Suricata causes an allowed transit connection to time out',flush=True)
finally:
    compose('start','suricata')
    healthy('suricata')

assert probe('users','10.77.50.10',80) == 0
assert probe('users','10.77.20.10',5432) == 10
assert audit().returncode == 0
print('PASS: all controls restored; allowed and denied paths rechecked',flush=True)
