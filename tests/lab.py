import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATHS = {'firewall':'/logs/firewall/events.jsonl','ssh':'/logs/ssh/auth.log',
                'nginx_access':'/logs/web/access.jsonl','nginx_error':'/logs/web/error.log'}


def source_offset(source):
    return int(execute('collector','stat','-c','%s',SOURCE_PATHS[source]).stdout)


def source_after(source, offset):
    return execute('collector','python3','-c',
                   'import sys; f=open(sys.argv[1],"rb"); f.seek(int(sys.argv[2])); sys.stdout.buffer.write(f.read())',
                   SOURCE_PATHS[source], str(offset)).stdout.splitlines()


def compose(*args, check=True, timeout=60):
    result = subprocess.run(['docker', 'compose', *args], cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if check:
        assert result.returncode == 0, result.stdout + result.stderr
    return result


def execute(service, *args, check=True, timeout=60):
    return compose('exec', '-T', service, *args, check=check, timeout=timeout)


def api(path):
    return json.loads(execute('collector', 'curl', '-fsS', 'http://127.0.0.1:8080' + path).stdout)


def watermark():
    # Let earlier source lines reach the index before taking a checkpoint.
    time.sleep(0.7)
    return api('/api/summary')['last_id']


def wait_events(after, source, predicate, seconds=12):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        rows = api(f'/api/events?after={after}&source={source}&limit=1000')
        matches = [e for e in rows if predicate(e)]
        if matches:
            return matches
        time.sleep(0.4)
    raise AssertionError(f'No fresh {source} event after {after} matched; last rows: {rows[-6:]}')


def probe(service, address, port):
    script = '''import socket,sys
try:
 s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=1.0);s.close()
except TimeoutError: sys.exit(10)
except ConnectionRefusedError: sys.exit(11)
except OSError as e: print(e);sys.exit(12)
'''
    return execute(service, 'python3', '-c', script, address, str(port), check=False).returncode
