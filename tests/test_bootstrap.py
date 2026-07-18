import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_live_stack_exists():
    result = subprocess.run(['docker', 'compose', 'ps', '--format', 'json'], cwd=ROOT,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(rows) == 10, 'All ten lab services must be running'
    assert all(row['State'] == 'running' for row in rows)
