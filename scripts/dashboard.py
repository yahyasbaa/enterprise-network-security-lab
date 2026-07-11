"""Opt-in loopback-only proxy, without exposing Docker service ports."""
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Proxy(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split('?')[0] not in ('/', '/api/events', '/api/summary', '/health'):
            self.send_error(404)
            return
        result = subprocess.run(['docker', 'compose', 'exec', '-T', 'collector', 'curl',
                                 '-fsS', '--max-time', '4', 'http://127.0.0.1:8080' + self.path],
                                cwd=ROOT, capture_output=True, timeout=8)
        self.send_response(200 if result.returncode == 0 else 502)
        self.send_header('Content-Type', 'text/html; charset=utf-8' if self.path == '/' else 'application/json')
        self.end_headers()
        self.wfile.write(result.stdout if result.returncode == 0 else b'{"error":"Collector unavailable"}')


if __name__ == '__main__':
    print('Security dashboard: http://127.0.0.1:8080 (Ctrl-C to stop)', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 8080), Proxy).serve_forever()
