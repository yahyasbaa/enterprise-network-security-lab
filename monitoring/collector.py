"""Local log pipeline: real source files -> normalized events -> SQLite + HTTP."""
import datetime as dt
import json
import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

DB = '/data/events.sqlite'
SOURCES = {'suricata': '/logs/suricata/eve.json',
           'firewall': '/logs/firewall/events.jsonl',
           'nginx_access': '/logs/web/access.jsonl',
           'nginx_error': '/logs/web/error.log', 'ssh': '/logs/ssh/auth.log'}
STATUS = {'last_poll': 0.0, 'error': None}


def normalize(source, line):
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    if source in ('suricata', 'firewall', 'nginx_access'):
        raw = json.loads(line)
    else:
        raw = {'message': line.strip()}
    alert = raw.get('alert', {})
    event = dict(timestamp=raw.get('timestamp', now), source=source,
                 src_ip=raw.get('src_ip'), dest_ip=raw.get('dest_ip'),
                 proto=raw.get('proto', 'SSH' if source == 'ssh' else 'HTTP'),
                 signature=alert.get('signature'), signature_id=alert.get('signature_id'),
                 severity=alert.get('severity'), category=alert.get('category'),
                 action=raw.get('action', alert.get('action')), raw=raw)
    if source == 'ssh':
        match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
        event.update(src_ip=match[1] if match else None, dest_ip='10.77.30.20',
                     category='authentication-failure' if 'Failed password' in line else 'ssh-event')
    elif source == 'nginx_error':
        match = re.search(r'client: (\d+\.\d+\.\d+\.\d+)', line)
        event.update(src_ip=match[1] if match else None, dest_ip='10.77.50.10',
                     category='authentication-failure' if 'password' in line or 'user ' in line else 'web-error')
    return event


def connect():
    db = sqlite3.connect(DB, timeout=10)
    db.execute('PRAGMA journal_mode=WAL')
    return db


def initialize(db):
    db.executescript('CREATE TABLE IF NOT EXISTS events\n        (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, sid INTEGER, event TEXT NOT NULL);\n        CREATE INDEX IF NOT EXISTS source_id ON events(source,id);\n        CREATE INDEX IF NOT EXISTS sid_id ON events(sid,id);\n        CREATE TABLE IF NOT EXISTS offsets (source TEXT PRIMARY KEY, inode INTEGER, offset INTEGER);')


def poll_sources(db, sources):
    errors = {}
    for source, filename in sources.items():
        try:
            path = Path(filename)
            if not path.exists():
                continue
            stat = path.stat()
            prior = db.execute('SELECT inode, offset FROM offsets WHERE source=?', (source,)).fetchone()
            offset = prior[1] if prior and prior[0] == stat.st_ino and prior[1] <= stat.st_size else 0
            with path.open('rb') as stream, db:
                stream.seek(offset)
                for _ in range(2000):
                    before = stream.tell()
                    line = stream.readline()
                    if not line.endswith(b'\n'):
                        stream.seek(before)
                        break
                    event = normalize(source, line.decode('utf-8', errors='replace'))
                    db.execute('INSERT INTO events (source, sid, event) VALUES (?, ?, ?)',
                               (source, event['signature_id'], json.dumps(event)))
                db.execute('INSERT OR REPLACE INTO offsets VALUES (?, ?, ?)', (source, stat.st_ino, stream.tell()))
        except Exception as exc:
            errors[source] = str(exc)
    with db:
        db.execute('DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-100000 FROM events)')
    return errors


def ingest():
    db = connect()
    while True:
        try:
            errors = poll_sources(db, SOURCES)
            STATUS.update(last_poll=time.time(), error=errors or None)
            if errors:
                print(f'Ingestion errors: {errors}', flush=True)
        except Exception as exc:
            STATUS['error'] = str(exc)
            print(f'Ingestion error: {exc}', flush=True)
        time.sleep(0.25)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        args = parse_qs(url.query)
        code = 200
        if url.path == '/health':
            healthy = time.time() - STATUS['last_poll'] < 10 and STATUS['error'] is None
            code = 200 if healthy else 503
            payload = {'healthy': healthy, **STATUS}
        elif url.path == '/api/events':
            try:
                after = max(0, int(args.get('after', ['0'])[0]))
                limit = min(1000, max(1, int(args.get('limit', ['200'])[0])))
                where, params = ['id > ?'], [after]
                for field, query in (('source', 'source'), ('sid', 'sid')):
                    if args.get(query, [''])[0]:
                        where.append(f'{field} = ?')
                        params.append(args[query][0])
                with connect() as db:
                    rows = db.execute(f'SELECT id, event FROM events WHERE {" AND ".join(where)} ORDER BY id DESC LIMIT ?', params + [limit]).fetchall()
                payload = [dict(id=i, **json.loads(event)) for i, event in rows]
            except ValueError:
                code, payload = 400, {'error': 'after and limit must be integers'}
        elif url.path == '/api/summary':
            with connect() as db:
                payload = {'sources': dict(db.execute('SELECT source, COUNT(*) FROM events GROUP BY source')),
                           'last_id': db.execute('SELECT COALESCE(MAX(id), 0) FROM events').fetchone()[0],
                           'alerts': db.execute('SELECT COUNT(*) FROM events WHERE sid IS NOT NULL').fetchone()[0]}
        elif url.path == '/':
            body = Path('/opt/lab/monitoring/dashboard.html').read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        else:
            code, payload = 404, {'error': 'not found'}
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    Path('/data').mkdir(exist_ok=True)
    with connect() as db:
        initialize(db)
    threading.Thread(target=ingest, daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
