import sqlite3
from monitoring import collector


def test_malformed_source_does_not_stop_other_sources_and_recovers(tmp_path):
    assert hasattr(collector, 'poll_sources'), 'Each source must be polled independently'
    bad = tmp_path / 'eve.json'
    good = tmp_path / 'access.jsonl'
    bad.write_text('invalid json\n')
    good.write_text('{"timestamp":"2026-01-01T00:00:00Z","status":200}\n')
    db = sqlite3.connect(':memory:')
    collector.initialize(db)
    sources = {'suricata': str(bad), 'nginx_access': str(good)}
    errors = collector.poll_sources(db, sources)
    assert set(errors) == {'suricata'}
    assert db.execute('SELECT source FROM events').fetchall() == [('nginx_access',)]
    assert db.execute('SELECT source FROM offsets').fetchall() == [('nginx_access',)]
    bad.write_text('{"event_type":"stats"}\n')
    assert collector.poll_sources(db, sources) == {}
    assert db.execute('SELECT source FROM events ORDER BY id').fetchall() == [('nginx_access',),('suricata',)]
    assert collector.poll_sources(db, sources) == {}
    assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 2


def test_partial_line_waits_for_newline_and_truncation_resets_offset(tmp_path):
    assert hasattr(collector, 'poll_sources')
    log = tmp_path / 'access.jsonl'
    log.write_text('{"status":200}')
    db = sqlite3.connect(':memory:')
    collector.initialize(db)
    sources = {'nginx_access':str(log)}
    collector.poll_sources(db, sources)
    assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 0
    with log.open('a') as stream:
        stream.write('\n')
    collector.poll_sources(db, sources)
    assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 1
    log.write_text('{}\n')
    collector.poll_sources(db, sources)
    assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 2
