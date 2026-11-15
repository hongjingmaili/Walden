"""Synthetic regression coverage for guarded, atomic AUTO reanchors."""
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

import test_reboot_tolerance as fixture


@pytest.fixture
def setup():
    import tempfile
    with tempfile.TemporaryDirectory(dir=fixture.ROOT, prefix='atomic-reanchor-') as root:
        yield fixture.setup(root, make_source_db=True)


def run_round(item):
    token, original = fixture.install_stubs(item['config'])
    try:
        return fixture.run_full_account_sync(item)
    finally:
        fixture.restore_stubs(token, original)


def snapshot(item):
    return fixture.snapshot(item['config'], item)


def assert_retry(item):
    result = run_round(item)
    assert 'scope_source_conflict' not in result['gaps']
    state = snapshot(item)
    assert state['anchor']['source_identity'] == item['live_identity']
    assert state['progress']['source_identity'] == item['live_identity']
    assert state['receipt']['auto'] is True


def test_locked_mirror_preserves_registry_then_retries(setup):
    before = snapshot(setup)
    lock = sqlite3.connect(setup['local_path'])
    try:
        lock.execute('BEGIN EXCLUSIVE')
        try:
            run_round(setup)
        except (sqlite3.OperationalError, fixture.MirrorError):
            pass
    finally:
        lock.close()
    assert snapshot(setup) == before
    assert_retry(setup)


@pytest.mark.parametrize('unsafe', ['symlink', 'wrong_binding', 'hardlink', 'mode', 'wal'])
def test_unsafe_mirror_leaves_reanchor_state_unchanged(setup, unsafe):
    path = Path(setup['local_path'])
    actual = path
    if unsafe in ('symlink', 'hardlink'):
        actual = path.with_suffix('.outside')
        path.rename(actual)
        if unsafe == 'symlink':
            path.symlink_to(actual)
        else:
            os.link(actual, path)
    elif unsafe == 'mode':
        path.chmod(0o644)
    else:
        with sqlite3.connect(path) as conn:
            if unsafe == 'wal':
                assert conn.execute('PRAGMA journal_mode=WAL').fetchone() == ('wal',)
            else:
                conn.execute("UPDATE __walden_binding SET account='different'")
    before = snapshot(setup)
    raw = actual.read_bytes()
    try:
        run_round(setup)
    except (sqlite3.OperationalError, fixture.MirrorError, OSError):
        pass
    assert actual.read_bytes() == raw
    assert snapshot(setup) == before


def test_interrupted_transaction_recovers_and_renumbers_again(setup):
    before = snapshot(setup)
    code = '''
import json, os, sys
from pathlib import Path
import test_reboot_tolerance as f
item = json.loads(sys.argv[1])
token, original = f.install_stubs(item['config'])
save = f.sc.save
def interrupt(conn, key, value):
    save(conn, key, value)
    if key.startswith('source_st_dev_renumber_receipt:'):
        os._exit(42)
f.sc.save = interrupt
f.run_full_account_sync(item)
'''
    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join(filter(None, [str(Path(__file__).parent), env.get('PYTHONPATH')]))
    import json
    completed = subprocess.run([sys.executable, '-B', '-c', code, json.dumps(setup)], env=env)
    assert completed.returncode == 42
    assert snapshot(setup) == before
    assert_retry(setup)
    fixture.repin(setup['config'], setup, setup['live_identity'][0] + 2000)
    assert_retry(setup)


def test_changed_source_header_leaves_reanchor_state_unchanged(setup):
    before = snapshot(setup)
    source = Path(setup['live_path'])
    source.write_bytes(b'changed-header!!' + source.read_bytes()[16:])
    mirror = Path(setup['local_path'])
    raw = mirror.read_bytes()
    result = run_round(setup)
    assert 'scope_source_conflict' in result['gaps']
    assert mirror.read_bytes() == raw
    assert snapshot(setup) == before


@pytest.mark.parametrize('raw', ['{}', '{"unexpected":true}', '[]'])
def test_name_mapping_progress_shape(setup, raw):
    with sqlite3.connect(setup['local_path']) as conn:
        conn.execute('CREATE TABLE Name2Id(user_name TEXT)')
        conn.execute("INSERT INTO Name2Id VALUES('synthetic_user')")
        conn.execute("INSERT INTO __walden_progress VALUES('Name2Id',?)", (raw,))
    if raw == '{}':
        assert_retry(setup)
    else:
        before = snapshot(setup)
        try:
            run_round(setup)
        except fixture.MirrorError:
            pass
        assert snapshot(setup) == before
    with sqlite3.connect(setup['local_path']) as conn:
        assert conn.execute("SELECT value FROM __walden_progress WHERE table_name='Name2Id'").fetchone() == (raw,)
        assert conn.execute('SELECT user_name FROM Name2Id').fetchall() == [('synthetic_user',)]


def test_missing_observation_is_not_repaired(setup):
    path = Path(setup['mirror_root']) / fixture.sc.REGISTRY
    with sqlite3.connect(path) as conn:
        conn.execute('DELETE FROM observations')
    before = snapshot(setup)
    with pytest.raises(fixture.MirrorError, match='scope_member_proof'):
        run_round(setup)
    assert snapshot(setup) == before
    with sqlite3.connect(path) as conn:
        assert conn.execute('SELECT count(*) FROM observations').fetchone() == (0,)


@pytest.mark.parametrize('which', ['mirror', 'registry'])
def test_metadata_trigger_cannot_mutate_copied_rows(setup, which):
    mirror = Path(setup['local_path'])
    with sqlite3.connect(mirror) as conn:
        conn.execute('CREATE TABLE copied_message(body TEXT)')
        conn.execute("INSERT INTO copied_message VALUES('synthetic original')")
        if which == 'mirror':
            conn.execute("""CREATE TRIGGER unexpected AFTER UPDATE ON __walden_progress
                BEGIN UPDATE copied_message SET body='unexpected'; END""")
    if which == 'registry':
        path = Path(setup['mirror_root']) / fixture.sc.REGISTRY
        with sqlite3.connect(path) as conn:
            conn.execute("""CREATE TRIGGER unexpected AFTER INSERT ON state
                BEGIN DELETE FROM members; END""")
    before = snapshot(setup)
    raw = mirror.read_bytes()
    if which == 'registry':
        with pytest.raises(fixture.MirrorError, match='local_trigger_unsupported'):
            run_round(setup)
    else:
        assert 'local_trigger_unsupported' in run_round(setup)['gaps']
    assert snapshot(setup) == before
    assert mirror.read_bytes() == raw
    with sqlite3.connect(mirror) as conn:
        assert conn.execute('SELECT body FROM copied_message').fetchall() == [('synthetic original',)]
