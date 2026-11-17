"""Synthetic account registry size, coherent local reads, and owned sync."""
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile

import pytest

from wechat_local import native_follow_grant, native_mirror_cli, native_window
from wechat_local import native_scope_contract as scope
from wechat_local.native_mirror_store import MirrorError
from wechat_local.native_schedule import _writer_state

import test_reboot_tolerance as fixture
from test_account_sync_status import authorized_round


MIB = 1024 * 1024
LARGE_REGISTRY_BYTES = 82 * MIB
CAP_BYTES = 128 * MIB
SYNTHETIC_TEXT = 'synthetic local message'
SYNTHETIC_CONTACT = 'synthetic_contact'


def make_fixture(root):
    item = fixture.setup(str(root), dev_delta=0, make_source_db=True)
    config = item['config']
    bin_path = Path(sys.executable).parent
    config.update(runtime_python=sys.executable, window_cli=str(bin_path / 'wechat-local-window'),
                  reply_cli=str(bin_path / 'wechat-local-reply'), passphrase_file=str(root / 'no-key'))
    profile = root / 'profile.json'
    receipt = root / 'receipt.json'
    raw = scope.encoded(dict(state='committed', contract=scope.fixed(config),
                             new_config_sha256=scope.digest(config), legacy_current_sha256=None))
    scope.create(receipt, raw)
    mirror = Path(config['mirror_root'])
    scope.create(mirror / scope.CURRENT, scope.encoded(dict(
        schema='walden.account.scope.current/1', contract=scope.fixed(config),
        receipt=str(receipt), receipt_sha256=scope.sha(raw))))
    scope.create(profile, scope.encoded(config))
    (mirror / '.writer.lock').touch(mode=0o600)
    item.update(profile=profile, registry=mirror / scope.REGISTRY, receipt=receipt)
    with sqlite3.connect(item['local_path']) as connection:
        connection.execute('CREATE TABLE ' + fixture.TABLE + '''
            (local_id INTEGER PRIMARY KEY, server_id INTEGER, local_type INTEGER,
            create_time INTEGER, real_sender_id INTEGER, message_content TEXT, WCDB_CT_message_content INTEGER)''')
        connection.execute('INSERT INTO ' + fixture.TABLE + ' VALUES(1,2,1,1000,0,?,0)', (SYNTHETIC_TEXT,))
        connection.execute('CREATE TABLE __walden_observed(table_name TEXT, local_id INTEGER, server_id TEXT, kind INTEGER, timestamp INTEGER, sender INTEGER, fingerprint TEXT)')
        progress = dict(source_identity=item['live_identity'], source_header_sha256=item['live_header'],
                        H=1, history=1, tail=1, target=1, history_complete=True, checked_at=1000)
        connection.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',
                           (json.dumps(progress), fixture.TABLE))
    return item


def pad_registry(path, target_bytes):
    """Grow the real SQLite file to the target page count, using created bytes."""
    with sqlite3.connect(path) as connection:
        page_size = connection.execute('PRAGMA page_size').fetchone()[0]
        assert target_bytes % page_size == 0
        connection.execute('CREATE TABLE IF NOT EXISTS synthetic_padding(value BLOB)')
        pages = connection.execute('PRAGMA page_count').fetchone()[0]
        target_pages = target_bytes // page_size
        # Overflow pages devote four bytes to their successor pointer.
        assert target_pages > pages
        connection.execute('INSERT INTO synthetic_padding VALUES(zeroblob(?))',
                           ((target_pages - pages) * (page_size - 4),))
        pages = connection.execute('PRAGMA page_count').fetchone()[0]
        assert pages == target_pages
    assert path.stat().st_size == target_bytes


def add_named_member(item):
    config = item['config']
    table = 'Msg_' + hashlib.md5(SYNTHETIC_CONTACT.encode()).hexdigest()
    observation = dict(contract=scope.fixed(config), shard=fixture.SHARD, source_identity=item['live_identity'],
                       header=item['live_header'], query_only=True, tables=[[table, fixture.SCHEMA]])
    with scope.registry(config, write=True) as connection:
        scope._register_members(config, connection, observation, [dict(
            table=table, schema_sha256=fixture.SCHEMA, username=SYNTHETIC_CONTACT, supported=True, available=True)])
        connection.commit()
    with sqlite3.connect(item['local_path']) as connection:
        connection.execute('CREATE TABLE ' + table + ' AS SELECT * FROM ' + fixture.TABLE)
        connection.execute('INSERT INTO __walden_progress SELECT ?,value FROM __walden_progress WHERE table_name=?',
                           (table, fixture.TABLE))


@pytest.fixture
def account(monkeypatch):
    with tempfile.TemporaryDirectory(dir=Path(__file__).parent, prefix='registry-capacity-') as directory:
        root = Path(directory)
        monkeypatch.setenv('XDG_STATE_HOME', str(root / 'state'))
        monkeypatch.setattr(native_follow_grant, 'validate', lambda _grant: None)
        yield make_fixture(root)


def local_status(account):
    return native_mirror_cli.main(['status', '--source-config', str(account['profile']), '--read-mode', 'local'])


def local_query(account):
    ref = scope.target_ref(account['config'], fixture.SHARD, fixture.TABLE)
    return native_mirror_cli.main(['query', '--source-config', str(account['profile']), '--read-mode', 'local',
                                   '--registered-target-ref', ref, '--limit', '1'])


def named_window(account):
    return native_window.main(['--source-config', str(account['profile']), '--read-mode', 'local',
                               '--conversation-username', SYNTHETIC_CONTACT, '--latest', '1'])


def test_live_scale_local_status_and_registered_query(account, capsys):
    add_named_member(account)
    pad_registry(account['registry'], LARGE_REGISTRY_BYTES)
    counter = scope.query_scope_guard(account['config'])
    assert local_status(account) == 1  # synthetic fixture retains unsupported-message-schema gaps
    status = json.loads(capsys.readouterr().out)
    assert status['source_opens'] == 0
    assert status['counts']['copied'] == 2
    assert local_query(account) == 0
    window = json.loads(capsys.readouterr().out)
    assert window['source_opens'] == 0
    assert [row['text'] for row in window['messages']] == [SYNTHETIC_TEXT]
    assert named_window(account) == 0
    named = json.loads(capsys.readouterr().out)
    assert named['source_opens'] == 0
    assert [row['text'] for row in named['messages']] == [SYNTHETIC_TEXT]
    assert scope.query_scope_guard(account['config']) == counter
    assert account['registry'].stat().st_size == LARGE_REGISTRY_BYTES


def test_live_scale_owned_round_keeps_existing_copy_proof(account):
    pad_registry(account['registry'], LARGE_REGISTRY_BYTES)
    before = scope.query_scope_guard(account['config'])
    result = authorized_round(account)
    assert result['source_opens'] == 1
    assert result['account_scope']['source_opens'] == 0
    assert result['account_scope']['counts']['copied'] == 1
    assert 'history_incomplete' not in result['gaps']
    assert scope.query_scope_guard(account['config']) == before
    assert _writer_state(account['config']) == 'free'


def test_over_capacity_still_rejects_local_reads(account, capsys):
    pad_registry(account['registry'], CAP_BYTES + 4096)
    assert local_status(account) == 2
    assert json.loads(capsys.readouterr().out)['error'] == 'mirror_operation_failed'
    assert local_query(account) == 2
    assert json.loads(capsys.readouterr().out)['error'] == 'mirror_operation_failed'
    with pytest.raises(MirrorError, match='local_registry_snapshot_budget'):
        scope.account_status(account['config'])


def test_in_progress_backup_rejects_actual_sqlite_growth(account):
    path = account['registry']
    pad_registry(path, LARGE_REGISTRY_BYTES)
    copied_pages = []

    class GrowDuringBackup:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, sql):
            return self.connection.execute(sql)

        def backup(self, destination, *, pages, progress, sleep):
            def grow_then_report(status, remaining, total):
                if not copied_pages:
                    pad_registry(path, CAP_BYTES + 4096)
                copied_pages.append(total)
                progress(status, remaining, total)
            self.connection.backup(destination, pages=pages, progress=grow_then_report, sleep=sleep)

    with sqlite3.connect(str(path)) as connection:
        with pytest.raises(MirrorError, match='local_registry_snapshot_budget'):
            scope._registry_snapshot(GrowDuringBackup(connection))
    assert copied_pages and copied_pages[0] * 4096 == LARGE_REGISTRY_BYTES
    assert copied_pages[-1] * 4096 == CAP_BYTES + 4096
    assert path.stat().st_size == CAP_BYTES + 4096


def test_live_scale_registry_lock_rejects_and_retries(account, capsys):
    pad_registry(account['registry'], LARGE_REGISTRY_BYTES)
    with sqlite3.connect(account['registry']) as lock:
        lock.execute('BEGIN EXCLUSIVE')
        try:
            assert local_status(account) == 2
            assert json.loads(capsys.readouterr().out)['error'] == 'mirror_operation_failed'
        finally:
            lock.rollback()
    assert local_status(account) == 1
    assert json.loads(capsys.readouterr().out)['counts']['copied'] == 1


def test_live_scale_snapshot_keeps_two_second_copy_budget(account, monkeypatch):
    import time

    pad_registry(account['registry'], LARGE_REGISTRY_BYTES)
    timeline = iter((0., 2.01))
    with sqlite3.connect(account['registry']) as connection:
        with monkeypatch.context() as context:
            context.setattr(time, 'monotonic', lambda: next(timeline))
            with pytest.raises(MirrorError, match='local_registry_snapshot_budget'):
                scope._registry_snapshot(connection)
    assert next(timeline, None) is None
    assert scope.account_status(account['config'])['counts']['copied'] == 1
