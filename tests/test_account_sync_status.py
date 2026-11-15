"""Focused synthetic coverage of the owned account round's status read."""
from pathlib import Path
import sqlite3
import tempfile

import pytest

import test_reboot_tolerance as fixture

from wechat_local import native_deadline, native_follow_grant
from wechat_local import native_scope_contract as scope
from wechat_local.native_mirror_store import MirrorError
from wechat_local.native_schedule import _writer_state


@pytest.fixture
def item(monkeypatch):
    # The OS job is synthetic, but its existing deadline and scope guards are real.
    monkeypatch.setattr(native_follow_grant, 'validate', lambda _grant: None)
    with tempfile.TemporaryDirectory(dir=Path(__file__).parent, prefix='status-') as root:
        value = fixture.setup(root, make_source_db=True)
        config = value['config']
        receipt = Path(root) / 'receipt.json'
        receipt_bytes = scope.encoded(dict(state='committed', contract=scope.fixed(config),
                                           new_config_sha256=scope.digest(config), legacy_current_sha256=None))
        scope.create(receipt, receipt_bytes)
        scope.create(Path(config['mirror_root']) / scope.CURRENT,
                     scope.encoded(dict(schema='walden.account.scope.current/1', contract=scope.fixed(config),
                                        receipt=str(receipt), receipt_sha256=scope.sha(receipt_bytes))))
        (Path(config['mirror_root']) / '.writer.lock').touch(mode=0o600)
        yield value


def authorized_round(item):
    grant = dict(kind='active', source_sha256=fixture.source_digest(item['config']))
    facts = dict(wall_until=30., continuous_start=0, continuous_until=30_000_000_000)
    deadline = native_follow_grant.FollowDeadline(facts, grant, wall=lambda: 0., continuous=lambda: 1)
    with native_deadline.activate_deadline(deadline):
        return fixture.run_full_account_sync(item)


def test_owned_status_skips_copy_but_local_status_keeps_snapshot(item, monkeypatch):
    copy_calls = []
    checked_views = []
    member = scope.member

    def reject_backup(_):
        copy_calls.append(True)
        raise MirrorError('local_registry_snapshot_budget')

    def inspect_status_view(config, db, shard, table):
        if db.execute('PRAGMA query_only').fetchone() == (1,):
            checked_views.append(shard)
            assert db.in_transaction
            assert _writer_state(config) == 'busy'
        return member(config, db, shard, table)

    monkeypatch.setattr(scope, '_registry_snapshot', reject_backup)
    monkeypatch.setattr(scope, 'member', inspect_status_view)
    token = scope.query_scope_guard(item['config'])
    result = authorized_round(item)
    assert 'scope_source_conflict' not in result['gaps']
    assert result['account_scope']['counts']['copied'] == 1
    assert result['account_scope']['source_opens'] == 0
    assert result['follow_observation']['known_backlog'] is True
    assert checked_views == [fixture.SHARD]
    assert copy_calls == []
    assert scope.query_scope_guard(item['config']) == token
    assert _writer_state(item['config']) == 'free'
    with pytest.raises(MirrorError, match='local_registry_snapshot_budget'):
        scope.account_status(item['config'])
    assert copy_calls == [True]


def test_owned_status_retains_registry_size_cap(item):
    path = Path(item['mirror_root']) / scope.REGISTRY
    with sqlite3.connect(path) as connection:
        connection.execute('CREATE TABLE synthetic_padding(value BLOB)')
        connection.execute('INSERT INTO synthetic_padding VALUES(zeroblob(?))', (65 * 1024 * 1024,))
    assert path.stat().st_size > 64 * 1024 * 1024
    with pytest.raises(MirrorError, match='local_registry_snapshot_budget'):
        authorized_round(item)
    assert _writer_state(item['config']) == 'free'


def test_owned_status_stops_on_existing_round_deadline(item, monkeypatch):
    expired = False
    member = scope.member

    def wall():
        return 31. if expired else 0.

    def expire_during_status(config, connection, shard, table):
        nonlocal expired
        if connection.execute('PRAGMA query_only').fetchone() == (1,):
            expired = True
        return member(config, connection, shard, table)

    monkeypatch.setattr(scope, 'member', expire_during_status)
    grant = dict(kind='active', source_sha256=fixture.source_digest(item['config']))
    facts = dict(wall_until=30., continuous_start=0, continuous_until=30_000_000_000)
    deadline = native_follow_grant.FollowDeadline(facts, grant, wall=wall, continuous=lambda: 1)
    with native_deadline.activate_deadline(deadline):
        with pytest.raises(MirrorError, match='schedule_deadline_expired'):
            fixture.run_full_account_sync(item)
    assert _writer_state(item['config']) == 'free'


def test_expiry_interrupts_long_owned_member_scan(item, monkeypatch):
    config = item['config']
    path = Path(item['mirror_root']) / scope.REGISTRY
    tables = ['Msg_' + format(i, '032x') for i in range(130)]
    observation = dict(contract=scope.fixed(config), shard=fixture.SHARD,
                       source_identity=item['prior_identity'], header=item['prior_header'],
                       query_only=True, tables=[[table, fixture.SCHEMA] for table in tables])
    with sqlite3.connect(path) as connection:
        scope._register_members(config, connection, observation, [
            dict(table=table, schema_sha256=fixture.SCHEMA, username=None,
                 supported=False, available=True) for table in tables])

    counts = dict(reads=0, grants=0)
    member = scope.member

    def sample_status(config, connection, shard, table):
        if connection.execute('PRAGMA query_only').fetchone() == (1,):
            counts['reads'] += 1
        return member(config, connection, shard, table)

    def count_grant(_grant):
        counts['grants'] += 1
        assert counts['reads'] < 64

    monkeypatch.setattr(scope, 'member', sample_status)
    monkeypatch.setattr(native_follow_grant, 'validate', count_grant)
    grant = dict(kind='active', source_sha256=fixture.source_digest(config))
    facts = dict(wall_until=30., continuous_start=0, continuous_until=30_000_000_000)
    deadline = native_follow_grant.FollowDeadline(
        facts, grant, wall=lambda: 31. if counts['reads'] else 0., continuous=lambda: 1)
    with native_deadline.activate_deadline(deadline):
        with pytest.raises(MirrorError, match='schedule_deadline_expired'):
            fixture.run_full_account_sync(item)
    assert counts['reads'] == 64
    assert _writer_state(config) == 'free'
