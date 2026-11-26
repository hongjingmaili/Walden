"""The real account copy and registered local read against isolated SQLite."""
import json
import sqlite3

import pytest

from test_account_sync_status import FIRST, PENDING, hinted_round, item, seed_tables
from test_reboot_tolerance import SHARD
from wechat_local import native_scope_contract as sc
from wechat_local.native_mirror_query import query_local
from wechat_local.native_mirror_store import MirrorStore
from wechat_local.source_records import SourceKey


def row(local_id, server_id=None):
    return local_id, server_id if server_id is not None else local_id * 10, 1, 1000 + local_id, 0, 'message ' + str(local_id), 0


def seed(item, *, floor=3):
    seed_tables(item, [(FIRST, 3, 3, [row(n) for n in range(1, floor + 1)]),
                       (PENDING, 1, 1, [row(1, 101)])])
    config = item['config']
    for table, limit in ((FIRST, 3), (PENDING, 1)):
        key = SourceKey(config['account_id'], config['source_generation'], SHARD, table)
        store = MirrorStore(item['local_path'], key)
        store.apply_batch(key, table, [(n, *row(n, 101 if table == PENDING else None)) for n in range(1, limit + 1)], store.progress(table))
    with sqlite3.connect(item['local_path']) as local:
        raw = local.execute('SELECT value FROM __walden_progress WHERE table_name=?', (FIRST,)).fetchone()[0]
        progress = json.loads(raw)
        progress['target'] = floor
        local.execute('UPDATE __walden_progress SET value=? WHERE table_name=?', (json.dumps(progress), FIRST))


def target(item, table):
    return sc.target_ref(item['config'], SHARD, table)


def messages(item, table):
    return query_local(item['config'], {'target_ref': target(item, table)})['messages']


def preserved(item):
    with sqlite3.connect(item['local_path']) as local:
        return (local.execute(f'SELECT rowid,* FROM {FIRST} ORDER BY rowid').fetchall(),
                local.execute('SELECT * FROM __walden_observed WHERE table_name=? ORDER BY local_id,fingerprint', (FIRST,)).fetchall(),
                local.execute('SELECT value FROM __walden_progress WHERE table_name=?', (FIRST,)).fetchone()[0])


def test_single_table_regression_does_not_stop_same_shard_and_restores_missing_interval(item, monkeypatch):
    seed(item, floor=5)
    before = preserved(item)
    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'DELETE FROM {FIRST} WHERE local_id>2')
        source.execute(f'INSERT INTO {PENDING} VALUES (?,?,?,?,?,?,?)', row(2, 102))

    result = hinted_round(item, monkeypatch)
    assert 'source_cursor_regression' not in result['gaps']
    assert 'source_table_cursor_pending' in result['gaps']
    rows,observations,raw=preserved(item)
    earlier,now=json.loads(before[2]),json.loads(raw)
    # This pre-existing fixture deliberately simulates a st_dev renumber.
    assert now.pop('source_identity')[1] == earlier.pop('source_identity')[1]
    assert (rows,observations,now) == (before[0],before[1],earlier)
    assert [m['local_id'] for m in messages(item, PENDING)] == [1, 2]

    with sqlite3.connect(item['source_db']) as source:
        source.executemany(f'INSERT INTO {FIRST} VALUES (?,?,?,?,?,?,?)', [row(3), row(4), row(5), row(6)])
    for hint in range(2, 5):
        hinted_round(item, monkeypatch, shards={SHARD: hint})
    assert [m['local_id'] for m in messages(item, FIRST)] == [1, 2, 3, 4, 5, 6]
    rows, observed, progress = preserved(item)
    assert rows[:3] == before[0]
    assert set(before[1]) <= set(observed)
    assert json.loads(progress)['target'] == 6


def test_reused_integer_identity_keeps_old_rows_and_merges_query(item, monkeypatch):
    seed(item)
    before = preserved(item)
    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'DELETE FROM {FIRST} WHERE local_id>=2')
    hinted_round(item, monkeypatch)
    with sqlite3.connect(item['source_db']) as source:
        replacement = list(row(2, 999))
        replacement[5] = 'new generation'
        source.executemany(f'INSERT INTO {FIRST} VALUES (?,?,?,?,?,?,?)', [replacement, row(4)])
    for hint in range(2, 5):
        hinted_round(item, monkeypatch, shards={SHARD: hint})
    assert [m['text'] for m in messages(item, FIRST)] == ['message 1', 'message 2', 'new generation', 'message 3', 'message 4']
    original, observations, _ = preserved(item)
    assert original == before[0]
    assert set(before[1]) <= set(observations)


def test_raised_max_with_changed_old_body_and_nonpositive_server_id_holds_and_never_overwrites(item, monkeypatch):
    seed(item)
    hinted_round(item, monkeypatch)
    config = item['config']
    key = SourceKey(config['account_id'], config['source_generation'], SHARD, FIRST)
    store = MirrorStore(item['local_path'], key)
    store.apply_batch(key, FIRST, [(3, *row(3, 0))], store.progress(FIRST))
    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'DELETE FROM {FIRST} WHERE local_id=3')
    hinted_round(item, monkeypatch, shards={SHARD: 2})
    before = preserved(item)
    with sqlite3.connect(item['source_db']) as source:
        different = list(row(3, 0))
        different[5] = 'same identifier with changed content'
        source.executemany(f'INSERT INTO {FIRST} VALUES (?,?,?,?,?,?,?)', [different, row(4)])
    result = hinted_round(item, monkeypatch, shards={SHARD: 3})
    assert result['gaps'] == ['source_table_cursor_pending']
    assert preserved(item) == before
    assert [message['local_id'] for message in messages(item, FIRST)] == [1, 2, 3]
    assert 'source_table_cursor_pending' in query_local(item['config'], {'target_ref': target(item, FIRST)})['gaps']
    assert 'source_table_cursor_pending' not in query_local(item['config'], {'target_ref': target(item, PENDING)})['gaps']


def test_bounded_verification_does_not_publish_earlier_new_row_into_old_generation(item, monkeypatch):
    seed(item)
    hinted_round(item, monkeypatch)
    with sqlite3.connect(item['local_path']) as local:
        local.execute(f'DELETE FROM {FIRST} WHERE local_id=2')
        local.execute('DELETE FROM __walden_observed WHERE table_name=? AND local_id=2', (FIRST,))
    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'DELETE FROM {FIRST} WHERE local_id=3')
    hinted_round(item, monkeypatch, shards={SHARD: 2})
    with sqlite3.connect(item['source_db']) as source:
        third = list(row(3, 149))
        third[5] = 'replacement after first validation page'
        source.execute(f'INSERT INTO {FIRST} VALUES (?,?,?,?,?,?,?)', third)
    # Recompute only the actual per-batch work after the source/profile grants
    # are already fixed. The table is fully identified and snapshots use SQL.
    from wechat_local import native_mirror_sync as sync
    normal_budget = sync._account_budget
    def bounded(config):
        result = normal_budget(config)
        result['rows'] = 2
        return result
    monkeypatch.setattr(sync, '_account_budget', bounded)
    before = preserved(item)
    hinted_round(item, monkeypatch, shards={SHARD: 3})
    assert preserved(item) == before
    for hint in range(4, 12):
        hinted_round(item, monkeypatch, shards={SHARD: hint})
    with sqlite3.connect(item['local_path']) as db:
        archived = db.execute('SELECT progress FROM __walden_cursor_epochs WHERE table_name=? AND epoch=0', (FIRST,)).fetchone()[0]
    assert archived == before[2]
    assert preserved(item)[:2] == before[:2]
    assert any(message['text'] == 'replacement after first validation page' for message in messages(item, FIRST))


def test_noninteger_max_is_only_a_table_gap_and_cannot_prove_a_epoch(item, monkeypatch):
    seed(item)
    hinted_round(item, monkeypatch)
    before = preserved(item)
    from test_account_sync_status import fixture
    from wechat_local import native_mirror_sync as sync

    class NonIntegerMaximum:
        def __init__(self, db):
            self.db = db

        def execute(self, sql, params=()):
            if sql.startswith('SELECT coalesce(max(local_id)') and FIRST in sql:
                return self.db.execute('SELECT 40.0')
            return self.db.execute(sql, params)

        def __getattr__(self, name):
            return getattr(self.db, name)

    def run(value):
        def factory(path):
            db = sqlite3.connect(item['source_db'])
            db.execute('PRAGMA query_only=ON')
            return NonIntegerMaximum(db)
        return sync._account_sync(value['config'], connection_factory=factory)

    monkeypatch.setattr(fixture, 'run_full_account_sync', run)
    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'INSERT INTO {PENDING} VALUES (?,?,?,?,?,?,?)', row(2, 102))
    result = hinted_round(item, monkeypatch, shards={SHARD: 2})
    assert result['gaps'] == ['source_table_cursor_pending']
    assert preserved(item) == before
    assert [m['local_id'] for m in messages(item, PENDING)] == [1, 2]
    assert all('table_generation' not in m['source'] for m in messages(item, FIRST))


def test_backing_wal_advances_after_reader_pins_and_healthy_sibling_still_commits(item, monkeypatch):
    import hashlib
    from pathlib import Path
    from test_account_sync_status import fixture
    from wechat_local import native_mirror_sync as sync

    item['prior_header'] = hashlib.sha256(Path(item['source_db']).read_bytes()[:16]).hexdigest()
    item['prior_identity'] = item['live_identity']
    with sc.registry(item['config'], write=True) as registry:
        sc.save(registry, 'shard_anchor:' + SHARD, dict(source_identity=item['prior_identity'],header=item['prior_header']))
        registry.commit()
    seed(item)
    live = Path(item['live_path'])
    live.write_bytes(Path(item['source_db']).read_bytes())
    modified = []
    armed = False

    class ObservedConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            result = super().execute(sql, parameters)
            if armed and not modified and sql.startswith('SELECT rowid,*') and FIRST in sql:
                with sqlite3.connect(live) as writer:
                    writer.execute(f'UPDATE {FIRST} SET server_id=149,message_content=? WHERE local_id=3', ('concurrent replacement',))
                modified.append(True)
            return result

    def run(value):
        def factory(path):
            db = sqlite3.connect(path, factory=ObservedConnection)
            db.execute('PRAGMA query_only=ON')
            return db
        return sync._account_sync(value['config'], connection_factory=factory)

    monkeypatch.setattr(fixture, 'run_full_account_sync', run)
    writer = sqlite3.connect(live)
    try:
        assert writer.execute('PRAGMA journal_mode=WAL').fetchone() == ('wal',)
        hinted_round(item, monkeypatch)
        with writer:
            writer.execute(f'DELETE FROM {FIRST} WHERE local_id=3')
        hinted_round(item, monkeypatch, shards={SHARD: 2})
        before = preserved(item)
        with writer:
            writer.executemany(f'INSERT INTO {FIRST} VALUES (?,?,?,?,?,?,?)', [row(3), row(4)])
            writer.execute(f'INSERT INTO {PENDING} VALUES (?,?,?,?,?,?,?)', row(2, 102))
        armed = True
        result = hinted_round(item, monkeypatch, shards={SHARD: 3})
        assert modified, (result['gaps'], result.get('shard_diagnostics'), result['round_diagnostics'], result['sources'])
        assert result['gaps'] == ['source_table_cursor_pending']
        assert preserved(item) == before
        assert [m['local_id'] for m in messages(item, PENDING)] == [1, 2]
        for hint in range(4, 8):
            hinted_round(item, monkeypatch, shards={SHARD: hint})
        assert any(m['text'] == 'concurrent replacement' for m in messages(item, FIRST))
        assert preserved(item)[:2] == before[:2]
    finally:
        writer.close()


def test_high_max_and_reused_id_in_one_snapshot_never_write_new_tail_to_original(item, monkeypatch):
    seed(item)
    hinted_round(item, monkeypatch)
    before = preserved(item)

    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'UPDATE {FIRST} SET server_id=812,message_content=? WHERE local_id=2', ('lower reused ID',))
        source.execute(f'INSERT INTO {FIRST} VALUES (?,?,?,?,?,?,?)', row(4))
        source.execute(f'INSERT INTO {PENDING} VALUES (?,?,?,?,?,?,?)', row(2, 102))

    result = hinted_round(item, monkeypatch, shards={SHARD: 2})
    assert result['gaps'] == []
    with sc.registry(item['config']) as registry:
        assert sc.registry_schema(registry) == 2
    with sqlite3.connect(item['local_path']) as db:
        assert db.execute('SELECT progress FROM __walden_cursor_epochs WHERE table_name=? AND epoch=0', (FIRST,)).fetchone()[0] == before[2]
    assert preserved(item)[:2] == before[:2]
    assert [message['local_id'] for message in messages(item, PENDING)] == [1, 2]

    for hint in range(3, 7):
        result = hinted_round(item, monkeypatch, shards={SHARD: hint})
        assert 'account_copy_init_progress_lost' not in result['gaps']
    observed = {(message['text'], message['source']['table_generation']) for message in messages(item, FIRST)}
    assert ('lower reused ID', 1) in observed
    assert ('message 2', 0) in observed
    assert ('message 4', 1) in observed
    assert ('message 4', 0) not in observed


def test_table_partial_keeps_normal_cadence_with_or_without_shard_retry():
    from wechat_local import native_background, native_follow_schedule, native_follow_state

    partial_cases = [
        (['source_table_cursor_pending'], dict(paused_tables=1, retrying_shards=0, successful_shards=0)),
        (['source_shard_retry_pending', 'source_table_cursor_pending'], dict(paused_tables=1, retrying_shards=1, successful_shards=1)),
    ]
    epoch = dict(pid=20, start=[1,2])
    generation = 'b' * 32
    for gaps, counts in partial_cases:
        runtime = dict(operation='a' * 32, attempts=1)
        output = native_follow_schedule.control_result(dict(gaps=gaps, partial_source=counts, source_opens=2))
        native_background._completed_attempt(runtime, 1, json.dumps(output).encode())
        completed = runtime['last_completed']
        assert native_follow_schedule.partial_completion(completed)
        completed.update(completed_at_ns=10_000_000_000, completed_at_continuous_ns=10_000_000_000)
        cadence = native_follow_schedule.plan(None, wall=10, continuous=10_000_000_000, interval=30, completion=completed)
        assert cadence['mode'] == 'normal'
        worker = dict(active=True, stop_confirmed=False, operation=completed['operation'], kind='active',
                      policy_generation=generation, app_epoch=epoch, last_completed=completed)
        state = native_follow_state.transition(dict(policy_generation=generation, app_epoch=epoch),
            enabled=True, policy_generation=generation, app=dict(state='running',epoch=epoch),
            worker=worker, wall=10, continuous=10_000_000_000)
        assert state['state'] == 'partial_source'
        assert state['pending_reasons'] == gaps
        assert state['observed_catchup_complete'] is None


@pytest.mark.parametrize('mode', ['zero_server_id', 'delete_all'])
def test_high_max_with_ambiguous_old_ids_cannot_add_rows_to_original(item, monkeypatch, mode):
    seed(item)
    hinted_round(item, monkeypatch)
    before = preserved(item)

    with sqlite3.connect(item['source_db']) as source:
        if mode == 'delete_all':
            source.execute(f'DELETE FROM {FIRST}')
        else:
            source.execute(f'UPDATE {FIRST} SET server_id=0 WHERE local_id=2')
        source.execute(f'INSERT INTO {FIRST} VALUES (?,?,?,?,?,?,?)', row(4))
        source.execute(f'INSERT INTO {PENDING} VALUES (?,?,?,?,?,?,?)', row(2, 102))

    for hint in range(2, 5):
        result = hinted_round(item, monkeypatch, shards={SHARD: hint})
        assert result['gaps'] == ['source_table_cursor_pending']
        assert preserved(item) == before
        assert [m['local_id'] for m in messages(item, PENDING)] == [1, 2]
    with sc.registry(item['config']) as registry:
        assert sc.registry_schema(registry) == 1


def test_identical_typed_row_with_unknown_server_id_allows_same_generation_tail(item, monkeypatch):
    seed(item)
    hinted_round(item, monkeypatch)
    config = item['config']
    key = SourceKey(config['account_id'], config['source_generation'], SHARD, FIRST)
    store = MirrorStore(item['local_path'], key)
    store.apply_batch(key, FIRST, [(2, *row(2, 0))], store.progress(FIRST))

    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'UPDATE {FIRST} SET server_id=0 WHERE local_id=2')
        source.execute(f'INSERT INTO {FIRST} VALUES (?,?,?,?,?,?,?)', row(4))

    result = hinted_round(item, monkeypatch, shards={SHARD: 2})
    assert result['gaps'] == []
    assert [m['local_id'] for m in messages(item, FIRST)] == [1, 2, 3, 4]
    assert 'cursor_epoch' not in store.progress(FIRST)


def test_middle_delete_with_positive_anchor_passes_tail_reuse_and_preserves_old_rows(item, monkeypatch):
    seed(item)
    hinted_round(item, monkeypatch)
    before = preserved(item)

    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'DELETE FROM {FIRST} WHERE local_id=2')
        source.execute(f'INSERT INTO {FIRST} VALUES (?,?,?,?,?,?,?)', row(4))

    result = hinted_round(item, monkeypatch, shards={SHARD: 2})
    assert result['gaps'] == []
    rows, observed, progress = preserved(item)
    assert rows[:3] == before[0]
    assert set(before[1]) <= set(observed)
    assert [m['local_id'] for m in messages(item, FIRST)] == [1, 2, 3, 4]
    assert 'cursor_epoch' not in json.loads(progress)


@pytest.mark.parametrize('multipage', [False, True])
def test_pending_table_recovers_with_middle_delete_same_server_revision_and_unlocks_media(item, monkeypatch, multipage):
    seed(item)
    # Replace row 1 with an image message (local_type=3) to verify media gating clears on recovery.
    img_row = (1, 10, 3, 1001, 0, '<msg><img md5="abc"/></msg>', 0)
    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'UPDATE {FIRST} SET local_type=?, message_content=? WHERE local_id=1', (img_row[2], img_row[5]))
    config = item['config']
    key = SourceKey(config['account_id'], config['source_generation'], SHARD, FIRST)
    store = MirrorStore(item['local_path'], key)
    store.apply_batch(key, FIRST, [(1, *img_row)], store.progress(FIRST))
    hinted_round(item, monkeypatch)

    # Enter source_table_cursor_pending via tail regression.
    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'DELETE FROM {FIRST} WHERE local_id=3')
    paused_result = hinted_round(item, monkeypatch, shards={SHARD: 2})
    assert 'source_table_cursor_pending' in paused_result['gaps']
    paused_query = query_local(config, {'target_ref': target(item, FIRST), 'images': True})
    assert paused_query['messages'][0]['media']['reason'] == 'cursor_generation_media_unavailable'
    before = preserved(item)

    # Now source deletes middle row 2, revises row 3 with SAME positive server_id=30, and adds row 4.
    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'DELETE FROM {FIRST} WHERE local_id=2')
        revised = list(row(3, 30))
        revised[5] = 'recalled or revised same server_id'
        source.executemany(f'INSERT INTO {FIRST} VALUES (?,?,?,?,?,?,?)', [revised, row(4)])

    if multipage:
        from wechat_local import native_mirror_sync as sync
        normal_budget = sync._account_budget
        def bounded(cfg):
            res = normal_budget(cfg)
            res['rows'] = 2
            return res
        monkeypatch.setattr(sync, '_account_budget', bounded)

    for hint in range(3, 10):
        result = hinted_round(item, monkeypatch, shards={SHARD: hint})
        if not result['gaps']:
            break
    assert result['gaps'] == []
    rows, observed, progress = preserved(item)
    # Old rows 1, 2 (deleted in source), and 3 (revised in source) are strictly preserved unchanged.
    assert rows[:3] == before[0]
    assert set(before[1]) <= set(observed)
    assert [m['local_id'] for m in messages(item, FIRST)] == [1, 2, 3, 4]
    assert json.loads(progress)['cursor_guarded'] is True

    # Media is unlocked (no longer cursor_generation_media_unavailable).
    recovered_query = query_local(config, {'target_ref': target(item, FIRST), 'images': True})
    assert 'source_table_cursor_pending' not in recovered_query['gaps']
    assert recovered_query['messages'][0]['media']['reason'] != 'cursor_generation_media_unavailable'

    # Subsequent round (account_recent recheck on cursor_guarded table) must NOT re-pause or overwrite row 3.
    followup = hinted_round(item, monkeypatch, shards={SHARD: 10})
    assert followup['gaps'] == []
    assert preserved(item)[0][:3] == before[0]


def test_middle_delete_combined_with_true_local_id_reuse_still_rotates(item, monkeypatch):
    seed(item)
    hinted_round(item, monkeypatch)
    before = preserved(item)

    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'DELETE FROM {FIRST} WHERE local_id=1')
        source.execute(f'UPDATE {FIRST} SET server_id=812, message_content=? WHERE local_id=2', ('reused with delete',))
        source.execute(f'INSERT INTO {FIRST} VALUES (?,?,?,?,?,?,?)', row(4))

    result = hinted_round(item, monkeypatch, shards={SHARD: 2})
    assert result['gaps'] == []
    assert preserved(item)[:2] == before[:2]
    for hint in range(3, 7):
        hinted_round(item, monkeypatch, shards={SHARD: hint})
    observed = {(m['text'], m['source'].get('table_generation')) for m in messages(item, FIRST)}
    assert ('message 1', 0) in observed
    assert ('message 2', 0) in observed
    assert ('reused with delete', 1) in observed
    assert ('message 4', 1) in observed


def test_delete_without_any_positive_server_id_anchor_fails_closed(item, monkeypatch):
    seed(item)
    hinted_round(item, monkeypatch)
    config = item['config']
    key = SourceKey(config['account_id'], config['source_generation'], SHARD, FIRST)
    store = MirrorStore(item['local_path'], key)
    store.apply_batch(key, FIRST, [(n, *row(n, 0)) for n in (1, 2, 3)], store.progress(FIRST))
    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'UPDATE {FIRST} SET server_id=0')
    before = preserved(item)

    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'DELETE FROM {FIRST} WHERE local_id=2')
        source.execute(f'INSERT INTO {FIRST} VALUES (?,?,?,?,?,?,?)', row(4))

    for hint in range(2, 5):
        result = hinted_round(item, monkeypatch, shards={SHARD: hint})
        assert result['gaps'] == ['source_table_cursor_pending']
        assert preserved(item) == before


def test_pending_state_validation_accepts_legacy_and_bool_rejects_malformed(item):
    from wechat_local import native_table_cursor as tc
    from wechat_local.native_mirror_store import MirrorError

    seed(item)
    with sc.registry(item['config'], write=True) as registry:
        legacy = dict(after=0, through=None, blocked=False, target=3, epoch=0)
        tc.set_pending(registry, SHARD, FIRST, legacy)
        assert tc.pending(registry, SHARD, FIRST) == legacy

        extended = dict(after=1, through=5, blocked=False, anchored=True, missing=True,
                        phase='verify', stamp='a' * 64, target=3, epoch=0)
        tc.set_pending(registry, SHARD, FIRST, extended)
        assert tc.pending(registry, SHARD, FIRST) == extended

        for bad in (dict(extended, anchored=1), dict(extended, missing='yes')):
            tc.set_pending(registry, SHARD, FIRST, bad)
            with pytest.raises(MirrorError, match='scope_copy_proof'):
                tc.pending(registry, SHARD, FIRST)
