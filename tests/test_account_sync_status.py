"""Focused synthetic coverage of the owned account round's status read."""
from pathlib import Path
import json
import sqlite3
import tempfile

import pytest

import test_reboot_tolerance as fixture

from wechat_local import native_deadline, native_follow_grant, native_media_work
from wechat_local import native_scope_contract as scope
from wechat_local.native_mirror_store import MirrorError
from wechat_local.native_schedule import _writer_state


@pytest.fixture
def item(monkeypatch, request):
    # The OS job is synthetic, but its existing deadline and scope guards are real.
    monkeypatch.setattr(native_follow_grant, 'validate', lambda _grant: None)
    with tempfile.TemporaryDirectory(dir=Path(__file__).parent, prefix='status-') as root:
        value = fixture.setup(root, make_source_db=True)
        config = value['config']
        config.update(getattr(request, 'param', {}))
        monkeypatch.setenv('XDG_STATE_HOME', str(Path(root) / 'state'))
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


def hinted_round(item, monkeypatch, *, shards=None):
    from wechat_local import native_follow_grant
    from wechat_local.native_follow_policy import Store
    root=Path(item['mirror_root']).parent/'follow'
    store=Store(root,create=True)
    operation='a'*32
    generation='b'*32
    nonce='c'*32
    node=Path(item['message_root']).stat()
    runtime=dict(operation=operation,grant_nonce=nonce,context={},shard_hints=dict(
        root_identity=[node.st_dev,node.st_ino],shards=shards or {fixture.SHARD:1},fallback=False))
    for name,value in (('instance.'+operation+'.json',runtime),('current.json',dict(nonce=operation)),
                       ('intent.json',dict(enabled=True,generation=generation))):
        if store.path(name).exists():store.atomic(name,value)
        else:store.immutable(name,value)
    grant=dict(kind='active',source_sha256=fixture.source_digest(item['config']),store_root=str(root),
               instance_nonce=operation,policy_generation=generation,nonce=nonce,os_context={})
    facts=dict(wall_until=30.,continuous_start=0,continuous_until=30_000_000_000)
    deadline=native_follow_grant.FollowDeadline(facts,grant,wall=lambda:0.,continuous=lambda:1)
    with native_deadline.activate_deadline(deadline):
        return fixture.run_full_account_sync(item)


@pytest.mark.parametrize('item',[{'mirror_account_rows':1,'mirror_account_tables':1}],indirect=True)
def test_new_tail_uses_only_batch_before_historical_backlog(item,monkeypatch):
    seed_round_tables(item,first_max=2)
    result=hinted_round(item,monkeypatch)
    assert not result['gaps']
    assert [(s['table'],s['tail']) for s in result['sources']]==[(FIRST,2)]
    with sqlite3.connect(item['local_path']) as db:
        remaining=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(PENDING,)).fetchone()[0])
    assert remaining['history']==0 and remaining['history_complete'] is False


@pytest.mark.parametrize('item',[{'mirror_account_rows':1,'mirror_account_tables':1}],indirect=True)
def test_new_tail_on_same_table_precedes_its_even_history_turn(item,monkeypatch):
    seed_round_tables(item,first_max=1,pending_max=2)
    result=hinted_round(item,monkeypatch)
    assert not result['gaps']
    assert [(s['table'],s['history'],s['tail']) for s in result['sources']]==[(PENDING,0,2)]


@pytest.mark.parametrize('item',[{'mirror_account_rows':1,'mirror_account_tables':1,
                                'mirror_batch_size':1}],indirect=True)
def test_continuous_new_tail_delays_history_and_rotates_hot_tables(item,monkeypatch):
    seed_round_tables(item,first_max=10,pending_max=2)
    first=hinted_round(item,monkeypatch)
    second=hinted_round(item,monkeypatch)
    assert [(s['table'],s['tail']) for s in first['sources']]==[(FIRST,2)]
    assert [(s['table'],s['tail']) for s in second['sources']]==[(PENDING,2)]
    assert second['sources'][0]['history']==0
    for _ in range(8):
        assert not hinted_round(item,monkeypatch)['gaps']
    with sqlite3.connect(item['local_path']) as db:
        progress={table:json.loads(raw) for table,raw in db.execute('SELECT table_name,value FROM __walden_progress')}
    assert progress[FIRST]['tail']==10
    assert progress[PENDING]['history']==0 and progress[PENDING]['tail']==2
    resumed=hinted_round(item,monkeypatch)
    assert [(s['table'],s['history']) for s in resumed['sources']]==[(PENDING,1)]


@pytest.mark.parametrize('item',[{'mirror_account_rows':1,'mirror_account_tables':1}],indirect=True)
def test_deferred_tail_keeps_hint_and_debt_without_advancing_any_message_watermark(item,monkeypatch):
    from wechat_local import native_mirror_sync as sync
    seed_round_tables(item,first_max=2)
    with monkeypatch.context() as stopped:
        stopped.setattr(sync,'_account_copy_table',lambda *args,**kwargs:None)
        result=hinted_round(item,monkeypatch)
    assert result['sources']==[]
    with scope.registry(item['config']) as db:
        pending=scope.state(db,'tail_probe:'+fixture.SHARD)
        assert pending['pending']==[[FIRST,2]]
        assert scope.state(db,'tail_hints',{}).get('shards',{}).get(fixture.SHARD,0)==0
    with sqlite3.connect(item['local_path']) as db:
        progress=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(FIRST,)).fetchone()[0])
    assert progress['history']==progress['tail']==progress['H']==1
    result=hinted_round(item,monkeypatch)
    assert [(s['table'],s['tail']) for s in result['sources']]==[(FIRST,2)]


def copy_synthetic_shard(item,name):
    import hashlib
    import shutil
    live=Path(item['message_root'])/name
    shutil.copyfile(item['live_path'],live)
    node=live.stat()
    identity=[node.st_dev,node.st_ino]
    header=hashlib.sha256(live.read_bytes()[:16]).hexdigest()
    target=Path(item['mirror_root'])/name
    with sqlite3.connect(item['local_path']) as original,sqlite3.connect(target) as copied:
        original.backup(copied)
        copied.execute('UPDATE __walden_binding SET shard=?',(name,))
        for table,raw in copied.execute('SELECT table_name,value FROM __walden_progress').fetchall():
            value=json.loads(raw)
            value.update(source_identity=identity,source_header_sha256=header)
            copied.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',(json.dumps(value),table))
    target.chmod(0o600)
    with scope.registry(item['config'],write=True) as registry:
        members=[json.loads(row[0]) for row in registry.execute('SELECT proof FROM members WHERE shard=?',(fixture.SHARD,))]
        observation=dict(contract=scope.fixed(item['config']),shard=name,source_identity=identity,header=header,
                         query_only=True,tables=[[row['table'],row['schema_sha256']] for row in members])
        scope._register_members(item['config'],registry,observation,members)
        roster=scope.state(registry,'roster',[])
        scope.save(registry,'roster',sorted(set(roster+[name])))
        registry.commit()
    return target


@pytest.mark.parametrize('item',[{'mirror_account_shards':1,'mirror_account_rows':1,
                                'mirror_account_tables':1}],indirect=True)
def test_changed_shard_bypasses_nineteen_shard_rotation_without_raising_open_budget(item,monkeypatch):
    seed_round_tables(item,first_max=2)
    for index in range(1,19):
        copy_synthetic_shard(item,f'message_{index}.db')
    result=hinted_round(item,monkeypatch,shards={'message_9.db':7})
    assert not result['gaps'] and result['source_opens']==1
    assert [(s['shard'],s['table'],s['tail']) for s in result['sources']]==[('message_9.db',FIRST,2)]


@pytest.mark.parametrize('item',[{'mirror_account_shards':1,'mirror_account_rows':1,
                                'mirror_account_tables':1}],indirect=True)
def test_previously_observed_tail_debt_precedes_history_without_a_vnode_hint(item):
    seed_round_tables(item,first_max=2)
    target=copy_synthetic_shard(item,'message_1.db')
    with sqlite3.connect(target) as local:
        value=json.loads(local.execute('SELECT value FROM __walden_progress WHERE table_name=?',(FIRST,)).fetchone()[0])
        value['target']=2
        local.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',(json.dumps(value),FIRST))
    result=authorized_round(item)
    assert not result['gaps'] and result['source_opens']==1
    assert [(s['shard'],s['table'],s['tail']) for s in result['sources']]==[('message_1.db',FIRST,2)]


@pytest.mark.parametrize('item',[{'mirror_account_shards':1,'mirror_account_rows':1,
                                'mirror_account_tables':1}],indirect=True)
def test_false_hint_cannot_hide_a_previously_observed_debt_on_another_shard(item,monkeypatch):
    seed_round_tables(item,first_max=2)
    target=copy_synthetic_shard(item,'message_1.db')
    with sqlite3.connect(target) as local:
        value=json.loads(local.execute('SELECT value FROM __walden_progress WHERE table_name=?',(FIRST,)).fetchone()[0])
        value['target']=2
        local.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',(json.dumps(value),FIRST))
    with sqlite3.connect(item['local_path']) as local:
        local.execute(f'INSERT INTO {FIRST} VALUES (2,2,1,1000,0,?,0)',('synthetic',))
        value=json.loads(local.execute('SELECT value FROM __walden_progress WHERE table_name=?',(FIRST,)).fetchone()[0])
        value['tail']=value['target']=2
        local.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',(json.dumps(value),FIRST))
    result=hinted_round(item,monkeypatch)
    assert not result['gaps'] and result['source_opens']==1
    assert [(s['shard'],s['table'],s['tail']) for s in result['sources']]==[('message_1.db',FIRST,2)]


@pytest.mark.parametrize('item',[{'mirror_account_shards':1,'mirror_account_rows':1,
                                'mirror_account_tables':1}],indirect=True)
def test_incomplete_known_debt_import_pauses_history_and_resumes_before_later_shard(item,monkeypatch):
    import shutil
    from wechat_local import native_mirror_sync as sync
    rows=[(1,1,1,1000,0,'synthetic',0)]
    seed_tables(item,[(f'Msg_{n:032x}',0,1,rows) for n in range(300)])
    target=copy_synthetic_shard(item,'message_1.db')
    other_source=Path(item['source_db']).with_name('other_source.sqlite')
    shutil.copyfile(item['source_db'],other_source)
    with sqlite3.connect(other_source) as source:
        source.execute(f'INSERT INTO {FIRST} VALUES (2,2,1,1000,0,?,0)',('new synthetic',))
    with sqlite3.connect(target) as local:
        value=json.loads(local.execute('SELECT value FROM __walden_progress WHERE table_name=?',(FIRST,)).fetchone()[0])
        value['target']=2
        local.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',(json.dumps(value),FIRST))
    def run(value):
        def factory(path):
            source=sqlite3.connect(other_source if path.name=='message_1.db' else item['source_db'])
            source.execute('PRAGMA query_only=ON')
            return source
        return sync._account_sync(value['config'],connection_factory=factory)
    auxiliary=[]
    def auxiliary_snapshot(*args):
        auxiliary.append(True)
        return dict(opens=0,rows=0,written=0,status='synthetic')
    monkeypatch.setattr(fixture,'run_full_account_sync',run)
    monkeypatch.setattr(sync,'_account_aux',auxiliary_snapshot)
    first=authorized_round(item)
    assert not first['gaps'] and first['sources']==[] and auxiliary==[]
    assert first['new_tail']['known_debt_import_complete'] is False
    assert first['new_tail']['probe_complete'] is False
    with scope.registry(item['config']) as registry:
        cursor=scope.state(registry,'tail_debt_cursor')
        assert cursor==dict(shard=fixture.SHARD,table=f'Msg_{255:032x}')
    second=authorized_round(item)
    assert not second['gaps']
    assert [(row['shard'],row['table'],row['tail']) for row in second['sources']]==[('message_1.db',FIRST,2)]
    for result in (first,second):
        assert result['new_tail']['metadata_tables']<=1024
        assert result['new_tail']['metadata_bytes']<=1024*1024
    with sqlite3.connect(item['local_path']) as local:
        assert all(json.loads(raw)['history']==0 for raw, in local.execute('SELECT value FROM __walden_progress'))
    resumed=authorized_round(item)
    assert resumed['new_tail']['known_debt_import_complete'] is True
    assert any(row['history']==1 for row in resumed['sources'])


@pytest.mark.parametrize('item',[{'mirror_account_shards':1}],indirect=True)
def test_auxiliary_snapshot_runs_after_new_tail_under_existing_separate_open_allowance(item,monkeypatch):
    from wechat_local import native_mirror_sync as sync
    seed_round_tables(item,first_max=2)
    events=[]
    copy=sync._account_copy_table
    def copy_then_record(*args,**kwargs):
        result=copy(*args,**kwargs)
        if result is not None:
            events.append((args[3],result['progress']['tail']))
        return result
    def auxiliary(*args):
        events.append('auxiliary')
        return dict(opens=1,rows=0,written=0,status='synthetic')
    monkeypatch.setattr(sync,'_account_copy_table',copy_then_record)
    monkeypatch.setattr(sync,'_account_aux',auxiliary)
    result=authorized_round(item)
    assert not result['gaps'] and result['source_opens']==2
    assert events[0]==(FIRST,2) and events[-1]=='auxiliary'


@pytest.mark.parametrize('item',[{'mirror_account_shards':1,'mirror_account_rows':1,
                                'mirror_account_tables':1}],indirect=True)
def test_auxiliary_due_survives_incomplete_import_without_cadence_phase_lock(item,monkeypatch):
    from wechat_local import native_mirror_sync as sync
    rows=[(1,1,1,1000,0,'synthetic',0)]
    seed_tables(item,[(f'Msg_{n:032x}',0,1,rows) for n in range(300)])
    auxiliary=[]
    round_number=0
    def auxiliary_snapshot(*args):
        auxiliary.append(round_number)
        return dict(opens=0,rows=0,written=0,status='synthetic')
    monkeypatch.setattr(sync,'_account_aux',auxiliary_snapshot)
    history_batches=0
    for round_number in range(8):
        result=authorized_round(item)
        assert not result['gaps']
        if not result['new_tail']['known_debt_import_complete']:
            assert result['sources']==[]
        history_batches+=len(result['sources'])
    assert history_batches>=3
    assert auxiliary==[1,5]


def test_tail_probe_interrupts_expensive_sql_and_preserves_unfinished_cursor(item,monkeypatch):
    from types import SimpleNamespace
    from wechat_local import native_mirror_sync as sync
    seed_round_tables(item,first_max=2,pending_max=2)
    clock=SimpleNamespace(value=0.)
    monkeypatch.setattr(sync,'time',SimpleNamespace(monotonic=lambda:clock.value,time=lambda:1000.))
    source=sqlite3.connect(item['source_db'])
    source.execute('PRAGMA query_only=ON')
    source.execute('BEGIN')
    local=sqlite3.connect(item['local_path'])
    callbacks=[]
    class Source:
        @property
        def in_transaction(self):
            return source.in_transaction

        def set_progress_handler(self,callback,steps):
            callbacks.append(callback)
            source.set_progress_handler(callback,steps)

        def execute(self,sql,args=()):
            if sql.startswith('SELECT coalesce(max(local_id)') and qi_first in sql:
                clock.value=3.
                return source.execute('WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<1000000) SELECT max(x) FROM n')
            return source.execute(sql,args)
    qi_first='"'+FIRST+'"'
    def budget():
        return dict(until=20.,tail_probe=dict(until=None,tables=0,bytes=0,limited=False))
    try:
        with scope.registry(item['config'],write=True) as registry:
            anchor=scope.state(registry,'shard_anchor:'+fixture.SHARD)
            state=sync._account_tail_probe(item['config'],Source(),registry,Path(item['live_path']),local,
                                          anchor,budget(),['fixture',1])
            assert state['after']==FIRST and state['pending']==[] and not state['complete']
            assert callbacks[-1] is None
            assert source.in_transaction and source.execute('PRAGMA query_only').fetchone()==(1,)
            clock.value=0.
            state=sync._account_tail_probe(item['config'],source,registry,Path(item['live_path']),local,
                                          anchor,budget(),['fixture',1])
            assert state['pending']==[[PENDING,2]] and not state['complete']
            # A newly discovered debt now yields immediately for guarded copy.
            assert state['after']==PENDING
            state=sync._account_tail_probe(item['config'],source,registry,Path(item['live_path']),local,
                                          anchor,budget(),['fixture',1],copied={PENDING})
            assert state['after']=='' and state['pending']==[[PENDING,2]]
        values=[json.loads(raw) for raw, in local.execute('SELECT value FROM __walden_progress')]
        assert all(value['tail']==value['H']==1 for value in values)
    finally:
        local.close();source.close()


@pytest.mark.parametrize('item',[{'mirror_account_rows':1,'mirror_account_tables':1,
                                'mirror_batch_size':1}],indirect=True)
def test_new_hint_discovers_another_hot_table_before_earlier_large_tail_drains(item,monkeypatch):
    seed_round_tables(item,first_max=10,pending_max=1)
    assert hinted_round(item,monkeypatch)['sources'][0]['tail']==2
    with sqlite3.connect(item['source_db']) as source:
        source.execute(f'INSERT INTO {PENDING} VALUES (2,2,1,1000,0,?,0)',('new synthetic',))
    assert hinted_round(item,monkeypatch,shards={fixture.SHARD:2})['sources'][0]['tail']==3
    third=hinted_round(item,monkeypatch,shards={fixture.SHARD:2})
    assert [(row['table'],row['history'],row['tail']) for row in third['sources']]==[(PENDING,0,2)]


def test_event_arriving_during_copy_is_not_acknowledged_by_the_earlier_round(item,monkeypatch):
    from wechat_local import native_mirror_sync as sync
    from wechat_local.native_follow_policy import Store
    seed_round_tables(item,first_max=2)
    copy=sync._account_copy_table
    def copy_then_hint(*args,**kwargs):
        result=copy(*args,**kwargs)
        grant=native_deadline._current.get().grant
        store=Store(grant['store_root'])
        name='instance.'+grant['instance_nonce']+'.json'
        parent=store.read(name)
        parent['shard_hints']['shards'][fixture.SHARD]=2
        store.atomic(name,parent)
        return result
    monkeypatch.setattr(sync,'_account_copy_table',copy_then_hint)
    result=hinted_round(item,monkeypatch)
    assert not result['gaps']
    store=Store(Path(item['mirror_root']).parent/'follow')
    assert store.read('instance.'+'a'*32+'.json')['shard_hints']['shards'][fixture.SHARD]==2
    with scope.registry(item['config']) as registry:
        assert scope.state(registry,'tail_hints')['shards'][fixture.SHARD]==1


@pytest.mark.parametrize('broken',['root','path','context'])
def test_shard_hint_is_only_same_root_and_context_metadata(item,monkeypatch,broken):
    from wechat_local import native_mirror_sync as sync
    from wechat_local.native_follow_policy import Store
    seed_round_tables(item,first_max=2)
    seen=[]
    read=sync._account_tail_hints
    def change_hint(config,grant):
        store=Store(grant['store_root'])
        name='instance.'+grant['instance_nonce']+'.json'
        parent=store.read(name)
        if broken=='root':
            parent['shard_hints']['root_identity']=[0,0]
        elif broken=='path':
            parent['shard_hints']['shards']={'../message_0.db':1}
        else:
            parent['context']={'foreign':True}
        store.atomic(name,parent)
        value=read(config,grant)
        seen.append(value)
        return value
    monkeypatch.setattr(sync,'_account_tail_hints',change_hint)
    result=hinted_round(item,monkeypatch)
    assert not result['gaps']
    assert seen==[({},True)] and result['new_tail']['hint_fallback'] is True


def test_owned_status_skips_copy_but_local_status_keeps_snapshot(item, monkeypatch):
    copy_calls = []
    checked_views = []
    member = scope.member

    def reject_backup(_):
        copy_calls.append(True)
        raise MirrorError('local_registry_snapshot_budget')

    def inspect_status_view(config, db, shard, table, **kwargs):
        if db.execute('PRAGMA query_only').fetchone() == (1,):
            checked_views.append(shard)
            assert db.in_transaction
            assert _writer_state(config) == 'busy'
        return member(config, db, shard, table, **kwargs)

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
        connection.execute('INSERT INTO synthetic_padding VALUES(zeroblob(?))', (129 * 1024 * 1024,))
    assert path.stat().st_size > 128 * 1024 * 1024
    with pytest.raises(MirrorError, match='local_registry_snapshot_budget'):
        authorized_round(item)
    assert _writer_state(item['config']) == 'free'


def test_owned_status_stops_on_existing_round_deadline(item, monkeypatch):
    expired = False
    member = scope.member

    def wall():
        return 31. if expired else 0.

    def expire_during_status(config, connection, shard, table, **kwargs):
        nonlocal expired
        if connection.execute('PRAGMA query_only').fetchone() == (1,):
            expired = True
        return member(config, connection, shard, table, **kwargs)

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

    def sample_status(config, connection, shard, table, **kwargs):
        if connection.execute('PRAGMA query_only').fetchone() == (1,):
            counts['reads'] += 1
        return member(config, connection, shard, table, **kwargs)

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


FIRST = 'Msg_' + '0' * 32
PENDING = 'Msg_' + 'f' * 32


def seed_round_tables(item, *, first_kind=1, first_max=1, first_tail_payload='synthetic',
                      pending_current=0, pending_max=1):
    """Build a ready table before a historical backlog."""
    tables = []
    for table, current, maximum, kind in ((FIRST, 1, first_max, first_kind),
                                          (PENDING, pending_current, pending_max, 1)):
        rows = [(n, n, kind, 1000, 0, first_tail_payload if table == FIRST and n > 1 else 'synthetic', 0)
                for n in range(1, maximum + 1)]
        tables.append((table, current, 1, rows))
    seed_tables(item, tables)


def seed_tables(item, tables):
    config = item['config']
    observation = dict(contract=scope.fixed(config), shard=fixture.SHARD,
                       source_identity=item['prior_identity'], header=item['prior_header'],
                       query_only=True, tables=[])
    members = []
    with sqlite3.connect(item['source_db']) as source, sqlite3.connect(item['local_path']) as mirror:
        mirror.execute('DELETE FROM __walden_progress')
        for table, history, ceiling, rows in tables:
            ddl = f"""CREATE TABLE {table} (local_id INTEGER PRIMARY KEY, server_id INTEGER,
                local_type INTEGER, create_time INTEGER, real_sender_id INTEGER,
                message_content TEXT, WCDB_CT_message_content INTEGER)"""
            source.execute(ddl)
            mirror.execute(ddl)
            insert = f'INSERT INTO {table} VALUES (?,?,?,?,?,?,?)'
            source.executemany(insert, rows)
            mirror.executemany(insert, (row for row in rows if row[0] <= history))
            progress = dict(H=ceiling, history=history, tail=ceiling, target=ceiling, history_complete=history >= ceiling,
                            checked_at=1000, source_identity=item['prior_identity'],
                            source_header_sha256=item['prior_header'])
            mirror.execute('INSERT INTO __walden_progress VALUES(?,?)', (table, json.dumps(progress)))
            schema = scope.sha(ddl.encode())
            observation['tables'].append([table, schema])
            members.append(dict(table=table, schema_sha256=schema, username=None,
                                supported=True, available=True, inventory_pass='old'))
    with scope.registry(config, write=True) as db:
        db.execute('DELETE FROM members')
        scope._register_members(config, db, observation, members)
        db.commit()


@pytest.mark.parametrize('item', [{'mirror_account_tables': 1}], indirect=True)
def test_single_copy_slot_handles_new_tail_then_resumes_history(item):
    seed_round_tables(item, first_max=2)

    first = authorized_round(item)
    assert [(row['table'], row['tail']) for row in first['sources']] == [(FIRST, 2)]
    assert first['sources'][0]['history_complete']

    second = authorized_round(item)
    assert [(row['table'], row['history']) for row in second['sources']] == [(PENDING, 1)]
    assert not first['gaps'] and not second['gaps']


@pytest.mark.parametrize('item', [{'mirror_account_tables': 2, 'mirror_account_bytes': 12 * 1024}],
                         indirect=True)
def test_ordinary_target_retries_a_row_deferred_by_remaining_byte_budget(item):
    seed_round_tables(item, first_max=2, first_tail_payload='x' * 6000)

    first = authorized_round(item)
    assert not first['gaps']
    assert [(row['table'],row['tail']) for row in first['sources']] == [(FIRST,2)]
    assert first['sources'][0]['history_complete']

    second = authorized_round(item)
    assert not second['gaps']
    assert [(row['table'],row['history'],row['tail']) for row in second['sources']]==[
        (FIRST,1,2),(PENDING,1,1)]


@pytest.mark.parametrize('item', [{'mirror_account_tables': 2, 'mirror_account_bytes': 18_000,
                                   'mirror_batch_size': 1}], indirect=True)
def test_table_deferred_after_an_ordinary_copy_gets_the_next_ordinary_visit(item):
    tables = []
    for index, size in enumerate((9000, 9000, 12600, 9000, 5400, 5400)):
        table = 'Msg_' + format(index, '032x')
        has_backlog = index in (1, 3, 4)
        history, ceiling = (0, 1200) if has_backlog else (1001, 1001)
        end = 1002 if index == 2 else 1200
        rows = [(n, n, 1, 1000, 0, 'a' * (size - 4111), 0) for n in range(1001, end + 1)]
        tables.append((table, history, ceiling, rows))
    seed_tables(item, tables)

    for _ in range(3):
        assert not authorized_round(item)['gaps']
    target = tables[2][0]
    with sqlite3.connect(item['local_path']) as mirror:
        assert mirror.execute(f'SELECT max(local_id) FROM {target}').fetchone() == (1002,)


@pytest.mark.parametrize('item', [{'mirror_account_tables': 2, 'mirror_account_bytes': 12 * 1024}],
                         indirect=True)
def test_ordinary_target_still_reports_a_row_over_the_entire_byte_budget(item):
    seed_round_tables(item, first_max=2, first_tail_payload='x' * 12_000)

    result = authorized_round(item)
    assert result['gaps'] == ['account_row_oversize']


@pytest.mark.parametrize('item', [{'mirror_account_tables': 2, 'mirror_account_bytes': 12 * 1024}],
                         indirect=True)
def test_ordinary_visit_still_reaches_smaller_row_after_sender_mapping(item):
    seed_round_tables(item, first_max=2, first_tail_payload='x' * 6000,
                      pending_current=1, pending_max=2)
    with sqlite3.connect(item['source_db']) as source:
        source.execute('INSERT INTO Name2Id VALUES (?)', ('x' * 4096,))

    result = authorized_round(item)
    assert not result['gaps']
    assert (PENDING, 2) in [(row['table'], row['tail']) for row in result['sources']]


@pytest.mark.parametrize('item', [{'mirror_account_rows': 1}], indirect=True)
def test_sender_mapping_using_last_row_does_not_complete_history(item):
    seed_round_tables(item)
    with sqlite3.connect(item['source_db']) as source:
        source.execute("INSERT INTO Name2Id VALUES ('synthetic_contact')")

    result = authorized_round(item)
    assert not result['gaps']
    assert result['account_scope']['counts']['raw_complete'] == 1


def test_media_enqueue_reuses_owned_member_and_skips_empty_batch(item, monkeypatch):
    seed_round_tables(item, first_kind=3, first_max=2)
    copies = []
    enqueue = native_media_work.enqueue_rows
    enqueued = []
    snapshot = scope._registry_snapshot

    def track_copy(db):
        copies.append(True)
        return snapshot(db)

    def track_enqueue(config, shard, table, username, columns, rows, **kwargs):
        enqueued.append((table, username, len(rows)))
        return enqueue(config, shard, table, username, columns, rows, **kwargs)

    monkeypatch.setattr(scope, '_registry_snapshot', track_copy)
    monkeypatch.setattr(native_media_work, 'enqueue_rows', track_enqueue)
    result = authorized_round(item)
    assert not result['gaps']
    pending_ref = scope.target_ref(item['config'], fixture.SHARD, PENDING)
    first_ref = scope.target_ref(item['config'], fixture.SHARD, FIRST)
    assert sorted(enqueued) == [(FIRST, first_ref, 1), (PENDING, pending_ref, 1)]
    jobs_path = Path(item['mirror_root']) / 'media-work.sqlite'
    assert jobs_path.exists()
    with sqlite3.connect(jobs_path) as jobs:
        assert jobs.execute('SELECT username,kind,status FROM jobs').fetchall() == [(first_ref, 'image', 'pending')]

    # At this point both tables are old and ready; a recheck has no rows to enqueue.
    enqueued.clear()
    assert not authorized_round(item)['gaps']
    assert enqueued == []
    assert copies == []


def test_status_checks_shared_proof_once_and_verifies_each_member(item, monkeypatch):
    seed_round_tables(item)
    config = item['config']
    digest = scope.digest
    proof_checks = []

    def track_digest(value):
        if isinstance(value, dict) and 'tables' in value:
            proof_checks.append(True)
        return digest(value)

    monkeypatch.setattr(scope, 'digest', track_digest)
    assert scope.account_status(config)['counts']['registered'] == 2
    assert proof_checks == [True]

    with scope.registry(config, write=True) as db:
        raw, = db.execute('SELECT proof FROM members WHERE table_name=?', (PENDING,)).fetchone()
        proof = json.loads(raw)
        proof['schema_sha256'] = '1' * 64
        db.execute('UPDATE members SET proof=? WHERE table_name=?', (json.dumps(proof), PENDING))
        db.commit()
    with pytest.raises(MirrorError, match='scope_member_proof'):
        scope.account_status(config)


def test_media_enqueue_rechecks_revocation_after_raw_commit(item, monkeypatch):
    from wechat_local.native_mirror_store import MirrorStore

    seed_round_tables(item, first_kind=3, first_max=2)
    apply_batch = MirrorStore.apply_batch
    revoked = False

    def revoke_after_raw_commit(store, source, table, rows, progress, **kwargs):
        nonlocal revoked
        written = apply_batch(store, source, table, rows, progress, **kwargs)
        if table == FIRST and rows:
            revoked = True
        return written

    def check_grant(_grant):
        if revoked:
            raise MirrorError('synthetic_follow_revoked')

    monkeypatch.setattr(MirrorStore, 'apply_batch', revoke_after_raw_commit)
    monkeypatch.setattr(native_follow_grant, 'validate', check_grant)
    with pytest.raises(MirrorError, match='synthetic_follow_revoked'):
        authorized_round(item)
    assert revoked
    assert not (Path(item['mirror_root']) / 'media-work.sqlite').exists()


def test_media_backfill_reaches_existing_queue_without_full_registry_snapshot(item, monkeypatch):
    seed_round_tables(item, first_kind=3)

    def reject_snapshot(_):
        raise MirrorError('local_registry_snapshot_budget')

    def reject_source(_):
        raise AssertionError('unresolved local job must not open a source')

    monkeypatch.setattr(scope, '_registry_snapshot', reject_snapshot)
    result = native_media_work.run_media(item['config'], reject_source)
    assert result['media_backfill']['status'] == 'processed_page'
    assert result['media_backfill']['rows'] == 1
    jobs_path = Path(item['mirror_root']) / 'media-work.sqlite'
    with sqlite3.connect(jobs_path) as jobs:
        assert jobs.execute('SELECT kind,status,reason FROM jobs').fetchall() == [
            ('image', 'pending', 'identity_pending')
        ]


def test_media_backfill_still_rejects_oversized_registry(item, monkeypatch):
    seed_round_tables(item, first_kind=3)
    monkeypatch.setattr(scope, '_REGISTRY_MAX_BYTES', 1)
    with pytest.raises(MirrorError, match='local_registry_snapshot_budget'):
        native_media_work.backfill(item['config'])


def test_media_registry_busy_defers_without_advancing_the_page(item):
    seed_round_tables(item, first_kind=3)
    registry_path = Path(item['mirror_root']) / scope.REGISTRY
    facts = {}
    with sqlite3.connect(registry_path) as locked:
        locked.execute('BEGIN EXCLUSIVE')
        assert native_media_work.backfill(item['config'], diagnostic=facts) == 0
    assert facts == {'status': 'pending_writer', 'rows': 0, 'complete': False}
    with scope.registry(item['config'], snapshot=False) as db:
        assert scope.state(db, 'media_backfill') is None


def test_media_page_releases_reader_before_fresh_binding_check(item, monkeypatch):
    import subprocess
    import sys

    seed_round_tables(item, first_kind=3)
    registry_path = Path(item['mirror_root']) / scope.REGISTRY
    member, safe = scope.member, scope._safe
    reading = None
    checked = False
    script = """
import sqlite3, sys
with sqlite3.connect(sys.argv[1], timeout=2) as db:
    assert sys.stdin.readline().strip() == 'go'
    db.execute('BEGIN IMMEDIATE')
    db.execute("INSERT INTO state VALUES ('synthetic_writer', 'true')")
    print('committing', flush=True)
    db.commit()
"""
    with subprocess.Popen([sys.executable, '-B', '-I', '-c', script, str(registry_path)],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as writer:
        def start_writer_from_read_snapshot(config, db, shard, table, **options):
            nonlocal reading
            if reading is None and db.execute('PRAGMA query_only').fetchone() == (1,):
                assert db.in_transaction
                reading = db
                writer.stdin.write('go\n')
                writer.stdin.flush()
                assert writer.stdout.readline().strip() == 'committing'
            return member(config, db, shard, table, **options)

        def observe_fresh_binding_check(path):
            nonlocal checked
            if path == registry_path and reading is not None and not checked:
                assert not reading.in_transaction
                assert writer.wait(timeout=2) == 0
                checked = True
            return safe(path)

        monkeypatch.setattr(scope, 'member', start_writer_from_read_snapshot)
        monkeypatch.setattr(scope, '_safe', observe_fresh_binding_check)
        facts = {}
        try:
            assert native_media_work.backfill(item['config'], diagnostic=facts) == 1
        finally:
            writer.stdin.close()
        assert checked and facts['status'] == 'processed_page'


def test_media_registry_other_sqlite_failures_propagate_and_close(item, monkeypatch):
    seed_round_tables(item)
    reads = []

    def damaged_member(config, db, *args, **options):
        reads.append(db)
        raise sqlite3.OperationalError('malformed registry')

    monkeypatch.setattr(scope, 'member', damaged_member)
    with pytest.raises(sqlite3.OperationalError, match='malformed registry'):
        native_media_work.backfill(item['config'])
    assert len(reads) == 1
    with pytest.raises(sqlite3.ProgrammingError, match='closed database'):
        reads[0].execute('SELECT 1')


def test_media_registry_budget_processes_verified_prefix_and_resumes(item, monkeypatch):
    seed_round_tables(item, first_kind=3)
    monkeypatch.setattr(native_media_work, 'BACKFILL_PROOF_SECONDS', 0, raising=False)

    assert native_media_work.backfill(item['config']) == 1
    with scope.registry(item['config'], snapshot=False) as db:
        assert scope.state(db, 'media_backfill') == [fixture.SHARD, FIRST]
    assert native_media_work.backfill(item['config']) == 0
    with scope.registry(item['config'], snapshot=False) as db:
        assert scope.state(db, 'media_backfill') == [fixture.SHARD, PENDING]
