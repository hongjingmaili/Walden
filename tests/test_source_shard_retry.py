"""Known local Source retry must remain partial through the real control chain."""
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
from wechat_local import native_background as background
from wechat_local import native_mirror_sync as sync,native_scope_contract as sc
from wechat_local.native_follow_schedule import control_result,plan
from wechat_local.native_follow_state import transition


def completed(result):
    runtime=dict(operation='a'*32,attempts=1)
    background._completed_attempt(runtime,1,json.dumps(control_result(result)).encode())
    return runtime['last_completed']


def test_verified_local_retry_stays_exit_one_but_does_not_stop_healthy_source_cadence():
    result=dict(gaps=['source_shard_retry_pending'],source_opens=2,
                partial_source=dict(successful_shards=1,retrying_shards=1))
    done=completed(result)
    assert done['exit_code']==1 and done['observation'] is None
    assert done['failure_class']=='partial_retryable'
    state=plan(None,wall=10,continuous=10*10**9,interval=30,completion=dict(done,
          completed_at_ns=10*10**9,completed_at_continuous_ns=10*10**9))
    assert state['mode']=='normal' and state['next_due_continuous_ns']==40*10**9
    epoch=dict(pid=20,start=[1,2]);generation='b'*32
    worker=dict(active=True,stop_confirmed=False,operation=done['operation'],kind='active',
                policy_generation=generation,app_epoch=epoch,last_completed=done)
    viewed=transition(dict(policy_generation=generation,app_epoch=epoch),enabled=True,
        policy_generation=generation,app=dict(state='running',epoch=epoch),worker=worker,
        wall=10,continuous=10*10**9)
    assert viewed['state']=='partial_source' and viewed['action']=='wait'
    assert viewed['observed_catchup_complete'] is not True


@pytest.mark.parametrize('changes',[
    dict(gaps=['source_unavailable_or_unsupported']),
    dict(gaps=['source_identity_mismatch']),
    dict(gaps=['scope_registry_binding']),
    dict(partial_source=dict(successful_shards=0,retrying_shards=1)),
    dict(partial_source=dict(successful_shards=1,retrying_shards=0)),
    dict(partial_source=dict(successful_shards=1,retrying_shards=True)),
    dict(partial_source=dict(successful_shards=1,retrying_shards=1,untrusted='private')),
])
def test_unknown_contract_or_invalid_partial_metadata_retains_global_backoff(changes):
    result=dict(gaps=['source_shard_retry_pending'],source_opens=2,
                partial_source=dict(successful_shards=1,retrying_shards=1));result.update(changes)
    done=completed(result)
    assert done['failure_class']!='partial_retryable'
    state=plan(None,wall=10,continuous=10*10**9,interval=30,completion=done)
    assert state['mode'] in ('backoff','blocked')


@pytest.fixture
def real_sqlcipher_busy(tmp_path):
    from sqlcipher3 import dbapi2 as sql
    path=tmp_path/'encrypted-synthetic.sqlite'
    first,second=sql.connect(str(path)),sql.connect(str(path),timeout=0)
    try:
        for db in (first,second):db.execute("PRAGMA key='synthetic-retry-test-key'")
        first.execute('CREATE TABLE t(n INTEGER)');first.commit()
        assert second.execute('SELECT count(*) FROM t').fetchone()==(0,)
        first.execute('BEGIN EXCLUSIVE')
        try:second.execute('SELECT * FROM t').fetchall()
        except sql.Error as error:
            assert type(getattr(error,'sqlite_errorcode',None)) is int
            assert error.sqlite_errorcode & 255==5
            return error
        raise AssertionError('exclusive encrypted SQLite writer did not produce BUSY')
    finally:
        second.close();first.rollback();first.close()


def test_actual_encrypted_sqlcipher_busy_has_trusted_primary_code(real_sqlcipher_busy):
    from wechat_local import native_mirror_sync as sync
    info=sync._account_error_info(real_sqlcipher_busy,'source_probe')
    assert info==dict(stage='source_probe',exception_family='sqlite_operational',sqlite_primary_code=5,errno=None)


@pytest.mark.parametrize('kind',['unknown','no_code','permission','corrupt','wrapped'])
def test_unknown_or_global_error_is_not_reclassified_from_text_or_untrusted_code(kind,real_sqlcipher_busy):
    import sqlite3
    from sqlcipher3 import dbapi2 as sql
    from wechat_local import native_mirror_sync as sync
    if kind=='unknown':
        class Untrusted(Exception):sqlite_errorcode=5
        error=Untrusted('private text database is locked')
    elif kind=='no_code':error=sqlite3.OperationalError('private text database is locked')
    elif kind=='permission':error=PermissionError(13,'private path')
    elif kind=='corrupt':
        error=sql.DatabaseError('private body');error.sqlite_errorcode=11
    else:
        error=RuntimeError('private wrapper');error.__cause__=real_sqlcipher_busy
    assert sync._account_busy(error) is False
    assert 'private' not in json.dumps(sync._account_error_info(error,'source_probe'))


import test_account_sync_status as fixture
from test_account_sync_status import item


@pytest.mark.parametrize('item',[{'mirror_account_shards':2}],indirect=True)
def test_one_verified_busy_shard_keeps_its_debt_and_does_not_backoff_the_other(item,monkeypatch,real_sqlcipher_busy):
    import sqlite3
    from pathlib import Path
    from wechat_local import native_mirror_sync as sync,native_scope_contract as sc
    fixture.seed_round_tables(item,first_max=2)
    fixture.copy_synthetic_shard(item,'message_1.db')
    with sqlite3.connect(item['local_path']) as local:
        value=json.loads(local.execute('SELECT value FROM __walden_progress WHERE table_name=?',(fixture.FIRST,)).fetchone()[0]);value['target']=2
        local.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',(json.dumps(value),fixture.FIRST))
    clock=SimpleNamespace(wall=1000.,tick=10*10**9)
    monkeypatch.setattr(sync,'_account_retry_clock',lambda:(clock.wall,clock.tick))
    attempted=[]
    class Connection:
        def __init__(self,db,busy):self.db,self.busy=db,busy
        @property
        def in_transaction(self):return self.db.in_transaction
        def execute(self,sql,args=()):
            if self.busy and sql.startswith('SELECT coalesce(max(local_id)'):
                raise real_sqlcipher_busy
            return self.db.execute(sql,args)
        def __getattr__(self,key):return getattr(self.db,key)
    def run(value):
        def factory(path):
            attempted.append(path.name)
            db=sqlite3.connect(item['source_db']);db.execute('PRAGMA query_only=ON')
            return Connection(db,path.name==fixture.fixture.SHARD)
        return sync._account_sync(value['config'],connection_factory=factory)
    monkeypatch.setattr(fixture.fixture,'run_full_account_sync',run)
    hints={fixture.fixture.SHARD:1,'message_1.db':1}
    first=fixture.hinted_round(item,monkeypatch,shards=hints)
    assert first['gaps']==['source_shard_retry_pending']
    assert first['partial_source']==dict(successful_shards=1,retrying_shards=1)
    assert [(row['shard'],row['tail']) for row in first['sources']]==[('message_1.db',2)]
    done=completed(first);assert done['failure_class']=='partial_retryable'
    with sc.registry(item['config']) as registry:
        retry=sc.state(registry,'source_retry:'+fixture.fixture.SHARD)
        due=retry['schedule']['next_due_continuous_ns']
        assert sc.state(registry,'tail_probe:'+fixture.fixture.SHARD)['pending']==[[fixture.FIRST,2]]
    attempted.clear()
    second=fixture.hinted_round(item,monkeypatch,shards={name:99 for name in hints})
    assert second['gaps']==['source_shard_retry_pending']
    assert attempted==['message_1.db']
    with sc.registry(item['config']) as registry:
        assert sc.state(registry,'source_retry:'+fixture.fixture.SHARD)['schedule']['next_due_continuous_ns']==due
    with sqlite3.connect(item['local_path']) as local:
        value=json.loads(local.execute('SELECT value FROM __walden_progress WHERE table_name=?',(fixture.FIRST,)).fetchone()[0])
        assert value['tail']==1
    assert second['source_attempts']==1


@pytest.mark.parametrize('item',[{'mirror_account_shards':2}],indirect=True)
def test_same_source_renumber_and_new_instance_do_not_advance_retry_deadline(item,monkeypatch,real_sqlcipher_busy):
    from pathlib import Path
    from wechat_local import native_mirror_sync as sync,native_scope_contract as sc
    from wechat_local.native_follow_policy import Store
    fixture.seed_round_tables(item,first_max=2)
    fixture.copy_synthetic_shard(item,'message_1.db')
    clock=SimpleNamespace(wall=1000.,tick=10*10**9)
    monkeypatch.setattr(sync,'_account_retry_clock',lambda:(clock.wall,clock.tick))
    store_root=Path(item['mirror_root']).parent/'follow'
    grant=dict(source_sha256=fixture.fixture.source_digest(item['config']),policy_generation='b'*32,
               instance_nonce='a'*32,store_root=str(store_root))
    with sc.registry(item['config'],write=True) as registry:
        sync._account_record_retry(item['config'],registry,fixture.fixture.SHARD,grant,
            sync._account_error_info(real_sqlcipher_busy,'source_probe'))
        original=sc.state(registry,'source_retry:'+fixture.fixture.SHARD)
        registry.commit()
    result=fixture.hinted_round(item,monkeypatch,shards={fixture.fixture.SHARD:1,'message_1.db':1})
    assert result['source_opens']==1 and result['source_attempts']==1
    assert result['gaps']==['source_shard_retry_pending']
    with sc.registry(item['config'],write=True) as registry:
        current=sc.state(registry,'source_retry:'+fixture.fixture.SHARD)
        assert current['binding']['anchor']==original['binding']['anchor']
        assert current['schedule']==original['schedule']
        newer=dict(grant,instance_nonce='d'*32)
        clock.wall=10**9;clock.tick=0
        assert sync._account_retry_ready(item['config'],registry,fixture.fixture.SHARD,newer) is False
        store=Store(store_root)
        store.immutable('policy.'+'b'*32+'.json',dict(generation='b'*32,store_root=str(store_root),
                          source_signature=grant['source_sha256']))
        assert sync._account_retry_ready(item['config'],registry,fixture.fixture.SHARD,
                                       dict(newer,policy_generation='e'*32)) is False
        stale=dict(current);stale['binding']=dict(current['binding'],source_sha256='0'*64)
        sc.save(registry,'source_retry:'+fixture.fixture.SHARD,stale)
        with pytest.raises(sc.MirrorError,match='source_retry_binding'):
            sync._account_retry_ready(item['config'],registry,fixture.fixture.SHARD,newer)


@pytest.mark.parametrize('stage',['source_open','registry'])
@pytest.mark.parametrize('item',[{'mirror_account_shards':2}],indirect=True)
def test_busy_before_source_guards_or_in_global_registry_still_uses_global_backoff(item,monkeypatch,real_sqlcipher_busy,stage):
    import sqlite3
    from wechat_local import native_mirror_sync as sync,native_scope_contract as sc
    fixture.seed_round_tables(item,first_max=2)
    fixture.copy_synthetic_shard(item,'message_1.db')
    if stage=='source_open':
        def run(value):
            def factory(path):
                if path.name==fixture.fixture.SHARD:raise real_sqlcipher_busy
                db=sqlite3.connect(item['source_db']);db.execute('PRAGMA query_only=ON');return db
            return sync._account_sync(value['config'],connection_factory=factory)
        monkeypatch.setattr(fixture.fixture,'run_full_account_sync',run)
    else:
        register=sc.register
        def broken_register(config,registry,observation,members):
            if observation['shard']==fixture.fixture.SHARD:raise real_sqlcipher_busy
            return register(config,registry,observation,members)
        monkeypatch.setattr(sc,'register',broken_register)
    result=fixture.hinted_round(item,monkeypatch,shards={fixture.fixture.SHARD:1,'message_1.db':1})
    assert result['gaps']==['source_unavailable_or_unsupported']
    assert result['shard_diagnostics'][0]['stage']==stage
    assert result['shard_diagnostics'][0]['sqlite_primary_code']==5
    assert 'partial_source' not in result
    done=completed(result)
    assert done['failure_class']!='partial_retryable'
    assert done['shard_diagnostics']==result['shard_diagnostics']
    assert plan(None,wall=10,continuous=10*10**9,interval=30,completion=done)['mode']=='backoff'


@pytest.mark.parametrize('payload',[
    [{'stage':'private-path','exception_family':'sqlite_operational','sqlite_primary_code':5,'errno':None}],
    [{'stage':'source_probe','exception_family':'private-class','sqlite_primary_code':5,'errno':None}],
    [{'stage':'source_probe','exception_family':'sqlite_operational','sqlite_primary_code':'private','errno':None}],
    [{'stage':'source_probe','exception_family':'sqlite_operational','sqlite_primary_code':5,'errno':None,'args':'private'}],
])
def test_control_frame_drops_noncanonical_diagnostic_payload(payload):
    frame=control_result(dict(gaps=['source_unavailable_or_unsupported'],shard_diagnostics=payload))
    assert 'private' not in json.dumps(frame) and 'shard_diagnostics' not in frame


@pytest.mark.parametrize('boundary',['raw_child','control_result'])
def test_conflicting_global_failure_reason_cannot_be_downgraded_to_partial(boundary):
    value=dict(gaps=['source_shard_retry_pending'],source_opens=2,
               partial_source=dict(successful_shards=1,retrying_shards=1),
               failure_reason='source_identity_mismatch',failure_class='permanent')
    frame=control_result(value) if boundary=='control_result' else value
    runtime=dict(operation='a'*32,attempts=1)
    background._completed_attempt(runtime,1,json.dumps(frame).encode())
    done=runtime['last_completed']
    observed=plan(None,wall=10,continuous=10**10,interval=30,completion=done)
    print(json.dumps(dict(boundary=boundary,frame=frame,failure_class=done.get('failure_class'),mode=observed['mode'])))
    assert done['failure_class']!='partial_retryable' and observed['mode'] in ('backoff','blocked')

@pytest.mark.parametrize('item',[{'mirror_account_shards':4}],indirect=True)
def test_four_cooling_debts_cannot_stop_fifth_healthy_hinted_source(item,monkeypatch,real_sqlcipher_busy):
    fixture.seed_round_tables(item,first_max=2)
    targets={fixture.fixture.SHARD:Path(item['local_path'])}
    for n in range(1,5):targets[f'message_{n}.db']=fixture.copy_synthetic_shard(item,f'message_{n}.db')
    grant=dict(source_sha256=fixture.fixture.source_digest(item['config']),policy_generation='b'*32,
               instance_nonce='a'*32,store_root=str(Path(item['mirror_root']).parent/'follow'))
    monkeypatch.setattr(sync,'_account_retry_clock',lambda:(1000.,10**10))
    for name in list(targets)[:4]:
        with sqlite3.connect(targets[name]) as db:
            raw=db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(fixture.FIRST,)).fetchone()[0]
            value=json.loads(raw);value['target']=2
            db.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',(json.dumps(value),fixture.FIRST))
        with sc.registry(item['config'],write=True) as db:
            sync._account_record_retry(item['config'],db,name,grant,sync._account_error_info(real_sqlcipher_busy,'source_probe'))
            db.commit()
    hints={name:1 for name in targets}
    result=fixture.hinted_round(item,monkeypatch,shards=hints)
    done=completed(result);schedule=plan(None,wall=1000.,continuous=10**10,interval=30,completion=done)
    print(json.dumps(dict(source_opens=result['source_opens'],source_attempts=result['source_attempts'],
                         partial_source=result.get('partial_source'),gaps=result['gaps'],sources=result['sources'],
                         schedule_mode=schedule['mode'],backoff=schedule['backoff'])))
    assert result['source_attempts']<=4 and result['source_opens']<=4
    assert any(row['shard']=='message_4.db' and row['tail']==2 for row in result['sources']) or schedule['mode']=='normal'


@pytest.mark.parametrize('changes,expected',[
    ({}, 'normal'),
    (dict(failure_reason='source_identity_mismatch',failure_class='permanent'), 'blocked'),
    (dict(failure_class='permanent'), 'backoff'),
    (dict(failure_class='retryable'), 'backoff'),
    (dict(failure_reason='unknown'), 'backoff'),
    (dict(gaps=['source_shard_retry_pending','scope_registry_binding']), 'blocked'),
    (dict(partial_source=dict(successful_shards=0,retrying_shards=1)), 'backoff'),
])
def test_owned_once_cli_preserves_valid_partial_and_global_failures(monkeypatch,capsys,tmp_path,changes,expected):
    from wechat_local import native_mirror_cli as cli
    result=dict(gaps=['source_shard_retry_pending'],source_opens=2,
                partial_source=dict(successful_shards=1,retrying_shards=1))
    result.update(changes)
    monkeypatch.setenv('XDG_STATE_HOME',str(tmp_path/'state'))
    monkeypatch.setenv('WALDEN_FOLLOW_CONTROL_RESULT','1')
    monkeypatch.setattr(cli,'load_source_config',lambda *_,**__:{})
    monkeypatch.setattr(cli,'run_owned_once',lambda *_,**__:dict(result))
    code=cli.main(['once','--source-config','/synthetic/profile.json','--operation-record','/synthetic/record.owned'])
    frame=json.loads(capsys.readouterr().out)
    runtime=dict(operation='a'*32,attempts=1)
    background._completed_attempt(runtime,code,json.dumps(frame).encode())
    done=runtime['last_completed'];schedule=plan(None,wall=10,continuous=10**10,interval=30,completion=done)
    assert code==1 and frame['gaps']==sorted(set(result['gaps']))
    assert schedule['mode']==expected
    assert (done.get('failure_class')=='partial_retryable')==(expected=='normal')
    assert (frame.get('partial_source') is not None)==(expected=='normal')
    assert done['observation'] is None and done['source_db_connections'] is None
