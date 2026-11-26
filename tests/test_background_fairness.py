"""Mechanism checks; final installed SDK chain is separate evidence."""
import json,sqlite3
import pytest
from test_account_sync_status import item
from test_incremental_history_work import Driver,seed,inject,count_history
from wechat_local import native_scope_contract as sc,native_mirror_sync as sync
from wechat_local import native_follow_schedule as schedule

def test_continuous_tail_has_bounded_committed_history_opportunity(item,monkeypatch):
    seed(item,count=30,ceiling=4000);d=Driver(item);batches=[]
    original=sync._account_copy_table
    def observed(*a,**kw):
        value=original(*a,**kw)
        if value and value['rows']:batches.append((value['batch_kind'],value['rows'],value['progress']['history']))
        return value
    monkeypatch.setattr(sync,'_account_copy_table',observed)
    monkeypatch.setattr(sc,'account_status',lambda *a,**kw:pytest.fail('round invoked full account status'))
    try:
        start=count_history(item)
        for n in range(2,12):
            inject(item,d,n);value=d.round()
            assert value['gaps']==[],(n,batches,value['round_diagnostics'],value.get('shard_diagnostics'))
            assert value['follow_observation']['complete'] is False
            assert value['follow_observation']['status_check']=='not_run'
            assert schedule.round_diagnostics(value) is not None
        assert count_history(item)>start,(batches,value)
        run=0;seen_history=0
        for kind,rows,position in batches:
            if kind=='tail':run+=1
            elif kind=='history':
                assert run<=3,batches
                run=0;seen_history+=1
                assert rows<=500
        assert seen_history>=2,batches
        with sc.registry(item['config']) as db:turn=sc.state(db,'history_fair_turn')
        assert turn['finished']>0
    finally:d.close()

def test_completed_batch_diagnostics_are_bounded_and_sanitized():
    from wechat_local.native_account_round import Evidence
    evidence=Evidence()
    for n in range(100):evidence.add('local_commit','history',target='a'*64,rows=500,written=500,H=10000,history=n*500,tail=10000)
    value=dict(round_diagnostics=evidence.result());frame=schedule.round_diagnostics(value)
    assert len(frame['events'])<=64 and frame['dropped']>0
    assert len(json.dumps(frame).encode())<=16384
    frame['events'][0]['path']='private-path'
    assert schedule.round_diagnostics(dict(round_diagnostics=frame)) is None

def test_unknown_completion_keeps_finite_normal_cadence():
    completion=dict(operation='a',attempt=1,exit_code=0,observed_complete=False,known_backlog=False,completed_at_ns=0,completed_at_continuous_ns=0)
    plan=schedule.plan(None,wall=0,continuous=0,interval=30,completion=completion)
    assert plan['mode']=='normal' and plan['next_due_continuous_ns']==30_000_000_000 and not plan['due']

def test_local_history_commit_survives_unpublished_fairness_and_resumes(item,monkeypatch):
    from wechat_local.native_mirror_store import MirrorStore
    seed(item,count=30,ceiling=4000);d=Driver(item);original=MirrorStore.apply_batch;committed=[]
    def interruption(self,key,table,rows,progress,**kw):
        result=original(self,key,table,rows,progress,**kw)
        if table==__import__('test_incremental_history_work').HISTORY and rows and not committed:
            committed.append(progress['history']);raise SystemExit('synthetic crash after atomic local commit')
        return result
    try:
        with monkeypatch.context() as m:
            m.setattr(MirrorStore,'apply_batch',interruption)
            with pytest.raises(SystemExit):d.round()
        assert committed==[500] and count_history(item)==500
        values=[]
        for n in range(2,8):inject(item,d,n);values.append(d.round())
        assert all(not v['gaps'] for v in values),values
        assert count_history(item)>500
        assert any(any(e['reason']=='recovered_history_commit' for e in v['round_diagnostics']['events']) for v in values)
        with sc.registry(item['config']) as db:turn=sc.state(db,'history_fair_turn')
        assert turn['finished']>0 and turn['streak']<=3
    finally:d.close()


def test_independent_status_timeout_cannot_reclassify_committed_round(item,monkeypatch):
    import time
    from wechat_local import native_registry_reuse as reuse
    from wechat_local.native_mirror_store import MirrorError
    from pathlib import Path
    from wechat_local.native_registry_migrate import migrate
    from wechat_local.native_follow_policy import digest
    seed(item,count=30,ceiling=2000)
    Path(item['mirror_root']).chmod(0o700)
    profile=Path(item['mirror_root']).parent/'independent-status.json';sc.create(profile,sc.encoded(item['config']))
    assert migrate(item['config'],profile,confirmed=True,expected_source_sha256=digest(item['config']))['status']=='registry_reused'
    d=Driver(item)
    try:
        value=d.round();before=count_history(item)
        assert not value['gaps'] and before>0
        initial=reuse._Read.__init__
        def expired(self):initial(self);self.until=time.monotonic()-1
        with monkeypatch.context() as m:
            m.setattr(reuse._Read,'__init__',expired)
            with pytest.raises(MirrorError,match='registry_reuse_read_budget'):
                sc.account_status(item['config'])
        assert count_history(item)==before
        assert value['follow_observation']['complete'] is False
        assert value['account_scope']['check']=='not_run'
    finally:d.close()

def test_publication_budget_defers_before_local_batch_and_next_round_resumes(item,monkeypatch):
    from wechat_local import native_account_round as rw
    seed(item,count=30,ceiling=2000);d=Driver(item);original=rw.prepare;hit=[]
    def exhausted(registry,shard,table,progress,budget,**kw):
        if kw['history'] and not hit:
            budget['tail_probe']['bytes']=budget['tail_probe']['ceiling']-1024;hit.append(True)
        return original(registry,shard,table,progress,budget,**kw)
    try:
        with monkeypatch.context() as m:
            m.setattr(rw,'prepare',exhausted);value=d.round()
        assert hit and not value['gaps'] and count_history(item)==0
        events=[v for v in value['round_diagnostics']['events'] if v['stage']=='budget']
        assert any(v.get('stop_kind')=='metadata_bytes' and v['used']<v['limit'] and v['required']>v['limit']-v['used'] for v in events),events
        assert value['follow_observation']['complete'] is False
        assert not d.round()['gaps'] and count_history(item)>0
    finally:d.close()


def test_repeated_inflight_restart_cannot_mint_recovery_tail_allowance(item):
    from wechat_local import native_account_round as rw
    from pathlib import Path
    seed(item,count=3,ceiling=20)
    paths=[Path(item['live_path'])]
    with sc.registry(item['config'],write=True) as db:
        for round_number in (0,1,2):
            budget=sync._account_budget(item['config']);budget['tail_probe']=dict(bytes=0,tables=0,ceiling=1000000)
            rw.start(db,paths,budget,round_number,'instance')
            if round_number==1:assert budget['_fair_turn']['streak']==2
            if round_number==2:assert budget['_fair_turn']['streak']==3
            db.commit()  # Crash before finished; same metadata publication boundary.

def test_entry_metadata_budget_stop_is_deferred_not_a_missing_turn_crash(item,monkeypatch):
    from wechat_local import native_account_round as rw
    seed(item,count=3,ceiling=20);d=Driver(item);original=rw.start
    def exhausted(registry,paths,budget,*args):
        budget['tail_probe']['bytes']=budget['tail_probe']['ceiling']
        return original(registry,paths,budget,*args)
    try:
        with monkeypatch.context() as m:
            m.setattr(rw,'start',exhausted);result=d.round()
        assert result['gaps']==[] and result['rows_written']==0
        assert result['new_tail']['work_budget_limited'] is True
        assert result['follow_observation']['complete'] is False
        assert count_history(item)==0
    finally:d.close()

@pytest.mark.parametrize('kind,expected,limit,used',[('rows','rows',500,500),('bytes','row_bytes',8000,8000),('tables','tables',256,256),('metadata','metadata_bytes',900000,900000)])
def test_deferral_records_the_actual_triggering_budget(kind,expected,limit,used):
    from wechat_local.native_account_round import Evidence,deferred
    budget=dict(rows=500,used_rows=500,bytes=8000,used_bytes=8000,tables=256,used_tables=256,tail_probe=dict(bytes=900000,ceiling=900000))
    evidence=Evidence();deferred(evidence,budget,kind)
    frame=schedule.round_diagnostics(dict(round_diagnostics=evidence.result()))
    event=frame['events'][0]
    assert (event['stop_kind'],event['limit'],event['used'])==(expected,limit,used)

@pytest.mark.parametrize('item',[{'mirror_account_tables':2,'mirror_account_bytes':12*1024}],indirect=True)
def test_remaining_byte_deferral_records_required_row_without_changing_retry(item):
    import test_account_sync_status as f
    from pathlib import Path
    from wechat_local.native_mirror_store import MirrorStore
    from wechat_local.source_records import SourceKey
    from wechat_local.native_account_round import Evidence,deferred
    f.seed_round_tables(item,first_max=2,first_tail_payload='x'*6000)
    assert not f.authorized_round(item)['gaps']  # Original guarded AUTO/source path.
    key=SourceKey(item['config']['account_id'],item['config']['source_generation'],f.fixture.SHARD,f.PENDING)
    store=MirrorStore(Path(item['local_path']),key);pg=store.progress(f.PENDING)
    budget=sync._account_budget(item['config']);budget['used_bytes']=budget['bytes']-1
    source=sqlite3.connect(item['source_db']);source.execute('PRAGMA query_only=ON');source.execute('BEGIN')
    try:
        with sc.registry(item['config']) as registry:
            entry=sync._account_copy_table(item['config'],source,Path(item['live_path']),f.PENDING,store,pg['source_identity'],pg['source_header_sha256'],budget,registry=registry,media_username='synthetic')
        assert entry is None and store.progress(f.PENDING)==pg
        fact=budget.pop('_copy_deferral');evidence=Evidence();deferred(evidence,budget,fact['reason'],location='copy_rows',fact=fact)
        event=schedule.round_diagnostics(dict(round_diagnostics=evidence.result()))['events'][0]
        assert event['stop_kind']=='row_bytes' and event['required']>event['limit']-event['used']
    finally:source.close()

def test_bounded_history_import_keeps_its_actual_page_stop_fact(item):
    import test_account_sync_status as f
    seed(item,count=300,ceiling=2000);d=Driver(item)
    try:
        result=d.round()
        events=[v for v in result['round_diagnostics']['events'] if v.get('at_stage')=='history_import']
        assert any(v.get('stop_kind')=='metadata_tables' and v['limit']==256 and v['used']==256 for v in events),events
        assert not result['gaps']
    finally:d.close()
