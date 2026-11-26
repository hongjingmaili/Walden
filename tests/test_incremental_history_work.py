"""Real synthetic account copy/query chain; only OS/config and encrypted I/O are replaced."""
import contextlib,hashlib,io,json,os,sqlite3,time
from pathlib import Path
import pytest
import test_account_sync_status as f
from test_account_sync_status import item
from test_vnode_priority_kinds import watcher,event
from wechat_local import native_deadline as nd,native_follow_grant as fg,native_scope_contract as sc,native_mirror_sync as sync
from wechat_local.native_follow_policy import Store

HISTORY=f.FIRST
USERNAME='synthetic-new-priority'
NEW='Msg_'+hashlib.md5(USERNAME.encode()).hexdigest()

class Driver:
    def __init__(self,item):
        self.item=item;self.root=Path(item['message_root']);self.watch,self.queue=watcher(self.root)
        self.store=Store(self.root.parent/'follow',create=True);self.operation='a'*32;self.policy='b'*32;self.nonce='c'*32
        self.publish()
    def publish(self):
        self.runtime=dict(operation=self.operation,grant_nonce=self.nonce,context={},shard_hints=dict(
            root_identity=self.watch.identity,shards=dict(self.watch.shard_generations),
            fallback=bool(self.watch.fallback_generation),coverage_version=1,
            uncertain_generation=getattr(self.watch,'uncertain_generation',1)))
        for name,value in [('instance.'+self.operation+'.json',self.runtime),('current.json',dict(nonce=self.operation)),('intent.json',dict(enabled=True,generation=self.policy))]:
            (self.store.atomic if self.store.path(name).exists() else self.store.immutable)(name,value)
    def notify(self,kind='db',shard=f.fixture.SHARD):
        path=self.root/(shard+'-shm' if kind=='shm' else shard)
        if kind=='unknown':value=type('Event',(),dict(ident=999999,fflags=16,flags=0))()
        else:value=event(self.watch,path)
        self.queue.batches=[[value],[]];self.watch.wait(0);self.publish()
    def round(self):
        grant=dict(kind='active',source_sha256=f.fixture.source_digest(self.item['config']),store_root=str(self.store.root),
                   instance_nonce=self.operation,policy_generation=self.policy,nonce=self.nonce,os_context={})
        deadline=fg.FollowDeadline(dict(wall_until=30.,continuous_start=0,continuous_until=30_000_000_000),grant,wall=lambda:0.,continuous=lambda:1)
        with nd.activate_deadline(deadline):return f.fixture.run_full_account_sync(self.item)
    def close(self):self.watch.close()


def seed(item,count=300,ceiling=30000,*,mapping=True):
    rows=[(n,n,1,1000,0,'synthetic-history',0) for n in range(1,ceiling+1)]
    tables=[(HISTORY,0,ceiling,rows),(NEW,1,1,[(1,1,1,1000,0,'old-tail',0)])]
    tables += [('Msg_'+format((1<<128)-1-n,'032x'),1,1,[(1,1,1,1000,0,'completed',0)]) for n in range(count-2)]
    f.seed_tables(item,tables)
    with sqlite3.connect(item['source_db']) as db:
        db.execute('PRAGMA journal_mode=WAL');db.execute('INSERT INTO Name2Id VALUES(?)',(USERNAME,))
    from wechat_local.native_mirror_store import MirrorStore
    from wechat_local.source_records import SourceKey
    key=SourceKey(item['config']['account_id'],item['config']['source_generation'],f.fixture.SHARD,'Name2Id')
    if mapping:
        store=MirrorStore(Path(item['local_path']),key);store.ensure_table(key,'CREATE TABLE Name2Id(user_name TEXT)')
        store.apply_batch(key,'Name2Id',[(1,USERNAME)],{})
    (Path(item['message_root'])/(f.fixture.SHARD+'-shm')).touch()


def count_history(item):
    with sqlite3.connect(item['local_path']) as db:return db.execute('SELECT count(*) FROM "'+HISTORY+'" WHERE local_id<=30000').fetchone()[0]


def warm(driver,rounds=4):
    results=[]
    for _ in range(rounds):
        value=driver.round();assert not value['gaps'];results.append(value)
    return results


def work_state(item):
    with sc.registry(item['config']) as db:return sc.state(db,'account_work')


def inject(item,driver,identifier=2):
    with sqlite3.connect(item['source_db']) as db:db.execute('INSERT INTO "'+NEW+'" VALUES(?,?,?,?,?,?,?)',(identifier,identifier,1,int(time.time()),0,'injected-'+str(identifier),0))
    committed=time.monotonic();driver.notify();return committed


def formal_local(item,monkeypatch,capsys,identifier):
    from wechat_local import native_window,native_mirror_cli
    monkeypatch.setattr(native_mirror_cli,'load_source_config',lambda *args,**kwargs:item['config'])
    rc=native_window.main(['--source-config',str(Path(item['message_root']).parent/'synthetic.json'),'--read-mode','local','--conversation-username',USERNAME,'--latest','5'])
    result=json.loads(capsys.readouterr().out)
    assert 'source_opens' in result,result
    assert result['source_opens']==0 and any(v['local_id']==identifier for v in result['messages']),result
    return rc,result


def test_legitimate_scan_then_twenty_quiet_rounds_keep_copying_history(item):
    seed(item);d=Driver(item)
    try:
        warm(d)
        assert work_state(item)['ready'] is True
        before=count_history(item);advanced=[];results=[]
        for _ in range(20):
            prior=count_history(item);value=d.round();results.append(value);advanced.append(count_history(item)-prior)
            assert not value['gaps'] and value['source_attempts']<=4 and value['source_opens']<=4
            assert value['rows_read']<=2000 and value['new_tail']['metadata_bytes']<=1048576 and value['new_tail']['metadata_tables']<=1024
        assert all(n>=500 for n in advanced),advanced
        assert count_history(item)-before>=10000
    finally:d.close()


@pytest.mark.parametrize('change',['shm','external_commit','restart','lost_state','unknown','worker'])
def test_commit_witness_and_listener_generation_boundaries(item,change):
    seed(item);d=Driver(item)
    try:
        warm(d);assert work_state(item)['ready']
        previous=work_state(item)
        if change in ('shm','unknown'):d.notify(change)
        elif change=='restart':d.operation='d'*32;d.publish()
        elif change=='worker':d.nonce='e'*32;d.publish()
        elif change=='lost_state':
            with sc.registry(item['config'],write=True) as db:sc.save(db,'account_work',None);db.commit()
        else:
            local=Path(item['local_path']);stamp=local.stat()
            from wechat_local.native_mirror_store import MirrorStore
            from wechat_local.source_records import SourceKey
            key=SourceKey(item['config']['account_id'],item['config']['source_generation'],f.fixture.SHARD,HISTORY)
            with sync.writer_lock(Path(item['mirror_root'])):
                store=MirrorStore(local,key);progress=store.progress(HISTORY);store.apply_batch(key,HISTORY,[],progress)
            os.utime(local,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
        before=count_history(item);value=d.round()
        if change in ('shm','worker'):assert value['new_tail']['incremental_work_ready'] and count_history(item)>before
        else:
            assert not value['new_tail']['incremental_work_ready'] and count_history(item)==before
            if change=='external_commit':assert previous['pins'][f.fixture.SHARD]['commit']!=work_state(item)['pins'][f.fixture.SHARD]['commit']
    finally:d.close()


@pytest.mark.parametrize('item',[{'mirror_account_rows':501}],indirect=True)
def test_new_tail_uses_remaining_single_batch_before_history(item,monkeypatch,capsys):
    seed(item);d=Driver(item)
    try:
        warm(d)
        with sqlite3.connect(item['source_db']) as db:db.executemany('INSERT INTO "'+NEW+'" VALUES(?,?,?,?,?,?,?)',[(n,n,1,int(time.time()),0,'injected-tail',0) for n in range(2,502)])
        d.notify();before=count_history(item);value=d.round()
        assert count_history(item)==before and value['sources'][0]['table']==NEW and value['sources'][0]['tail']==501
        assert value['rows_read']<=501
        rc,result=formal_local(item,monkeypatch,capsys,501);assert rc==0 and result['gaps']==[]
    finally:d.close()


@pytest.mark.parametrize('kind',['db','unknown'])
def test_event_during_history_stops_next_batch_then_formal_local_sees_tail(item,monkeypatch,capsys,kind):
    seed(item);d=Driver(item)
    try:
        warm(d);copy=sync._account_copy_table;seen=[];injected=[]
        def during(*args,**kwargs):
            result=copy(*args,**kwargs);seen.append(args[3])
            if args[3]==HISTORY and not injected:
                injected.append(inject(item,d))
                if kind=='unknown':d.notify('unknown')
            return result
        before=count_history(item)
        with monkeypatch.context() as m:m.setattr(sync,'_account_copy_table',during);first=d.round()
        actual_history=count_history(item)-before;assert actual_history==500
        assert seen==[HISTORY],seen
        second=d.round();assert any(v['table']==NEW and v['tail']==2 for v in second['sources'])
        rc,result=formal_local(item,monkeypatch,capsys,2);assert rc==0 and result['gaps']==[]
        latency=time.monotonic()-injected[0];assert latency<30
        Path('../during-history-'+kind+'.json').write_text(json.dumps(dict(kind=kind,commit_to_formal_seconds=latency,round_opportunities=2,first_history_batch_rows=actual_history,first_source_opens=first['source_opens'],next_source_opens=second['source_opens'],formal_exit=rc,formal_gaps=result['gaps'],formal_source_opens=result['source_opens'],synthetic=True),indent=2)+'\n')
    finally:d.close()


def test_partial_commit_before_certificate_publication_forces_real_rescan(item,monkeypatch):
    seed(item);d=Driver(item)
    try:
        warm(d);finish=sync._account_work_finish
        with monkeypatch.context() as m:
            m.setattr(sync,'_account_work_finish',lambda *args,**kwargs:(_ for _ in ()).throw(RuntimeError('synthetic publication interruption')))
            with pytest.raises(RuntimeError):d.round()
        before=count_history(item);value=d.round()
        assert not value['new_tail']['incremental_work_ready'] and count_history(item)==before
        assert sync._account_work_finish is finish
    finally:d.close()


def test_missing_initial_attribution_is_preserved_as_real_formal_query_refusal(item,monkeypatch,capsys):
    from wechat_local import native_mirror_cli as cli,native_window,failure_evidence as e
    seed(item,mapping=False);d=Driver(item)
    try:
        warm(d,4);inject(item,d);d.round()
        captured=[];original=cli.error_fields
        def record(error):captured.append(str(error));return original(error)
        monkeypatch.setattr(cli,'load_source_config',lambda *args,**kwargs:item['config'])
        monkeypatch.setattr(cli,'error_fields',record)
        rc=native_window.main(['--source-config',str(d.root.parent/'synthetic.json'),'--read-mode','local','--conversation-username',USERNAME,'--latest','5'])
        result=json.loads(capsys.readouterr().out)
        assert rc==2 and captured==['scope_not_authorized']
        proof=e.lookup(result['error_id'])
        Path(os.environ.get('WALDEN_NEGATIVE_EVIDENCE','../formal-attribution-negative.json')).write_text(json.dumps(dict(formal_exit=rc,error_enum=captured[0],evidence=proof,synthetic=True),indent=2)+'\n')
    finally:d.close()


def test_four_real_data_priorities_do_not_insert_a_history_source(item):
    seed(item,count=12);paths=[]
    for number in range(1,4):
        path=f.copy_synthetic_shard(item,f'message_{number}.db');paths.append(path)
        with sqlite3.connect(path) as db:db.execute("UPDATE __walden_progress SET value='{}' WHERE table_name='Name2Id'")
    d=Driver(item)
    try:
        warm(d);before=count_history(item)
        with sqlite3.connect(item['source_db']) as db:db.execute('INSERT INTO "'+NEW+'" VALUES(2,2,1,1700000000,0,?,0)',('four-new-tails',))
        for number in range(4):d.notify(shard=f'message_{number}.db')
        value=d.round()
        assert value['source_attempts']==value['source_opens']==4 and count_history(item)==before
        assert {row['shard'] for row in value['sources'] if row['table']==NEW and row['tail']==2}=={f'message_{n}.db' for n in range(4)}
    finally:d.close()


def test_existing_writer_lock_rejects_concurrent_official_progress_writer(item,monkeypatch):
    seed(item,count=12);d=Driver(item)
    try:
        warm(d);original=sync._account_copy_table;rejected=[]
        def copy(*args,**kwargs):
            with pytest.raises(sync.MirrorError,match='sync_busy'):
                with sync.writer_lock(Path(item['mirror_root']),0):raise AssertionError('second writer admitted')
            rejected.append(True);return original(*args,**kwargs)
        monkeypatch.setattr(sync,'_account_copy_table',copy);value=d.round()
        assert rejected and not value['gaps']
    finally:d.close()


def test_revocation_during_history_preserves_source_refusal(item,monkeypatch):
    seed(item,count=12);d=Driver(item)
    try:
        warm(d);copy=sync._account_copy_table;rows=[]
        def validate(grant):
            store=Store(grant['store_root']);fg._enabled_intent(store,grant);fg._instance_runtime(store,grant)
        monkeypatch.setattr(fg,'validate',validate)
        def revoke(*args,**kwargs):
            result=copy(*args,**kwargs);rows.append(args[3])
            d.store.atomic('intent.json',dict(enabled=False,generation=d.policy))
            return result
        monkeypatch.setattr(sync,'_account_copy_table',revoke)
        with pytest.raises(sync.MirrorError,match='follow_revoked'):d.round()
        assert rows==[HISTORY]
    finally:d.close()


def test_same_coverage_probe_reuse_invalidates_on_data_unknown_missing_and_ttl(item,monkeypatch):
    seed(item,count=12);d=Driver(item);original=sync._account_tail_probe;counts=[]
    def traced(*args,**kwargs):
        seen=[];args[1].set_trace_callback(lambda sql:seen.append(sql) if sql.startswith('SELECT coalesce(max(local_id)') else None)
        try:return original(*args,**kwargs)
        finally:args[1].set_trace_callback(None);counts.append(len(seen))
    monkeypatch.setattr(sync,'_account_tail_probe',traced)
    try:
        warm(d);counts.clear();d.round();assert counts==[0]
        for kind in ('db','unknown'):
            d.notify(kind);counts.clear();d.round();assert counts[0]>=12
        with sc.registry(item['config'],write=True) as db:sc.save(db,'account_work',None);db.commit()
        counts.clear();d.round();assert counts[0]>=12
        now=sync.time.time
        with monkeypatch.context() as m:
            m.setattr(sync.time,'time',lambda:now()+301);counts.clear();d.round();assert counts[0]>=12
    finally:d.close()


def test_drained_known_tail_leaves_same_round_room_for_other_history_source(item,monkeypatch):
    seed(item,count=12);path=f.copy_synthetic_shard(item,'message_1.db')
    with sqlite3.connect(path) as db:db.execute("UPDATE __walden_progress SET value='{}' WHERE table_name='Name2Id'")
    other=Path(item['source_db']).with_name('second-source.sqlite')
    with sqlite3.connect(item['source_db']) as source,sqlite3.connect(other) as target:source.backup(target)
    def account(value):
        def factory(path):
            conn=sqlite3.connect(other if path.name=='message_1.db' else item['source_db']);conn.execute('PRAGMA query_only=ON');return conn
        return sync._account_sync(value['config'],connection_factory=factory)
    monkeypatch.setattr(f.fixture,'run_full_account_sync',account);d=Driver(item)
    try:
        warm(d)
        with sqlite3.connect(item['source_db']) as db:db.executemany('INSERT INTO "'+NEW+'" VALUES(?,?,?,?,?,?,?)',[(n,n,1,1700000000,0,'new-tail',0) for n in range(2,2502)])
        d.notify();first=d.round()
        with sc.registry(item['config']) as db:assert sc.state(db,'tail_probe:message_0.db')['pending']==[[NEW,2501]]
        with sqlite3.connect(path) as db:before=db.execute('SELECT count(*) FROM "'+HISTORY+'"').fetchone()[0]
        second=d.round()
        assert second['source_opens']<=4 and second['rows_read']<=2000
        assert second['sources'][0]['table']==NEW
        assert max(row['tail'] for row in second['sources'] if row['table']==NEW)==2501
        with sqlite3.connect(path) as db:assert db.execute('SELECT count(*) FROM "'+HISTORY+'"').fetchone()[0]>before
    finally:d.close()


def test_cross_source_known_tails_copy_before_further_discovery_and_keep_debt(item,monkeypatch):
    seed(item,count=12);second=f.copy_synthetic_shard(item,'message_1.db');d=Driver(item)
    probe=sync._account_tail_probe;post_probe=[]
    def observed_probe(*args,**kwargs):
        if kwargs.get('copied'):post_probe.append(args[3].name)
        return probe(*args,**kwargs)
    try:
        warm(d);monkeypatch.setattr(sync,'_account_tail_probe',observed_probe)
        next_id=2
        for opportunity in range(3):
            with sqlite3.connect(item['source_db']) as db:
                db.executemany('INSERT INTO "'+NEW+'" VALUES(?,?,?,?,?,?,?)',
                    [(n,n,1,1700000000,0,'two-hot-sources',0) for n in range(next_id,next_id+2500)])
            next_id+=2500
            d.notify(shard=f.fixture.SHARD);d.notify(shard='message_1.db')
            before=[]
            for path in (Path(item['local_path']),second):
                with sqlite3.connect(path) as db:before.append(db.execute('SELECT count(*) FROM "'+NEW+'"').fetchone()[0])
            old_history=count_history(item);value=d.round()
            assert value['gaps']==[] and value['source_opens']==2 and value['source_attempts']==2
            assert value['rows_read']<=2000 and value['new_tail']['metadata_bytes']<=1048576
            assert count_history(item)==old_history and not post_probe
            assert {row['shard'] for row in value['sources'] if row['table']==NEW}=={f.fixture.SHARD,'message_1.db'}
            for index,path in enumerate((Path(item['local_path']),second)):
                with sqlite3.connect(path) as db:assert db.execute('SELECT count(*) FROM "'+NEW+'"').fetchone()[0]-before[index]==500
            with sc.registry(item['config']) as db:
                for shard in (f.fixture.SHARD,'message_1.db'):
                    assert sc.state(db,'tail_probe:'+shard)['pending']==[[NEW,next_id-1]]
    finally:d.close()


# r3 actual table/byte opportunity cursor regressions.
import json,sqlite3
from pathlib import Path
import pytest
from test_incremental_history_work import Driver,seed,warm,count_history,NEW
from test_account_sync_status import item
import test_account_sync_status as f
from wechat_local import native_scope_contract as sc

@pytest.mark.parametrize('item',[{'mirror_account_tables':1},{'mirror_account_bytes':6000}],indirect=True)
def test_two_known_hot_sources_rotate_copy_priority_when_only_one_table_batch_fits(item):
 seed(item,count=12);second=f.copy_synthetic_shard(item,'message_1.db');d=Driver(item);observed=[];totals=[0,0];next_id=2
 try:
  warm(d)
  for number in range(4):
   with sqlite3.connect(item['source_db']) as db:db.executemany('INSERT INTO "'+NEW+'" VALUES(?,?,?,?,?,?,?)',[(n,n,1,1700000000,0,'synthetic continuous hot tail',0) for n in range(next_id,next_id+2500)])
   next_id+=2500;d.notify(shard='message_0.db');d.notify(shard='message_1.db');before=[]
   for path in (Path(item['local_path']),second):
    with sqlite3.connect(path) as db:before.append(db.execute('SELECT count(*) FROM "'+NEW+'"').fetchone()[0])
   history=count_history(item);value=d.round();added=[]
   for index,path in enumerate((Path(item['local_path']),second)):
    with sqlite3.connect(path) as db:added.append(db.execute('SELECT count(*) FROM "'+NEW+'"').fetchone()[0]-before[index])
    totals[index]+=added[-1]
   with sc.registry(item['config']) as db:after=sc.state(db,'tail_shard_after')
   observed.append(dict(opportunity=number+1,added=added,tail_shard_after=after,source_opens=value['source_opens'],rows_read=value['rows_read']))
   assert count_history(item)==history and value['gaps']==[] and value['rows_read']<=2000
  print(json.dumps(dict(rounds=observed,totals=totals)))
  assert all(n>0 for n in totals)
 finally:d.close()
