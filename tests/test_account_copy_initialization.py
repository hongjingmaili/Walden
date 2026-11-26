"""Owned new inventory members; legacy absence never proves first copy."""
import json
import sqlite3
import shutil
from pathlib import Path

import pytest

import test_account_sync_status as f
from test_account_sync_status import item
from test_incremental_history_work import Driver, seed, warm
from wechat_local import native_scope_contract as sc
from wechat_local import native_mirror_sync as sync, native_account_copy_init as ci
from wechat_local.native_mirror_store import MirrorError, MirrorStore

NEW='Msg_'+'1'*32


def add_source(item, count=1001):
    with sqlite3.connect(item['source_db']) as db:
        ddl=db.execute('SELECT sql FROM sqlite_master WHERE name=?',(f.FIRST,)).fetchone()[0]
        db.execute(ddl.replace(f.FIRST,NEW))
        db.executemany('INSERT INTO '+NEW+' VALUES(?,?,?,?,?,?,?)',
                       [(n,n,1,1000,0,'synthetic-new-member',0) for n in range(1,count+1)])


def test_new_member_copies_actual_latest_suffix_before_prefix(item):
    seed(item,count=2,ceiling=2);driver=Driver(item)
    try:
        warm(driver);add_source(item);driver.notify()
        values=[]
        for _ in range(8):
            values.append(driver.round())
            assert not values[-1]['gaps'],values[-1]
            with sqlite3.connect(item['local_path']) as db:
                row=db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(NEW,)).fetchone()
                if row:
                    progress=json.loads(row[0])
                    if progress.get('initial_suffix_pending') is False:
                        ids=[v[0] for v in db.execute('SELECT local_id FROM '+NEW+' ORDER BY local_id')]
                        assert ids==list(range(502,1002))
                        assert progress['history']==0 and progress['H']==1001 and not progress['history_complete']
                        assert values[-1]['rows_read']<=2000
                        break
        else:pytest.fail(str(values))
        with sc.registry(item['config']) as db:
            marker=sc.state(db,'copy_init_done:'+f.fixture.SHARD+':'+NEW)
            assert marker['status']=='completed' and marker['generation']==progress['copy_init_generation']
        from wechat_local.native_mirror_query import query_local
        query=query_local(item['config'],dict(target_ref=marker['proof']['ref'],limit=5))
        assert query['source_opens']==0 and any(row['local_id']==1001 for row in query['messages'])
        assert not query['coverage']['history_complete'] and 'history_incomplete' in query['gaps']
    finally:driver.close()


def test_atomic_suffix_survives_missing_final_receipt(item,monkeypatch):
    seed(item,count=2,ceiling=2);driver=Driver(item)
    try:
        warm(driver);add_source(item);driver.notify()
        original=ci.finish;failed=[]
        def stop(*args,**kwargs):
            if args[2]==NEW and not failed:failed.append(True);raise MirrorError('synthetic_after_local_commit')
            return original(*args,**kwargs)
        monkeypatch.setattr(ci,'finish',stop)
        for _ in range(4):
            driver.round()
            if failed:break
        assert failed
        with sqlite3.connect(item['local_path']) as db:
            prior=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(NEW,)).fetchone()[0])
            assert prior['history']==0 and not prior['initial_suffix_pending']
        for _ in range(4):
            driver.round()
            with sc.registry(item['config']) as db:done=sc.state(db,'copy_init_done:'+f.fixture.SHARD+':'+NEW)
            if done:break
        assert done['generation']==prior['copy_init_generation']
        with sqlite3.connect(item['local_path']) as db:
            current=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(NEW,)).fetchone()[0])
            assert current['H']==prior['H'] and current['history']>=prior['history']
    finally:driver.close()


def test_new_shard_shared_shell_and_siblings_progress_without_initial_hash_recheck(item,monkeypatch):
    seed(item,count=2,ceiling=2);driver=Driver(item)
    try:
        warm(driver);add_source(item)
        path=Path(item['message_root'])/'message_1.db';shutil.copyfile(item['source_db'],path)
        def run(value):
            def factory(p):
                db=sqlite3.connect(str(path) if p.name==path.name else value['source_db']);db.execute('PRAGMA query_only=ON');return db
            return sync._account_sync(value['config'],connection_factory=factory)
        monkeypatch.setattr(f.fixture,'run_full_account_sync',run);driver.notify(kind='unknown')
        results=[]
        for _ in range(12):
            results.append(driver.round())
            with sc.registry(item['config']) as db:
                done=db.execute("SELECT count(*) FROM state WHERE key LIKE 'copy_init_done:message_1.db:%'").fetchone()[0]
            if done==3:break
        assert done==3,results
        with sqlite3.connect(Path(item['mirror_root'])/path.name) as db:
            progress=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(NEW,)).fetchone()[0])
            assert progress['H']==1001 and not progress['initial_suffix_pending']
        assert not list(Path(item['mirror_root']).glob('.copy-init-message_1.db-*.db'))
    finally:driver.close()


def test_legacy_absence_and_lost_completed_progress_cannot_be_reinitialized(item):
    seed(item,count=2,ceiling=2);driver=Driver(item)
    try:
        warm(driver)
        with sc.registry(item['config']) as db:proof=sc.member(item['config'],db,f.fixture.SHARD,f.FIRST)
        from wechat_local.source_records import SourceKey
        source=SourceKey(item['config']['account_id'],item['config']['source_generation'],f.fixture.SHARD,f.FIRST)
        store=MirrorStore(Path(item['local_path']),source)
        with sqlite3.connect(item['local_path']) as db:
            ddl=db.execute('SELECT sql FROM sqlite_master WHERE name=?',(f.FIRST,)).fetchone()[0]
            db.execute('DELETE FROM __walden_progress WHERE table_name=?',(f.FIRST,))
        budget=dict(tail_probe=dict(bytes=0,ceiling=1000000))
        with sc.registry(item['config'],write=True) as db:
            with pytest.raises(MirrorError,match='account_copy_init_unknown'):
                ci.prepare_local(item['config'],db,proof,store,source,ddl,2,budget)
        with sqlite3.connect(item['local_path']) as db:assert db.execute('SELECT count(*) FROM '+f.FIRST).fetchone()[0]==2
    finally:driver.close()


@pytest.mark.parametrize('count',[0,1001])
def test_new_shard_uncommitted_stage_is_preserved_and_not_allocated_every_retry(item,monkeypatch,count):
    seed(item,count=2,ceiling=2);driver=Driver(item)
    try:
        warm(driver);add_source(item,count)
        path=Path(item['message_root'])/'message_1.db';shutil.copyfile(item['source_db'],path)
        def run(value):
            def factory(p):
                db=sqlite3.connect(str(path) if p.name==path.name else value['source_db']);db.execute('PRAGMA query_only=ON');return db
            return sync._account_sync(value['config'],connection_factory=factory)
        monkeypatch.setattr(f.fixture,'run_full_account_sync',run);driver.notify(kind='unknown')
        original=ci.shell_hash;interrupted=[]
        def fail(path,budget,**kwargs):
            if not interrupted:interrupted.append(True);raise MirrorError('synthetic_pre_receipt_failure')
            return original(path,budget,**kwargs)
        monkeypatch.setattr(ci,'shell_hash',fail)
        results=[]
        for _ in range(12):
            results.append(driver.round())
            if any('account_copy_init_uncommitted_stage' in r['gaps'] for r in results):break
        assert interrupted and any('account_copy_init_uncommitted_stage' in r['gaps'] for r in results)
        stages=list(Path(item['mirror_root']).glob('.copy-init-message_1.db-*.db'))
        assert len(stages)==1 and not (Path(item['mirror_root'])/'message_1.db').exists()
        identity=stages[0].stat().st_ino
        for _ in range(3):driver.round()
        assert list(Path(item['mirror_root']).glob('.copy-init-message_1.db-*.db'))==stages and stages[0].stat().st_ino==identity
        from wechat_local.native_follow_schedule import failure_details
        assert failure_details(['account_copy_init_uncommitted_stage'])['failure_class']=='permanent'
    finally:driver.close()


@pytest.mark.parametrize('tamper',['replace_stage','corrupt_stage','target_competitor'])
def test_committed_shell_is_never_adopted_after_replacement_or_target_competition(item,monkeypatch,tamper):
    seed(item,count=2,ceiling=2);driver=Driver(item)
    try:
        warm(driver);add_source(item)
        path=Path(item['message_root'])/'message_1.db';shutil.copyfile(item['source_db'],path)
        def run(value):
            def factory(p):
                db=sqlite3.connect(str(path) if p.name==path.name else value['source_db']);db.execute('PRAGMA query_only=ON');return db
            return sync._account_sync(value['config'],connection_factory=factory)
        monkeypatch.setattr(f.fixture,'run_full_account_sync',run);driver.notify(kind='unknown')
        for _ in range(8):
            driver.round()
            with sc.registry(item['config']) as db:shell=sc.state(db,'copy_shell:message_1.db')
            if shell:break
        assert shell
        stage=Path(item['mirror_root'])/shell['stage'];target=Path(item['mirror_root'])/'message_1.db'
        assert stage.exists() and not target.exists()
        if tamper=='replace_stage':
            stage.rename(stage.with_suffix('.preserved'));shutil.copyfile(stage.with_suffix('.preserved'),stage);stage.chmod(0o600)
        elif tamper=='corrupt_stage':
            with stage.open('ab') as stream:stream.write(b'unknown')
        else:target.write_bytes(b'foreign');target.chmod(0o600)
        raw=stage.read_bytes();inode=stage.stat().st_ino
        values=[]
        for _ in range(3):
            try:values.append(driver.round())
            except MirrorError as error:values.append(dict(gaps=[str(error)]))
        assert any(set(v['gaps']) & {'account_copy_init_local_replaced','account_copy_init_shell_changed','source_identity_mismatch','source_unavailable_or_unsupported'} for v in values),values
        assert stage.read_bytes()==raw and stage.stat().st_ino==inode
        if tamper=='target_competitor':assert target.read_bytes()==b'foreign'
        else:assert not target.exists()
    finally:driver.close()


@pytest.mark.parametrize('loss',['table','progress','generation','file'])
def test_completed_receipt_never_recreates_lost_copy(item,loss):
    seed(item,count=2,ceiling=2);driver=Driver(item)
    try:
        warm(driver);add_source(item);driver.notify()
        for _ in range(6):
            driver.round()
            with sc.registry(item['config']) as db:marker=sc.state(db,'copy_init_done:'+f.fixture.SHARD+':'+NEW)
            if marker:break
        assert marker
        from wechat_local.source_records import SourceKey
        key=SourceKey(item['config']['account_id'],item['config']['source_generation'],f.fixture.SHARD,NEW)
        with sc.registry(item['config']) as db:proof=sc.member(item['config'],db,f.fixture.SHARD,NEW)
        if loss=='file':
            original=Path(item['local_path']);preserved=original.with_name('preserved-copy.db');original.rename(preserved)
        else:
            with sqlite3.connect(item['local_path']) as db:
                if loss=='table':db.execute('DROP TABLE '+NEW)
                elif loss=='progress':db.execute('DELETE FROM __walden_progress WHERE table_name=?',(NEW,))
                else:
                    progress=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(NEW,)).fetchone()[0]);progress['copy_init_generation']='0'*32
                    db.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',(json.dumps(progress),NEW))
        budget=dict(tail_probe=dict(bytes=0,ceiling=1000000))
        with sc.registry(item['config'],write=True) as db:
            with pytest.raises(MirrorError,match='account_copy_init_(local_missing|progress_lost)'):
                store=ci.open_store(item['config'],db,proof,key,budget)
                ci.prepare_local(item['config'],db,proof,store,key,'unused DDL',1001,budget)
        if loss=='file':assert preserved.exists() and not original.exists()
    finally:driver.close()


def test_completed_audit_dev_is_not_reused_as_current_authority(item):
    seed(item,count=2,ceiling=2);driver=Driver(item)
    try:
        warm(driver);add_source(item);driver.notify()
        for _ in range(6):
            driver.round()
            with sc.registry(item['config']) as db:marker=sc.state(db,'copy_init_done:'+f.fixture.SHARD+':'+NEW)
            if marker:break
        assert marker
        # Audit-only creation identities can predate a valid OS renumber. The
        # current Source/member/progress guards, not this audit, remain authority.
        marker['local'][0]+=1000;marker['proof']['source_identity'][0]+=1000
        with sc.registry(item['config'],write=True) as db:
            sc.save(db,'copy_init_done:'+f.fixture.SHARD+':'+NEW,marker);db.commit()
        values=[driver.round() for _ in range(3)]
        assert not any(value['gaps'] for value in values)
        with sqlite3.connect(item['local_path']) as db:
            progress=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(NEW,)).fetchone()[0])
            assert progress['copy_init_generation']==marker['generation'] and progress['history']>0
    finally:driver.close()


def test_completed_generation_survives_original_auto_renumber(item):
    seed(item,count=2,ceiling=2);driver=Driver(item)
    try:
        warm(driver);add_source(item);driver.notify()
        for _ in range(6):
            driver.round()
            with sc.registry(item['config']) as db:marker=sc.state(db,'copy_init_done:'+f.fixture.SHARD+':'+NEW)
            if marker:break
        assert marker
        with sqlite3.connect(item['local_path']) as local:
            before=local.execute('SELECT * FROM '+NEW+' ORDER BY local_id').fetchall()
        node=Path(item['live_path']).stat();current=[node.st_dev,node.st_ino];old=[node.st_dev+1000,node.st_ino]
        # Reproduce a prior boot's consistent metadata. Source inode/header,
        # config, schema and copied rows stay exactly the same synthetic data.
        with sc.registry(item['config'],write=True) as db:
            anchor=sc.state(db,'shard_anchor:'+f.fixture.SHARD);anchor['source_identity']=old;sc.save(db,'shard_anchor:'+f.fixture.SHARD,anchor)
            entries=db.execute('SELECT table_name,proof FROM members WHERE shard=?',(f.fixture.SHARD,)).fetchall()
            observation=dict(contract=sc.fixed(item['config']),shard=f.fixture.SHARD,source_identity=old,header=anchor['header'],query_only=True,
                tables=[[table,json.loads(raw)['schema_sha256']] for table,raw in entries])
            obs=sc.digest(observation);db.execute('INSERT INTO observations VALUES(?,?)',(obs,json.dumps(observation,sort_keys=True)))
            for table,raw in entries:
                proof=json.loads(raw);proof.update(source_identity=old,observation=obs)
                db.execute('UPDATE members SET proof=? WHERE shard=? AND table_name=?',(json.dumps(proof,sort_keys=True),f.fixture.SHARD,table))
            marker['proof']['source_identity']=old;marker['local'][0]+=1000
            sc.save(db,'copy_init_done:'+f.fixture.SHARD+':'+NEW,marker);db.commit()
        with sqlite3.connect(item['local_path']) as local:
            for table,raw in local.execute('SELECT table_name,value FROM __walden_progress').fetchall():
                progress=json.loads(raw)
                if progress:progress['source_identity']=old;local.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',(json.dumps(progress),table))
        value=driver.round()
        assert not value['gaps'] and value['auto_st_dev_renumber'][0]['old_source_identity']==old
        with sqlite3.connect(item['local_path']) as local:
            progress=json.loads(local.execute('SELECT value FROM __walden_progress WHERE table_name=?',(NEW,)).fetchone()[0])
            assert progress['source_identity']==current and progress['copy_init_generation']==marker['generation']
            for row in before:assert local.execute('SELECT * FROM '+NEW+' WHERE local_id=?',(row[0],)).fetchone()==row
        from wechat_local.native_source_recovery import anchors
        with pytest.raises(MirrorError,match='account_source_recovery_requires_registry_proof'):
            # Existing source-recovery is selected-only; it is no substitute
            # account recovery authority. Self proof is supplied by this fixture.
            from unittest.mock import patch
            with patch('wechat_local.source_setup._confirmed_self_username',return_value='synthetic_self'):anchors(item['config'])
    finally:driver.close()


@pytest.mark.parametrize('length',[1,5000,20000])
def test_shell_allocation_is_derived_from_same_metadata_schema_before_files(tmp_path,length):
    from wechat_local.source_records import SourceKey
    source=SourceKey('synthetic-'+('a'*length),'synthetic-generation','message_0.db',NEW)
    before=list(tmp_path.iterdir());expected=MirrorStore.metadata_shell_bytes(source)
    assert list(tmp_path.iterdir())==before
    target=tmp_path/'synthetic.db';MirrorStore(target,source)
    assert target.stat().st_size==expected


def test_prior_registration_survives_member_and_all_local_copy_record_loss(item):
    seed(item,count=2,ceiling=2);driver=Driver(item)
    try:
        warm(driver);table=f.FIRST;shard=f.fixture.SHARD
        with sc.registry(item['config'],write=True) as db:
            assert sc.member(item['config'],db,shard,table)
            db.execute('DELETE FROM members WHERE shard=? AND table_name=?',(shard,table))
            cursor=sc.state(db,'inventory:'+shard,{});cursor.update(after='',complete=False,refresh_requested=True);sc.save(db,'inventory:'+shard,cursor);db.commit()
        with sqlite3.connect(item['local_path']) as db:
            db.execute('DROP TABLE '+table);db.execute('DELETE FROM __walden_progress WHERE table_name=?',(table,));db.execute('DELETE FROM __walden_observed WHERE table_name=?',(table,))
        driver.notify(kind='unknown');values=[driver.round() for _ in range(4)]
        assert any('account_copy_init_unknown' in value['gaps'] for value in values)
        with sc.registry(item['config']) as db:
            assert sc.state(db,'copy_init:'+shard+':'+table) is None
            assert sc.state(db,'copy_init_done:'+shard+':'+table) is None
    finally:driver.close()


@pytest.mark.parametrize('item',[{'mirror_account_inventory':1}],indirect=True)
def test_fresh_inventory_crosses_small_pages_without_false_legacy_classification(item):
    seed(item,count=2,ceiling=2);driver=Driver(item)
    try:
        warm(driver)
        tables=['Msg_'+format(9000+n,'032x') for n in range(3)]
        with sqlite3.connect(item['source_db']) as db:
            ddl=db.execute('SELECT sql FROM sqlite_master WHERE name=?',(f.FIRST,)).fetchone()[0]
            for table in tables:db.execute(ddl.replace(f.FIRST,table))
        driver.notify()
        for _ in range(18):
            value=driver.round();assert not value['gaps'],value
            with sc.registry(item['config']) as db:
                done=[sc.state(db,'copy_init_done:'+f.fixture.SHARD+':'+table) for table in tables]
            if all(done):break
        assert all(done)
    finally:driver.close()
