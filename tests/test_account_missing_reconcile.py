"""Explicit legacy repair is distinct from trusted new inventory membership."""
import json
import sqlite3
import time
from pathlib import Path

import pytest
import test_account_sync_status as f
from test_account_sync_status import item
from test_incremental_history_work import Driver,seed,warm
from wechat_local import native_account_reconcile as repair,native_scope_contract as sc,native_account_copy_init as ci
from wechat_local.native_mirror_store import MirrorError
from wechat_local.native_follow_policy import digest

TARGET=f.FIRST


def missing(item,driver):
    seed(item,count=2,ceiling=2);warm(driver)
    with sc.registry(item['config']) as db:proof=sc.member(item['config'],db,f.fixture.SHARD,TARGET)
    with sqlite3.connect(item['local_path']) as db:
        db.execute('DROP TABLE '+TARGET);db.execute('DELETE FROM __walden_progress WHERE table_name=?',(TARGET,));db.execute('DELETE FROM __walden_observed WHERE table_name=?',(TARGET,))
    return proof


def others(item):
    with sqlite3.connect(item['local_path']) as db:
        return dict(tables={name:db.execute('SELECT * FROM '+name+' ORDER BY rowid').fetchall() for name, in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name GLOB 'Msg_*'") if name!=TARGET},
                    progress=db.execute('SELECT * FROM __walden_progress WHERE table_name<>? ORDER BY table_name',(TARGET,)).fetchall(),
                    observed=db.execute('SELECT * FROM __walden_observed WHERE table_name<>? ORDER BY table_name,local_id,fingerprint',(TARGET,)).fetchall())


def request(item,proof):
    plan=repair.authorize(item['config'],proof['ref'])
    assert plan['status']=='confirmation_required' and plan['source_opens']==0
    assert not (Path(item['mirror_root'])/repair.NAME).exists()
    return repair.authorize(item['config'],proof['ref'],confirmed=True,expected_source_sha256=plan['source_sha256'])


def test_explicit_single_copy_zero_other_message_writes_and_unknown_survives_new_H_completion(item):
    driver=Driver(item)
    try:
        proof=missing(item,driver);before=others(item);assert request(item,proof)['status']=='requested'
        initialized=driver.round()
        assert not initialized['gaps'] and initialized['account_copy_reconcile']['status']=='initialized'
        assert initialized['rows_read']==0 and initialized['source_opens']==1 and others(item)==before
        with sqlite3.connect(item['local_path']) as db:
            progress=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(TARGET,)).fetchone()[0])
            assert progress['H']==2 and progress['history']==0 and progress['initial_suffix_pending'] and progress['prior_coverage_unknown']
            assert db.execute('SELECT count(*) FROM '+TARGET).fetchone()==(0,)
        for _ in range(8):
            value=driver.round()
            if value['account_scope']['current_snapshot_complete']:break
        assert value['account_scope']['current_snapshot_complete'] and not value['account_scope']['raw_messages_complete']
        assert value['account_scope']['prior_coverage_unknown'] and not value['account_scope']['known_backlog']
        assert value['follow_observation']['complete'] and value['follow_observation']['prior_coverage_unknown']
        from wechat_local.native_follow_schedule import plan as cadence
        schedule=cadence(None,wall=0,continuous=0,interval=2,completion=dict(operation='synthetic',attempt=1,exit_code=0,
            observed_complete=value['follow_observation']['complete'],known_backlog=value['follow_observation']['known_backlog']))
        assert schedule['mode']=='idle',schedule
        from wechat_local.native_mirror_query import query_local
        query=query_local(item['config'],dict(target_ref=proof['ref'],limit=5))
        assert {v['local_id'] for v in query['messages']}=={1,2}
        assert query['coverage']['current_H_complete'] and not query['coverage']['history_complete']
        assert query['coverage']['prior_coverage_unknown'] and 'prior_history_coverage_unknown' in query['gaps']
        before_repeat=others(item)
        assert repair.authorize(item['config'],proof['ref'],confirmed=True,expected_source_sha256=digest(item['config']))['status']=='owned_copy_or_completed'
        assert others(item)==before_repeat
    finally:driver.close()


@pytest.mark.parametrize('item',[{'mirror_account_rows':1,'mirror_account_tables':1}],indirect=True)
def test_tail_arriving_between_management_and_suffix_gets_the_only_message_slot(item):
    from test_incremental_history_work import NEW
    driver=Driver(item)
    try:
        proof=missing(item,driver);request(item,proof)
        assert driver.round()['account_copy_reconcile']['status']=='initialized'
        with sqlite3.connect(item['source_db']) as db:db.execute('INSERT INTO '+NEW+' VALUES(2,2,1,?,0,?,0)',(int(time.time()),'synthetic new tail'))
        with sc.registry(item['config'],write=True) as db:sc.save(db,'names:'+f.fixture.SHARD,1);db.commit()
        driver.notify()
        value=driver.round()
        assert value['rows_read']==1 and [v['table'] for v in value['sources']]==[NEW]
        with sqlite3.connect(item['local_path']) as db:
            assert db.execute('SELECT local_id FROM '+NEW+' WHERE local_id=2').fetchone()==(2,)
            assert db.execute('SELECT count(*) FROM '+TARGET).fetchone()==(0,)
            progress=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(TARGET,)).fetchone()[0])
            assert progress['initial_suffix_pending'] and progress['prior_coverage_unknown']
    finally:driver.close()


@pytest.mark.parametrize('cut',['before_local','after_local'])
def test_authorized_interruption_resumes_exact_generation_without_resetting_others(item,monkeypatch,cut):
    driver=Driver(item)
    try:
        proof=missing(item,driver);request(item,proof);before=others(item)
        original=ci.prepare_local;interrupted=[]
        def stop(*args,**kwargs):
            if not interrupted:
                interrupted.append(True)
                if cut=='after_local':original(*args,**kwargs)
                raise KeyboardInterrupt()
            return original(*args,**kwargs)
        monkeypatch.setattr(ci,'prepare_local',stop)
        with pytest.raises(KeyboardInterrupt):driver.round()
        assert others(item)==before
        with sc.registry(item['config']) as db:prior=sc.state(db,'copy_init:'+f.fixture.SHARD+':'+TARGET)
        assert prior and prior['prior_coverage_unknown']
        for _ in range(6):
            value=driver.round()
            with sc.registry(item['config']) as db:done=sc.state(db,'copy_init_done:'+f.fixture.SHARD+':'+TARGET)
            if done:break
        assert done and done['generation']==prior['generation'] and done['prior_coverage_unknown']
    finally:driver.close()


@pytest.mark.parametrize('residual',['table','progress','observed','member','file','binding'])
def test_explicit_confirmation_cannot_repair_residuals_or_missing_member_or_shard(item,residual):
    driver=Driver(item)
    try:
        proof=missing(item,driver)
        if residual=='member':
            with sc.registry(item['config'],write=True) as db:db.execute('DELETE FROM members WHERE table_name=?',(TARGET,));db.commit()
        elif residual=='file':Path(item['local_path']).rename(Path(item['local_path']).with_name('preserved.db'))
        else:
            with sqlite3.connect(item['local_path']) as db:
                if residual=='table':db.execute('CREATE TABLE '+TARGET+'(unknown TEXT)')
                elif residual=='progress':db.execute('INSERT INTO __walden_progress VALUES(?,?)',(TARGET,'{}'))
                elif residual=='observed':db.execute('INSERT INTO __walden_observed VALUES(?,1,NULL,1,1,1,?)',(TARGET,'synthetic'))
                else:db.execute('UPDATE __walden_binding SET generation=?',('different',))
        with pytest.raises((MirrorError,OSError)):
            repair.authorize(item['config'],proof['ref'],confirmed=True,expected_source_sha256=digest(item['config']))
        assert not (Path(item['mirror_root'])/repair.NAME).exists()
    finally:driver.close()
