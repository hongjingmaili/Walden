"""Source replacement before publication rolls back; after COMMIT is uncertain."""
import json,shutil,sqlite3
from pathlib import Path
import pytest
import test_account_sync_status as f
from test_account_sync_status import item
from test_incremental_history_work import Driver
from test_account_missing_reconcile import missing,request,TARGET
from wechat_local import native_mirror_sync as sync,native_account_reconcile as repair,native_account_copy_init as ci,native_scope_contract as sc
from wechat_local.native_mirror_store import MirrorStore


@pytest.mark.parametrize('cut',['open','after_read','before_receipt_commit','before_local_commit','after_local_commit'])
def test_management_source_identity_boundary(item,monkeypatch,cut):
    driver=Driver(item)
    try:
        proof=missing(item,driver);request(item,proof);replaced=[]
        def replace():
            if replaced:return
            path=Path(item['live_path']);path.rename(path.with_name(path.name+'.preserved'));shutil.copyfile(path.with_name(path.name+'.preserved'),path);path.chmod(0o600);replaced.append(True)
        original_consume=repair.consume;inside=[]
        def consume(*args,**kwargs):inside.append(True);return original_consume(*args,**kwargs)
        monkeypatch.setattr(repair,'consume',consume)
        if cut=='open':
            def run(value):
                def factory(path):
                    db=sqlite3.connect(value['source_db']);db.execute('PRAGMA query_only=ON');replace();return db
                return sync._account_sync(value['config'],connection_factory=factory)
            monkeypatch.setattr(f.fixture,'run_full_account_sync',run)
        elif cut=='after_read':
            original=sync._account_source_read
            def read(conn,sql,*args,**kwargs):
                result=original(conn,sql,*args,**kwargs)
                if inside and 'max(local_id)' in sql:replace()
                return result
            monkeypatch.setattr(sync,'_account_source_read',read)
        elif cut=='before_receipt_commit':
            original=ci.save
            def save(reg,value,budget):
                result=original(reg,value,budget)
                if inside and value.get('prior_coverage_unknown'):replace()
                return result
            monkeypatch.setattr(ci,'save',save)
        elif cut=='before_local_commit':
            original=MirrorStore.apply_batch
            def apply(self,source,table,rows,progress,**kwargs):
                result=original(self,source,table,rows,progress,**kwargs)
                if inside and table==TARGET and kwargs.get('_connection') is not None:replace()
                return result
            monkeypatch.setattr(MirrorStore,'apply_batch',apply)
        else:
            original=ci.prepare_local
            def prepare(*args,**kwargs):
                result=original(*args,**kwargs);replace();return result
            monkeypatch.setattr(ci,'prepare_local',prepare)
        result=driver.round();assert replaced and 'scope_source_conflict' in result['gaps']
        assert result['account_copy_reconcile']['status']=='failed'
        with sqlite3.connect(item['local_path']) as db:
            table=db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(TARGET,)).fetchone();row=db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(TARGET,)).fetchone()
        with sc.registry(item['config']) as db:
            assert sc.state(db,'copy_init_done:'+f.fixture.SHARD+':'+TARGET) is None
            marker=sc.state(db,'copy_init:'+f.fixture.SHARD+':'+TARGET)
        if cut!='after_local_commit':assert table is None and row is None
        else:
            assert table and row and marker['status']=='prepared'
            progress=json.loads(row[0]);assert progress['initial_suffix_pending'] and progress['source_identity']==proof['source_identity']
            # Retain the exact old-Source pending state; no cleanup or successful
            # acceptance against the replacement is permitted on later rounds.
            next_round=driver.round();assert next_round['gaps']
        if cut in ('open','after_read','before_receipt_commit'):assert marker is None
    finally:driver.close()


@pytest.mark.parametrize('remaining',[100,50000])
def test_source_revalidation_keeps_budget_and_defers_without_false_success(item,monkeypatch,remaining):
    driver=Driver(item)
    try:
        proof=missing(item,driver);request(item,proof);original=repair.consume;budgets=[]
        def limited(config,registry,request,budget,*args,**kwargs):
            budget['tail_probe']['bytes']=budget['tail_probe']['ceiling']-remaining;budgets.append(budget)
            return original(config,registry,request,budget,*args,**kwargs)
        monkeypatch.setattr(repair,'consume',limited);result=driver.round()
        assert budgets and budgets[0]['tail_probe']['bytes']<=1048576
        if remaining==100:
            assert result['account_copy_reconcile']['status']!='initialized' and result['new_tail']['work_budget_limited']
            with sqlite3.connect(item['local_path']) as db:
                assert db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(TARGET,)).fetchone() is None
                assert db.execute('SELECT 1 FROM __walden_progress WHERE table_name=?',(TARGET,)).fetchone() is None
        else:assert result['account_copy_reconcile']['status']=='initialized' and not result['gaps']
    finally:driver.close()
