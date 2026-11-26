"""Boundary injection, separate from the measured full-scale debit RED."""
import pytest
from test_account_sync_status import item
from test_incremental_history_work import Driver,seed,warm
from wechat_local import native_mirror_sync as sync,native_account_witness as aw


@pytest.mark.parametrize('mode',['enabled','disabled','post_mode_failure'])
@pytest.mark.parametrize('remaining',[0,1])
def test_metadata_ceiling_reserves_actual_guarded_finalization(item,monkeypatch,mode,remaining):
    seed(item,count=12,ceiling=30000);driver=Driver(item)
    try:
        warm(driver)
        if mode=='disabled':
            runtime=driver.store.read('instance.'+driver.operation+'.json')
            runtime['shard_hints'].pop('coverage_version');driver.store.atomic('instance.'+driver.operation+'.json',runtime)
        owners=[];events=[];original_init=aw.AccountWitness.__init__;original_admit=sync._account_registry_admit
        def capture(self,*args,**kwargs):original_init(self,*args,**kwargs);owners.append(self)
        def admit(*args,**kwargs):
            value=original_admit(*args,**kwargs);events.append('admitted');return value
        monkeypatch.setattr(aw.AccountWitness,'__init__',capture);monkeypatch.setattr(sync,'_account_registry_admit',admit)
        original_registry=aw.AccountWitness.registry
        def registry(self,path,raw):
            raw.set_trace_callback(lambda sql:events.append(sql) if sql.upper() in ('COMMIT','BEGIN IMMEDIATE') else None)
            return original_registry(self,path,raw)
        monkeypatch.setattr(aw.AccountWitness,'registry',registry)
        original_probe=sync._account_tail_probe;stopped=[]
        def probe(*args,**kwargs):
            value=original_probe(*args,**kwargs)
            if not stopped:
                budget=args[6];budget['tail_probe']['bytes']=budget['tail_probe']['ceiling']-remaining;stopped.append(True)
            return value
        monkeypatch.setattr(sync,'_account_tail_probe',probe)
        original_mode=aw._Lease.mode;failed=[]
        def checked_mode(self):
            if mode=='post_mode_failure' and stopped and not failed and self.guard:
                failed.append(True);self.owner.invalidate('mode');raise aw.WorkChanged('account_work_changed')
            return original_mode(self)
        monkeypatch.setattr(aw._Lease,'mode',checked_mode)
        monkeypatch.setattr(sync,'_account_aux',lambda *a,**k:pytest.fail('aux started beyond metadata ceiling'))
        result=driver.round()
        assert stopped and not result['gaps']
        assert all(o.budget['tail_probe']['bytes']<=1048576 for o in owners)
        # Every physical commit reacquires the SQLite reservation and invokes
        # the real mandatory admission before any later commit can follow.
        commits=[n for n,event in enumerate(events) if event=='COMMIT']
        assert commits
        for n in commits:
            later=events[n+1:]
            assert 'BEGIN IMMEDIATE' in later and 'admitted' in later
            assert later.index('BEGIN IMMEDIATE')<later.index('admitted')
            if 'COMMIT' in later:assert later.index('admitted')<later.index('COMMIT')
        if mode=='post_mode_failure':assert failed
    finally:driver.close()
