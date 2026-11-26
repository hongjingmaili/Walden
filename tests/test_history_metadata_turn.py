"""Direct changed maintenance boundary; installed fullchain separately proves rows."""
import json,sqlite3,time
from pathlib import Path
import pytest
from test_account_sync_status import item
from test_incremental_history_work import Driver,seed,count_history,inject
from wechat_local import native_scope_contract as sc,native_mirror_sync as sync


def test_deferred_probe_preserves_pending_without_claiming_complete(item):
 seed(item,count=30,ceiling=2000)
 path=Path(item['message_root'])/'message_0.db';budget={'tail_probe':{'bytes':0,'tables':0,'until':None,'ceiling':707760},'until':time.monotonic()+20}
 class NotRead:
  def __getattr__(self,name):raise AssertionError('deferred discovery performed Source/local SQL')
 with sc.registry(item['config'],write=True)as db:
  key='tail_probe:'+path.name
  before={'after':'Msg_'+'a'*32,'pending':[['Msg_'+'b'*32,9]],'complete':True,'token':['old',1]}
  sc.save(db,key,before)
  state=sync._account_tail_probe(item['config'],NotRead(),db,path,NotRead(),{},budget,['new',2],defer_discovery=True)
  assert state['pending']==before['pending'] and not state['complete']
  assert sc.state(db,key)['pending']==before['pending'] and budget['tail_probe']['bytes']==0


def test_positive_history_uses_slot_without_inventory_refresh(item,monkeypatch):
 seed(item,count=30,ceiling=2000);d=Driver(item);calls=[];original=sync._account_tail_probe
 def trace(*a,**kw):calls.append(bool(kw.get('defer_discovery')));return original(*a,**kw)
 monkeypatch.setattr(sync,'_account_tail_probe',trace)
 try:
  value=d.round();value=d.round()
  assert any(calls) and count_history(item)>0
  assert any(e['reason']=='history_metadata_reserved'for e in value['round_diagnostics']['events'])
  assert value['new_tail']['metadata_bytes']<=1048576
 finally:d.close()


def test_new_tail_below_bound_keeps_original_discovery(item,monkeypatch):
 seed(item,count=30,ceiling=4000);d=Driver(item);calls=[];original=sync._account_tail_probe
 def trace(*a,**kw):calls.append(bool(kw.get('defer_discovery')));return original(*a,**kw)
 monkeypatch.setattr(sync,'_account_tail_probe',trace)
 try:
  inject(item,d,2);value=d.round()
  assert not any(calls)
  assert any(e.get('stage')=='local_commit' and e.get('reason')=='tail'for e in value['round_diagnostics']['events'])
 finally:d.close()


def test_changed_cookie_keeps_original_discovery(item,monkeypatch):
 seed(item,count=30,ceiling=4000);d=Driver(item);calls=[];original=sync._account_tail_probe
 def trace(*a,**kw):calls.append(bool(kw.get('defer_discovery')));return original(*a,**kw)
 try:
  d.round()
  with sqlite3.connect(item['source_db'])as db:db.execute('CREATE TABLE AdditionalMetadata(value INTEGER)')
  monkeypatch.setattr(sync,'_account_tail_probe',trace)
  d.round();assert calls and not any(calls)
 finally:d.close()


def test_existing_hint_before_fair_history_is_not_lost(item,monkeypatch):
 seed(item,count=30,ceiling=8000);d=Driver(item);batches=[];original=sync._account_copy_table
 def trace(*a,**kw):
  value=original(*a,**kw)
  if value and (value['history_advanced']or value['tail_advanced']):batches.append(value['batch_kind'])
  return value
 monkeypatch.setattr(sync,'_account_copy_table',trace)
 try:
  d.round()
  for identifier in (2,3,4):inject(item,d,identifier);d.round()
  inject(item,d,5)  # The one and only hint is already present before H starts.
  before=len(batches);d.round();assert batches[before:]==['history']
  before=len(batches);d.round();assert batches[before] == 'tail'
  with sqlite3.connect(item['local_path'])as db:
   from test_incremental_history_work import NEW
   assert db.execute('SELECT local_id FROM '+NEW+' WHERE local_id=5').fetchone()==(5,)
 finally:d.close()


def test_same_source_maintenance_restarts_after_actual_history_commit(item,monkeypatch):
 seed(item,count=30,ceiling=8000);d=Driver(item);original=sync._account_tail_probe;seen=[]
 try:
  d.round()
  with sc.registry(item['config'],write=True)as db:
   key='inventory:message_0.db';inv=sc.state(db,key);inv['checked_at_ns']=0;sc.save(db,key,inv);db.commit()
  before=count_history(item)
  def trace(*a,**kw):
   seen.append((kw.get('defer_discovery',False),count_history(item)))
   return original(*a,**kw)
  monkeypatch.setattr(sync,'_account_tail_probe',trace)
  d.round()
  assert seen[0]==(True,before)
  assert any(not deferred and count>before for deferred,count in seen)
  with sc.registry(item['config'])as db:assert sc.state(db,key)['checked_at_ns']>0
 finally:d.close()
