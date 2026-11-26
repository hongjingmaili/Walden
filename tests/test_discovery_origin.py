"""Bounded origin lifecycle components; installed SDK recovery is separate."""
import json,sqlite3,time
from pathlib import Path
import pytest
from wechat_local import native_account_round as rw,native_scope_contract as sc,native_mirror_sync as sync
from wechat_local.native_account_witness import WorkBudgetStop
from wechat_local.native_mirror_store import MirrorError
from test_account_sync_status import item
OLD='a'*32;NEW='b'*32;THIRD='c'*32;SHARD='message_0.db';ANCHOR={'source_identity':[7,8],'header':'d'*64}
def budget(limit=707760):return {'until':time.monotonic()+20,'tail_probe':{'bytes':0,'ceiling':limit}}
def db():
 c=sqlite3.connect(':memory:');c.execute('CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT)');sc.save(c,'shard_anchor:'+SHARD,ANCHOR);sc.save(c,'tail_probe:'+SHARD,{'token':[OLD,82],'after':'Msg_'+'e'*32,'complete':False,'pending':[]});return c

def test_positive_old_debt_survives_partial_pages_and_repeated_restart():
 c=db();old={'instance':OLD,'shards':{}};state_before=sc.state(c,'tail_probe:'+SHARD)
 assert rw.restore_discovery(c,[Path(SHARD)],budget(),old,NEW)=={SHARD}
 state=sc.state(c,'tail_probe:'+SHARD);origin=state['discovery_origin'];assert origin=={'instance':OLD,'sequence':82,'anchor':ANCHOR}
 assert all(state[k]==v for k,v in state_before.items())
 state['token']=[NEW,0];state['after']='Msg_'+'f'*32;sc.save(c,'tail_probe:'+SHARD,state)
 assert rw.restore_discovery(c,[Path(SHARD)],budget(),{'instance':NEW,'shards':{}},THIRD)=={SHARD}
 assert sc.state(c,'tail_probe:'+SHARD)['discovery_origin']==origin
 assert old=={'instance':OLD,'shards':{}}

@pytest.mark.parametrize('kind',['same_instance','completed','consumed','no_epoch','missing_shards','bad_token','bad_uncertainty'])
def test_unproven_or_finished_state_never_mints_new_tail_priority(kind):
 c=db();old={'instance':OLD,'shards':{}};instance=NEW;state=sc.state(c,'tail_probe:'+SHARD)
 if kind=='same_instance':instance=OLD
 elif kind=='completed':state['complete']=True
 elif kind=='consumed':old['shards'][SHARD]=82
 elif kind=='no_epoch':old={}
 elif kind=='missing_shards':old={'instance':OLD}
 elif kind=='bad_token':state['token']=[THIRD,82]
 else:state['token']=[OLD,82,'not-an-uncertainty-counter']
 sc.save(c,'tail_probe:'+SHARD,state)
 assert rw.restore_discovery(c,[Path(SHARD)],budget(),old,instance)==set()
 assert 'discovery_origin'not in sc.state(c,'tail_probe:'+SHARD)


def test_pending_service_and_full_discovery_are_both_required_for_release():
 c=db();rw.restore_discovery(c,[Path(SHARD)],budget(),{'instance':OLD,'shards':{}},NEW);state=sc.state(c,'tail_probe:'+SHARD)
 state.update(token=[NEW,0],complete=True,pending=[['Msg_'+'f'*32,9]])
 assert 'discovery_origin'in rw.finish_discovery(state,ANCHOR,budget())
 state['pending']=[];closed=rw.finish_discovery(state,ANCHOR,budget());assert 'discovery_origin'not in closed
 assert closed['token']==[NEW,0]and 'discovery_origin'in state


def test_budget_stop_does_not_publish_origin_or_new_consumed_epoch():
 c=db();old={'instance':OLD,'shards':{}};sc.save(c,'tail_hints',old);before=c.execute('SELECT key,value FROM state ORDER BY key').fetchall()
 with pytest.raises(WorkBudgetStop):rw.restore_discovery(c,[Path(SHARD)],budget(1),old,NEW)
 assert c.execute('SELECT key,value FROM state ORDER BY key').fetchall()==before
 assert sc.state(c,'tail_hints')==old


def test_origin_is_only_a_hint_and_never_authorizes_replaced_Source():
 c=db();rw.restore_discovery(c,[Path(SHARD)],budget(),{'instance':OLD,'shards':{}},NEW);before=sc.state(c,'tail_probe:'+SHARD)
 with pytest.raises(MirrorError,match='scope_source_conflict'):
  sync._account_shard_anchor_check({},c,Path(SHARD),[7,9],ANCHOR['header'])
 assert sc.state(c,'tail_probe:'+SHARD)==before
 sc.save(c,'shard_anchor:'+SHARD,{'source_identity':[7,9],'header':'d'*64})
 assert rw.restore_discovery(c,[Path(SHARD)],budget(),{'instance':NEW,'shards':{}},THIRD)==set()
 assert sc.state(c,'tail_probe:'+SHARD)==before


def test_existing_origin_shape_is_bounded_and_invalid_is_not_silently_reset():
 c=db();state=sc.state(c,'tail_probe:'+SHARD);state['discovery_origin']={'instance':'invalid'};sc.save(c,'tail_probe:'+SHARD,state)
 with pytest.raises(MirrorError,match='account_discovery_origin_invalid'):rw.restore_discovery(c,[Path(SHARD)],budget(),{},NEW)
 assert sc.state(c,'tail_probe:'+SHARD)==state


def test_partial_origin_quiet_never_compares_new_epoch_to_old_sequence():
 c=db();b=budget();rw.restore_discovery(c,[Path(SHARD)],b,{'instance':OLD,'shards':{}},NEW)
 state=sc.state(c,'tail_probe:'+SHARD);state['token']=[NEW,0];sc.save(c,'tail_probe:'+SHARD,state)
 b=budget();rw.restore_discovery(c,[Path(SHARD)],b,{'instance':NEW,'shards':{}},NEW)
 assert not rw.discovery_has_new_hint(SHARD,{SHARD:0},NEW,b)
 assert rw.discovery_has_new_hint(SHARD,{SHARD:1},NEW,b)
 assert sc.state(c,'tail_probe:'+SHARD)['discovery_origin']['sequence']==82


def test_latch_budget_failure_stops_body_before_any_new_epoch_publication(item,monkeypatch):
 from test_incremental_history_work import seed,Driver
 seed(item,count=30,ceiling=2000);d=Driver(item);old={'instance':THIRD,'shards':{}}
 try:
  with sc.registry(item['config'],write=True)as reg:
   sc.save(reg,'tail_hints',old);sc.save(reg,'tail_probe:'+SHARD,{'token':[THIRD,82],'after':'','complete':False,'pending':[]});reg.commit()
  original=rw.restore_discovery
  def exhausted(registry,paths,budget,*args,**kwargs):
   budget['tail_probe']['ceiling']=1
   return original(registry,paths,budget,*args,**kwargs)
  # Controlled metadata failure only; no Source guard or grant is replaced here.
  monkeypatch.setattr(rw,'restore_discovery',exhausted)
  value=d.round();assert value['source_opens']==0
  with sc.registry(item['config'])as reg:assert sc.state(reg,'tail_hints')==old
  assert any(e.get('at_stage')=='hint_recovery'for e in value['round_diagnostics']['events'])
 finally:d.close()


def test_charged_prefix_survives_later_budget_stop_without_epoch_switch():
 c=db();second='message_1.db';sc.save(c,'shard_anchor:'+second,ANCHOR);sc.save(c,'tail_probe:'+second,sc.state(c,'tail_probe:'+SHARD));old={'instance':OLD,'shards':{}};sc.save(c,'tail_hints',old)
 one=budget();rw.restore_discovery(c,[Path(SHARD)],one,old,NEW)
 first_cost=one['tail_probe']['bytes'];first=sc.state(c,'tail_probe:'+SHARD);first.pop('discovery_origin');sc.save(c,'tail_probe:'+SHARD,first)
 with pytest.raises(WorkBudgetStop):rw.restore_discovery(c,[Path(SHARD),Path(second)],budget(first_cost+1),old,NEW)
 assert 'discovery_origin'in sc.state(c,'tail_probe:'+SHARD)
 assert 'discovery_origin'not in sc.state(c,'tail_probe:'+second)
 assert sc.state(c,'tail_hints')==old
 assert rw.restore_discovery(c,[Path(SHARD),Path(second)],budget(),old,THIRD)=={SHARD,second}
 assert sc.state(c,'tail_probe:'+SHARD)['discovery_origin']['instance']==OLD


def test_partial_discovery_uses_existing_quiet_turn_instead_of_starving_H(item):
 from test_incremental_history_work import seed,Driver,count_history
 seed(item,count=1000,ceiling=4000);d=Driver(item);old={'instance':THIRD,'shards':{}}
 try:
  with sc.registry(item['config'],write=True)as reg:
   sc.save(reg,'tail_hints',old);sc.save(reg,'tail_probe:'+SHARD,{'token':[THIRD,82],'after':'','complete':False,'pending':[]});reg.commit()
  first=d.round()
  assert any(e['reason']=='discovery_page_deferred'for e in first['round_diagnostics']['events'])
  before=count_history(item);second=d.round();assert count_history(item)>before
  assert any(e['stage']=='local_commit'and e['reason']=='history'for e in second['round_diagnostics']['events'])
 finally:d.close()


def test_origin_only_quiet_survives_actual_selection_with_empty_current_hints(item):
 import inspect,sys
 from test_incremental_history_work import seed,Driver
 seed(item,count=30,ceiling=4000);d=Driver(item)
 d.watch.shard_generations.clear();d.watch.fallback_generation=1;d.publish()
 # Valid previous-round quiet and unresolved old positive token. This is a
 # component state fixture; no product selector, guard or Source call is faked.
 with sc.registry(item['config'],write=True)as reg:
  sc.save(reg,'tail_hints',{'instance':THIRD,'shards':{}})
  sc.save(reg,'tail_probe:'+SHARD,{'token':[THIRD,82],'after':'','complete':False,'pending':[]})
  sc.save(reg,'tail_hint_quiet',{SHARD:sc.state(reg,'round_number',0)+1});reg.commit()
 lines,first_line=inspect.getsourcelines(sync._account_sync)
 select_line=first_line+next(i for i,line in enumerate(lines)if line.lstrip().startswith('fresh=[p for p in paths'))
 selected=[];previous_trace=sys.gettrace()
 def observe(frame,event,arg):
  if event=='line'and frame.f_code is sync._account_sync.__code__ and frame.f_lineno==select_line:
   selected.append((SHARD in frame.f_locals['quiet'],SHARD in frame.f_locals['discovery'],SHARD in frame.f_locals['hints']))
  return observe
 try:
  sys.settrace(observe)
  try:value=d.round()
  finally:sys.settrace(previous_trace)
  assert selected==[(True,True,False)]
  assert not any(e.get('reason')=='tail_priority'for e in value['round_diagnostics']['events'])
 finally:d.close()
