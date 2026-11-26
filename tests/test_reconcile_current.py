import hashlib,json,os,sqlite3
from pathlib import Path
import pytest
from test_account_sync_status import item
from test_incremental_history_work import Driver
from test_account_missing_reconcile import missing,request,others,TARGET
from wechat_local import native_account_reconcile as repair,native_scope_contract as sc
from wechat_local.native_follow_policy import digest
from wechat_local.native_mirror_store import MirrorError

def test_explicit_current_request_preserves_old_raw_and_fails_old_schema(item):
 d=Driver(item)
 try:
  proof=missing(item,d);request(item,proof);p=Path(item['mirror_root'])/repair.NAME;old=p.read_bytes();profile=Path(item['mirror_root']).parent/'current-config.json';sc.create(profile,sc.encoded(item['config']))
  value=repair.authorize(item['config'],proof['ref'],confirmed=True,expected_source_sha256=digest(item['config']),current=True,expected_request_sha256=sc.sha(old),profile_path=profile)
  assert value['status']=='current_qualification_requested'and value['source_opens']==0
  new=json.loads(p.read_text());assert new['schema']!='walden.account.missing-copy-reconcile/1'
  assert new['legacy_raw'].encode()==old and new['legacy_sha256']==sc.sha(old)
  assert (p.parent/('.account-copy-reconcile.previous.'+sc.sha(old)+'.json')).read_bytes()==old
  assert repair.read(item['config'])['generation']==json.loads(old)['generation']
 finally:d.close()

def remount(monkeypatch,delta=2):
 native=(os.stat,os.lstat,os.fstat,Path.stat,Path.lstat)
 class Stamp:
  def __init__(self,value):self.value=value
  def __getattr__(self,n):return self.value.st_dev+delta if n=='st_dev'else getattr(self.value,n)
  def __getitem__(self,i):v=list(self.value);v[2]+=delta;return tuple(v)[i]
  def __iter__(self):v=list(self.value);v[2]+=delta;return iter(tuple(v))
  def __len__(self):return len(self.value)
 def wrap(value):return value if isinstance(value,Stamp)else Stamp(value)
 monkeypatch.setattr(os,'stat',lambda *a,**k:wrap(native[0](*a,**k)));monkeypatch.setattr(os,'lstat',lambda *a,**k:wrap(native[1](*a,**k)));monkeypatch.setattr(os,'fstat',lambda *a,**k:wrap(native[2](*a,**k)))
 monkeypatch.setattr(Path,'stat',lambda *a,**k:wrap(native[3](*a,**k)));monkeypatch.setattr(Path,'lstat',lambda *a,**k:wrap(native[4](*a,**k)))

def test_current_qualification_two_identity_layers_and_only_target_component(item,monkeypatch):
 d=Driver(item)
 try:
  proof=missing(item,d);request(item,proof);p=Path(item['mirror_root'])/repair.NAME;old=p.read_bytes();before=others(item)
  profile=Path(item['mirror_root']).parent/'current-config.json';sc.create(profile,sc.encoded(item['config']))
  d.store.immutable('policy.'+d.policy+'.json',dict(profile_path=str(profile),source_signature=digest(item['config'])))
  with monkeypatch.context()as shifted:
   remount(shifted)
   d.close();d=Driver(item)
   with pytest.raises(MirrorError):repair.authorize(item['config'],proof['ref'],confirmed=True,expected_source_sha256=digest(item['config']))
   repair.authorize(item['config'],proof['ref'],confirmed=True,expected_source_sha256=digest(item['config']),current=True,expected_request_sha256=sc.sha(old),profile_path=profile)
   initialized=[];aligned=False
   for _ in range(12):
    v=d.round();assert not v['gaps'],v
    initialized.append(v.get('account_copy_reconcile'))
    if not aligned and v.get('account_copy_reconcile',{}).get('status')in ('qualified','initialized'):
     aligned=True;at_alignment=others(item)
     assert at_alignment['tables']==before['tables']and at_alignment['observed']==before['observed']
     for (name,a),(other,b)in zip(before['progress'],at_alignment['progress']):
      assert name==other;a=json.loads(a);b=json.loads(b);a.pop('source_identity',None);b.pop('source_identity',None);assert a==b

    with sqlite3.connect(item['local_path'])as db:
     exists=db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(TARGET,)).fetchone()
     rows=db.execute('SELECT count(*)FROM '+TARGET).fetchone()[0]if exists else 0
    if rows==2:break
   assert rows==2,initialized
   after=others(item);assert after['tables']==before['tables']and after['observed']==before['observed']
   for (name,a),(other,b)in zip(before['progress'],after['progress']):
    assert name==other;a=json.loads(a);b=json.loads(b);assert all(a.get(k)==b.get(k)for k in ('H','history','tail'))
   with sc.registry(item['config'])as db:
    current=sc.member(item['config'],db,'message_0.db',TARGET);assert current['source_identity'][0]==proof['source_identity'][0]+2
 finally:d.close()

@pytest.mark.parametrize('mode,reason,reset',[('blocked','account_reconcile_source_conflict',True),('blocked','scope_source_conflict',False),('backoff','source_retry_backoff',False)])
def test_schedule_token_once_keeps_completion_and_other_backoff(item,mode,reason,reset):
 from wechat_local.native_reconcile_current import schedule_admission
 d=Driver(item)
 try:
  proof=missing(item,d);request(item,proof);p=Path(item['mirror_root'])/repair.NAME;old=p.read_bytes();profile=p.parent.parent/'current-config.json';sc.create(profile,sc.encoded(item['config']))
  repair.authorize(item['config'],proof['ref'],confirmed=True,expected_source_sha256=digest(item['config']),current=True,expected_request_sha256=sc.sha(old),profile_path=profile)
  prior=dict(mode=mode,failure_reason=reason,last_completion=['d'*32,1],next_due_at_ns=9999999999999999999,next_due_continuous_ns=9999999999999999999,backoff=300)
  runtime=dict(segment=None,source_schedule=prior);policy=dict(profile_path=str(profile),source_signature=digest(item['config']))
  update=schedule_admission(item['config'],runtime,policy);assert update['source_schedule']['last_completion']==prior['last_completion']and update['source_schedule']['failure_reason']==reason
  assert (update['source_schedule']['mode']=='normal')is reset
  if not reset:assert update['source_schedule']==prior
  runtime.update(update);runtime['operation']='restart'
  assert schedule_admission(item['config'],runtime,policy)is None
  again=repair.authorize(item['config'],proof['ref'],confirmed=True,expected_source_sha256=digest(item['config']),current=True,expected_request_sha256=sc.sha(old),profile_path=profile)
  assert again['request_sha256']==sc.sha(p.read_bytes())and schedule_admission(item['config'],runtime,policy)is None
 finally:d.close()

def current_setup(item,d):
 proof=missing(item,d);request(item,proof);p=Path(item['mirror_root'])/repair.NAME;old=p.read_bytes();profile=p.parent.parent/'current-config.json';sc.create(profile,sc.encoded(item['config']))
 d.store.immutable('policy.'+d.policy+'.json',dict(profile_path=str(profile),source_signature=digest(item['config'])))
 repair.authorize(item['config'],proof['ref'],confirmed=True,expected_source_sha256=digest(item['config']),current=True,expected_request_sha256=sc.sha(old),profile_path=profile)
 return proof,profile,p

def test_current_empty_initialization_does_not_wait_for_optional_spare(item,monkeypatch):
 from wechat_local import native_mirror_sync as sync
 d=Driver(item)
 try:
  proof,profile,p=current_setup(item,d);before=others(item)
  # Incomplete optional discovery is not permission to copy messages. The
  # explicitly authorized management turn only creates the target's empty PG.
  monkeypatch.setattr(sync,'_account_known_tail_debts',lambda *a,**k:False)
  value=d.round();assert not value['gaps'],value
  assert value['account_copy_reconcile']['status']=='initialized'
  assert value['rows_read']==0
  with sqlite3.connect(item['local_path'])as db:
   assert db.execute('SELECT COUNT(*)FROM '+TARGET).fetchone()==(0,)
   pg=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(TARGET,)).fetchone()[0])
   assert pg['H']==2 and pg['history']==0 and pg['tail']==2 and pg['initial_suffix_pending']is True
  assert others(item)==before
 finally:d.close()

@pytest.mark.parametrize('change',['source_copy','local_copy','source_volume','nonempty','profile','missing_volume'])
def test_current_rejects_wrong_object_volume_residual_and_profile(item,monkeypatch,change):
 from wechat_local import native_reconcile_current as current
 d=Driver(item)
 try:
  proof,profile,request_path=current_setup(item,d);source=Path(item['message_root'])/'message_0.db';local=Path(item['local_path'])
  if change in ('source_copy','local_copy'):
   path=source if change=='source_copy'else local;raw=path.read_bytes();path.rename(path.with_suffix('.preserved'));path.write_bytes(raw);path.chmod(0o600)
  elif change=='source_volume':
   native=current._volume;inode=source.stat().st_ino
   monkeypatch.setattr(current,'_volume',lambda fd:'f'*32 if os.fstat(fd).st_ino==inode else native(fd))
  elif change=='nonempty':
   with sqlite3.connect(local)as db:db.execute('CREATE TABLE '+TARGET+'(local_id INTEGER PRIMARY KEY)')
  elif change=='profile':profile.write_bytes(profile.read_bytes()+b' ')
  elif change=='missing_volume':
   v=json.loads(request_path.read_text());v['confirmation']['local'].pop('volume_uuid');request_path.write_bytes(sc.encoded(v))
  try:v=d.round()
  except MirrorError:pass
  else:assert v['gaps'],v
  with sqlite3.connect(local)as db:
   pg=db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(TARGET,)).fetchone();assert pg is None
 finally:d.close()

@pytest.mark.parametrize('stage',['qualified_before_commit','qualified_committed'])
def test_qualification_commit_interruption_durable_and_repeat(item,monkeypatch,stage):
 from wechat_local import native_reconcile_current as current
 d=Driver(item)
 try:
  proof,profile,p=current_setup(item,d);raw=p.read_bytes();before=others(item);seen=[]
  def point(value):
   if value==stage and not seen:seen.append(True);raise KeyboardInterrupt()
  monkeypatch.setattr(current,'_checkpoint',point)
  with pytest.raises(KeyboardInterrupt):d.round()
  assert p.read_bytes()==raw and others(item)==before
  for _ in range(12):
   v=d.round();assert not v['gaps'],v
   with sqlite3.connect(item['local_path'])as db:
    yes=db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(TARGET,)).fetchone();rows=db.execute('SELECT COUNT(*)FROM '+TARGET).fetchone()[0]if yes else 0
   if rows==2:break
  assert rows==2 and seen
 finally:d.close()

def test_failed_current_object_ticket_survives_new_policy_without_Source_retry(item,monkeypatch):
 from wechat_local import native_reconcile_current as current
 d=Driver(item)
 try:
  proof,profile,p=current_setup(item,d);source=Path(item['message_root'])/'message_0.db';native=current._volume;inode=source.stat().st_ino
  with monkeypatch.context()as wrong:
   wrong.setattr(current,'_volume',lambda fd:'f'*32 if os.fstat(fd).st_ino==inode else native(fd))
   result=d.round();assert result['gaps']==['account_reconcile_current_unproven']
  request=repair.read(item['config'])
  with sc.registry(item['config'])as db:
   ticket=sc.state(db,current.admission_key(request));assert ticket['phase']=='blocked'and ticket['authority']=='none'
  policy=dict(profile_path=str(profile),source_signature=digest(item['config']))
  fresh=dict(segment=None,source_schedule=dict(mode='normal',last_completion=None,backoff=0))
  value=current.schedule_admission(item['config'],fresh,policy)
  assert value['source_schedule']['mode']=='blocked'and value['source_schedule']['failure_reason']=='account_reconcile_current_unproven'
  fresh.update(value);assert current.schedule_admission(item['config'],fresh,policy)is None
  result=d.round();assert result['source_opens']==0 and result['gaps']==['account_reconcile_current_unproven']
 finally:d.close()

def three_missing(item,d,*,confirm=True):
 from test_incremental_history_work import seed,warm
 seed(item,count=4,ceiling=2);warm(d)
 with sc.registry(item['config'])as db:
  rows=db.execute("SELECT table_name FROM members WHERE table_name<>? ORDER BY table_name",(TARGET,)).fetchall()
  absent=[r[0]for r in rows[-2:]];assert len(absent)==2
  proof=sc.member(item['config'],db,'message_0.db',TARGET)
  refs=[sc.member(item['config'],db,'message_0.db',t)['ref']for t in absent]
 with sqlite3.connect(item['local_path'])as db:
  for t in [TARGET]+absent:
   db.execute('DROP TABLE '+t);db.execute('DELETE FROM __walden_progress WHERE table_name=?',(t,));db.execute('DELETE FROM __walden_observed WHERE table_name=?',(t,))
 request(item,proof);p=Path(item['mirror_root'])/repair.NAME;old=p.read_bytes();profile=p.parent.parent/'current-config.json';sc.create(profile,sc.encoded(item['config']))
 d.store.immutable('policy.'+d.policy+'.json',dict(profile_path=str(profile),source_signature=digest(item['config'])))
 if confirm:repair.authorize(item['config'],proof['ref'],confirmed=True,expected_source_sha256=digest(item['config']),current=True,expected_request_sha256=sc.sha(old),profile_path=profile,withheld_refs=refs)
 return absent,refs,proof,profile,p,old

def test_exact_two_withheld_keep_three_none_and_target_real_rows(item):
 d=Driver(item)
 try:
  absent,refs,proof,profile,p,old=three_missing(item,d);seen=set()
  for _ in range(16):
   value=d.round();assert not value['gaps'],value
   seen.update(row['target_ref']for row in value.get('account_copy_withheld',[]))
   with sqlite3.connect(item['local_path'])as db:
    for t in absent:
     assert not db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(t,)).fetchone()
     assert not db.execute('SELECT 1 FROM __walden_progress WHERE table_name=?',(t,)).fetchone()
     assert not db.execute('SELECT 1 FROM __walden_observed WHERE table_name=?',(t,)).fetchone()
    exists=db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(TARGET,)).fetchone()
    rows=db.execute('SELECT local_id FROM '+TARGET+' ORDER BY local_id').fetchall()if exists else[]
   if seen==set(refs)and rows==[(1,),(2,)]:break
  assert seen==set(refs)and rows==[(1,),(2,)]
  assert value['follow_observation']['complete']is False
  assert json.loads(p.read_bytes())['legacy_raw'].encode()==old
 finally:d.close()

def test_nonapproved_missing_ref_keeps_original_failure(item):
 d=Driver(item)
 try:
  absent,refs,proof,profile,p,old=three_missing(item,d,confirm=False)
  repair.authorize(item['config'],proof['ref'],confirmed=True,expected_source_sha256=digest(item['config']),current=True,expected_request_sha256=sc.sha(old),profile_path=profile,withheld_refs=refs[:1])
  for _ in range(16):
   value=d.round()
   if value['gaps']:break
  assert value['gaps']==['account_copy_init_unknown'],value
 finally:d.close()

@pytest.mark.parametrize('residual',['table','progress','observed'])
def test_withheld_residual_keeps_failure(item,residual):
 d=Driver(item)
 try:
  absent,refs,proof,profile,p,old=three_missing(item,d)
  value=d.round();assert not value['gaps']
  with sqlite3.connect(item['local_path'])as db:
   if residual=='table':db.execute('CREATE TABLE '+absent[0]+'(local_id INTEGER PRIMARY KEY)')
   elif residual=='progress':db.execute('INSERT INTO __walden_progress VALUES(?,?)',(absent[0],'{}'))
   else:
    db.execute('INSERT INTO __walden_observed VALUES(?,?,?,?,?,?,?)',(absent[0],1,'123',1,1,1,'f'*64))
  for _ in range(16):
   value=d.round()
   if value['gaps']:break
  assert value['gaps'],value
 finally:d.close()

def test_completed_target_does_not_release_withheld_current_source_guard(item,monkeypatch):
 from wechat_local import native_reconcile_current as current
 d=Driver(item)
 try:
  absent,refs,proof,profile,p,old=three_missing(item,d)
  for _ in range(16):
   value=d.round();assert not value['gaps'],value
   with sc.registry(item['config'])as db:
    ci=__import__('wechat_local.native_account_copy_init',fromlist=['read']).read(db,'message_0.db',TARGET,dict(tail_probe=dict(bytes=0,ceiling=1048576)))
   if ci and ci['status']=='completed':break
  assert ci['status']=='completed'
  native=current._volume;source_inode=(Path(item['message_root'])/'message_0.db').stat().st_ino
  monkeypatch.setattr(current,'_volume',lambda fd:'f'*32 if os.fstat(fd).st_ino==source_inode else native(fd))
  value=d.round();assert value['source_opens']==0 and value['gaps']==['account_reconcile_current_unproven']
 finally:d.close()

@pytest.mark.parametrize('item',[{'mirror_lock_timeout':.01}],indirect=True)
def test_withheld_confirmation_cannot_compete_with_writer(item):
 from wechat_local.native_mirror_sync import writer_lock
 d=Driver(item)
 try:
  absent,refs,proof,profile,p,old=three_missing(item,d,confirm=False)
  with writer_lock(Path(item['mirror_root']),.01):
   with pytest.raises(MirrorError):repair.authorize(item['config'],proof['ref'],confirmed=True,expected_source_sha256=digest(item['config']),current=True,expected_request_sha256=sc.sha(old),profile_path=profile,withheld_refs=refs)
  assert p.read_bytes()==old
 finally:d.close()

def test_qualification_budget_defers_bound_object_across_new_policy(item,monkeypatch):
 from wechat_local import native_reconcile_current as current
 from wechat_local.native_account_witness import WorkBudgetStop
 d=Driver(item)
 try:
  proof,profile,p=current_setup(item,d);seen=[]
  def stop(stage):
   if stage=='qualified_before_commit'and not seen:
    seen.append(True);raise WorkBudgetStop('account_copy_init_metadata_deferred',budget_kind='metadata_bytes',limit=1048576,used=1048576,required=16)
  monkeypatch.setattr(current,'_checkpoint',stop)
  value=d.round();assert not value['gaps']and value['new_tail']['work_budget_limited']
  request=repair.read(item['config'])
  with sc.registry(item['config'])as db:
   ticket=sc.state(db,current.admission_key(request));assert ticket['phase']=='bound'and ticket['source']
  d.policy='e'*32;d.store.immutable('policy.'+d.policy+'.json',dict(profile_path=str(profile),source_signature=digest(item['config'])));d.publish()
  for _ in range(12):
   value=d.round();assert not value['gaps'],value
   with sqlite3.connect(item['local_path'])as db:
    exists=db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(TARGET,)).fetchone();rows=db.execute('SELECT COUNT(*)FROM '+TARGET).fetchone()[0]if exists else 0
   if rows==2:break
  assert rows==2 and seen
 finally:d.close()

def test_confirmed_same_volume_objects_survive_later_device_renumber(item,monkeypatch):
 d=Driver(item)
 try:
  absent,refs,proof,profile,p,old=three_missing(item,d)
  for _ in range(16):
   value=d.round();assert not value['gaps'],value
   with sqlite3.connect(item['local_path'])as db:
    exists=db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(TARGET,)).fetchone();rows=db.execute('SELECT COUNT(*)FROM '+TARGET).fetchone()[0]if exists else 0
   if rows==2:break
  assert rows==2
  with monkeypatch.context()as shifted:
   remount(shifted);d.close();d=Driver(item)
   for _ in range(12):
    value=d.round();assert not value['gaps'],value
    if {r['target_ref']for r in value.get('account_copy_withheld',[])}==set(refs):break
   assert {r['target_ref']for r in value.get('account_copy_withheld',[])}==set(refs)
   with sqlite3.connect(item['local_path'])as db:assert db.execute('SELECT local_id FROM '+TARGET+' ORDER BY local_id').fetchall()==[(1,),(2,)]
 finally:d.close()

def test_worker_control_preserves_withheld_commit_and_terminal_frame():
 from wechat_local.native_follow_schedule import control_result
 frame=dict(version=1,dropped=0,events=[dict(stage='selection',reason='unowned_copy_withheld',elapsed_ms=1,target='a'*64),dict(stage='local_commit',reason='suffix',elapsed_ms=2,rows=1,H=2,history=0,tail=2),dict(stage='terminal',reason='authorization_checked',elapsed_ms=3,duration_ms=1)])
 result=control_result(dict(gaps=[],source_opens=1,round_diagnostics=frame))
 assert result.get('round_diagnostics')==frame

def test_interrupted_legacy_request_keeps_permanent_invalid_classification(item):
 from wechat_local.native_follow_schedule import failure_details
 d=Driver(item)
 try:
  proof=missing(item,d);request(item,proof);p=Path(item['mirror_root'])/repair.NAME;p.write_bytes(p.read_bytes().rstrip()[:-1])
  with pytest.raises(MirrorError,match='^account_reconcile_request_invalid$')as error:repair.read(item['config'])
  assert failure_details([str(error.value)])['failure_class']=='permanent'
 finally:d.close()
