import time
from pathlib import Path
import pytest
from test_media_priority import queue
from wechat_local import native_media_work as work
from wechat_local import native_deadline


def test_same_child_continues_only_after_real_ready_progress(queue,monkeypatch):
 from wechat_local import native_media_dispatch as dispatch
 config,add,run,attempted=queue
 for i in range(1,14):add(i,when=1)
 monkeypatch.setattr(dispatch,'resource_state',lambda:dict(reason=None))
 out=dispatch.run(config,lambda p:(_ for _ in ()).throw(AssertionError('unexpectedSource')))
 assert out['media_completed']==13 and out['media_attempted']==13
 assert out['media_batches']>=4 and len(attempted)==13
 assert out['media_dispatch_reason']=='no_progress'  # Unconfigured OCR makes no ready progress.

def test_no_progress_stops_without_empty_spin(queue,monkeypatch):
 from wechat_local import native_media_dispatch as dispatch
 config,add,run,attempted=queue;add(999)
 monkeypatch.setattr(dispatch,'resource_state',lambda:dict(reason=None))
 out=dispatch.run(config,lambda p:None)
 assert out['media_batches']==1 and out['media_completed']==0 and attempted==[999]
 assert out['media_dispatch_reason']=='no_progress'


@pytest.mark.parametrize('reason',['resource_pressure','metrics_unavailable'])
def test_pressure_or_unknown_metrics_yields_before_any_claim(queue,monkeypatch,reason):
 from wechat_local import native_media_dispatch as dispatch
 config,add,run,attempted=queue;add(1)
 monkeypatch.setattr(dispatch,'resource_state',lambda:dict(reason=reason))
 out=dispatch.run(config,lambda p:None)
 assert out['media_attempted']==0 and attempted==[] and out['media_dispatch_reason']==reason
 with work._connect(config)as c:assert c.execute('SELECT status,attempts FROM jobs').fetchone()==('pending',0)


def test_single_child_safety_item_cap_and_remaining_work(queue,monkeypatch):
 from wechat_local import native_media_dispatch as dispatch
 config,add,run,attempted=queue
 for i in range(1,41):add(i,when=1)
 monkeypatch.setattr(dispatch,'resource_state',lambda:dict(reason=None))
 out=dispatch.run(config,lambda p:None)
 assert out['media_attempted']+out['image_ocr_attempted']==32 and out['media_completed']>0 and out['media_dispatch_reason']=='item_cap'


def test_active_remaining_deadline_is_not_reset(queue,monkeypatch):
 from wechat_local import native_media_dispatch as dispatch
 config,add,run,attempted=queue;add(1)
 monkeypatch.setattr(dispatch,'resource_state',lambda:dict(reason=None))
 deadline=native_deadline.Deadline.create(1)
 with native_deadline.activate_deadline(deadline):out=dispatch.run(config,lambda p:None)
 assert out['media_dispatch_reason']=='deadline_near'and attempted==[]


def test_inter_item_writer_busy_releases_unprocessed_claims(queue,monkeypatch):
 from wechat_local import native_media_dispatch as dispatch
 from wechat_local.native_mirror_sync import writer_lock
 config,add,run,attempted=queue
 for i in range(1,5):add(i)
 monkeypatch.setattr(dispatch,'resource_state',lambda:dict(reason=None))
 with writer_lock(Path(config['mirror_root']),0):out=dispatch.run(config,lambda p:None)
 assert out['media_dispatch_reason']=='writer_busy'and out['media_attempted']==0
 with work._connect(config)as c:assert c.execute("SELECT count(*) FROM jobs WHERE status='running'").fetchone()==(0,)


def test_cancel_before_third_codec_does_not_consume_unstarted_history_turn(queue,monkeypatch):
 from wechat_local import native_mirror_media as media
 config,add,run,attempted=queue
 for i in range(1,9):add(i,when=1)
 for i in range(100,140):add(i,fresh=True)
 capture=media.capture_window_images;calls=[0]
 def interrupted(*args,**kwargs):
  calls[0]+=1
  if calls[0]==3:raise KeyboardInterrupt()
  return capture(*args,**kwargs)
 monkeypatch.setattr(media,'capture_window_images',interrupted)
 for _ in range(4):
  calls[0]=0
  with pytest.raises(KeyboardInterrupt):run(4)
 with work._connect(config)as c:
  old_ready=sum(1 for source,status in c.execute('SELECT source,status FROM jobs')if __import__('json').loads(source)['local_id']<100 and status=='ready')
  assert old_ready>=2
  assert c.execute("SELECT count(*) FROM jobs WHERE status='running'").fetchone()==(0,)


def test_ocr_old_ready_has_bounded_opportunity_with_new_images(queue):
 config,add,run,attempted=queue
 for i in range(1,5):add(i,when=1)
 run(4)
 class Recognizer:
  identity='synthetic-ocr'
  def recognize_png(self,payload,timeout):
   time.sleep(.01)
   return dict(text='synthetic',confidence=1)
 engine=Recognizer()
 for i in range(100,124):add(i,fresh=True)
 run(24)
 for _ in range(8):work.run_image_derivations(config,recognizer=engine,limit=1)
 with work._connect(config)as c:
  rows=c.execute("SELECT source,status FROM image_derivations WHERE engine=?",(engine.identity,)).fetchall()
  assert sum(1 for source,status in rows if __import__('json').loads(source)['local_id']<100 and status=='ready')>=2


@pytest.mark.parametrize('error_type',[PermissionError,__import__('wechat_local.live_readonly',fromlist=['LiveReadonlyError']).LiveReadonlyError])
def test_systemic_source_open_failure_stops_batch_and_releases_claims(queue,monkeypatch,error_type):
 from wechat_local import native_media_dispatch as dispatch,native_mirror_media as media
 from wechat_local.native_mirror_store import MirrorError
 config,add,run,_=queue
 for i in range(1,5):add(i)
 monkeypatch.setattr(dispatch,'resource_state',lambda:dict(reason=None))
 actual=media.capture_window_images;opens=[]
 def capture(config,root,window,opener,**kw):
  opener(Path(config['image_database']))
  return actual(config,root,window,opener,**kw)
 def unavailable(path):opens.append(path);raise error_type('synthetic denied')
 monkeypatch.setattr(media,'capture_window_images',capture)
 with pytest.raises(MirrorError,match='media_source_unavailable'):dispatch.run(config,unavailable)
 assert len(opens)==1
 with work._connect(config)as c:assert c.execute("SELECT count(*) FROM jobs WHERE status='pending' AND attempts=0").fetchone()==(4,)


def test_real_expired_deadline_does_not_publish_ready_and_releases_exact_claim(queue,monkeypatch):
 from wechat_local import native_mirror_media as media
 from wechat_local.native_mirror_store import MirrorError
 config,add,run,_=queue;add(1)
 capture=media.capture_window_images
 def late(*args,**kw):
  result=capture(*args,**kw);time.sleep(1.05);return result
 monkeypatch.setattr(media,'capture_window_images',late)
 deadline=native_deadline.Deadline.create(1)
 with native_deadline.activate_deadline(deadline):
  with pytest.raises(MirrorError,match='schedule_deadline_expired'):run()
 with work._connect(config)as c:assert c.execute('SELECT status,attempts,lease FROM jobs').fetchone()==('pending',0,0)


def test_each_item_selection_is_inside_immediate_transaction(queue,monkeypatch):
 config,add,run,_=queue;add(1)
 original=work._select_jobs
 def checked(c,*args):
  assert c.in_transaction, 'selection before write transaction'
  return original(c,*args)
 monkeypatch.setattr(work,'_select_jobs',checked)
 run(1)


def test_voice_capture_systemic_source_marker_escapes_without_next_item(queue):
 from wechat_local import native_mirror_media as media
 from wechat_local.native_mirror_store import MirrorError
 config,add,run,_=queue;add(1,kind=34);add(2,kind=34)
 config['voice_databases']=[str(Path(config['message_root'])/'voice_0.db')]
 config['voice_discovery_complete']=True;config['voice_discovery_status']='complete'
 opens=[]
 def unavailable(path):opens.append(path);raise MirrorError('media_source_unavailable')
 with pytest.raises(MirrorError,match='media_source_unavailable'):
  media.save_voices(config,Path(config['mirror_root']),config['mirror_scope'],unavailable)
 assert len(opens)==1


def test_dynamic_ocr_maintenance_is_one_bounded_opportunity_per_batch(queue,monkeypatch):
 from wechat_local import native_media_dispatch as dispatch
 config,add,run,_=queue
 for i in range(1,65):add(i,when=1)
 run(64)
 class Recognizer:
  identity='bounded-synthetic-ocr'
  def recognize_png(self,payload,timeout):return dict(text='synthetic',confidence=1)
 monkeypatch.setattr(dispatch,'resource_state',lambda:dict(reason=None))
 calls=[];native=work._image_payload
 def counted(*args,**kwargs):
  value=native(*args,**kwargs);calls.append(len(value[0]));return value
 monkeypatch.setattr(work,'_image_payload',counted)
 result=dispatch.run(config,lambda p:None,recognizer=Recognizer())
 assert result['image_ocr_completed']>=1
 assert result['image_ocr_maintenance']['verified']<=8
 assert result['image_ocr_maintenance']['admission_checked']<=8
 assert result['image_ocr_maintenance']['payload_reads']<=16
 assert len(calls)<=result['image_ocr_maintenance']['payload_reads']+2*result['image_ocr_attempted']


@pytest.mark.parametrize('busy',[True,False])
def test_continuation_lock_yields_but_nonbusy_error_stays_visible(queue,monkeypatch,busy):
 import sqlite3
 from wechat_local import native_media_dispatch as dispatch
 config,add,run,_=queue
 for i in range(1,7):add(i,when=1)
 monkeypatch.setattr(dispatch,'resource_state',lambda:dict(reason=None))
 eligible=dispatch._eligible
 def unavailable(*args):
  if not busy:raise sqlite3.OperationalError('database disk image is malformed')
  with sqlite3.connect(Path(config['mirror_root'])/'media-work.sqlite')as writer:
   writer.execute('BEGIN EXCLUSIVE')
   return eligible(*args)
 monkeypatch.setattr(dispatch,'_eligible',unavailable)
 if busy:
  result=dispatch.run(config,lambda p:None)
  assert result['media_dispatch_reason']=='media_store_busy'and result['media_completed']==3
 else:
  with pytest.raises(sqlite3.OperationalError,match='malformed'):dispatch.run(config,lambda p:None)
 with work._connect(config)as c:
  assert c.execute("SELECT count(*) FROM jobs WHERE status='ready'").fetchone()==(3,)
  assert c.execute("SELECT count(*) FROM jobs WHERE status='pending' AND attempts=0").fetchone()==(3,)
  assert c.execute("SELECT count(*) FROM jobs WHERE status='running'").fetchone()==(0,)


@pytest.mark.parametrize('revoked',[False,True])
def test_scoped_voice_reads_real_payload_outside_writer_and_guards_reference(queue,monkeypatch,revoked):
 import hashlib
 import json
 import sqlite3
 from contextlib import contextmanager
 from wechat_local import native_mirror_media as media, voice_transcript
 from wechat_local.native_mirror_sync import writer_lock
 from wechat_local.native_mirror_store import MirrorError

 config,add,_,_=queue
 add(1,kind=34)
 root=Path(config['mirror_root'])
 source=Path(config['message_root']);source.mkdir()
 voice=source/'voice_0.db'
 config.update(voice_databases=[str(voice)],voice_discovery_complete=True,voice_discovery_status='complete')
 shard='message_1.db';username=config['mirror_scope'][0]
 table='Msg_'+hashlib.md5(username.encode()).hexdigest()
 with sqlite3.connect(root/shard) as copied:
  item=copied.execute(f'SELECT server_id,local_id,create_time,local_type,NULL,real_sender_id,message_content,WCDB_CT_message_content FROM {table}').fetchone()
 key=media.voice_key(config,shard,username,item)
 payload=b'#!SILK_V3'+b'real synthetic payload'
 with sqlite3.connect(voice) as db:
  db.execute('CREATE TABLE Name2Id(user_name TEXT)')
  db.execute('INSERT INTO Name2Id VALUES(?)',(username,))
  db.execute('CREATE TABLE VoiceInfo(chat_name_id INTEGER,create_time INTEGER,local_id INTEGER,svr_id INTEGER,voice_data BLOB)')
  db.execute('INSERT INTO VoiceInfo VALUES(1,?,?,?,?)',(item[2],item[1],item[0],payload))

 def opener(path):
  assert path==voice
  db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
  db.execute('PRAGMA query_only=ON')
  return db
 saw_read=[]
 native=voice_transcript.capture_bound_voice
 def capture(*args,**kwargs):
  with writer_lock(root,0):
   saw_read.append(True)
  return native(*args,**kwargs)
 monkeypatch.setattr(voice_transcript,'capture_bound_voice',capture)
 @contextmanager
 def guard():
  with writer_lock(root,0):
   if revoked and saw_read:
    raise media.MediaItemDeferred('cursor_generation_media_unavailable')
   yield
 args=(config,root,[username],opener)
 kws=dict(selected={(shard,table,1)},capture_guard=guard)
 if revoked:
  with pytest.raises(MirrorError,match='cursor_generation_media_unavailable'):
   media.save_voices(*args,**kws)
  assert not (root/'voice-state'/f'{key}.json').exists()
 else:
  assert media.save_voices(*args,**kws)==[]
  state=json.loads((root/'voice-state'/f'{key}.json').read_text())
  filename=media._voice_payload_name(key,state)
  assert state['saved'] is True and state['sha256']==hashlib.sha256(payload).hexdigest()
  assert (root/'voice-payloads'/filename).read_bytes()==payload
 assert saw_read==[True]
