import hashlib,json,sqlite3,time
from pathlib import Path
import pytest
from wechat_local import native_media_work as work
from wechat_local import native_mirror_media as media

COLS=['local_id','server_id','local_type','create_time','real_sender_id','message_content','WCDB_CT_message_content']
@pytest.fixture
def queue(tmp_path,monkeypatch):
 root=tmp_path/'mirror';root.mkdir(mode=0o700)
 config=dict(account_id='synthetic-account',source_generation='synthetic-generation',mirror_scope=['synthetic-chat'],mirror_root=str(root),message_root=str(tmp_path/'source'),image_database=str(tmp_path/'resource.db'),image_attachments_root=str(tmp_path/'attachments'))
 table='Msg_'+hashlib.md5(b'synthetic-chat').hexdigest();shard='message_1.db'
 with sqlite3.connect(root/shard)as c:
  c.execute('CREATE TABLE __walden_binding(account_id,source_generation,shard)');c.execute('INSERT INTO __walden_binding VALUES(?,?,?)',(config['account_id'],config['source_generation'],shard))
  c.execute('CREATE TABLE '+table+'(local_id INTEGER PRIMARY KEY,server_id INTEGER,local_type INTEGER,create_time INTEGER,real_sender_id INTEGER,message_content,WCDB_CT_message_content INTEGER)')
 attempted=[]
 def capture(config,root,window,opener,**kw):
  item=window['messages'][0];i=item['source']['local_id'];attempted.append(i)
  if i==999:raise RuntimeError('synthetic item unavailable')
  import struct,zlib
  def chunk(kind,data):return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
  payload=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',8,8,8,2,0,0,0))+chunk(b'IDAT',zlib.compress((b'\0'+b'\xff\xff\xff'*8)*8))+chunk(b'IEND',b'')
  output=root/'media-images';output.mkdir(mode=0o700,exist_ok=True);file=output/'synthetic.png';file.write_bytes(payload);file.chmod(0o600)
  item['image']=dict(status='decoded',representations=[dict(status='decoded',path=str(file),size=[8,8])]);return []
 monkeypatch.setattr(media,'capture_window_images',capture)
 def add(i,*,fresh=False,when=None,kind=3,prior=None):
  now=int(time.time());row=(i,i,kind,now if when is None else when,1,b'<img/>',0)
  with sqlite3.connect(root/shard)as c:c.execute('INSERT INTO '+table+' VALUES(?,?,?,?,?,?,?)',row)
  arrival=dict(kind='tail_increment',before_tail=i-1,prior_max=i-1,through_tail=i,prior_checked_at=now-1 if prior is None else prior,observed_at=now)if fresh else None
  work.enqueue_rows(config,shard,table,'synthetic-chat',COLS,[row],**({'arrival':arrival}if arrival else{}))
 def run(n=4):return work.run_media(config,lambda _:(_ for _ in ()).throw(AssertionError('unexpected Source open')),limit=n)
 return config,add,run,attempted

def test_new_tail_served_ahead_of_large_history_and_history_gets_service(queue):
 config,add,run,attempted=queue
 for i in range(1,49):add(i,when=int(time.time())-86400)
 add(100,fresh=True);run()
 assert attempted[0]==100
 assert any(i<100 for i in attempted)

def test_continuous_recent_arrivals_do_not_starve_history_across_calls(queue):
 config,add,run,attempted=queue
 for i in range(1,25):add(i,when=1)
 for batch in range(5):
  for i in range(4):add(100+batch*4+i,fresh=True)
  run()
 assert sum(i<100 for i in attempted)>=5
 assert max(sum(1 for x in attempted[a:a+4]if x>=100)for a in range(0,len(attempted),4))<=3

def test_recent_message_time_without_tail_boundary_remains_history(queue):
 config,add,run,_=queue;add(1)
 with work._connect(config)as c:
  assert c.execute('SELECT recent_at,arrival FROM jobs').fetchone()==(0,'unproven_or_history')

def test_same_job_is_not_promoted_by_later_reenqueue(queue):
 config,add,run,_=queue;add(1,when=1)
 with work._connect(config)as c:source=json.loads(c.execute('SELECT source FROM jobs').fetchone()[0])
 # A repeat scan uses INSERT OR IGNORE and cannot turn an existing job into new arrival.
 work.enqueue(config,'synthetic-chat',source,'image')
 with work._connect(config)as c:assert c.execute('SELECT recent_at FROM jobs').fetchone()==(0,)

def test_one_missing_item_does_not_block_the_remaining_claims(queue):
 config,add,run,attempted=queue;add(999,fresh=True);add(1000,fresh=True);add(1,when=1)
 out=run();assert 1000 in attempted and out['media_completed']>=1

def test_old_schema_upgrade_preserves_old_job_bytes_and_marks_no_new_arrival(queue):
 config,add,run,_=queue;add(1,when=1)
 path=Path(config['mirror_root'])/'media-work.sqlite'
 with sqlite3.connect(path)as c:
  columns=[r[1]for r in c.execute('PRAGMA table_info(jobs)')]
  if 'recent_at'in columns:
   c.execute('ALTER TABLE jobs RENAME TO upgraded_jobs')
   c.execute('CREATE TABLE jobs(key TEXT PRIMARY KEY,username TEXT NOT NULL,source TEXT NOT NULL,kind TEXT NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT0,due REAL NOT NULL DEFAULT0,lease REAL NOT NULL DEFAULT0,result TEXT,reason TEXT,version TEXT NOT NULL)'.replace('DEFAULT0','DEFAULT 0'))
   c.execute('INSERT INTO jobs SELECT key,username,source,kind,status,attempts,due,lease,result,reason,version FROM upgraded_jobs');c.execute('DROP TABLE upgraded_jobs')
  before=c.execute('SELECT key,source,status,attempts,due,lease,result,reason,version FROM jobs').fetchall()
 with work._connect(config,True)as c:
  assert c.execute('SELECT key,source,status,attempts,due,lease,result,reason,version FROM jobs').fetchall()==before
  assert c.execute('SELECT recent_at FROM jobs').fetchone()==(0,)


def test_history_image_and_audio_both_get_bounded_turns(queue):
 config,add,run,_=queue
 for i in range(1,17):add(i,when=1,kind=34 if i%2 else 3)
 for i in range(100,116):add(i,fresh=True)
 chosen=[]
 for batch in range(4):
  c=work._connect(config,True)
  try:
   with c:
    rows=work._select_jobs(c,time.time(),4,None)
    chosen.extend((json.loads(r[2])['local_id'],r[3])for r in rows)
    c.executemany("UPDATE jobs SET status='ready' WHERE key=?",[(r[0],)for r in rows])
  finally:c.close()
 historical=[kind for i,kind in chosen if i<100]
 assert len(historical)==4 and set(historical[:2])=={'image','audio'}

def test_expired_or_missing_start_facts_cannot_promote(queue):
 config,add,run,_=queue
 add(1,fresh=True,when=1)
 with work._connect(config)as c:assert c.execute('SELECT recent_at FROM jobs').fetchone()==(0,)


@pytest.mark.parametrize('silence',[87,3600])
def test_pinned_arrival_after_long_quiet_tail_still_goes_before_existing_jobs(queue,silence):
 config,add,run,attempted=queue
 now=int(time.time())
 add(1,when=1)
 add(10,fresh=True,when=now-1,prior=now-silence)
 run()
 assert attempted==[10,1]


def test_late_old_message_at_new_id_does_not_use_recent_lane(queue):
 config,add,run,attempted=queue
 now=int(time.time())
 add(30,fresh=True,when=now-45,prior=now-20)
 with work._connect(config)as c:
  assert c.execute('SELECT recent_at FROM jobs').fetchone()==(0,)
