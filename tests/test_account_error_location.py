import json,sqlite3
from types import SimpleNamespace
import pytest
from wechat_local import native_mirror_sync as sync,native_follow_schedule as schedule
from wechat_local.native_mirror_store import MirrorStore
from wechat_local.source_records import SourceKey
from test_account_commit_witness import setup
from test_account_sync_status import item
from wechat_local.native_account_witness import WorkChanged


def test_actual_source_max_failure_has_safe_phase(tmp_path):
 db=sqlite3.connect(':memory:');path=tmp_path/'source.db';path.touch()
 store=SimpleNamespace(progress=lambda _:dict(H=10,history=0,tail=10))
 cfg=dict(account_id='synthetic-account',source_generation='synthetic-generation')
 with pytest.raises(sqlite3.Error)as caught:
  sync._account_copy_table(cfg,db,path,'Msg_'+'a'*32,store,[1,2],'a'*64,{},registry=None,media_username='synthetic')
 detail=sync._account_error_info(caught.value,'source_copy')
 assert detail['operation_phase']=='source_max'
 assert detail['exception_family']=='sqlite_operational'
 assert schedule.shard_diagnostics({'shard_diagnostics':[detail]})==[detail]
 assert 'SELECT'not in json.dumps(detail)and str(tmp_path)not in json.dumps(detail)
 db.close()


def test_actual_local_commit_busy_is_not_a_source_read(tmp_path,monkeypatch):
 p=tmp_path/'local.db';table='Msg_'+'b'*32;key=SourceKey('synthetic-account','synthetic-generation','message_0.db',table);store=MirrorStore(p,key)
 store.ensure_table(key,'CREATE TABLE '+table+'(local_id INTEGER PRIMARY KEY,server_id INTEGER,local_type INTEGER,create_time INTEGER,real_sender_id INTEGER,message_content TEXT,WCDB_CT_message_content INTEGER)')
 reader=sqlite3.connect(p);reader.execute('BEGIN');reader.execute('SELECT COUNT(*) FROM '+table).fetchone()
 writers=[]
 def connect():
  conn=sqlite3.connect(p,timeout=0);writers.append(conn);return conn
 monkeypatch.setattr(store,'connect',connect)
 try:
  with pytest.raises(sqlite3.OperationalError)as caught:store.apply_batch(key,table,[(1,1,1,1,1000,0,'synthetic',0)],{'H':1,'history':1,'tail':1})
  detail=sync._account_error_info(caught.value,'source_copy')
  assert detail['operation_phase']=='local_commit'
  assert detail['commit_state']=='unknown'
 finally:
  reader.rollback();reader.close()
  for writer in writers:writer.rollback();writer.close()
 with sqlite3.connect(p)as c:assert c.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]==0


def test_physical_commit_then_revalidation_failure_is_not_rollback(tmp_path):
 p,owner=setup(tmp_path);lease=owner.connect(p);raw=lease.raw
 class Gap:
  def __getattr__(self,name):return getattr(raw,name)
  def commit(self):
   raw.commit()
   with sqlite3.connect(p)as external:external.execute('UPDATE value SET n=n+1')
 lease.raw=Gap()
 with pytest.raises(WorkChanged)as caught:
  with lease as db:db.execute('UPDATE value SET n=2')
 detail=sync._account_error_info(caught.value,'source_copy')
 assert detail['operation_phase']=='local_commit_revalidate'
 assert detail['commit_state']=='physical_commit_returned'
 with sqlite3.connect(p)as db:assert db.execute('SELECT n FROM value').fetchone()[0]==3


def test_extended_code_and_missing_runtime_capability_remain_explicit():
 e=sqlite3.DatabaseError('private SQL/body/path not retained');e.sqlite_errorcode=2067
 d=sync._account_error_info(e,'source_copy');assert d['sqlite_primary_code']==19 and d['sqlite_extended_code']==2067
 assert schedule.shard_diagnostics({'shard_diagnostics':[d]})==[d]
 absent=sync._account_error_info(sqlite3.DatabaseError('not logged'),'source_copy');assert absent['sqlite_primary_code']is None and 'sqlite_extended_code'not in absent
 assert 'private'not in json.dumps(d)


def test_old_shard_frame_stays_readable_and_unknown_fields_reject():
 old=dict(stage='source_copy',exception_family='sqlite_database',sqlite_primary_code=None,errno=None)
 assert schedule.shard_diagnostics({'shard_diagnostics':[old]})==[old]
 assert schedule.shard_diagnostics({'shard_diagnostics':[dict(old,operation_phase='private-path')]})==[]


def test_actual_rows_pg_commit_then_real_deadline_guard_rejects(tmp_path,monkeypatch):
 import hashlib
 from pathlib import Path
 from wechat_local.native_deadline import Deadline,activate_deadline
 from wechat_local.native_mirror_store import MirrorError
 source_root=tmp_path/'source';source_root.mkdir();path=source_root/'message_0.db';local=tmp_path/'local.db';table='Msg_'+'d'*32
 ddl='CREATE TABLE '+table+'(local_id INTEGER PRIMARY KEY,server_id INTEGER,local_type INTEGER,create_time INTEGER,real_sender_id INTEGER,message_content TEXT,WCDB_CT_message_content INTEGER)'
 with sqlite3.connect(path)as db:
  db.execute(ddl);db.executemany('INSERT INTO '+table+' VALUES(?,?,?,?,?,?,?)',[(n,n,1,1000,0,'synthetic',0)for n in range(1,801)])
 node=path.stat();identity=[node.st_dev,node.st_ino];header=hashlib.sha256(path.read_bytes()[:16]).hexdigest()
 config=dict(account_id='synthetic-account',source_generation='synthetic-generation');key=SourceKey(config['account_id'],config['source_generation'],path.name,table);store=MirrorStore(local,key);store.ensure_table(key,ddl)
 store.apply_batch(key,table,[],dict(H=800,history=0,tail=800,target=800,source_identity=identity,source_header_sha256=header))
 now=[0.0];deadline=Deadline(dict(wall_until=10.,continuous_start=0,continuous_until=10_000_000_000),wall=lambda:now[0],continuous=lambda:int(now[0]*1e9))
 original=MirrorStore.apply_batch
 def commit_then_expire(*args,**kw):
  value=original(*args,**kw);now[0]=11.;return value
 monkeypatch.setattr(MirrorStore,'apply_batch',commit_then_expire)
 with sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True)as source:
  source.execute('PRAGMA query_only=ON')
  with activate_deadline(deadline),pytest.raises(MirrorError,match='schedule_deadline_expired')as caught:
   sync._account_copy_table(config,source,path,table,store,identity,header,sync._account_budget(config),registry=None,media_username='synthetic',force_history=True)
 detail=sync._account_error_info(caught.value,'source_copy')
 assert detail['operation_phase']=='copy_guard'and detail['commit_state']=='physical_commit_returned'
 with sqlite3.connect(local)as db:
  assert db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]==500
  assert json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()[0])['history']==500
