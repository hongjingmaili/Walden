"""Actual local SQLite transactions, including writers outside Walden's flock."""
from pathlib import Path
import sqlite3,time
import pytest
from wechat_local.native_account_witness import AccountWitness,WorkChanged


def setup(tmp_path):
    p=tmp_path/'synthetic.db'
    with sqlite3.connect(p) as db:db.execute('CREATE TABLE value(id INTEGER PRIMARY KEY,n INTEGER)');db.execute('INSERT INTO value VALUES(1,1)')
    p.chmod(0o600)
    budget=dict(until=time.monotonic()+20,tail_probe=dict(bytes=0))
    owner=AccountWitness(tmp_path,budget);owner.seed(p,owner.pin(p));return p,owner


@pytest.mark.parametrize('sql',[
    'SELECT * FROM value','UPDATE value SET n=n WHERE id=1',
    'INSERT OR IGNORE INTO value VALUES(1,1)',
    'CREATE TABLE IF NOT EXISTS value(id INTEGER PRIMARY KEY,n INTEGER)',
    'UPDATE value SET n=n+1 WHERE id=1','CREATE INDEX value_n ON value(n)',
])
def test_own_read_noop_dml_and_ddl_have_proven_same_connection_chain(tmp_path,sql):
    p,owner=setup(tmp_path)
    with owner.connect(p) as db:db.execute(sql).fetchall()
    assert owner.changed is None and owner.transactions==1
    owner.compare_all();assert owner.budget['tail_probe']['bytes']<1048576


def test_foreign_commit_before_own_transaction_is_rejected(tmp_path):
    p,owner=setup(tmp_path)
    with sqlite3.connect(p) as external:external.execute('UPDATE value SET n=n+1')
    with pytest.raises(WorkChanged):owner.connect(p)
    assert owner.changed=='local_commit'


@pytest.mark.parametrize('sql',['UPDATE value SET n=n WHERE id=1','INSERT OR IGNORE INTO value VALUES(1,1)','SELECT * FROM value'])
def test_foreign_commit_after_own_commit_before_pin_cannot_masquerade_as_own_plus_one(tmp_path,sql):
    p,owner=setup(tmp_path);lease=owner.connect(p);raw=lease.raw
    class Gap:
        def __getattr__(self,name):return getattr(raw,name)
        def commit(self):
            raw.commit()
            with sqlite3.connect(p) as external:external.execute('UPDATE value SET n=n+1')
    lease.raw=Gap()
    with pytest.raises(WorkChanged):
        with lease as db:db.execute(sql).fetchall()
    assert owner.changed=='foreign_commit'


def test_sqlite_reservation_rejects_foreign_writer_without_walden_lock(tmp_path):
    p,owner=setup(tmp_path)
    with owner.connect(p) as db:
        with sqlite3.connect(p,timeout=0) as external:
            with pytest.raises(sqlite3.OperationalError):external.execute('UPDATE value SET n=n+1')
        db.execute('UPDATE value SET n=n+1')
    assert owner.changed is None


def test_rollback_never_renews_a_certificate(tmp_path):
    p,owner=setup(tmp_path);before=owner.expected[str(p)].copy()
    with pytest.raises(RuntimeError):
        with owner.connect(p) as db:db.execute('UPDATE value SET n=2');raise RuntimeError('synthetic transaction abort')
    assert owner.changed=='rollback' and owner.expected[str(p)]==before
    with sqlite3.connect(p) as db:assert db.execute('SELECT n FROM value').fetchone()==(1,)


@pytest.mark.parametrize('pragma',["journal_mode=WAL","locking_mode=EXCLUSIVE"])
def test_unsupported_sqlite_mode_is_not_forced_into_acceptance(tmp_path,pragma):
    p,owner=setup(tmp_path);raw=sqlite3.connect(p);raw.execute('PRAGMA '+pragma).fetchall()
    try:
        with pytest.raises(WorkChanged):owner.registry(p,raw)
        assert owner.changed=='mode'
    finally:raw.close()


def test_expired_deadline_and_metadata_exhaustion_stop_witness_reads(tmp_path):
    p,owner=setup(tmp_path);owner.budget['tail_probe']['bytes']=1048576
    with pytest.raises(WorkChanged):owner.connect(p)
    assert owner.changed=='witness_budget'
    owner=AccountWitness(tmp_path,dict(until=time.monotonic()-1,tail_probe=dict(bytes=0)))
    with pytest.raises(WorkChanged):owner.pin(p)


def test_registry_publication_counter_only_accepts_a_known_changed_payload(tmp_path):
    p,owner=setup(tmp_path);raw=sqlite3.connect(p);lease=owner.registry(p,raw)
    try:
        lease.publication=(lease.before['counter']+1)%(1<<32);lease.execute('UPDATE value SET n=n+1');lease.commit()
        assert owner.changed is None
        lease.publication=(lease.before['counter']+1)%(1<<32);lease.execute('INSERT OR IGNORE INTO value VALUES(1,1)')
        with pytest.raises(WorkChanged):lease.commit()
        assert owner.changed=='publication'
    finally:raw.close()


# Real initial-reservation admission regression from independent r2 review.
import json,sqlite3
from pathlib import Path
import pytest
from test_incremental_history_work import Driver,seed,warm,count_history,work_state
from test_account_sync_status import item
from wechat_local import native_mirror_sync as sync,native_account_witness as aw

@pytest.mark.parametrize('kind',['trigger','binding'])
def test_registry_authorization_is_rechecked_under_begin_immediate_before_writes(item,monkeypatch,kind):
 seed(item,count=12);d=Driver(item)
 try:
  warm(d);assert work_state(item)['ready'];original=aw.AccountWitness.registry;injected=[]
  def admit(owner,path,raw):
   if not injected:
    injected.append(True)
    # Exact window after initial registry binding/trigger checks, before new SQLite reservation.
    with sqlite3.connect(path) as external:
     if kind=='trigger':external.execute('CREATE TRIGGER foreign_state_write AFTER INSERT ON state BEGIN SELECT 1; END')
     else:external.execute('UPDATE binding SET value=?',(json.dumps(dict(foreign=True)),))
   return original(owner,path,raw)
  monkeypatch.setattr(aw.AccountWitness,'registry',admit);before=count_history(item)
  error=None;result=None
  try:result=d.round()
  except sync.MirrorError as e:error=str(e)
  print(json.dumps(dict(kind=kind,error=error,history_added=count_history(item)-before,gaps=None if result is None else result['gaps'])))
  assert error in ('local_trigger_unsupported','scope_registry_binding')
  assert count_history(item)==before
 finally:d.close()

@pytest.mark.parametrize('kind',['foreign_commit','wal'])
def test_initial_optional_registry_witness_mismatch_keeps_guarded_reconciliation(item,monkeypatch,kind):
 seed(item,count=300);d=Driver(item)
 try:
  warm(d);assert work_state(item)['ready'];original=aw.AccountWitness.registry;injected=[]
  def admit(owner,path,raw):
   if not injected:
    injected.append(True)
    with sqlite3.connect(path) as external:
     if kind=='wal':external.execute('PRAGMA journal_mode=WAL')
     else:external.execute("UPDATE state SET value=value||' ' WHERE key='account_work'")
   return original(owner,path,raw)
  monkeypatch.setattr(aw.AccountWitness,'registry',admit)
  value=d.round()
  assert value['gaps']==[] and not value['new_tail']['incremental_work_ready']
  assert value['follow_observation']['complete'] is False
 finally:d.close()


# r3 mandatory admission / optional witness boundary.
import json,sqlite3
from pathlib import Path
import pytest
from test_incremental_history_work import Driver,seed,warm,count_history,work_state
from test_account_sync_status import item
from wechat_local import native_mirror_sync as sync,native_scope_contract as sc

@pytest.mark.parametrize('kind',['missing_coverage','wal_fallback'])
def test_optional_cache_absence_does_not_drop_registry_authority_reservation(item,monkeypatch,kind):
 seed(item,count=12);d=Driver(item);attempted=[];blocked=[];original=sync._require_trigger_free;commit=sync._account_registry_commit
 try:
  warm(d);assert work_state(item)['ready'];registry=Path(item['mirror_root'])/sc.REGISTRY
  def inject():
   attempted.append(True)
   try:
    with sqlite3.connect(registry,timeout=0) as external:external.execute('CREATE TRIGGER cache_fallback_foreign AFTER INSERT ON state BEGIN SELECT 1; END')
   except sqlite3.OperationalError:blocked.append(True)
  if kind=='missing_coverage':
   value=d.store.read('instance.'+d.operation+'.json');value['shard_hints'].pop('coverage_version');d.store.atomic('instance.'+d.operation+'.json',value)
   def checked(conn,alias):
    result=original(conn,alias)
    if not attempted:inject()
    return result
   monkeypatch.setattr(sync,'_require_trigger_free',checked)
  else:
   with sqlite3.connect(registry) as external:external.execute('PRAGMA journal_mode=WAL')
   def committed(conn):
    result=commit(conn)
    if not attempted:inject()
    return result
   monkeypatch.setattr(sync,'_account_registry_commit',committed)
  before=count_history(item);error=None;result=None
  try:result=d.round()
  except sync.MirrorError as e:error=str(e)
  print(json.dumps(dict(kind=kind,error=error,history_added=count_history(item)-before,blocked=bool(blocked),attempted=bool(attempted),gaps=None if result is None else result['gaps'])))
  assert attempted
  assert blocked or error=='local_trigger_unsupported'
  if not blocked:assert count_history(item)==before
 finally:d.close()

@pytest.mark.parametrize('terminal',['ordinary','revoked','expired','cap'])
def test_source_body_expiry_keeps_only_bounded_guarded_local_finalization(item,monkeypatch,terminal):
 seed(item,count=12);d=Driver(item)
 try:
  warm(d);original=sync._account_copy_table
  from wechat_local import native_follow_grant as fg
  from wechat_local.native_follow_policy import Store
  def validate(grant):
   store=Store(grant['store_root']);fg._enabled_intent(store,grant);fg._instance_runtime(store,grant)
  monkeypatch.setattr(fg,'validate',validate)
  after_body=[];seen=[]
  def run(value):
   def factory(path):
    db=sqlite3.connect(value['source_db']);db.execute('PRAGMA query_only=ON')
    db.set_trace_callback(lambda sql:seen.append(sql) if after_body and sql.lstrip().upper().startswith(('SELECT','PRAGMA')) else None)
    return db
   return sync._account_sync(value['config'],connection_factory=factory)
  # Exercise H, then stop the Source body exactly after the committed batch.
  def stop_body(*args,**kwargs):
   value=original(*args,**kwargs)
   if not after_body:
    after_body.append(True);args[7]['until']=time.monotonic()-1
    if terminal=='revoked':d.store.atomic('intent.json',dict(enabled=False,generation=d.policy))
    elif terminal=='expired':
     from wechat_local import native_deadline as nd
     nd._current.get().facts['wall_until']=-1
    elif terminal=='cap':args[7]['tail_probe']['bytes']=1048576
   return value
  import test_account_sync_status as f
  monkeypatch.setattr(f.fixture,'run_full_account_sync',run);monkeypatch.setattr(sync,'_account_copy_table',stop_body)
  if terminal=='ordinary':
   result=d.round();assert result['gaps']==[] and result['new_tail']['incremental_work_ready'] is False
   assert result['follow_observation']['complete'] is False
   assert result['new_tail']['metadata_bytes']<=1048576
  else:
   expected={'revoked':'follow_revoked','expired':'schedule_deadline_expired','cap':'account_work_changed'}[terminal]
   with pytest.raises(sync.MirrorError,match=expected):d.round()
  assert after_body and not seen
 finally:d.close()
