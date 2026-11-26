"""Versioned observation storage; current registry and complete small history.

Only disk writers attach history. Ordinary snapshots keep their original cap.
Table-list objects are immutable and are never an independent source authority.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import contextlib
import contextvars
import time
from .native_mirror_store import MirrorError

FORMAT='walden.registry.reuse/1'
VALUE=1024*1024
BUCKETS=8
HEX=re.compile('[0-9a-f]{64}\\Z')
GEN=re.compile('[0-9a-f]{32}\\Z')
HISTORY_SQL="CREATE TABLE records(id TEXT PRIMARY KEY CHECK(typeof(id)='text' AND length(id)=64 AND id NOT GLOB '*[^0-9a-f]*'),proof TEXT NOT NULL CHECK(typeof(proof)='text' AND length(CAST(proof AS BLOB))<=1048576 AND json_valid(proof)))"
MEMBERS_SQL='CREATE TABLE history_members(shard TEXT NOT NULL,table_name TEXT NOT NULL,observation TEXT NOT NULL,PRIMARY KEY(shard,table_name))'
HISTORY_TRIGGERS={
    'history_no_update':"CREATE TRIGGER history_no_update BEFORE UPDATE ON records BEGIN SELECT RAISE(ABORT,'history_immutable'); END",
    'history_no_delete':"CREATE TRIGGER history_no_delete BEFORE DELETE ON records BEGIN SELECT RAISE(ABORT,'history_immutable'); END",
    'history_no_replace':"CREATE TRIGGER history_no_replace BEFORE INSERT ON records WHEN EXISTS(SELECT 1 FROM records WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'history_immutable'); END",
}
_reading=contextvars.ContextVar('registry_reuse_objects',default=None)
_attached=contextvars.ContextVar('registry_reuse_attached',default=None)

def _connections():
    value=_attached.get()
    if value is None:value={};_attached.set(value)
    return value

def _connection_id(conn):return id(getattr(conn,'raw',conn))
def forget(conn):_connections().pop(_connection_id(conn),None)

READ_SECONDS=15.

class _Read:
    def __init__(self):self.bytes=0;self.until=time.monotonic()+READ_SECONDS
    def check(self):
        from .native_deadline import check_deadline
        check_deadline()
        fail(time.monotonic()<=self.until,'registry_reuse_read_budget')
    def take(self,size):
        self.check();fail(type(size) is int and 0<=size<=VALUE and self.bytes+size<=16*1024*1024,'registry_reuse_read_budget')
        self.bytes+=size

@contextlib.contextmanager
def reading():
    current=_reading.get()
    if current is not None:
        current.check();yield current;return
    token=_reading.set(_Read())
    try:yield _reading.get()
    finally:_reading.reset(token)

def dump(value):return json.dumps(value,sort_keys=True)
def fail(condition,code='registry_reuse_invalid'):
    if not condition:raise MirrorError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()

def binding(conn):
    rows=conn.execute('SELECT value FROM binding LIMIT 2').fetchall()
    fail(len(rows)==1)
    try:value=json.loads(rows[0][0])
    except (ValueError,TypeError):raise MirrorError('scope_registry_binding') from None
    fail(rows[0][0]==dump(value),'scope_registry_binding')
    return value

def descriptor(config,conn):
    from . import native_scope_contract as sc
    value=binding(conn)
    if value==sc.fixed(config):
        fail(dump(value)==dump(sc.fixed(config)),'scope_registry_binding');return None
    fail(type(value) is dict and value.get('schema')==FORMAT
         and set(value)=={'schema','contract','generation'} and dump(value.get('contract'))==dump(sc.fixed(config))
         and type(value.get('generation')) is str and GEN.fullmatch(value['generation']) is not None,
         'scope_registry_binding')
    return value

def storage_root(config,value):
    from .native_scope_add import directory
    root=Path(config['mirror_root'])/('__walden_registry_'+value['generation'])
    with directory(Path(config['mirror_root'])):pass
    with directory(root):pass
    return root

def validate_history(config,conn,*,_value=None):
    from . import native_scope_contract as sc
    value=descriptor(config,conn) if _value is None else _value
    if value is None:return
    fail(conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='history_members'").fetchall()==[(MEMBERS_SQL,)],'registry_reuse_history_invalid')
    fail(sc.state(conn,'history_ready')=='walden.registry.history/1','registry_reuse_history_invalid')
    counts=sc.state(conn,'history_counts');count=sc.state(conn,'history_members_count')
    fail(type(count) is int and count>=0 and type(counts) is list and len(counts)==BUCKETS
         and all(type(n) is int and n>=0 for n in counts),'registry_reuse_history_invalid')
    root=storage_root(config,value)
    for n in range(BUCKETS):_private(root/(str(n)+'.db'))

def _private(path):
    from .native_scope_contract import _safe
    return _safe(path)

def _read(path):
    from .native_scope_add import directory
    with directory(Path(path).parent) as parent:
        identity=_private(path)
        fd=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    try:
        before=os.fstat(fd);fail(before.st_size<=VALUE,'registry_reuse_value_budget')
        budget=_reading.get()
        if budget is not None:budget.take(before.st_size)
        raw=os.read(fd,VALUE+1);after=os.fstat(fd)
        fail(len(raw)==before.st_size and (before.st_dev,before.st_ino)==identity
             and (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
             ==(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
             and _private(path)==identity,'registry_reuse_object_changed')
        return raw
    finally:os.close(fd)

def _immutable(path,raw):
    from .native_scope_add import create
    fail(len(raw)<=VALUE,'registry_reuse_value_budget')
    try:create(path,raw)
    except FileExistsError:
        fail(_read(path)==raw,'registry_reuse_object_conflict');return
    fail(_read(path)==raw,'registry_reuse_object_changed')

def attached(config,conn,bucket,*,write):
    from . import native_scope_contract as sc
    from .live_readonly import readonly_database_uri
    value=descriptor(config,conn);fail(value is not None)
    root=storage_root(config,value);path=root/(str(bucket)+'.db');identity=_private(path)
    alias='h'+str(bucket)
    current={row[1]:row[2] for row in conn.execute('PRAGMA database_list')}
    if alias not in current:
        uri=str(path) if write else readonly_database_uri(path)
        conn.execute('ATTACH DATABASE ? AS '+alias,(uri,))
        _connections().setdefault(_connection_id(conn),{})[alias]=(str(path),identity)
    else:fail(Path(current[alias])==path,'registry_reuse_archive_changed')
    fail(_connections().get(_connection_id(conn),{}).get(alias)==(str(path),identity),'registry_reuse_archive_changed')
    fail(conn.execute('SELECT value FROM '+alias+'.binding LIMIT 2').fetchall()==[(dump(value),)],'registry_reuse_archive_binding')
    _archive_schema(conn,alias)
    sc._registry_page_size(conn if alias=='main' else _Alias(conn,alias))
    fail(_private(path)==identity,'registry_reuse_archive_changed')
    owner=getattr(conn,'owner',None)
    if owner is not None:owner.admit_cost=_cost(config,value,len(_connections().get(_connection_id(conn),{})))
    return alias,path,identity

class _Alias:
    def __init__(self,conn,alias):self.conn=conn;self.alias=alias
    def execute(self,sql):
        fail(sql in ('PRAGMA page_size','PRAGMA page_count'))
        return self.conn.execute(sql.replace('PRAGMA ','PRAGMA '+self.alias+'.'))

def archive_guard(config,conn):
    """Renewed with the main authority after every physical disk COMMIT."""
    value=descriptor(config,conn)
    if value is None:return
    validate_history(config,conn,_value=value)
    from .native_source_recovery import atomic_preflight
    databases=list(conn.execute('PRAGMA database_list'))
    aliases=[row[1] for row in databases if row[1]!='temp']
    from . import native_scope_contract as sc
    sc._registry_page_size(conn)
    for _,alias,path in databases:
        if re.fullmatch('h[0-7]',alias):
            expected=storage_root(config,value)/(alias[1:]+'.db')
            fail(Path(path)==expected,'registry_reuse_archive_changed')
            fail(_connections().get(_connection_id(conn),{}).get(alias)==(str(expected),_private(expected)),'registry_reuse_archive_changed')
            fail(conn.execute('SELECT value FROM '+alias+'.binding LIMIT 2').fetchall()==[(dump(value),)],'registry_reuse_archive_binding')
            _archive_schema(conn,alias)
            sc._registry_page_size(_Alias(conn,alias))
    # The main must be a real disk database for SQLite's super-journal contract.
    fail(next(row[2] for row in databases if row[1]=='main')!='','registry_reuse_disk_writer_required')
    atomic_preflight(conn,aliases)

def commit(config,conn,*,budget=None):
    if hasattr(conn,'owner'):return conn.commit()
    from . import native_scope_contract as sc
    if descriptor(config,conn) is None:return conn.commit()
    before=sc.query_scope_guard(config);identity=_private(Path(config['mirror_root'])/sc.REGISTRY)
    if budget is not None:
        from .native_account_copy_init import charge
        charge(budget,admission_cost(config,conn))
    archive_guard(config,conn);conn.commit()
    fail(_private(Path(config['mirror_root'])/sc.REGISTRY)==identity,'scope_registry_replaced')
    descriptor(config,conn);archive_guard(config,conn);sc.query_scope_guard(config,before)

def _archive_schema(conn,alias):
    expected={('binding','CREATE TABLE binding(value TEXT NOT NULL)'),('records',HISTORY_SQL)}|set(HISTORY_TRIGGERS.items())
    fail(set(conn.execute('SELECT name,sql FROM '+alias+".sqlite_master WHERE type IN ('table','view','trigger')"))==expected,'registry_reuse_archive_schema')
    fail(conn.execute('PRAGMA '+alias+'.schema_version').fetchone()==(5,),'registry_reuse_archive_schema')

def _cost(config,storage,count):
    from . import native_scope_contract as sc
    if storage is None:return len(dump(sc.fixed(config)).encode())+64
    n=len(dump(storage).encode())
    # Main binding reads plus control/schema/compile-options, and each archive
    # binding/schema/path/mode/size before AND after the physical commit.
    return 4*n+8192+2*count*(n+1536)

def admission_cost(config,conn,*,maximum=False):
    return _cost(config,descriptor(config,conn),BUCKETS if maximum else len(_connections().get(_connection_id(conn),{})))

def _split(config,observation,raw):
    from . import native_scope_contract as sc
    fail(type(observation) is dict and type(observation.get('tables')) is list)
    fail(observation.get('contract')==sc.fixed(config) and sc.SHARD.fullmatch(observation.get('shard','')) is not None
         and type(observation.get('source_identity')) is list and len(observation['source_identity'])==2
         and all(type(n) is int and n>=0 for n in observation['source_identity'])
         and type(observation.get('header')) is str and HEX.fullmatch(observation['header']) is not None and observation.get('query_only') is True)
    tables=observation['tables']
    fail(all(type(pair) is list and len(pair)==2 and sc.TABLE.fullmatch(pair[0]) is not None
             and type(pair[1]) is str and HEX.fullmatch(pair[1]) is not None for pair in tables))
    # Existing registry writers use this exact encoding. Preserve every field,
    # including unknown fields; never silently rewrite a legacy serialized proof.
    fail(raw==dump(observation),'registry_reuse_encoding_unsupported')
    boundary={key:observation[key] for key in ('contract','shard','source_identity','header')}
    payload=dict(boundary=boundary,tables=tables)
    list_raw=dump(payload).encode();reference=sha(list_raw)
    fields={key:value for key,value in observation.items() if key!='tables'}
    record=dump(dict(schema=FORMAT,fields=fields,tables_ref=reference,original_bytes=len(raw.encode()),list_bytes=len(list_raw)))
    fail(len(raw.encode())<=VALUE and len(record.encode())<=VALUE and len(list_raw)<=VALUE,'registry_reuse_value_budget')
    return reference,list_raw,record

def store(config,conn,observation,*,raw=None,budget=None):
    from . import native_scope_contract as sc
    raw=dump(observation) if raw is None else raw;oid=sc.digest(observation)
    value=descriptor(config,conn)
    if value is None:
        conn.execute('INSERT OR IGNORE INTO observations VALUES(?,?)',(oid,raw));return oid
    reference,list_raw,record=_split(config,observation,raw)
    budget=budget or getattr(getattr(conn,'owner',None),'budget',None)
    if budget is not None:
        from .native_account_copy_init import charge
        charge(budget,8*len(observation['tables']))
    new_tables={table for table,_ in observation['tables'] if conn.execute(
        'SELECT 1 FROM history_members WHERE shard=? AND table_name=?',(observation['shard'],table)).fetchone() is None}
    expanded=None
    if new_tables:
        prior=_history_rows(conn,observation['shard'],budget)
        fail(sc.state(conn,'history_digest:'+observation['shard'],_history_digest({}))==_history_digest(prior),'registry_reuse_history_invalid')
        expanded=dict(prior)
        for table in new_tables:expanded[table]=oid
    if budget is not None:
        from .native_account_copy_init import charge
        # Pay all known object/record inputs and outputs before file creation.
        charge(budget,len(list_raw)+3*len(record.encode())
               +sum(len(dump(pair).encode())+128 for pair in observation['tables'])
               +len(dump(value).encode())*2+1024
               +(BUCKETS+2)*(len(os.fsencode(config['mirror_root']))+128))
    alias,_,_=attached(config,conn,int(oid[0],16)%BUCKETS,write=True)
    from .native_source_recovery import atomic_preflight
    atomic_preflight(conn,['main',alias])
    _immutable(storage_root(config,value)/'lists'/(reference+'.json'),list_raw)
    length=conn.execute('SELECT typeof(proof),length(CAST(proof AS BLOB)) FROM '+alias+'.records WHERE id=?',(oid,)).fetchone()
    fail(length is None or length==('text',len(record.encode())),'registry_reuse_observation_conflict')
    existing=None if length is None else conn.execute('SELECT proof FROM '+alias+'.records WHERE id=?',(oid,)).fetchone()
    fail(existing is None or existing==(record,),'registry_reuse_observation_conflict')
    if existing is None:
        conn.execute('INSERT INTO '+alias+'.records VALUES(?,?)',(oid,record))
        counts=sc.state(conn,'history_counts');fail(type(counts) is list and len(counts)==BUCKETS)
        counts[int(oid[0],16)%BUCKETS]+=1;sc.save(conn,'history_counts',counts)
    conn.execute('INSERT OR IGNORE INTO observations VALUES(?,?)',(oid,record))
    count=0
    for pair in observation['tables']:
        cursor=conn.execute('INSERT OR IGNORE INTO history_members VALUES(?,?,?)',(observation['shard'],pair[0],oid))
        count+=cursor.rowcount
    if count:sc.save(conn,'history_members_count',sc.state(conn,'history_members_count')+count)
    if expanded is not None:sc.save(conn,'history_digest:'+observation['shard'],_history_digest(expanded))
    return oid

def observation(config,conn,oid):
    from . import native_scope_contract as sc
    fail(type(oid) is str and HEX.fullmatch(oid) is not None,'scope_member_proof')
    row=conn.execute('SELECT proof FROM observations WHERE id=?',(oid,)).fetchone()
    fail(row is not None,'scope_member_proof')
    value=json.loads(row[0]);storage=descriptor(config,conn)
    if storage is None:return value
    fail(type(value) is dict and value.get('schema')==FORMAT and type(value.get('fields')) is dict)
    reference=value.get('tables_ref');fail(type(reference) is str and HEX.fullmatch(reference) is not None)
    path=storage_root(config,storage)/'lists'/(reference+'.json')
    fail(path.lstat().st_size==value.get('list_bytes'),'registry_reuse_object_changed')
    budget=_reading.get()
    if budget is not None:budget.take(len(row[0].encode()))
    raw=_read(path)
    fail(sha(raw)==reference,'registry_reuse_object_changed')
    payload=json.loads(raw);result=dict(value['fields']);result['tables']=payload.get('tables')
    boundary={key:result.get(key) for key in ('contract','shard','source_identity','header')}
    fail(payload.get('boundary')==boundary and type(result['tables']) is list)
    canonical=dump(result)
    fail(sc.digest(result)==oid and len(canonical.encode())==value.get('original_bytes') and len(raw)==value.get('list_bytes'),'scope_member_proof')
    if budget is not None:budget.check()
    return result

def observation_size(config,conn,oid):
    """Actual wrapper/list input bytes; all size facts rechecked at use."""
    if descriptor(config,conn) is None:
        row=conn.execute('SELECT length(CAST(proof AS BLOB)) FROM observations WHERE id=?',(oid,)).fetchone()
        return None if row is None else row[0]
    row=conn.execute("SELECT length(CAST(proof AS BLOB)),json_extract(proof,'$.list_bytes') FROM observations WHERE id=?",(oid,)).fetchone()
    if row is None:return None
    fail(type(row[1]) is int and 0<=row[1]<=VALUE,'registry_reuse_value_budget')
    return row[0]+row[1]

def prune(config,conn):
    if descriptor(config,conn) is not None:
        conn.execute("DELETE FROM observations WHERE id NOT IN (SELECT json_extract(proof,'$.observation') FROM members)")

def _history_digest(rows):
    return sha(dump(sorted(rows.items())).encode())

def _history_rows(conn,shard,budget=None):
    from . import native_scope_contract as sc
    result={}
    for table,oid in conn.execute('SELECT table_name,observation FROM history_members WHERE shard=? ORDER BY table_name',(shard,)):
        fail(type(table) is str and sc.TABLE.fullmatch(table) is not None
             and type(oid) is str and HEX.fullmatch(oid) is not None,'registry_reuse_history_invalid')
        if budget is not None:
            from .native_account_copy_init import charge
            from .native_account_witness import WorkBudgetStop
            if time.monotonic()>=budget['until']:raise WorkBudgetStop('registry_reuse_history_deferred',budget_kind='source_ms',limit=20000,used=max(0,int((time.monotonic()-budget.get('started',budget['until']-20))*1000)))
            charge(budget,len(table.encode())+len(oid.encode()))
        result[table]=oid
    return result

def seen(config,conn,shard,table,budget=None):
    from . import native_scope_contract as sc
    if descriptor(config,conn) is None:return None
    validate_history(config,conn)
    fail(conn.execute('SELECT COUNT(*) FROM history_members').fetchone()[0]==sc.state(conn,'history_members_count'),'registry_reuse_history_invalid')
    rows=_history_rows(conn,shard,budget)
    fail(sc.state(conn,'history_digest:'+shard,_history_digest({}))==_history_digest(rows),'registry_reuse_history_invalid')
    counts=sc.state(conn,'history_counts');fail(type(counts) is list and len(counts)==BUCKETS,'registry_reuse_history_invalid')
    for bucket in range(BUCKETS):
        alias,_,_=attached(config,conn,bucket,write=True)
        if budget is not None:
            from .native_account_copy_init import charge
            charge(budget,len(dump(descriptor(config,conn)).encode())+32)
        fail(conn.execute('SELECT COUNT(*) FROM '+alias+'.records').fetchone()[0]==counts[bucket],'registry_reuse_history_invalid')
    return table in rows
