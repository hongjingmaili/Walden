"""Explicit, bounded streaming conversion of an existing account registry.

The serializer also accepts a read-only frozen input and private output. That
does not rebind its logical contract or make the output a deployed mirror.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid
import ctypes
import sys
import contextvars
import functools
from collections import OrderedDict
from . import native_registry_reuse as reuse
from .native_mirror_store import MirrorError

ROWS=65536
BYTES=128*1024*1024
SECONDS=60.
_until=contextvars.ContextVar('registry_migration_until',default=None)

def _clock():
    from .native_deadline import check_deadline
    check_deadline();until=_until.get()
    reuse.fail(until is None or time.monotonic()<until,'registry_migration_budget')

def _bounded(function):
    @functools.wraps(function)
    def run(*args,**kwargs):
        previous=_until.get();limit=time.monotonic()+120.
        token=_until.set(min(previous,limit) if previous is not None else limit)
        try:_clock();return function(*args,**kwargs)
        finally:_until.reset(token)
    return run

class _Budget:
    def __init__(self):self.until=time.monotonic()+SECONDS;self.bytes=0;self.rows=0
    def check(self):
        _clock()
        reuse.fail(time.monotonic()<self.until,'registry_migration_budget')
    def take(self,n):
        self.check();self.rows+=1;self.bytes+=n
        reuse.fail(self.rows<=ROWS and self.bytes<=BYTES,'registry_migration_budget')

def _encoding(db):
    value=db.execute('PRAGMA encoding').fetchone()[0]
    reuse.fail(value in ('UTF-8','UTF-16le','UTF-16be'),'registry_migration_encoding_unsupported')
    return 1 if value=='UTF-8' else 2

def _rows(db,table,columns,budget):
    """Only integer rowid traversal; size headers precede value materialization."""
    factor=_encoding(db);names=','.join(columns)
    headers=','.join('typeof('+name+'),octet_length('+name+')' for name in columns)
    for row in db.execute('SELECT rowid,'+headers+' FROM '+table+' NOT INDEXED ORDER BY rowid'):
        budget.check()
        for kind,size in zip(row[1::2],row[2::2]):
            reuse.fail(kind=='text' and type(size) is int and 0<=factor*size<=reuse.VALUE,'registry_migration_value_invalid')
        budget.take(factor*sum(row[2::2]))
        values=db.execute('SELECT '+names+' FROM '+table+' WHERE rowid=?',(row[0],)).fetchone()
        reuse.fail(values is not None and all(type(value) is str for value in values),'registry_migration_value_invalid')
        reuse.fail(all(len(value.encode())<=factor*size for value,size in zip(values,row[2::2])),'registry_migration_value_invalid')
        yield values

def _create(path):
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
    return sqlite3.connect(str(path),timeout=.1)

def _mode(db):
    db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=FULL')

def preflight(db):
    """No writes or text-index comparison before all legacy value headers fit."""
    budget=_Budget();factor=_encoding(db)
    try:db.execute("SELECT octet_length('')").fetchone()
    except sqlite3.Error:raise MirrorError('registry_migration_sqlite_unsupported') from None
    reuse.fail({row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}=={'binding','state','members','observations'},'scope_registry_schema')
    specifications=[('binding',[('value',reuse.VALUE)]),('state',[('key',1024),('value',reuse.VALUE)]),
                    ('members',[('shard',128),('table_name',36),('proof',reuse.VALUE)]),
                    ('observations',[('id',64),('proof',reuse.VALUE)])]
    for table,columns in specifications:
        headers=','.join('typeof('+name+'),octet_length('+name+')' for name,_ in columns)
        for row in db.execute('SELECT '+headers+' FROM '+table+' NOT INDEXED ORDER BY rowid'):
            budget.check()
            for (name,maximum),kind,size in zip(columns,row[::2],row[1::2]):
                limit=maximum if maximum==reuse.VALUE else maximum*factor
                reuse.fail(kind=='text' and type(size) is int and 0<=size<=limit
                           and factor*size<=reuse.VALUE,'registry_migration_value_invalid')
            budget.take(factor*sum(row[1::2]))
    return dict(rows=budget.rows,bytes=budget.bytes)

def build(config,source,output,*,generation=None):
    """Unpublished private output only; no Source, profile, or message writes."""
    from . import native_scope_contract as sc
    budget=_Budget();output=Path(output)
    reuse.fail(output.is_dir() and not any(output.iterdir()),'registry_migration_output_not_empty')
    try:source.execute("SELECT octet_length('')").fetchone()
    except sqlite3.Error:raise MirrorError('registry_migration_sqlite_unsupported') from None
    expected=reuse.dump(sc.fixed(config))
    reuse.fail(source.execute('SELECT value FROM binding LIMIT 2').fetchall()==[(expected,)],'scope_registry_binding')
    reuse.fail(source.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' LIMIT 1").fetchone() is None,'scope_registry_schema')
    value=dict(schema=reuse.FORMAT,contract=sc.fixed(config),generation=generation or uuid.uuid4().hex)
    reuse.fail(reuse.GEN.fullmatch(value['generation']) is not None)
    data=output;(data/'lists').mkdir(mode=0o700)
    main=output/'main.db';db=_create(main);_mode(db)
    counts=[0]*reuse.BUCKETS;history={};references=set();found=set();objects={};obs_count=0
    current_checks=[];state_bytes={};current_observation_bytes={}
    raw_hashes=[hashlib.sha256() for _ in range(reuse.BUCKETS)];old_text_hashes={}
    try:
        db.executescript('CREATE TABLE binding(value TEXT NOT NULL);CREATE TABLE observations(id TEXT PRIMARY KEY,proof TEXT NOT NULL);'
            'CREATE TABLE members(shard TEXT,table_name TEXT,proof TEXT NOT NULL,PRIMARY KEY(shard,table_name));'
            'CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT NOT NULL);'+reuse.MEMBERS_SQL+';')
        db.execute('INSERT INTO binding VALUES(?)',(reuse.dump(value),));db.commit()
        for bucket in range(reuse.BUCKETS):
            path=data/(str(bucket)+'.db');archive=_create(path)
            try:
                _mode(archive);archive.execute('CREATE TABLE binding(value TEXT NOT NULL)');archive.execute(reuse.HISTORY_SQL)
                for sql in reuse.HISTORY_TRIGGERS.values():archive.execute(sql)
                archive.execute('INSERT INTO binding VALUES(?)',(reuse.dump(value),));archive.commit()
            finally:archive.close()
            db.execute('ATTACH DATABASE ? AS h'+str(bucket),(str(path),))
        from .native_source_recovery import atomic_preflight
        atomic_preflight(db,['main']+['h'+str(n) for n in range(reuse.BUCKETS)])
        db.execute('BEGIN IMMEDIATE')
        for key,raw in _rows(source,'state',['key','value'],budget):
            reuse.fail(key not in ('history_counts','history_members_count') and not key.startswith('history_digest:'),'registry_migration_state_conflict')
            json.loads(raw);db.execute('INSERT INTO state VALUES(?,?)',(key,raw));state_bytes[key]=len(raw.encode())
        for shard,table,raw in _rows(source,'members',['shard','table_name','proof'],budget):
            proof=json.loads(raw)
            reuse.fail(sc.SHARD.fullmatch(shard) is not None and sc.TABLE.fullmatch(table) is not None
                       and type(proof) is dict and reuse.HEX.fullmatch(proof.get('observation','')) is not None,'scope_member_proof')
            references.add(proof['observation']);current_checks.append((shard,table,proof['observation'],len(raw.encode())))
            db.execute('INSERT INTO members VALUES(?,?,?)',(shard,table,raw))
        for oid,raw in _rows(source,'observations',['id','proof'],budget):
            reuse.fail(reuse.HEX.fullmatch(oid) is not None,'scope_member_proof')
            observation=json.loads(raw)
            reuse.fail(sc.digest(observation)==oid,'scope_member_proof')
            reference,payload,record=reuse._split(config,observation,raw)
            if reference not in objects:
                reuse._immutable(data/'lists'/(reference+'.json'),payload);objects[reference]=len(payload)
            bucket=int(oid[0],16)%reuse.BUCKETS
            db.execute('INSERT INTO h'+str(bucket)+'.records VALUES(?,?)',(oid,record));counts[bucket]+=1
            if oid in references:
                db.execute('INSERT INTO observations VALUES(?,?)',(oid,record));found.add(oid);current_observation_bytes[oid]=len(raw.encode())
            for table,_ in observation['tables']:
                history.setdefault((observation['shard'],table),oid)
            reuse.fail(len(history)<=ROWS,'registry_migration_budget')
            raw_hashes[bucket].update(oid.encode()+b'\0'+raw.encode()+b'\0');obs_count+=1
            old_text_hashes[oid]=reuse.sha(raw.encode())
        reuse.fail(references==found,'scope_member_proof')
        # Validate original member authority inside the same frozen source read.
        # Every legacy observation key/value has already passed the bounded scan.
        validated=OrderedDict()
        for shard,table,oid,size in current_checks:
            budget.take(size+state_bytes.get('shard_anchor:'+shard,0))
            if oid not in validated:budget.take(current_observation_bytes[oid]+len(expected.encode()))
            sc.member(config,source,shard,table,_observations=validated)
            budget.check()
        db.executemany('INSERT INTO history_members VALUES(?,?,?)',[(shard,table,oid) for (shard,table),oid in history.items()])
        for shard in {key[0] for key in history}:
            sc.save(db,'history_digest:'+shard,reuse._history_digest({table:oid for (name,table),oid in history.items() if name==shard}))
        sc.save(db,'history_counts',counts);sc.save(db,'history_members_count',len(history))
        sc.save(db,'history_ready','walden.registry.history/1')
        for alias in ['main']+['h'+str(n) for n in range(reuse.BUCKETS)]:sc._registry_page_size(db if alias=='main' else reuse._Alias(db,alias))
        budget.check();db.commit()
        for reference in objects:
            budget.check();reuse.fail(reuse.sha(reuse._read(data/'lists'/(reference+'.json')))==reference,'registry_reuse_object_changed')
        # The second pass reads the compact output, not the old input again.
        # Group by the immutable list reference. The old temporal order may
        # interleave more lists than the small LRU; rereading that order would
        # waste the same bounded input allowance on repeated identical objects.
        # Per-ID text hashes prove exact old bytes without retaining old texts.
        verify_bytes=0;restored_count=0;cache=OrderedDict()
        for bucket in range(reuse.BUCKETS):
            for oid,record in db.execute("SELECT id,proof FROM h"+str(bucket)+".records NOT INDEXED ORDER BY json_extract(proof,'$.tables_ref'),rowid"):
                budget.check();verify_bytes+=len(oid.encode())+len(record.encode())
                entry=json.loads(record);reference=entry['tables_ref'];payload=cache.get(reference)
                if payload is None:
                    raw=reuse._read(data/'lists'/(reference+'.json'));verify_bytes+=len(raw)
                    reuse.fail(reuse.sha(raw)==reference,'registry_reuse_object_changed')
                    payload=json.loads(raw)
                    if len(cache)==32:cache.popitem(last=False)
                    cache[reference]=payload
                else:cache.move_to_end(reference)
                reuse.fail(verify_bytes<=BYTES,'registry_migration_budget')
                observation=dict(entry['fields'],tables=payload['tables']);text=reuse.dump(observation)
                reuse.fail(sc.digest(observation)==oid,'registry_migration_restore_failed')
                reuse.fail(old_text_hashes.pop(oid,None)==reuse.sha(text.encode()),'registry_migration_restore_failed')
                restored_count+=1
        reuse.fail(restored_count==obs_count and not old_text_hashes,'registry_migration_restore_failed')
        budget.check()
        result=dict(schema='walden.registry.build/1',generation=value['generation'],observations=obs_count,
                    current_observations=len(found),historical_members=len(history),lists=len(objects),list_bytes=sum(objects.values()),
                    original_bucket_sha256=[h.hexdigest() for h in raw_hashes],exact_old_texts_restored=restored_count,input_materialized_bytes=budget.bytes,
                    verification_materialized_bytes=verify_bytes,input_rows=budget.rows,
                    seconds=SECONDS-(budget.until-time.monotonic()),source_opens=0)
    finally:db.close()
    result['files']={str(path.relative_to(output)):file_hash(path,budget) for path in output.rglob('*') if path.is_file()}
    reuse._immutable(output/'build.json',(reuse.dump(result)+'\n').encode())
    return result

def file_hash(path,budget=None):
    from .native_scope_add import directory
    h=hashlib.sha256()
    with directory(Path(path).parent) as parent:
        reuse._private(path)
        fd=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
    try:
        before=os.fstat(fd)
        while True:
            _clock()
            if budget is not None:budget.check()
            raw=os.read(fd,1024*1024)
            if not raw:break
            h.update(raw)
        after=os.fstat(fd)
        reuse.fail((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
                   ==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'registry_migration_file_changed')
    finally:os.close(fd)
    return h.hexdigest()

PENDING='.registry-reuse.pending.json'
RETRY='.registry-reuse.retry.json'

def _info(path):
    from .native_scope_contract import _safe
    value=Path(path).lstat();_safe(path)
    return [value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns]

def _directory_info(path):
    import stat
    value=Path(path).lstat()
    reuse.fail(stat.S_ISDIR(value.st_mode) and stat.S_IMODE(value.st_mode)==0o700 and value.st_uid==os.getuid(),'registry_migration_stage_invalid')
    return [value.st_dev,value.st_ino,value.st_uid]

def _rename(source,destination,*,exchange=False):
    """Public kernel swap/no-replace; preserve either target at every race."""
    from .native_scope_add import directory
    _clock()
    lib=ctypes.CDLL(None,use_errno=True)
    if sys.platform=='darwin':fn=lib.renameatx_np;flag=2 if exchange else 4
    elif hasattr(lib,'renameat2'):fn=lib.renameat2;flag=2 if exchange else 1
    else:raise MirrorError('registry_migration_atomic_unavailable')
    fn.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    with directory(Path(source).parent) as src,directory(Path(destination).parent) as dst:
        if fn(src,os.fsencode(Path(source).name),dst,os.fsencode(Path(destination).name),flag):
            raise OSError(ctypes.get_errno(),'registry_migration_rename_failed')
        os.fsync(src);os.fsync(dst)
    _clock()

def _quiet(path):
    reuse.fail(not any(os.path.lexists(str(path)+suffix) for suffix in ('-journal','-wal','-shm')),'registry_migration_journal_present')

def _verify_build(directory,result):
    _manifest(result)
    expected=set(result['files'])|{'build.json','seal.json'}
    actual={str(path.relative_to(directory)) for path in directory.rglob('*') if path.is_file()}
    reuse.fail(actual==expected,'registry_migration_stage_changed')
    for name,expected_hash in result['files'].items():
        path=directory/name
        reuse.fail(not path.is_symlink() and file_hash(path)==expected_hash,'registry_migration_stage_changed')

def _manifest(result):
    import re
    reuse.fail(type(result) is dict and type(result.get('files')) is dict
               and all(type(name) is str and re.fullmatch(r'(?:main\.db|[0-7]\.db|lists/[0-9a-f]{64}\.json)',name)
                       and type(h) is str and reuse.HEX.fullmatch(h) for name,h in result['files'].items()),'registry_migration_stage_changed')
    reuse.fail({'main.db'}|{str(n)+'.db' for n in range(reuse.BUCKETS)}<=set(result['files']),'registry_migration_stage_changed')

def _seal(stage,journal,result):
    from .native_scope_add import directory
    path=stage/'seal.json'
    with directory(stage) as parent:
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        own=os.fstat(fd)
        value=dict(schema='walden.registry.seal/1',generation=journal['generation'],
                   old_sha256=journal['old_sha256'],stage_identity=_directory_info(stage),
                   seal_identity=[own.st_dev,own.st_ino,own.st_uid],build_sha256=file_hash(stage/'build.json'),
                   identities={name:_info(stage/name)[:2] for name in result['files']})
        raw=(reuse.dump(value)+'\n').encode()
        reuse.fail(len(raw)<=4*1024*1024,'registry_migration_manifest_budget')
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.fsync(parent)

def _verify_seal(stage,journal,result,*,published=False):
    from .native_scope_add import read
    _manifest(result)
    raw,fact=read(stage/'seal.json');value=json.loads(raw)
    own=fact['stat']
    reuse.fail(type(value) is dict and value.get('schema')=='walden.registry.seal/1'
               and value.get('generation')==journal['generation'] and value.get('old_sha256')==journal['old_sha256']
               and value.get('stage_identity')==_directory_info(stage)
               and value.get('seal_identity')==[own['dev'],own['ino'],own['uid']]
               and value.get('build_sha256')==file_hash(stage/'build.json')
               and type(value.get('identities')) is dict and set(value['identities'])==set(result['files']),'registry_migration_seal_changed')
    for name,expected in value['identities'].items():
        if published and name=='main.db':continue
        reuse.fail(_info(stage/name)[:2]==expected and file_hash(stage/name)==result['files'][name],'registry_migration_stage_changed')
    return value

def _resume_build(config,path,journal,stage):
    from .live_readonly import readonly_database_uri
    reuse.fail(_info(path)==journal['old_identity'] and file_hash(path)==journal['old_sha256'],'registry_migration_source_changed')
    _quiet(path)
    db=sqlite3.connect(readonly_database_uri(path),uri=True,timeout=.1)
    try:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN');preflight(db)
        result=build(config,db,stage,generation=journal['generation'])
        reuse.fail(_info(path)==journal['old_identity'] and file_hash(path)==journal['old_sha256'],'registry_migration_source_changed')
        _seal(stage,journal,result)
        return result
    finally:db.close()

def _profile(config,profile,expected=None):
    """Pin the actual private profile, not only a caller's loaded dictionary."""
    from .native_scope_add import read
    from .native_follow_policy import digest
    raw,fact=read(profile)
    try:value=json.loads(raw)
    except (ValueError,TypeError):raise MirrorError('registry_migration_profile_changed') from None
    reuse.fail(type(value) is dict and digest(value)==digest(config),'registry_migration_profile_changed')
    fact=dict(fact,path=str(Path(profile).absolute()))
    reuse.fail(expected is None or fact==expected,'registry_migration_profile_changed')
    return fact

@_bounded
def migrate(config,profile,*,confirmed=False,expected_source_sha256=None,_checkpoint=lambda name:None):
    """One explicit local storage conversion; never opens Source or services."""
    from . import native_scope_contract as sc
    from .native_scope_add import create,encoded,read
    from .native_mirror_sync import writer_lock
    from .native_follow_policy import digest,Store,default_root
    from .live_readonly import readonly_database_uri
    reuse.fail(sc.mode(config)=='account','account_scope_required')
    root=Path(config['mirror_root']);path=root/sc.REGISTRY
    profile_fact=_profile(config,profile)
    before=sc.query_scope_guard(config)
    # A compatible current generation needs no storage mutation, and remains
    # usable during an already-enabled repeated setup.
    if not any((root/name).exists() or (root/name).is_symlink() for name in (PENDING,RETRY)):
        identity=_info(path)
        probe=sqlite3.connect(readonly_database_uri(path),uri=True,timeout=.1)
        try:
            probe.execute('PRAGMA query_only=ON');probe.execute('BEGIN')
            current=reuse.descriptor(config,probe)
            if current is not None:
                reuse.validate_history(config,probe)
                sc._registry_page_size(probe)
                reuse.fail(_info(path)==identity,'scope_registry_replaced');sc.query_scope_guard(config,before)
                _profile(config,profile,profile_fact)
                return dict(status='preserved_existing_registry',generation=current['generation'],source_opens=0,local_message_mutated=False)
        finally:probe.close()
    reuse.fail(not (Store(default_root(profile)).read('intent.json') or {}).get('enabled'),'registry_migration_stop_required')
    if not confirmed:
        return dict(status='confirmation_required',source_sha256=digest(config),source_opens=0,local_message_mutated=False)
    reuse.fail(expected_source_sha256==digest(config),'registry_migration_confirmation_required')
    sc._safe(root/'.writer.lock')
    with writer_lock(root,0):
        sc.query_scope_guard(config,before)
        pending=root/PENDING
        if pending.exists() or pending.is_symlink():
            raw,_=read(pending);journal=json.loads(raw)
            reuse.fail(type(journal) is dict and journal.get('schema')=='walden.registry.pending/1'
                and journal.get('contract')==sc.fixed(config) and journal.get('config_sha256')==digest(config)
                and journal.get('profile')==profile_fact
                and type(journal.get('generation')) is str and reuse.GEN.fullmatch(journal['generation']) is not None
                and type(journal.get('old_identity')) is list and len(journal['old_identity'])==4
                and all(type(n) is int and n>=0 for n in journal['old_identity'])
                and type(journal.get('stage_identity')) is list and len(journal['stage_identity'])==3
                and all(type(n) is int and n>=0 for n in journal['stage_identity'])
                and type(journal.get('old_sha256')) is str and reuse.HEX.fullmatch(journal['old_sha256']) is not None,'registry_migration_pending_invalid')
            reuse.fail(journal.get('root_identity')==_directory_info(root),'registry_migration_root_changed')
            original_stage=root/('.registry-reuse-stage-'+journal['generation'])
            stage=original_stage
            published=root/('__walden_registry_'+journal['generation'])
            retry=None
            retry_paths=[p for p in (root/RETRY,published/'retry.json') if p.exists() or p.is_symlink()]
            reuse.fail(len(retry_paths)<=1,'registry_migration_pending_invalid')
            if retry_paths:
                retry=json.loads(read(retry_paths[0])[0])
                reuse.fail(type(retry) is dict and retry.get('schema')=='walden.registry.retry/1'
                           and retry.get('pending_sha256')==reuse.sha(raw)
                           and _directory_info(original_stage)==journal['stage_identity'],'registry_migration_pending_invalid')
                stage=original_stage/'attempt2'
            expected_identity=retry['stage_identity'] if retry is not None else journal['stage_identity']
            locations=[p for p in (stage,published) if p.exists() or p.is_symlink()]
            reuse.fail(len(locations)==1 and _directory_info(locations[0])==expected_identity,'registry_migration_stage_changed')
            stage=locations[0]
            try:
                result=json.loads(reuse._read(stage/'build.json'))
                if not (stage/'seal.json').exists():raise FileNotFoundError()
            except FileNotFoundError:
                reuse.fail(stage!=published,'registry_migration_incomplete_stage')
                if not any(stage.iterdir()):
                    result=_resume_build(config,path,journal,stage)
                else:
                    # Preserve an interrupted partial attempt. One fresh owned
                    # retry is bounded; it never clears or adopts those files.
                    reuse.fail(retry is None,'registry_migration_retry_exhausted')
                    next_stage=stage/'attempt2'
                    reuse.fail(not next_stage.exists() and not next_stage.is_symlink(),'registry_migration_incomplete_stage')
                    next_stage.mkdir(mode=0o700)
                    retry=dict(schema='walden.registry.retry/1',pending_sha256=reuse.sha(raw),stage_identity=_directory_info(next_stage))
                    create(root/RETRY,encoded(retry));_checkpoint('retry_reserved')
                    stage=next_stage
                    result=_resume_build(config,path,journal,stage)
            reuse.fail(result.get('generation')==journal['generation'],'registry_migration_stage_changed')
        else:
            reuse.fail(not (root/RETRY).exists() and not (root/RETRY).is_symlink(),'registry_migration_pending_invalid')
            _quiet(path)
            db=sqlite3.connect(readonly_database_uri(path),uri=True,timeout=.1)
            try:
                db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
                storage=reuse.descriptor(config,db)
                if storage is not None:
                    sc._registry_page_size(db)
                    return dict(status='preserved_existing_registry',generation=storage['generation'],source_opens=0,local_message_mutated=False)
                preflight(db)
                # Preserve unknown abandoned attempts, do not make unbounded new
                # stages or infer ownership from an empty SQLite file.
                reuse.fail(not any(root.glob('.registry-reuse-stage-*')),'registry_migration_unwitnessed_stage')
                identity=_info(path);old_hash=file_hash(path)
                generation=uuid.uuid4().hex;stage=root/('.registry-reuse-stage-'+generation);stage.mkdir(mode=0o700)
                journal=dict(schema='walden.registry.pending/1',contract=sc.fixed(config),config_sha256=digest(config),profile=profile_fact,
                             generation=generation,old_identity=identity,old_sha256=old_hash,stage_identity=_directory_info(stage),root_identity=_directory_info(root))
                create(pending,encoded(journal));_checkpoint('prepared')
                result=build(config,db,stage,generation=generation)
                _seal(stage,journal,result)
                reuse.fail(_info(path)==identity and file_hash(path)==old_hash,'registry_migration_source_changed')
            finally:db.close()
            _checkpoint('built')
        _profile(config,profile,profile_fact)
        expected_new=result['files']['main.db'];old_hash=journal['old_sha256']
        reuse.fail(_directory_info(root)==journal['root_identity'],'registry_migration_root_changed')
        canonical_hash=file_hash(path)
        published=root/('__walden_registry_'+journal['generation'])
        if canonical_hash==old_hash:
            reuse.fail(_info(path)==journal['old_identity'],'registry_migration_source_changed')
            _quiet(path);_verify_build(stage,result);seal=_verify_seal(stage,journal,result)
            sc.query_scope_guard(config,before)
            if stage!=published:
                _rename(stage,published);stage=published
            _checkpoint('auxiliary_published')
            reuse.fail(_info(path)==journal['old_identity'] and file_hash(path)==old_hash,'registry_migration_source_changed')
            _verify_build(stage,result);seal=_verify_seal(stage,journal,result)
            reuse.fail(_info(stage/'main.db')[:2]==seal['identities']['main.db']
                       and file_hash(stage/'main.db')==expected_new,'registry_migration_stage_changed')
            _profile(config,profile,profile_fact)
            sc.query_scope_guard(config,before)
            _rename(stage/'main.db',path,exchange=True)
            _checkpoint('exchanged')
        else:
            reuse.fail(stage==published and canonical_hash==expected_new,'registry_migration_publication_unknown')
            seal=_verify_seal(stage,journal,result,published=True)
        reuse.fail(_info(path)[:2]==seal['identities']['main.db'],'registry_migration_publication_unknown')
        # A racing replacement is retained by SWAP, never overwritten or
        # silently rolled back. Pending keeps ordinary new readers/writers out.
        old=stage/'old.db'
        if not old.exists():
            reuse.fail(_info(stage/'main.db')[:2]==journal['old_identity'][:2]
                       and file_hash(stage/'main.db')==old_hash,'registry_migration_old_target_changed')
            _rename(stage/'main.db',old)
        reuse.fail(_info(old)==journal['old_identity'] and file_hash(old)==old_hash
                   and _info(path)[:2]==seal['identities']['main.db'] and file_hash(path)==expected_new,'registry_migration_publication_unknown')
        _checkpoint('old_preserved')
        _profile(config,profile,profile_fact)
        sc.query_scope_guard(config,before)
        committed=dict(schema='walden.registry.migration/1',state='committed',contract=sc.fixed(config),
                       generation=journal['generation'],old_backup=str(old.relative_to(root)),old_sha256=old_hash,
                       initial_registry_sha256=expected_new,observations=result['observations'],lists=result['lists'],source_opens=0)
        receipt=stage/'receipt.json'
        try:create(receipt,encoded(committed))
        except FileExistsError:reuse.fail(read(receipt)[0]==encoded(committed),'registry_migration_receipt_changed')
        _checkpoint('receipt')
        _profile(config,profile,profile_fact)
        sc.query_scope_guard(config,before)
        reuse.fail(_directory_info(root)==journal['root_identity'],'registry_migration_root_changed')
        seal=_verify_seal(stage,journal,result,published=True)
        reuse.fail(_info(old)==journal['old_identity'] and file_hash(old)==old_hash
                   and _info(path)[:2]==seal['identities']['main.db'] and file_hash(path)==expected_new,
                   'registry_migration_publication_unknown')
        reuse.fail(read(pending)[0]==encoded(journal),'registry_migration_pending_changed')
        if (root/RETRY).exists():_rename(root/RETRY,stage/'retry.json')
        _rename(pending,stage/'pending.json')
        return dict(status='registry_reused',generation=journal['generation'],observations=result['observations'],
                    current_observations=result['current_observations'],lists=result['lists'],source_opens=0,
                    old_registry_preserved=True,local_message_mutated=False)
