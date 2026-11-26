"""Owned first-copy receipts. Absence in a legacy mirror grants no ownership."""
from __future__ import annotations

import json
import hashlib
import os
import re
import sqlite3
import time
from pathlib import Path

from .common import quote_identifier as qi
from .native_mirror_store import MirrorError


def key(shard, table):
    return 'copy_init:'+shard+':'+table


def charge(budget, size):
    from .native_account_witness import WorkBudgetStop
    probe=budget['tail_probe']
    if probe['bytes']+size>probe['ceiling']:
        probe['limited']=True
        budget['_copy_init_stopped']=True
        raise WorkBudgetStop(budget_kind='metadata_bytes',limit=probe['ceiling'],used=probe['bytes'],required=size)
    probe['bytes']+=size


def read(registry, shard, table, budget):
    name=key(shard,table)
    rows=registry.execute('SELECT key,length(CAST(value AS BLOB)) FROM state WHERE key IN (?,?)',(name,name.replace('copy_init:','copy_init_done:',1))).fetchall()
    charge(budget,32)
    if len(rows)>1:raise MirrorError('account_copy_init_invalid')
    row=(rows[0][1],) if rows else None
    if rows:name=rows[0][0]
    if row is None:return None
    if row[0]>16384:raise MirrorError('account_copy_init_invalid')
    charge(budget,row[0])
    raw=registry.execute('SELECT value FROM state WHERE key=?',(name,)).fetchone()[0]
    try:value=json.loads(raw)
    except (TypeError,ValueError):raise MirrorError('account_copy_init_invalid') from None
    if (type(value) is not dict or type(value.get('version')) is not int or value['version']!=1 or value.get('status') not in ('prepared','completed')
            or (value['status']=='completed')!=name.startswith('copy_init_done:')
            or not isinstance(value.get('generation'),str) or re.fullmatch('[0-9a-f]{32}',value['generation']) is None
            or value.get('shard')!=shard or value.get('table')!=table
            or type(value.get('proof')) is not dict
            or value.get('local') is not None and (type(value['local']) is not list or len(value['local'])!=2 or any(type(v) is not int for v in value['local']))):
        raise MirrorError('account_copy_init_invalid')
    proof=value['proof']
    if (set(proof)!={'contract','ref','source_identity','header','schema_sha256'} or type(proof['contract']) is not dict
            or type(proof['source_identity']) is not list or len(proof['source_identity'])!=2 or any(type(n) is not int or n<0 for n in proof['source_identity'])
            or any(type(proof[k]) is not str or re.fullmatch('[0-9a-f]{64}',proof[k]) is None for k in ('ref','header','schema_sha256'))):
        raise MirrorError('account_copy_init_invalid')
    if value.get('stage') is not None:
        shell=value.get('shell_bytes')
        if (type(value['stage']) is not str or not value['stage'].startswith('.copy-init-'+shard+'-')
                or re.fullmatch(r'\.copy-init-(?:biz_)?message_[0-9]+\.db-[0-9a-f]{32}-[0-9a-f]{16}\.db',value['stage']) is None
                or type(shell) is not dict or set(shell)!={'size','sha256'} or type(shell['size']) is not int or not 0<shell['size']<=65536
                or type(shell['sha256']) is not str or re.fullmatch('[0-9a-f]{64}',shell['sha256']) is None):raise MirrorError('account_copy_init_invalid')
    return value


def save(registry, value, budget):
    from . import native_scope_contract as sc
    charge(budget,len(json.dumps(value,sort_keys=True).encode()))
    name=key(value['shard'],value['table'])
    if value['status']=='completed':
        sc.save(registry,name.replace('copy_init:','copy_init_done:',1),value)
        registry.execute('DELETE FROM state WHERE key=?',(name,))
    else:sc.save(registry,name,value)


def binding(config, proof):
    from . import native_scope_contract as sc
    return dict(contract=sc.fixed(config),ref=proof['ref'],source_identity=proof['source_identity'],
                header=proof['header'],schema_sha256=proof['schema_sha256'])


def local_identity(path):
    from . import native_scope_contract as sc
    sc._safe(path)
    node=path.stat()
    return [node.st_dev,node.st_ino]


def check_shell_target(config, registry, shard, budget):
    """Reject a competing public file before ordinary local metadata readers."""
    from . import native_scope_contract as sc
    name='copy_shell:'+shard
    length=registry.execute('SELECT length(CAST(value AS BLOB)) FROM state WHERE key=?',(name,)).fetchone()
    charge(budget,16)
    if length is None:return
    if length[0]>16384:raise MirrorError('account_copy_init_invalid')
    charge(budget,length[0]);value=sc.state(registry,name)
    if (type(value) is not dict or type(value.get('local')) is not list or len(value['local'])!=2
            or any(type(v) is not int for v in value['local']) or type(value.get('stage')) is not str
            or re.fullmatch(r'\.copy-init-(?:biz_)?message_[0-9]+\.db-[0-9a-f]{32}-[0-9a-f]{16}\.db',value['stage']) is None
            or not value['stage'].startswith('.copy-init-'+shard+'-')):raise MirrorError('account_copy_init_invalid')
    path=Path(config['mirror_root'])/shard
    if path.exists() and ((path.parent/value['stage']).exists() or local_identity(path)!=value['local']):
        raise MirrorError('account_copy_init_local_replaced')


def shell_hash(path, budget, *, _reserved_bytes=None):
    node=path.stat()
    if node.st_size>65536 or any(Path(str(path)+suffix).exists() for suffix in ('-wal','-journal')):
        raise MirrorError('account_copy_init_shell_changed')
    if _reserved_bytes is None:charge(budget,node.st_size)
    elif node.st_size!=_reserved_bytes:raise MirrorError('account_copy_init_shell_changed')
    with path.open('rb') as stream:
        before=os.fstat(stream.fileno());raw=stream.read(65537);after=os.fstat(stream.fileno())
    fields=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    if fields(before)!=fields(after) or fields(after)!=fields(path.stat()):raise MirrorError('account_copy_init_shell_changed')
    return dict(size=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def prepare_new(config, registry, shard, table, proof, budget, *, _persist=True):
    """Only the caller's newly inserted inventory member may mint a receipt."""
    from . import native_scope_contract as sc
    from .live_readonly import readonly_database_uri
    if read(registry,shard,table,budget) is not None:raise MirrorError('account_copy_init_conflict')
    # Current-members absence is not historical absence. This scalar query
    # stays within SQLite; prior table observations are positive legacy evidence
    # even when the member and all three local copy records have disappeared.
    # A timeout/unknown can never mint ownership. The caller has not inserted
    # this inventory observation yet, so no current observation is excluded.
    from .native_account_witness import WorkBudgetStop
    observation_started=time.monotonic();until=min(budget['until'],observation_started+2.)
    if time.monotonic()>=until:
        budget['_copy_init_stopped']=True
        raise WorkBudgetStop('account_copy_init_observation_deferred',budget_kind='metadata_ms',limit=max(0,int((until-observation_started)*1000)),used=max(0,int((time.monotonic()-observation_started)*1000)))
    charge(budget,16)
    registry.set_progress_handler(lambda:int(time.monotonic()>=until),1000)
    try:
        from .native_registry_reuse import seen
        historical=seen(config,registry,shard,table,budget)
        if historical is None:
            invalid=registry.execute("SELECT 1 FROM observations WHERE CASE WHEN json_valid(proof)=0 THEN 1 ELSE json_type(proof) IS NOT 'object' OR json_type(proof,'$.tables') IS NOT 'array' OR json_type(proof,'$.shard') IS NOT 'text' OR json_type(proof,'$.contract') IS NOT 'object' OR json_type(proof,'$.source_identity') IS NOT 'array' OR json_type(proof,'$.query_only') IS NOT 'true' END LIMIT 1").fetchone()
            if invalid:raise MirrorError('account_copy_init_invalid')
            previous=registry.execute("SELECT 1 FROM observations WHERE instr(proof,?)>0 AND json_extract(proof,'$.shard')=? AND EXISTS (SELECT 1 FROM json_each(observations.proof,'$.tables') AS t WHERE json_extract(t.value,'$[0]')=?) LIMIT 1",(table,shard,table)).fetchone()
        else:previous=historical
    except sqlite3.OperationalError:
        if time.monotonic()<until:raise MirrorError('account_copy_init_invalid') from None
        budget['_copy_init_stopped']=True
        raise WorkBudgetStop('account_copy_init_observation_deferred',budget_kind='metadata_ms',limit=max(0,int((until-observation_started)*1000)),used=max(0,int((time.monotonic()-observation_started)*1000))) from None
    finally:registry.set_progress_handler(None,0)
    if previous:raise MirrorError('account_copy_init_unknown')
    path=Path(config['mirror_root'])/shard
    identity=None
    if path.exists():
        identity=local_identity(path)
        with sqlite3.connect(readonly_database_uri(path),uri=True) as db:
            if db.execute('SELECT * FROM __walden_binding').fetchall()!=[(config['account_id'],config['source_generation'],shard)]:raise MirrorError('source_identity_mismatch')
            if (db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(table,)).fetchone()
                    or db.execute('SELECT 1 FROM __walden_progress WHERE table_name=?',(table,)).fetchone()
                    or db.execute('SELECT 1 FROM __walden_observed WHERE table_name=? LIMIT 1',(table,)).fetchone()):
                raise MirrorError('account_copy_init_unowned_local')
    value=dict(version=1,shard=shard,table=table,generation=os.urandom(16).hex(),
               status='prepared',proof=binding(config,proof),local=identity)
    if _persist:save(registry,value,budget)
    else:charge(budget,len(json.dumps(value,sort_keys=True).encode()))
    return value


def has_pending(registry, shard, budget):
    prefix='copy_init:'+shard+':'
    row=registry.execute('SELECT key FROM state WHERE key>=? AND key<? LIMIT 1',(prefix,prefix+'~')).fetchone()
    charge(budget,16+(len(row[0].encode()) if row else 0))
    return row is not None


def pending(registry, shard, budget, *, after='', limit=64):
    prefix='copy_init:'+shard+':'
    # A bounded cyclic page; the ordinary copy cursor supplies fairness.
    rows=registry.execute('SELECT key,length(CAST(value AS BLOB)) FROM state WHERE key>=? AND key<? ORDER BY key LIMIT ?',
                          (prefix+after,prefix+'~',limit)).fetchall()
    charge(budget,16*len(rows))
    if not rows and after:return pending(registry,shard,budget,limit=limit)
    result=[]
    for name,_ in rows:
        table=name[len(prefix):]
        value=read(registry,shard,table,budget)
        if value['status']=='prepared':result.append(table)
    return result


def validate(config, proof, value, path):
    if value['proof']!=binding(config,proof):raise MirrorError('account_copy_init_source_changed')
    if value['local'] is not None and value['local']!=local_identity(path):raise MirrorError('account_copy_init_local_replaced')


def completed_binding(config, proof, value):
    current=binding(config,proof)
    if any(value['proof'].get(name)!=current[name] for name in ('contract','ref','schema_sha256')):
        raise MirrorError('account_copy_init_source_changed')


def open_store(config, registry, proof, source, budget, *, witness=None):
    from .native_mirror_store import MirrorStore
    path=Path(config['mirror_root'])/source.shard_name
    value=read(registry,source.shard_name,source.table_name,budget)
    if value is None:
        if not path.is_file():raise MirrorError('account_copy_init_unknown')
        return MirrorStore(path,source,witness=witness)
    if value['status']=='completed':
        completed_binding(config,proof,value)
        if not path.is_file():raise MirrorError('account_copy_init_local_missing')
        # The publication receipt has been consumed. Subsequent copies use
        # the original current Source/progress guards, including AUTO renumber.
        return MirrorStore(path,source,witness=witness)
    if value['proof']!=binding(config,proof):raise MirrorError('account_copy_init_source_changed')
    if value['local'] is None:
        from . import native_scope_contract as sc
        shell_key='copy_shell:'+source.shard_name
        size=registry.execute('SELECT length(CAST(value AS BLOB)) FROM state WHERE key=?',(shell_key,)).fetchone()
        charge(budget,16)
        shell=None
        if size:
            if size[0]>16384:raise MirrorError('account_copy_init_invalid')
            charge(budget,size[0]);shell=sc.state(registry,shell_key)
            if (type(shell) is not dict or shell.get('source')!=dict(contract=sc.fixed(config),shard=source.shard_name,
                    source_identity=proof['source_identity'],header=proof['header'])
                    or type(shell.get('local')) is not list or len(shell['local'])!=2
                    or any(type(v) is not int for v in shell['local'])
                    or type(shell.get('stage')) is not str or re.fullmatch(r'\.copy-init-(?:biz_)?message_[0-9]+\.db-[0-9a-f]{32}-[0-9a-f]{16}\.db',shell['stage']) is None
                    or not shell['stage'].startswith('.copy-init-'+source.shard_name+'-')
                    or type(shell.get('bytes')) is not dict or type(shell['bytes'].get('size')) is not int
                    or type(shell['bytes'].get('sha256')) is not str or re.fullmatch('[0-9a-f]{64}',shell['bytes']['sha256']) is None):
                raise MirrorError('account_copy_init_invalid')
        if source.shard_name in budget.get('_new_copy_shells',set()):return None
        if shell is not None:
            value.update(local=shell['local'],stage=shell['stage'],shell_bytes=shell['bytes']);save(registry,value,budget)
        else:
            if path.exists():raise MirrorError('account_copy_init_unowned_local')
            if any(path.parent.glob('.copy-init-'+source.shard_name+'-*.db')):
                # A shell created before its registry receipt committed is not
                # evidence we may adopt. Preserve it and stop automatic retry;
                # no new stage is allocated each background round.
                raise MirrorError('account_copy_init_uncommitted_stage')
        # Do not expose an uncommitted shell at the public shard path. Reserve
        # the entire bounded receipt write before creating any file.
            stage=path.parent/('.copy-init-'+source.shard_name+'-'+value['generation']+'-'+os.urandom(8).hex()+'.db')
            shell=dict(source=dict(contract=sc.fixed(config),shard=source.shard_name,source_identity=proof['source_identity'],header=proof['header']),local=[(1<<64)-1,(1<<64)-1],stage=stage.name,bytes=dict(size=65536,sha256='0'*64))
            shell_bytes=MirrorStore.metadata_shell_bytes(source)
            if shell_bytes>65536:raise MirrorError('account_copy_init_invalid')
            # No file exists until all remaining stage hash and receipt writes
            # are paid. Ordinary budget deferral must never create an orphan.
            charge(budget,shell_bytes+len(json.dumps(shell,sort_keys=True).encode()))
            fd=os.open(stage,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.close(fd)
            initial=os.stat(stage,follow_symlinks=False)
            MirrorStore(stage,source)
            if local_identity(stage)!=[initial.st_dev,initial.st_ino]:raise MirrorError('account_copy_init_local_replaced')
            with stage.open('rb') as stream:os.fsync(stream.fileno())
            from .native_scope_add import directory
            with directory(path.parent) as parent:os.fsync(parent)
            shell.update(local=local_identity(stage),bytes=shell_hash(stage,budget,_reserved_bytes=shell_bytes));sc.save(registry,shell_key,shell)
            budget.setdefault('_new_copy_shells',set()).add(source.shard_name)
            return None
    if value.get('stage') is not None:
        name=value['stage']
        if type(name) is not str or re.fullmatch(r'\.copy-init-(?:biz_)?message_[0-9]+\.db-[0-9a-f]{32}-[0-9a-f]{16}\.db',name) is None or not name.startswith('.copy-init-'+source.shard_name+'-'):
            raise MirrorError('account_copy_init_invalid')
        stage=path.parent/name
        if stage.exists():
            if local_identity(stage)!=value['local']:raise MirrorError('account_copy_init_local_replaced')
            if shell_hash(stage,budget)!=value['shell_bytes']:raise MirrorError('account_copy_init_shell_changed')
            from .native_onboarding import _publish_directory
            # Same-parent exclusive rename, including parent fsync. It applies
            # equally to files and directories; never replace an existing target.
            if stage.parent!=path.parent:raise MirrorError('account_copy_init_invalid')
            try:_publish_directory(stage,path)
            except FileExistsError:
                raise MirrorError('account_copy_init_local_replaced') from None
        elif not path.is_file():raise MirrorError('account_copy_init_local_missing')
        else:
            # Initial bytes cease to be a valid hash after an owned local
            # transaction advances this shard (possibly a sibling member).
            from .live_readonly import readonly_database_uri
            with sqlite3.connect(readonly_database_uri(path),uri=True) as db:
                row=db.execute("SELECT table_name,value FROM __walden_progress WHERE table_name GLOB 'Msg_*' ORDER BY table_name LIMIT 1").fetchone()
            if row is None:
                if shell_hash(path,budget)!=value['shell_bytes']:raise MirrorError('account_copy_init_shell_changed')
            else:
                charge(budget,len(row[1].encode()))
                try:progress=json.loads(row[1])
                except (TypeError,ValueError):raise MirrorError('account_copy_init_invalid') from None
                sibling=read(registry,source.shard_name,row[0],budget)
                if (type(progress) is not dict or sibling is None or sibling['local'] not in (None,value['local'])
                        or progress.get('copy_init_generation')!=sibling['generation']
                        or progress.get('source_identity')!=proof['source_identity'] or progress.get('source_header_sha256')!=proof['header']):
                    raise MirrorError('account_copy_init_progress_lost')
    validate(config,proof,value,path)
    return MirrorStore(path,source,witness=witness)


def prepare_local(config, registry, proof, store, source, ddl, maximum, budget, *, _commit_check=None):
    """Inventory has committed already. DDL and initial cursor share one txn."""
    value=read(registry,source.shard_name,source.table_name,budget)
    progress=store.progress(source.table_name)
    if value is None:
        if progress is None:raise MirrorError('account_copy_init_unknown')
        return progress
    if value['status']!='completed':
        validate(config,proof,value,store.path)
        if value['local'] is None:raise MirrorError('account_copy_init_invalid')
    else:completed_binding(config,proof,value)
    if progress is not None:
        if progress.get('copy_init_generation')!=value['generation']:
            raise MirrorError('account_copy_init_progress_lost')
        if value['status']=='completed':
            with store.connect() as local:
                if not local.execute('SELECT 1 FROM sqlite_master WHERE type=\'table\' AND name=?',(source.table_name,)).fetchone():
                    raise MirrorError('account_copy_init_progress_lost')
                if progress.get('tail',0)>0 and (not local.execute('SELECT 1 FROM '+qi(source.table_name)+' LIMIT 1').fetchone()
                        or not local.execute('SELECT 1 FROM __walden_observed WHERE table_name=? LIMIT 1',(source.table_name,)).fetchone()):
                    raise MirrorError('account_copy_init_progress_lost')
        return progress
    if value['status']=='completed':raise MirrorError('account_copy_init_progress_lost')
    with store.connect() as local:
        if not local.in_transaction:local.execute('BEGIN IMMEDIATE')
        if local_identity(store.path)!=value['local']:raise MirrorError('account_copy_init_local_replaced')
        if local.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' LIMIT 1").fetchone():raise MirrorError('local_trigger_unsupported')
        if (local.execute('SELECT 1 FROM sqlite_master WHERE name=?',(source.table_name,)).fetchone()
                or local.execute('SELECT 1 FROM __walden_observed WHERE table_name=? LIMIT 1',(source.table_name,)).fetchone()):
            raise MirrorError('account_copy_init_unowned_local')
        store.ensure_table(source,ddl,_connection=local)
        progress=dict(H=maximum,history=0,tail=maximum,target=maximum,history_complete=False,
                      initial_suffix_pending=True,copy_init_generation=value['generation'],
                      source_identity=proof['source_identity'],source_header_sha256=proof['header'],checked_at=int(time.time()))
        if value.get('prior_coverage_unknown') is True:
            progress.update(prior_coverage_unknown=True,reconcile_request_sha256=value['reconcile_request_sha256'])
        store.apply_batch(source,source.table_name,[],progress,_connection=local)
        if local_identity(store.path)!=value['local']:raise MirrorError('account_copy_init_local_replaced')
        if _commit_check is not None:_commit_check()
    return progress


def finish(registry, shard, table, progress, budget):
    if progress.get('initial_suffix_pending') is not False:return
    value=read(registry,shard,table,budget)
    if value is None or value['generation']!=progress.get('copy_init_generation'):raise MirrorError('account_copy_init_progress_lost')
    if value['status']=='completed':return
    value['status']='completed';save(registry,value,budget)
    if not has_pending(registry,shard,budget):
        from . import native_scope_contract as sc
        name='copy_shell:'+shard
        size=registry.execute('SELECT length(CAST(value AS BLOB)) FROM state WHERE key=?',(name,)).fetchone()
        charge(budget,16)
        if size:
            if size[0]>16384:raise MirrorError('account_copy_init_invalid')
            charge(budget,2*size[0]);shell=sc.state(registry,name)
            sc.save(registry,'copy_shell_done:'+shard,shell)
            registry.execute('DELETE FROM state WHERE key=?',(name,))
