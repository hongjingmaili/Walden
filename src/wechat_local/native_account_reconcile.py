"""One explicitly confirmed missing account copy; no implicit legacy adoption."""
import json
import os
import re
import sqlite3
import stat
import time
from pathlib import Path

from .native_mirror_store import MirrorError, MirrorStore
from . import native_scope_contract as sc, native_account_copy_init as ci
from .native_follow_policy import digest as source_digest
from .live_readonly import readonly_database_uri

NAME='.account-copy-reconcile.json'
SCHEMA='walden.account.missing-copy-reconcile/1'


def absent(config, shard, table):
    path=Path(config['mirror_root'])/shard
    if not path.is_file():raise MirrorError('account_reconcile_local_invalid')
    identity=ci.local_identity(path)  # Never create a missing whole shard.
    try:
        with sqlite3.connect(readonly_database_uri(path),uri=True,timeout=.1) as db:
            if db.execute('SELECT * FROM __walden_binding').fetchall()!=[(config['account_id'],config['source_generation'],shard)]:raise MirrorError('source_identity_mismatch')
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' LIMIT 1").fetchone():raise MirrorError('local_trigger_unsupported')
            if (db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(table,)).fetchone()
                    or db.execute('SELECT 1 FROM __walden_progress WHERE table_name=?',(table,)).fetchone()
                    or db.execute('SELECT 1 FROM __walden_observed WHERE table_name=? LIMIT 1',(table,)).fetchone()):
                raise MirrorError('account_reconcile_copy_not_absent')
    except sqlite3.Error:raise MirrorError('account_reconcile_local_invalid') from None
    if ci.local_identity(path)!=identity:raise MirrorError('account_copy_init_local_replaced')
    return identity


def read(config, budget=None):
    path=Path(config['mirror_root'])/NAME
    try:node=path.lstat()
    except FileNotFoundError:return None
    if node.st_size>16384:raise MirrorError('account_reconcile_request_invalid')
    if budget is not None:ci.charge(budget,node.st_size+64)
    raw,_=sc.read(path)
    try:value=json.loads(raw)
    except (ValueError,TypeError):raise MirrorError('account_reconcile_request_invalid') from None
    from . import native_reconcile_current as current
    if type(value)is dict and value.get('schema')==current.SCHEMA:return current.decode(config,value,raw)
    return decode_legacy(config,raw)


def decode_legacy(config,raw):
    try:value=json.loads(raw)
    except (ValueError,TypeError):raise MirrorError('account_reconcile_request_invalid') from None
    if (type(value) is not dict or value.get('schema')!=SCHEMA or value.get('contract')!=sc.fixed(config)
            or set(value)!={'schema','contract','source_sha256','target_ref','generation','shard','table','proof','local','prior_coverage_unknown'}
            or value.get('source_sha256')!=source_digest(config) or value.get('prior_coverage_unknown') is not True
            or type(value.get('generation')) is not str or re.fullmatch('[0-9a-f]{32}',value['generation']) is None
            or type(value.get('shard')) is not str or sc.SHARD.fullmatch(value['shard']) is None
            or type(value.get('table')) is not str or sc.TABLE.fullmatch(value['table']) is None
            or value.get('target_ref')!=sc.target_ref(config,value['shard'],value['table'])
            or type(value.get('proof')) is not dict or type(value.get('local')) is not list
            or len(value['local'])!=2 or any(type(n) is not int for n in value['local'])):
        raise MirrorError('account_reconcile_request_invalid')
    proof=value['proof']
    if (set(proof)!={'contract','ref','source_identity','header','schema_sha256'} or proof['contract']!=sc.fixed(config)
            or proof['ref']!=value['target_ref'] or type(proof['source_identity']) is not list or len(proof['source_identity'])!=2
            or any(type(n) is not int or n<0 for n in proof['source_identity'])
            or any(type(proof[k]) is not str or re.fullmatch('[0-9a-f]{64}',proof[k]) is None for k in ('header','schema_sha256'))):
        raise MirrorError('account_reconcile_request_invalid')
    return dict(value,request_sha256=sc.sha(raw))


def member(config, registry, shard, table, budget):
    size=registry.execute('SELECT length(CAST(proof AS BLOB)) FROM members WHERE shard=? AND table_name=?',(shard,table)).fetchone()
    ci.charge(budget,16)
    if size is None:raise MirrorError('account_reconcile_source_conflict')
    ci.charge(budget,size[0])
    try:preview=json.loads(registry.execute('SELECT proof FROM members WHERE shard=? AND table_name=?',(shard,table)).fetchone()[0])
    except (ValueError,TypeError):raise MirrorError('scope_member_proof') from None
    if type(preview) is not dict or type(preview.get('observation')) is not str:raise MirrorError('scope_member_proof')
    from .native_registry_reuse import observation_size
    observed_size=observation_size(config,registry,preview['observation'])
    observation=None if observed_size is None else (observed_size,)
    ci.charge(budget,16)
    if observation is None:raise MirrorError('scope_member_proof')
    ci.charge(budget,size[0]+observation[0])
    return sc.member(config,registry,shard,table)


def pending(config, registry, budget, *, check_done=False):
    request=read(config,budget)
    if request is None:return None
    if '_current'in request:
        from .native_reconcile_current import pending as current_pending
        value=current_pending(config,registry,request,budget)
        budget['_current_reconcile_request']=request
        return value
    return pending_legacy(config,registry,request,budget,check_done=check_done)


def pending_legacy(config,registry,request,budget,*,check_done=False):
    shard,table=request['shard'],request['table']
    value=ci.read(registry,shard,table,budget)
    if value is not None:
        if (value.get('reconcile_request_sha256')!=request['request_sha256'] or value.get('prior_coverage_unknown') is not True
                or value['generation']!=request['generation']):raise MirrorError('account_reconcile_request_conflict')
        if value['status']=='completed' and not check_done:
            ci.completed_binding(config,request['proof'],value)
            return None  # Consumed audit never becomes new Source authority.
    proof=member(config,registry,shard,table,budget)
    if value is not None:
        if value['status']=='completed':
            ci.completed_binding(config,proof,value)
        else:ci.validate(config,proof,value,Path(config['mirror_root'])/shard)
        local_path=Path(config['mirror_root'])/shard
        if not local_path.is_file():raise MirrorError('account_copy_init_local_missing')
        ci.local_identity(local_path)
        with sqlite3.connect(readonly_database_uri(Path(config['mirror_root'])/shard),uri=True,timeout=.1) as db:
            if db.execute('SELECT * FROM __walden_binding').fetchall()!=[(config['account_id'],config['source_generation'],shard)]:raise MirrorError('source_identity_mismatch')
            row=db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()
            present=db.execute('SELECT 1 FROM sqlite_master WHERE type=\'table\' AND name=?',(table,)).fetchone()
        if row:
            ci.charge(budget,len(row[0].encode()))
            try:progress=json.loads(row[0])
            except (ValueError,TypeError):raise MirrorError('account_reconcile_local_invalid') from None
            if (not present or type(progress) is not dict or progress.get('copy_init_generation')!=request['generation']
                    or progress.get('prior_coverage_unknown') is not True or progress.get('reconcile_request_sha256')!=request['request_sha256']):
                raise MirrorError('account_reconcile_request_conflict')
            return None  # Normal owned copying, not another management round.
        if value['status']=='completed':raise MirrorError('account_copy_init_progress_lost')
    if (request['proof']!=ci.binding(config,proof) or request['local']!=absent(config,shard,table)
            or proof.get('supported') is not True or proof.get('available') is not True):
        raise MirrorError('account_reconcile_source_conflict')
    return request


def authorize(config, target_ref, *, confirmed=False, expected_source_sha256=None,current=False,expected_request_sha256=None,profile_path=None,withheld_refs=()):
    """Local-only plan/confirmation; actual Source work stays in owned follow."""
    from .native_mirror_sync import writer_lock, mirror_root, _account_budget
    if withheld_refs and not current:raise MirrorError('account_reconcile_confirmation_required')
    if type(target_ref) is not str or re.fullmatch('[0-9a-f]{64}',target_ref) is None:raise MirrorError('account_reconcile_target_required')
    if sc.mode(config)!='account':raise MirrorError('account_scope_required')
    if confirmed and expected_source_sha256!=source_digest(config):raise MirrorError('account_reconcile_confirmation_required')
    root=mirror_root(config,create=False);sc._safe(root/'.writer.lock')
    with writer_lock(root,float(config.get('mirror_lock_timeout',10))):
        before=sc.query_scope_guard(config)
        if current:
            if not confirmed or profile_path is None or type(expected_request_sha256)is not str:raise MirrorError('account_reconcile_confirmation_required')
            from .native_reconcile_current import confirm
            return confirm(config,profile_path,target_ref,expected_request_sha256,withheld_refs)
        if expected_request_sha256 is not None:raise MirrorError('account_reconcile_confirmation_required')
        selected=sc.selection(config,ref=target_ref)
        if len(selected)!=1:raise MirrorError('account_reconcile_target_required')
        shard,table,proof=selected[0];budget=_account_budget(config);budget['tail_probe']=dict(bytes=0,ceiling=1048576)
        with sc.registry(config,snapshot=False) as registry:
            existing=read(config)
            if existing is not None:
                if existing['target_ref']!=target_ref:raise MirrorError('account_reconcile_request_conflict')
                active=pending(config,registry,budget,check_done=True)
                return dict(status='requested' if active else 'owned_copy_or_completed',target_ref=target_ref,source_opens=0,prior_coverage_unknown=True)
            if ci.read(registry,shard,table,budget) is not None:raise MirrorError('account_reconcile_existing_initialization')
            if proof.get('supported') is not True or proof.get('available') is not True:raise MirrorError('account_reconcile_source_conflict')
            identity=absent(config,shard,table)
        plan=dict(status='confirmation_required',target_ref=target_ref,source_sha256=source_digest(config),source_opens=0,
                  local_message_mutated=False,prior_coverage_unknown=True)
        if not confirmed:return plan
        value=dict(schema=SCHEMA,contract=sc.fixed(config),source_sha256=source_digest(config),target_ref=target_ref,
                   generation=os.urandom(16).hex(),shard=shard,table=table,proof=ci.binding(config,proof),local=identity,
                   prior_coverage_unknown=True)
        sc.query_scope_guard(config,before);sc.create(root/NAME,sc.encoded(value))
        return dict(plan,status='requested',stage='awaiting_owned_follow')


def consume(config, registry, request, budget, deadline, connection_factory, result):
    """Only one target's DDL/progress; the caller performs no ordinary copies."""
    from . import native_mirror_sync as sync
    from .source_records import SourceKey
    from .native_deadline import _current
    from .native_follow_grant import FollowDeadline
    if (not isinstance(deadline,FollowDeadline) or _current.get() is not deadline
            or deadline.grant.get('kind')!='active' or deadline.grant.get('source_sha256')!=source_digest(config)
            or not getattr(registry,'guard_valid',False)):
        raise MirrorError('account_source_role_required')
    if '_current'in request:
        from . import native_reconcile_current as current
        current.qualify(config,registry,request,budget,deadline,connection_factory,result)
        request=dict(request,local=current.local_check(config,request,budget),proof=ci.binding(config,member(config,registry,request['shard'],request['table'],budget)))
    shard,table=request['shard'],request['table'];path=Path(config['message_root'])/shard
    deadline.check()
    if time.monotonic()>=budget['until']:return False
    result['source_attempts']+=1
    proof=member(config,registry,shard,table,budget)
    ci.charge(budget,16)
    source_fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    node=os.fstat(source_fd);header=sc.sha(os.read(source_fd,16))
    if [node.st_dev,node.st_ino]!=proof['source_identity'] or header!=proof['header']:
        os.close(source_fd);raise MirrorError('scope_source_conflict')
    try:conn=connection_factory(path)
    except BaseException:
        os.close(source_fd);raise
    result['source_opens']+=1
    try:
        def progress():
            deadline.check()
            return int(time.monotonic()>=budget['until'])
        conn.set_progress_handler(progress,1000)
        ci.charge(budget,8)
        if conn.execute('PRAGMA query_only').fetchone()!=(1,):raise MirrorError('source_not_readonly')
        conn.execute('BEGIN');sync._validate_message_cursor(conn,table)
        ci.charge(budget,8);cookie=sync._account_source_read(conn,'PRAGMA schema_version',stage='source_copy').fetchone()[0]
        ci.charge(budget,8)
        size=sync._account_source_read(conn,"SELECT length(CAST(sql AS BLOB)) FROM sqlite_master WHERE type='table' AND name=?",(table,),stage='source_copy').fetchone()
        if size is None:raise MirrorError('source_schema_changed')
        ci.charge(budget,size[0])
        ddl=sync._account_source_read(conn,"SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,),stage='source_copy').fetchone()
        if ddl is None or sc.sha(ddl[0].encode())!=proof['schema_sha256']:raise MirrorError('source_schema_changed')
        def verify_source():
            deadline.check()
            if '_current'in request:
                from .native_reconcile_current import state,opened,ident,local_check
                current_state=state(registry,request,budget)
                if current_state is None:raise MirrorError('account_reconcile_current_unproven')
                with opened(path,config,expected=current_state['source'])as(_fd,_pin):local_check(config,request,budget)
            if time.monotonic()>=budget['until']:
                from .native_account_witness import WorkBudgetStop
                raise WorkBudgetStop('account_reconcile_source_budget',budget_kind='source_ms',limit=20000,used=max(0,int((time.monotonic()-budget.get('started',budget['until']-20))*1000)))
            ci.charge(budget,16+8+8+len(ddl[0].encode()))
            current=path.lstat();held=os.fstat(source_fd)
            if (not stat.S_ISREG(current.st_mode) or [current.st_dev,current.st_ino]!=proof['source_identity']
                    or [held.st_dev,held.st_ino]!=proof['source_identity']):raise MirrorError('scope_source_conflict')
            os.lseek(source_fd,0,os.SEEK_SET)
            if sc.sha(os.read(source_fd,16))!=proof['header']:raise MirrorError('scope_source_conflict')
            if (sync._account_source_read(conn,'PRAGMA query_only',stage='source_copy').fetchone()!=(1,)
                    or sync._account_source_read(conn,'PRAGMA schema_version',stage='source_copy').fetchone()!=(cookie,)
                    or sync._account_source_read(conn,"SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,),stage='source_copy').fetchone()!=ddl):
                raise MirrorError('source_schema_changed')
        verify_source()
        ci.charge(budget,8)
        maximum=sync._account_source_read(conn,'SELECT coalesce(max(local_id),0) FROM '+sync.qi(table),stage='source_copy').fetchone()[0]
        if type(maximum) is not int or maximum<0:raise MirrorError('source_cursor_regression')
        deadline.check()
        if time.monotonic()>=budget['until']:return False
        value=ci.read(registry,shard,table,budget)
        if value is None:
            if absent(config,shard,table)!=request['local']:raise MirrorError('account_copy_init_local_replaced')
            value=dict(version=1,shard=shard,table=table,generation=request['generation'],status='prepared',
                       proof=ci.binding(config,proof),local=request['local'],prior_coverage_unknown=True,
                       reconcile_request_sha256=request['request_sha256'])
            registry.execute('SAVEPOINT reconcile_prepare')
            try:
                ci.save(registry,value,budget);verify_source()
            except BaseException:
                registry.execute('ROLLBACK TO reconcile_prepare');registry.execute('RELEASE reconcile_prepare');raise
            registry.execute('RELEASE reconcile_prepare');sync._account_registry_commit(registry)
            verify_source()
        key=SourceKey(config['account_id'],config['source_generation'],shard,table)
        store=MirrorStore(Path(config['mirror_root'])/shard,key)
        verify_source()
        if '_current'in request:
            reserve=budget['tail_probe'].get('guard_finish_reserve',0)+2*(len(sc.encoded(request['_current']))+len(sc.encoded(request['proof']))+2048)
            if budget['tail_probe']['bytes']+reserve>1048576:
                from .native_account_witness import WorkBudgetStop
                raise WorkBudgetStop('account_reconcile_publication_deferred',budget_kind='metadata_bytes',limit=1048576,used=budget['tail_probe']['bytes'],required=reserve)
        current=ci.prepare_local(config,registry,proof,store,key,ddl[0],maximum,budget,_commit_check=verify_source)
        # Cross-database namespace checks cannot be atomic with SQLite's local
        # COMMIT. A change in that last gap is an explicit failure, retaining
        # the owned old-Source pending record; never claim a successful repair.
        verify_source()
        if maximum==0 and current.get('initial_suffix_pending') is True:
            # The original guarded empty Source observation consumes no message
            # slot. Nonempty suffix copying remains in later ordinary rounds.
            entry=sync._account_copy_table(config,conn,path,table,store,proof['source_identity'],proof['header'],budget,
                                           registry=registry,media_username=proof['ref'],commit_check=verify_source)
            verify_source()
            if entry is not None:
                current=entry['progress']
                registry.execute('SAVEPOINT copy_finish')
                try:ci.finish(registry,shard,table,entry['progress'],budget)
                except BaseException:
                    registry.execute('ROLLBACK TO copy_finish');registry.execute('RELEASE copy_finish');raise
                registry.execute('RELEASE copy_finish')
        deadline.check()
        return dict(copy_pending=current.get('initial_suffix_pending') is True,H=current['H'])
    except sqlite3.OperationalError:
        deadline.check()
        if time.monotonic()>=budget['until']:return False
        raise
    finally:
        conn.set_progress_handler(None,0);conn.close();os.close(source_fd)
