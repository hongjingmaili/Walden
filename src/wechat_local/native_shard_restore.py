"""Explicit single-shard equivalent-file restoration. No Source or credential reads.

A pre-existing account pending fence blocks old and new ordinary entry points.
Only this operation's pinned plan, quiescent control and exact two file sides
may advance it. Initial hashes are publication evidence, never permanent pins.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid
from contextlib import closing
from collections import OrderedDict

from .native_mirror_store import MirrorError, lossless_text_rows
from .native_scope_add import create, read, encoded, directory
from .native_follow_policy import digest
from .native_source_recovery import row_hash
from . import native_scope_contract as sc
from . import native_registry_migrate as files

FORMAT='walden.local.shard.restore/1'
MAX_BYTES=128*1024*1024
MAX_ROW=1024*1024
MAX_TABLES=2048


def need(value, code):
    if not value:raise MirrorError('shard_restore_'+code)


def _json(path):
    raw,fact=read(path)
    try:value=json.loads(raw)
    except (TypeError,ValueError):raise MirrorError('shard_restore_record_invalid') from None
    need(type(value) is dict,'record_invalid')
    return value,raw,fact


def _plain_profile(path):
    # A narrowly scoped maintenance loader. It does not temporarily remove the
    # fence, read credentials, access Source, or mint ordinary Source authority.
    from .source_setup import _read_source_config_fd, _confirmed_self_username, _check_identity_config_parents
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:value,raw,_=_read_source_config_fd(fd)
    finally:os.close(fd)
    _confirmed_self_username(value,physical=False);_check_identity_config_parents(path)
    return value,raw,read(path)[1]


def _layout(config, *, output=None, replacement=None, state_root=None):
    # Check both lexical and resolved aliases before any lock/stage/output
    # creation. Resolving path metadata is not opening a Source database.
    def aliases(value):
        need(type(value) is str or isinstance(value,Path),'path_invalid')
        path=Path(value)
        need(path.is_absolute() and '..' not in path.parts,'path_invalid')
        try:return {Path(os.path.abspath(path)),path.resolve()}
        except (OSError,RuntimeError):raise MirrorError('shard_restore_path_invalid') from None
    roots=[]
    for key in ('live_db_root','message_root','image_attachments_root'):
        if config.get(key):roots.extend(aliases(config[key]))
    protected=[]
    for key in ('passphrase_file','session_database','encrypted_contact_database','image_database','image_key_config','image_credentials_status'):
        if config.get(key):protected.extend(aliases(config[key]))
    for value in config.get('voice_databases',[]):protected.extend(aliases(value))
    mirror=aliases(config['mirror_root'])
    need(all(not(a==b or a in b.parents or b in a.parents)for a in mirror for b in roots),'source_overlap')
    for value in (output,replacement,state_root):
        if value is None:continue
        values=aliases(value)
        need(all(not(a==b or b in a.parents)for a in values for b in roots),'source_overlap')
        need(all(a!=b for a in values for b in protected),'protected_path')
    if output is not None:
        need(all(not(a==b or b in a.parents)for a in aliases(output)for b in mirror),'plan_path')
    # Firmlink/mount aliases need not be lexical symlinks. Compare only the
    # known directory ancestry metadata; never enumerate/open Source contents.
    def ancestry(path):
        found=set()
        for node in (path,*path.parents):
            try:n=node.stat()
            except FileNotFoundError:continue
            except OSError:raise MirrorError('shard_restore_source_boundary_unknown') from None
            if stat.S_ISDIR(n.st_mode):found.add((n.st_dev,n.st_ino))
        return found
    root_ids=set();source_ancestors=set()
    for source in roots:
        try:n=source.stat()
        except FileNotFoundError:continue
        except OSError:raise MirrorError('shard_restore_source_boundary_unknown') from None
        need(stat.S_ISDIR(n.st_mode),'source_boundary_unknown')
        root_ids.add((n.st_dev,n.st_ino));source_ancestors.update(ancestry(source))
    for mirror_path in mirror:
        try:n=mirror_path.stat()
        except OSError:raise MirrorError('shard_restore_source_boundary_unknown') from None
        need((n.st_dev,n.st_ino) not in source_ancestors and not (ancestry(mirror_path)&root_ids),'source_overlap')
    for value in (output,replacement,state_root):
        if value is not None:need(not (ancestry(Path(value))&root_ids),'source_overlap')


def _stage(path,expected):
    need(files._directory_info(path)==expected,'stage_changed')


def _scope(p, *, pending=None):
    root=Path(p['old_config']['mirror_root'])
    _layout(p['old_config'],output=p['plan_path'],replacement=p['replacement'],state_root=p['state_root'])
    need(files._directory_info(root)==p['root_identity'],'root_changed')
    if 'registry_identity' in p:need(list(sc._safe(root/sc.REGISTRY))==p['registry_identity'],'registry_changed')
    if pending is None:sc._pending(root)
    else:
        need(not os.path.lexists(root/'.scope-add.pending'),'foreign_pending')
        raw,fact=read(root/sc.PENDING)
        need(raw==pending['raw'] and fact==pending['fact'],'pending_changed')
        _stage(Path(p['state_root']),pending['stage_identity'])
        if 'expected_identity' in pending:need(list(sc._safe(root/sc.PENDING))==pending['expected_identity'],'pending_changed')
    need(sc._account_current_proof(p['old_config'])==tuple(p['scope_token']),'scope_changed')
    config,raw,fact=_plain_profile(Path(p['profile']))
    need(config==p['old_config'] and fact==p['profile_fact'] and hashlib.sha256(raw).hexdigest()==p['profile_sha256'],'profile_changed')
    need(sc._safe(root/'.writer.lock')==tuple(p['writer_identity']),'writer_lock_changed')


def _database(path):
    files._quiet(path);sc._safe(path)
    need(Path(path).stat().st_size<=MAX_BYTES,'file_budget')
    c=sqlite3.connect('file:'+str(Path(path))+'?mode=ro',uri=True,timeout=.1)
    c.execute('PRAGMA query_only=ON');c.execute('PRAGMA cache_size=-2048');c.execute('BEGIN')
    c.set_progress_handler(lambda: int(_expired()),1000)
    return c


def _expired():
    try:files._clock();return False
    except MirrorError:return True


def _summary(path, *, require_integrity=False):
    from .common import quote_identifier as qi
    c=_database(path);total=0;count=0;tables={};schema=[]
    try:
        encoding=c.execute('PRAGMA encoding').fetchone()[0]
        need(encoding in ('UTF-8','UTF-16le','UTF-16be'),'encoding')
        factor=1 if encoding=='UTF-8' else 2
        try:c.execute("SELECT octet_length('')").fetchone()
        except sqlite3.Error:raise MirrorError('shard_restore_sqlite_unsupported') from None
        for kind,name,owner,sql in c.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'):
            files._clock()
            need(kind in ('table','index'),'unsupported_schema')
            schema.append([kind,name,owner,sql]);need(len(schema)<=MAX_TABLES*8,'schema_budget')
            if kind!='table':continue
            need(bool(re.fullmatch(r'Msg_[0-9a-f]{32}',name)) or name in ('Name2Id','__walden_binding','__walden_progress','__walden_observed','sqlite_sequence'),'unsupported_schema')
            need(sql is not None and 'VIRTUAL TABLE' not in sql.upper() and 'WITHOUT ROWID' not in sql.upper(),'unsupported_schema')
            cols=[r[1] for r in c.execute('PRAGMA table_info('+qi(name)+')')]
            need(cols and len(cols)<=128,'unsupported_schema')
            need(len(tables)<MAX_TABLES,'table_budget')
            headers=','.join('typeof('+qi(k)+'),octet_length('+qi(k)+')' for k in cols)
            h=hashlib.sha256();n=0
            for row in c.execute('SELECT rowid,'+headers+' FROM '+qi(name)+' NOT INDEXED ORDER BY rowid'):
                files._clock();size=0
                for kind_,length in zip(row[1::2],row[2::2]):
                    if kind_=='null':continue
                    need(type(length) is int and 0<=length<=MAX_ROW and factor*length<=MAX_ROW,'row_budget')
                    size+=factor*length
                total+=size
                need(total<=MAX_BYTES,'input_budget')
                with lossless_text_rows(c):
                    actual=c.execute('SELECT rowid,* FROM '+qi(name)+' WHERE rowid=?',(row[0],)).fetchone()
                need(actual is not None,'row_changed');h.update(bytes.fromhex(row_hash(actual)));n+=1
            tables[name]=dict(rows=n,sha256=h.hexdigest());count+=n
        if require_integrity:
            need([r[0] for r in c.execute('PRAGMA main.integrity_check')]==['ok'],'integrity')
        return dict(schema_sha256=digest(schema),tables=tables,rows=count,input_reserve_bytes=total)
    finally:c.close()


def _registry_image(c, key):
    # Current main is still protected by its original 128MiB cap. Streaming
    # hashes leave archive/list content and all authority rows untouched.
    sc._registry_page_size(c);h=hashlib.sha256();count=0
    for table,columns in [('binding','value'),('observations','id,proof'),('members','shard,table_name,proof'),('state','key,value')]:
        for row in c.execute('SELECT '+columns+' FROM '+table+' NOT INDEXED ORDER BY rowid'):
            files._clock()
            if table=='state' and row[0] in ('account_work',key):continue
            raw=encoded([table,list(row)]);count+=len(raw);need(count<=MAX_BYTES,'registry_budget');h.update(raw)
    return h.hexdigest()


def _members(config,c,shard,local):
    with closing(_database(local)) as db:
        need(db.execute('SELECT * FROM __walden_binding').fetchall()==[(config['account_id'],config['source_generation'],shard)],'binding')
        need(c.execute('SELECT 1 FROM state WHERE key LIKE ? LIMIT 1',('copy_init:'+shard+':%',)).fetchone() is None,'prepared_copy')
        need(c.execute('SELECT 1 FROM state WHERE key=?',('copy_shell:'+shard,)).fetchone() is None,'prepared_copy')
        observations=OrderedDict();n=0
        for table, in c.execute('SELECT table_name FROM members WHERE shard=? ORDER BY table_name',(shard,)):
            files._clock();proof=sc.member(config,c,shard,table,_observations=observations)
            sql=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
            pg=db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()
            need(sql is not None and pg is not None,'member_copy_missing')
            need(hashlib.sha256(sql[0].encode()).hexdigest()==proof['schema_sha256'],'member_schema')
            value=json.loads(pg[0])
            need(value.get('source_identity')==proof['source_identity'] and value.get('source_header_sha256')==proof['header'],'member_source')
            n+=1
        need(n>0,'no_members')
        return n


def _control(p, *, initial=False, held=False):
    from .native_scope_migrate import _quiescent, _control_facts
    if initial:
        value=_quiescent(p,initial=True)
        if 'quiescence' in p:need(value['control']==p['quiescence']['control'],'control_changed')
        return value
    # Same existing post-pending quiescence predicates, with the original SDK
    # proof pinned in this plan instead of a different migration's directory.
    from . import native_follow as follow
    from .native_schedule import LaunchctlTransport, _observe, _writer_state
    run=LaunchctlTransport();before=_control_facts(p,run)
    need(run.context==p['follow']['context'] and before==p['quiescence']['control'],'control_changed')
    need(follow.kernel.drained(before['listener']),'listener_not_drained')
    if before['worker'] is not None:need(run.process.drained(before['worker']['leader']),'worker_not_drained')
    need(_observe(run,before['listener_target'])=='absent','listener_present')
    if before['worker_target'] is not None:need(_observe(run,before['worker_target'])=='absent','worker_present')
    if not held:need(_writer_state(p['old_config'])=='free','writer_busy')
    need(run.context==p['follow']['context'] and _control_facts(p,run)==before,'control_changed')
    return dict(control=before)


@files._bounded
def plan(profile,replacement,target_ref,output):
    from .source_setup import load_source_config
    from .native_scope_add import _follow
    from .native_mirror_sync import writer_lock
    profile=Path(profile).absolute();output=Path(output).absolute();replacement=Path(replacement).absolute()
    config=load_source_config(profile,physical=False);need(sc.mode(config)=='account','account_required')
    _layout(config,output=output,replacement=replacement)
    root=Path(config['mirror_root']);need(output.parent!=root and not output.exists(),'plan_path')
    token=sc.query_scope_guard(config);profile_raw,profile_fact=read(profile)
    store,follow=_follow(profile,config)
    generation=uuid.uuid4().hex;state_root=root/('.shard-restore-'+generation)
    p=dict(schema=FORMAT,owner='single_local_shard',generation=generation,profile=str(profile),profile_fact=profile_fact,
           profile_sha256=hashlib.sha256(profile_raw).hexdigest(),old_config=config,scope_token=list(token),
           root_identity=files._directory_info(root),writer_identity=list(sc._safe(root/'.writer.lock')),
           follow=follow,policy=store.read('policy.'+follow['generation']+'.json'),runtime=store.read('instance.'+follow['nonce']+'.json'),
           state_root=str(state_root),plan_path=str(output),replacement=str(replacement),tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    p['quiescence']=_control(p,initial=True)
    with writer_lock(root,0):
        _scope(p)
        need(not state_root.exists() and not any(root.glob('.shard-restore-*')),'prior_attempt')
        with sc.registry(config,snapshot=False) as c:
            matches=[(s,t) for s,t in c.execute('SELECT shard,table_name FROM members') if sc.target_ref(config,s,t)==target_ref]
            need(len(matches)==1,'target')
            shard,_=matches[0];old=root/shard
            need(old!=replacement and files._info(old)[:2]!=files._info(replacement)[:2],'same_file')
            n=_members(config,c,shard,old)
            p.update(shard=shard,target_ref=target_ref,old_identity=files._info(old),old_sha256=files.file_hash(old),
                     replacement_identity=files._info(replacement),replacement_sha256=files.file_hash(replacement),
                     registry_identity=list(sc._safe(root/sc.REGISTRY)))
            key='local_shard_restore:'+generation;p['record_key']=key;p['registry_image']=_registry_image(c,key)
            a=_summary(old);b=_summary(replacement,require_integrity=True)
            need(a['schema_sha256']==b['schema_sha256'] and a['tables']==b['tables'],'not_equivalent')
            p.update(equivalence_sha256=digest([a['schema_sha256'],a['tables']]),rows=a['rows'],tables=len(a['tables']),members=n)
        need(files._info(old)==p['old_identity'] and files.file_hash(old)==p['old_sha256'],'old_changed')
        need(files._info(replacement)==p['replacement_identity'] and files.file_hash(replacement)==p['replacement_sha256'],'replacement_changed')
        _scope(p);_control(p,held=True)
        create(output,encoded(p))
    return dict(status='planned',plan=str(output),plan_sha256=hashlib.sha256(encoded(p)).hexdigest(),tables=p['tables'],rows=p['rows'],source_opens=0)


def _load(path,expected):
    p,raw,_=_json(path)
    need(expected is not None and hashlib.sha256(raw).hexdigest()==expected and p.get('schema')==FORMAT and p.get('owner')=='single_local_shard','plan')
    need(p.get('tool_sha256')==hashlib.sha256(Path(__file__).read_bytes()).hexdigest() and re.fullmatch('[0-9a-f]{32}',p.get('generation','')),'plan')
    need(sc.SHARD.fullmatch(p.get('shard','')) and p.get('state_root')==str(Path(p['old_config']['mirror_root'])/('.shard-restore-'+p['generation'])),'plan')
    need(p.get('record_key')=='local_shard_restore:'+p['generation'],'plan')
    _layout(p['old_config'],output=p['plan_path'],replacement=p['replacement'],state_root=p['state_root'])
    _layout(p['old_config'],output=Path(path).absolute())
    return p,raw


def _exact(path,identity,sha256):
    path=Path(path);files._quiet(path)
    with directory(path.parent) as parent:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            before=os.fstat(fd);fields=lambda n:[n.st_dev,n.st_ino,n.st_size,n.st_mtime_ns]
            need(fields(before)==identity and stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid()
                 and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1,'side_changed')
            h=hashlib.sha256()
            while True:
                files._clock();raw=os.read(fd,1024*1024)
                if not raw:break
                h.update(raw)
            after=os.fstat(fd);current=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            need(fields(after)==fields(current)==identity and before.st_ctime_ns==after.st_ctime_ns==current.st_ctime_ns
                 and h.hexdigest()==sha256,'side_changed')
        finally:os.close(fd)
    files._quiet(path)


def _committed(p,plan_sha,new_identity):
    return dict(schema=FORMAT,state='committed',plan_sha256=plan_sha,shard=p['shard'],
        old_identity=p['old_identity'],old_sha256=p['old_sha256'],initial_new_identity=new_identity,
        initial_new_sha256=p['replacement_sha256'],equivalence_sha256=p['equivalence_sha256'])


def _copy(source,dest):
    # Interrupted unsealed copies are retained and refused, never adopted or
    # silently truncated. Automatic resume begins at a durably sealed image.
    from .native_scope_add import directory
    fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with Path(source).open('rb') as src:
            while True:
                files._clock();raw=src.read(1024*1024)
                if not raw:break
                at=0
                while at<len(raw):at+=os.write(fd,raw[at:])
        os.fsync(fd);n=os.fstat(fd);identity=[n.st_dev,n.st_ino,n.st_size,n.st_mtime_ns]
    finally:os.close(fd)
    with directory(Path(dest).parent) as parent:os.fsync(parent)
    return identity


@files._bounded
def restore(path,expected,*,confirmed=False,_checkpoint=lambda stage:None):
    from .native_mirror_sync import writer_lock
    p,plan_raw=_load(path,expected);config=p['old_config'];root=Path(config['mirror_root'])
    stage=Path(p['state_root']);canonical=root/p['shard'];pending=root/sc.PENDING
    marker=dict(schema=FORMAT,state='pending',owner='single_local_shard',plan_sha256=expected,generation=p['generation'])
    fence=None
    if os.path.lexists(pending):
        value,raw,fact=_json(pending)
        stage_id=value.get('stage_identity')
        need(type(stage_id) is list and len(stage_id)==3 and all(type(v)is int and v>=0 for v in stage_id),'foreign_pending')
        marker=dict(marker,stage_identity=stage_id)
        need(raw==encoded(marker),'foreign_pending');fence=dict(raw=raw,fact=fact,stage_identity=stage_id)
    else:
        _scope(p)
        if (stage/'receipt.json').exists():
            receipt,_,_=_json(stage/'receipt.json')
            need(receipt.get('state')=='committed' and receipt.get('plan_sha256')==expected,'receipt')
            _stage(stage,receipt['stage_identity'])
            with writer_lock(root,0):
                _scope(p);_stage(stage,receipt['stage_identity'])
                need(list(sc._safe(canonical))==receipt['initial_new_identity'][:2],'side_changed')
                _exact(stage/'old.db',p['old_identity'],p['old_sha256'])
                record=_committed(p,expected,receipt['initial_new_identity'])
                need(receipt==dict(record,stage_identity=receipt['stage_identity'],old_preserved=True),'receipt')
                with sc.registry(config,snapshot=False) as c:
                    need(sc.state(c,p['record_key'])==record,'record_changed')
                _scope(p);_stage(stage,receipt['stage_identity'])
                need(list(sc._safe(canonical))==receipt['initial_new_identity'][:2],'side_changed')
            # Ordinary subsequent sync may have advanced this file. Do not
            # compare against its initial hash or reinstall the old snapshot.
            return dict(status='already_restored',publication_only=True,source_opens=0,mutated=False)
        need(not stage.exists(),'unwitnessed_stage')
        _control(p,initial=True)
    if not confirmed:return dict(status='confirmation_required',source_opens=0,mutated=False)
    with writer_lock(root,0):
        if fence is None:
            _scope(p);_control(p,held=True)
            _exact(canonical,p['old_identity'],p['old_sha256'])
            _exact(Path(p['replacement']),p['replacement_identity'],p['replacement_sha256'])
            stage.mkdir(mode=0o700)
            stage_id=files._directory_info(stage)
            create(stage/'owner.json',encoded(dict(schema=FORMAT,plan_sha256=expected,stage_identity=stage_id)))
            # Existing _quiescent pins the already-stopped control image, not
            # Source authority; store it before the old entry points are fenced.
            _control(p,held=True)
            create(stage/'quiescence.json',encoded(p['quiescence']))
            marker=dict(marker,stage_identity=stage_id);marker_raw=encoded(marker)
            create(pending,marker_raw);raw,fact=read(pending)
            fence=dict(raw=raw,fact=fact,stage_identity=stage_id,expected_identity=list(sc._safe(pending)))
            _checkpoint('blocked')
            _scope(p,pending=fence)
            copied_identity=_copy(p['replacement'],stage/'new.db')
            _exact(Path(p['replacement']),p['replacement_identity'],p['replacement_sha256'])
            _exact(stage/'new.db',copied_identity,p['replacement_sha256'])
            _stage(stage,stage_id)
            create(stage/'seal.json',encoded(dict(schema=FORMAT,plan_sha256=expected,stage_identity=stage_id,new_identity=copied_identity,pending_identity=fence['expected_identity'])))
        _stage(stage,fence['stage_identity'])
        try:owner,_,_=_json(stage/'owner.json');seal,_,_=_json(stage/'seal.json')
        except FileNotFoundError:raise MirrorError('shard_restore_unsealed_stage') from None
        need(owner==dict(schema=FORMAT,plan_sha256=expected,stage_identity=fence['stage_identity']),'stage_changed')
        need(seal.get('schema')==FORMAT and seal.get('plan_sha256')==expected and seal.get('stage_identity')==fence['stage_identity'],'seal')
        pin=seal.get('pending_identity')
        need(type(pin)is list and len(pin)==2 and all(type(v)is int and v>=0 for v in pin),'seal')
        fence['expected_identity']=pin
        new_id=seal['new_identity'];_scope(p,pending=fence);_control(p,held=True)
        _checkpoint('before_swap')
        _scope(p,pending=fence)
        if list(sc._safe(canonical))==p['old_identity'][:2]:
            _exact(canonical,p['old_identity'],p['old_sha256'])
            _exact(stage/'new.db',new_id,p['replacement_sha256'])
            files._rename(stage/'new.db',canonical,exchange=True)
            _scope(p,pending=fence)
            _checkpoint('swapped')
            _scope(p,pending=fence)
        else:need(list(sc._safe(canonical))==new_id[:2],'side_changed')
        _exact(canonical,new_id,p['replacement_sha256'])
        if not (stage/'old.db').exists():
            _exact(stage/'new.db',p['old_identity'],p['old_sha256'])
            files._rename(stage/'new.db',stage/'old.db')
        _scope(p,pending=fence)
        _exact(stage/'old.db',p['old_identity'],p['old_sha256'])
        record=_committed(p,expected,new_id)
        _scope(p,pending=fence);_control(p,held=True)
        need(list(sc._safe(root/sc.REGISTRY))==p['registry_identity'],'registry_changed')
        with sc.registry(config,write=True) as c:
            from .native_mirror_sync import _require_trigger_free
            _require_trigger_free(c,'main')
            need(_registry_image(c,p['record_key'])==p['registry_image'],'registry_changed')
            existing=sc.state(c,p['record_key'])
            need(existing is None or existing==record,'record_changed')
            if existing is None:
                sc.save(c,'account_work',None);sc.save(c,p['record_key'],record);c.commit()
            need(sc.state(c,p['record_key'])==record and sc.state(c,'account_work') is None,'record_changed')
            need(_registry_image(c,p['record_key'])==p['registry_image'],'registry_changed')
        _checkpoint('registered')
        _scope(p,pending=fence);_control(p,held=True)
        _exact(canonical,new_id,p['replacement_sha256']);_exact(stage/'old.db',p['old_identity'],p['old_sha256'])
        receipt=dict(record,stage_identity=fence['stage_identity'],old_preserved=True)
        if (stage/'receipt.json').exists():need(read(stage/'receipt.json')[0]==encoded(receipt),'receipt')
        else:create(stage/'receipt.json',encoded(receipt))
        _checkpoint('receipt')
        _scope(p,pending=fence);_control(p,held=True)
        _exact(canonical,new_id,p['replacement_sha256']);_exact(stage/'old.db',p['old_identity'],p['old_sha256'])
        _scope(p,pending=fence)
        need(read(pending)==(fence['raw'],fence['fact']),'pending_changed')
        files._rename(pending,stage/'pending.json')
    return dict(status='restored',source_opens=0,old_preserved=True,tables=p['tables'],rows=p['rows'],physical_replacement=True)


def status(path,expected):
    p,_=_load(path,expected);root=Path(p['old_config']['mirror_root']);stage=Path(p['state_root'])
    if os.path.lexists(root/sc.PENDING):
        value,raw,_=_json(root/sc.PENDING)
        need(value.get('schema')==FORMAT and value.get('owner')=='single_local_shard' and value.get('plan_sha256')==expected,'foreign_pending')
        return dict(status='pending',writer_authorized=False,source_opens=0)
    return dict(status='receipt_present' if (stage/'receipt.json').exists() else 'planned',source_opens=0)
