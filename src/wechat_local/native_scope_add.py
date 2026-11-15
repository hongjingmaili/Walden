"""One explicit daily-scope append. No Source reads, sync, service control or reset."""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid
from .native_mirror_store import MirrorError


def need(ok, code='scope_add_refused'):
    if not ok:raise MirrorError(code)


def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def marker_path(profile):return Path(profile).absolute().with_name(Path(profile).name+'.scope-add.pending')


def identity(info, stable=False):
    names=('st_dev','st_ino','st_uid','st_gid','st_nlink')
    if stat.S_ISDIR(info.st_mode):names=('st_dev','st_ino','st_uid','st_gid')
    elif not stable:names+=('st_size','st_mtime_ns','st_ctime_ns')
    return dict({k[3:]:getattr(info,k) for k in names},mode=stat.S_IMODE(info.st_mode))


@contextmanager
def directory(path):
    path=Path(path).absolute();need('..' not in path.parts)
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for name in path.parts[1:]:
            nxt=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=nxt;info=os.fstat(fd)
            need(info.st_uid in (0,os.getuid()) and not info.st_mode&0o022,'scope_add_unsafe_parent')
        yield fd
    finally:os.close(fd)


def read(path):
    path=Path(path).absolute()
    with directory(path.parent) as parent:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o600
                 and info.st_nlink==1 and info.st_size<=4*1024*1024,'scope_add_unsafe_file')
            raw=stream.read(4*1024*1024+1)
            need(identity(info)==identity(os.fstat(stream.fileno())) and len(raw)==info.st_size,'scope_add_file_changed')
        return raw,dict(sha256=sha(raw),stat=identity(info),parent=identity(os.fstat(parent),True))


def create(path,raw):
    path=Path(path)
    with directory(path.parent) as parent:
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),0o600);stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.fsync(parent)
    return read(path)[1]


def scope_guard(profile, before=None):
    """Normal loader has no bypass: any pending/foreign/corrupt marker refuses."""
    path=Path(profile).expanduser().absolute();marker=marker_path(path)
    try:marker.lstat()
    except FileNotFoundError:pass
    else:raise MirrorError('scope_add_pending')
    current=dict(stat=identity(path.lstat()),parent=identity(path.parent.stat(),True))
    if before is not None:need(current==before,'scope_add_profile_changed')
    # This is a before/after observation, not an atomic lock for in-flight queries.
    try:marker.lstat()
    except FileNotFoundError:return current
    raise MirrorError('scope_add_pending')


def query_scope_guard(config):
    """Checkpoints only: reject pending migration or an old loaded daily scope."""
    if not config.get('mirror_root'):return
    root=Path(config['mirror_root'])
    try:(root/'.scope-add.pending').lstat()
    except FileNotFoundError:pass
    else:raise MirrorError('scope_add_pending')
    try:raw,_=read(root/'.scope-add.current')
    except FileNotFoundError:return
    value=json.loads(raw)
    need(value.get('schema')=='walden.scope-add.current/1' and value.get('binding')==
         [config['account_id'],config['source_generation'],config['mirror_scope']], 'scope_add_config_stale')
    receipt,_=read(value['receipt'])
    need(sha(receipt)==value.get('receipt_sha256') and json.loads(receipt).get('state')=='committed','scope_add_commit_invalid')
    try:(root/'.scope-add.pending').lstat()
    except FileNotFoundError:return
    raise MirrorError('scope_add_pending')


def loaded_scope_guard(profile,config):
    # Old immutable policy snapshots remain readable by original SDK Stop. Only
    # the authenticated current profile is checked here; query checks all scopes.
    if not config.get('mirror_root'):return
    try:raw,_=read(Path(config['mirror_root'])/'.scope-add.current')
    except FileNotFoundError:return
    value=json.loads(raw);need(value.get('schema')=='walden.scope-add.current/1','scope_add_commit_invalid')
    current=str(Path(profile).expanduser().absolute())
    if current==value.get('prior_snapshot'):
        from .native_follow_policy import digest
        need(digest(config)==value.get('prior_signature'),'scope_add_commit_invalid')
        return
    query_scope_guard(config)


def scope_bytes(raw, scope):
    """Replace only the unique root mirror_scope value, retaining all other bytes."""
    text=raw.decode('utf-8')
    def unique(pairs):
        result={}
        for k,v in pairs:
            need(k not in result,'scope_add_duplicate_config_key');result[k]=v
        return result
    value=json.loads(text,object_pairs_hook=unique)
    need(type(value) is dict and 'mirror_scope' in value,'scope_add_scope_missing')
    decoder=json.JSONDecoder();at=0
    def ws(i):
        while i<len(text) and text[i] in ' \t\r\n':i+=1
        return i
    at=ws(at);need(text[at]=='{');at+=1;found=None
    while True:
        at=ws(at)
        if text[at]=='}':break
        key,end=decoder.raw_decode(text,at);at=ws(end);need(text[at]==':');start=ws(at+1)
        _,end=decoder.raw_decode(text,start)
        if key=='mirror_scope':need(found is None);found=(start,end)
        at=ws(end)
        if text[at]=='}':break
        need(text[at]==',');at+=1
    need(found is not None)
    a,z=found;result=(text[:a]+json.dumps(scope,ensure_ascii=False,separators=(',',':'))+text[z:]).encode()
    expected=dict(value,mirror_scope=scope);need(json.loads(result)==expected)
    return result


def _profile(raw):
    from .source_setup import _decode_source_config,_confirmed_self_username
    value=_decode_source_config(raw)
    need(_confirmed_self_username(value,physical=False) is not None,'scope_add_self_unconfirmed')
    return value


def _daily(config):
    from .native_follow_policy import Store
    from .native_mirror_sync import mirror_root
    root=mirror_root(config,create=False)
    need(Store(root).read('request-window.json') is None,'scope_add_request_cache_forbidden')
    need((root/'__walden_status.db').is_file(),'scope_add_existing_daily_required')
    return root


def _media(config, writable=False):
    from .live_readonly import readonly_database_uri
    path=_daily(config)/'media-work.sqlite'
    with directory(path.parent):
        info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid()
            and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'scope_add_media_identity')
    c=sqlite3.connect(readonly_database_uri(path).replace('mode=ro','mode=rw') if writable else readonly_database_uri(path),uri=True,timeout=.1)
    if not writable:c.execute('PRAGMA query_only=ON')
    return c,dict(stat=identity(info,True),parent=identity(path.parent.stat(),True))


def _binding(c):
    rows=c.execute('SELECT id,value FROM binding').fetchall()
    need(len(rows)==1 and rows[0][0]==1,'scope_add_media_binding')
    return rows[0][1]


def effects(c):
    """Exact schema and typed row/rowid digest; excludes only singleton binding value."""
    from .common import quote_identifier as qi
    from .native_mirror_store import lossless_text_rows
    from .native_source_recovery import row_hash
    schema=c.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name").fetchall()
    result=dict(schema_sha256=sha(encoded(schema)),tables={},user_version=c.execute('PRAGMA user_version').fetchone()[0],application_id=c.execute('PRAGMA application_id').fetchone()[0])
    for kind,name,_,ddl in schema:
        if kind!='table' or name=='binding':continue
        need(not ddl or 'WITHOUT ROWID' not in ddl.upper(),'scope_add_unsupported_media_schema')
        with lossless_text_rows(c):hashes=sorted(row_hash(row) for row in c.execute('SELECT rowid,* FROM '+qi(name)))
        result['tables'][name]=dict(count=len(hashes),sha256=sha(encoded(hashes)))
    return result


def _actor_status(state,grant,snapshot):
    if grant['kind']=='request':
        from .native_request_record import inspect
        return inspect(state,grant,snapshot)
    from .native_schedule import inspect_status
    runtime=Path(snapshot['runtime_python'])
    need(grant['kind'] in ('directory_probe','source_recovery') and runtime.is_absolute()
         and snapshot['window_cli']==str(runtime.parent/'wechat-local-window')
         and snapshot['reply_cli']==str(runtime.parent/'wechat-local-reply')
         and Path(state['profile']).is_absolute() and Path(state['services']).is_absolute(),'scope_add_actor_metadata')
    observed=inspect_status(snapshot,state['profile'],runtime.parent/'wechat-local-sync',state['services'],follow_grant=state['descriptor'])
    if observed.get('stop_confirmed') is True:
        need(observed.get('operation_id')==state.get('operation'),'scope_add_actor_metadata')
    return observed


def _actor_metadata(profile, config):
    """Enumerate only protected role metadata, never selected cache bodies."""
    from .native_target_request import root_for
    from .native_follow_policy import Store,digest
    from .native_schedule import _config_facts
    root=root_for(config);records=[]
    patterns=(('requests','*/request.json','request'),('requests','*/runtime-*/request.json','request'),
              ('directory-probes','*/probe.json','directory_probe'),('source-recovery','*/*/recovery.json','source_recovery'))
    paths=[]
    for folder,pattern,kind in patterns:
        base=root/folder
        need(not base.is_symlink(),'scope_add_actor_metadata')
        if base.exists():
            Store(base)
            from .native_request_record import _empty_container
            units=list(base.iterdir());need(len(units)<=256,'scope_add_actor_limit')
            for unit in units:
                Store(unit)
                if folder=='requests':
                    need((unit/'request.json').is_file() or _empty_container(unit,runtime_dirs=True),'scope_add_actor_metadata')
                    for child in unit.glob('runtime-*'):
                        Store(child);need((child/'request.json').is_file() or _empty_container(child),'scope_add_actor_metadata')
                elif folder=='directory-probes':
                    need((unit/'probe.json').is_file() or _empty_container(unit),'scope_add_actor_metadata')
                else:
                    children=[x for x in unit.iterdir() if x.is_dir() or x.is_symlink()]
                    need(bool(children) or _empty_container(unit),'scope_add_actor_metadata')
                    for child in children:
                        Store(child);need((child/'recovery.json').is_file(),'scope_add_actor_metadata')
            matches=list(base.glob(pattern));need(len(matches)<=256,'scope_add_actor_limit')
            paths.extend((path,kind) for path in matches)
    need(len(paths)<=256,'scope_add_actor_limit')
    for path,kind in sorted(paths):
        Store(path.parent);state_raw,state_fact=read(path);state=json.loads(state_raw)
        grant_raw,grant_fact=read(state['descriptor']['path']);grant=json.loads(grant_raw)
        need(grant.get('kind')==kind and grant.get('authorized') is True and digest(grant)==state['descriptor']['sha256']==state['active_grant_sha256'], 'scope_add_actor_metadata')
        need(type(grant.get('source_profile')) is str and Path(grant['source_profile']).is_absolute(),'scope_add_actor_metadata')
        if grant['source_profile']!=str(profile):continue
        snapshot_raw,snapshot_fact=read(state['profile']);snapshot=_profile(snapshot_raw)
        need(all(encoded(snapshot.get(k))==encoded(config.get(k)) for k in
                 ('account_id','source_generation','self_identity','live_db_root','message_root','passphrase_file'))
             and digest(snapshot)==grant['snapshot_sha256'] and _config_facts(snapshot)==grant['config_sha256'], 'scope_add_actor_metadata')
        facts=dict(path=str(path),state=state_fact,grant=grant_fact,snapshot=snapshot_fact,kind=kind)
        records.append(dict(facts=facts,state=state,grant=grant,snapshot=snapshot))
    return records



def actor_cohort(profile,config,*,capability=None,recovery_capability=None,proof_sink=None):
    records=[]
    for item in _actor_metadata(profile,config):
        facts=item['facts'];state=item['state'];grant=item['grant'];snapshot=item['snapshot']
        observed=_actor_status(state,grant,snapshot)
        if facts['kind']=='directory_probe' and observed.get('state')=='unknown' and capability is not None:
            from .native_schedule import inspect_scope_probe_terminal_status
            special=inspect_scope_probe_terminal_status(capability)
            need(special.get('status')=='retired_probe_terminal_proven','scope_add_independent_actor_not_stopped')
            need(special['record_sha256']==facts['state']['sha256'] and special['record_path']==facts['path'],'scope_add_actor_changed')
            observed=special['proof'];facts=dict(facts,retired_probe_terminal_proven=True)
            if proof_sink is not None:proof_sink.append(special)
        if facts['kind']=='source_recovery' and observed.get('state')=='unknown' and recovery_capability is not None:
            from .native_schedule import inspect_scope_recovery_terminal_status
            special=inspect_scope_recovery_terminal_status(recovery_capability,facts['path'],facts['state']['sha256'])
            need(special.get('status')=='retired_recovery_terminal_proven' and special['record_path']==facts['path'] and special['record_sha256']==facts['state']['sha256'],'scope_add_independent_actor_not_stopped')
            observed=special['proof'];facts=dict(facts,retired_recovery_terminal_proven=True)
            if proof_sink is not None:proof_sink.append(special)
        need(observed.get('registration')=='absent' and observed.get('group_drained') is True
             and observed.get('writer_lock')=='free' and observed.get('stop_confirmed') is True,'scope_add_independent_actor_not_stopped')
        records.append(facts)
    if recovery_capability is not None:
        from .native_schedule import _scope_recovery_authority_check
        _scope_recovery_authority_check(recovery_capability,recovery_capability._run)
    return records


def _probe_file(path):
    path=Path(path)
    try:return read(path)[1]
    except FileNotFoundError:
        with directory(path.parent) as parent:
            return dict(absent=True,parent=identity(os.fstat(parent),True))


def _probe_pin(profile,config,record_path,record_sha,current_context):
    import re,plistlib
    from . import native_schedule as sdk
    from .native_target_request import root_for
    from .native_follow_policy import Store,digest
    need(type(record_sha) is str and re.fullmatch('[0-9a-f]{64}',record_sha) is not None,'scope_add_probe_pin')
    record_path=Path(record_path).absolute();cohort=_actor_metadata(profile,config)
    probes=[v for v in cohort if v['facts']['kind']=='directory_probe']
    need(len(probes)==1 and probes[0]['facts']['path']==str(record_path)
         and probes[0]['facts']['state']['sha256']==record_sha,'scope_add_probe_pin')
    item=probes[0];state=item['state'];grant=item['grant'];snapshot=item['snapshot'];unit=record_path.parent
    runtime=Path(snapshot['runtime_python'])
    need(snapshot.get('mirror_root')==str(unit/'cache') and runtime.is_absolute()
         and snapshot.get('window_cli')==str(runtime.parent/'wechat-local-window')
         and snapshot.get('reply_cli')==str(runtime.parent/'wechat-local-reply'),'scope_add_probe_snapshot_binding')
    canonical=root_for(config)/'directory-probes'
    need(unit.parent==canonical and record_path.name=='probe.json' and re.fullmatch('[0-9a-f]{32}',unit.name) is not None,'scope_add_probe_pin')
    nonce=grant.get('nonce');descriptor=state['descriptor']
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce) is not None
         and grant.get('root')==grant.get('store_root')==str(unit)
         and grant.get('source_profile')==state.get('source_profile')==str(profile)
         and grant.get('kind')=='directory_probe' and grant.get('authorized') is True
         and grant.get('scope')=='directory_discovery_once' and grant.get('instance_nonce')==state.get('id')==unit.name
         and grant.get('snapshot')==state['profile']==str(unit/'source.json')
         and descriptor['path']==str(unit/('grant.'+nonce+'.json'))
         and descriptor.get('label_id')==digest([config['account_id'],config['source_generation'],'directory_probe'])[:20]+'.'+unit.name
         and state.get('services')==str(unit/'workers'),'scope_add_probe_pin')
    services=Path(state['services']);Store(services)
    label=sdk._schedule_label(snapshot,descriptor);active=services/(label+'.plist')
    slot=sdk._slot_view(active)
    if active.exists():selected=active;suffix=''
    else:
        archives=list(services.glob(active.name+'.disabled-*'))
        need(bool(archives),'scope_add_probe_pin')
        def order(path):
            value=path.name[len(active.name+'.disabled-'):]
            need(value.isdecimal(),'scope_add_probe_pin');return int(value)
        selected=max(archives,key=order);suffix=selected.name[len(active.name):]
    owned=active.with_suffix('.owned').with_name(active.with_suffix('.owned').name+suffix)
    need(state.get('record')==str(active.with_suffix('.owned')),'scope_add_probe_pin')
    plist_raw,plist_fact=read(selected);owned_raw,owned_fact=read(owned)
    payload=plistlib.loads(plist_raw);record=json.loads(owned_raw)
    need(record.get('operation')==state.get('operation') and type(state.get('operation')) is str
         and re.fullmatch('[0-9a-f]{32}',state['operation']) is not None
         and record.get('follow_grant')==descriptor['path'] and record.get('follow_grant_sha256')==descriptor['sha256']
         and record.get('config_sha256')==sdk._config_facts(snapshot)
         and record.get('plist_sha256')==sha(plist_raw)
         and sdk._probe_same(record.get('plist_identity'),[plist_fact['stat']['dev'],plist_fact['stat']['ino']])
         and sdk._probe_same(record.get('os_context'),grant.get('os_context'))
         and sdk._probe_same(state.get('os_context'),grant.get('os_context')),'scope_add_probe_pin')
    need(sdk._probe_same(record.get('os_context'),current_context)
         or sdk._retired_context_delta(record.get('os_context'),current_context),'scope_add_probe_context')
    need(type(grant.get('round_seconds')) is int and grant['round_seconds']==30
         and all(type(v) is int and v==1 for v in (grant.get('interval_seconds'),descriptor.get('interval_seconds'),record.get('interval_seconds')))
         and sdk._probe_same(grant.get('deadline'),descriptor.get('deadline'))
         and sdk._probe_same(grant.get('deadline'),record.get('deadline')),'scope_add_probe_deadline')
    sdk._probe_expired(grant['deadline'])
    paths=[active,active.with_suffix('.owned'),active.with_suffix('.runtime'),active.with_suffix('.active'),active.with_suffix('.starting'),active.with_suffix('.submission')]
    paths+=[selected,owned]+[active.with_suffix(ext).with_name(active.with_suffix(ext).name+suffix) for ext in ('.runtime','.active','.starting','.submission')]
    files={str(path):_probe_file(path) for path in sorted(set(paths))}
    need(_probe_file(selected)==plist_fact and _probe_file(owned)==owned_fact,'scope_add_probe_changed')
    need(encoded(sdk._slot_view(active))==encoded(slot)
         and encoded([v['facts'] for v in _actor_metadata(profile,config)])==encoded([v['facts'] for v in cohort]),'scope_add_actor_changed')
    need(all(_probe_file(path)==fact for path,fact in files.items()),'scope_add_probe_changed')
    return dict(record_path=str(record_path),record_sha256=record_sha,state=state,grant=grant,snapshot=snapshot,
        record=record,payload=payload,files=files,slot=json.loads(json.dumps(slot)),cohort=[v['facts'] for v in cohort],
        raw_old_context=record['os_context'],raw_current_context=current_context)


def _scope_actor_base_facts(plan_path,expected_plan_sha):
    from . import native_schedule as sdk
    path=Path(plan_path).absolute();plan_raw,plan_fact=read(path);p=_plan(path,expected_plan_sha)
    need(p.get('plan_path')==str(path) and p.get('scope_sdk_sha256')==sha(Path(sdk.__file__).read_bytes()),'scope_add_actor_authority')
    profile=Path(p['profile']);pending=False
    for marker in (marker_path(profile),Path(p['mirror_root'])/'.scope-add.pending'):
        try:marker.lstat();pending=True
        except FileNotFoundError:pass
    if pending:
        _,_,old,_=_authenticate(p,expected_plan_sha);current_raw,current_fact=read(profile)
    else:
        scope_guard(profile);current_raw,current_fact=read(profile)
        need(current_fact==p['profile_fact'] and sha(current_raw)==p['old_sha256'],'scope_add_foreign_profile');old=_profile(current_raw)
    need(old['mirror_scope']==p['old_scope'],'scope_add_actor_authority')
    ref_raw,ref_fact=read(p['reference']);need(ref_fact==p['reference_fact'] and sha(ref_raw)==p['reference_sha256'],'scope_add_reference_changed')
    need(read(path)==(plan_raw,plan_fact) and read(profile)==(current_raw,current_fact),'scope_add_actor_changed')
    return p,old,dict(plan_path=str(path),plan_sha256=expected_plan_sha,plan_fact=plan_fact,current_c=current_fact,reference=ref_fact)


def _scope_actor_facts_final(p,common):
    need(read(common['plan_path'])[1]==common['plan_fact'] and read(p['profile'])[1]==common['current_c']
         and read(p['reference'])[1]==common['reference'],'scope_add_actor_changed')


def _scope_probe_authority_facts(plan_path,expected_plan_sha,current_context):
    from . import native_schedule as sdk
    p,old,common=_scope_actor_base_facts(plan_path,expected_plan_sha)
    need(type(p.get('probe')) is dict and sdk._probe_same(current_context,p['probe']['raw_current_context']),'scope_add_probe_authority')
    pin=_probe_pin(Path(p['profile']),old,p['probe']['record_path'],p['probe']['record_sha256'],current_context)
    need(encoded(pin)==encoded(p['probe']),'scope_add_probe_changed');_scope_actor_facts_final(p,common)
    return dict(common,record_sha256=pin['record_sha256'],state=pin['state'],grant=pin['grant'],snapshot=pin['snapshot'],record=pin['record'],payload=pin['payload'],pin=pin)


def _recovery_artifact_fact(path):
    path=Path(path)
    with directory(path.parent) as parent:
        info=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o400,'scope_add_recovery_artifact')
        return dict(stat=identity(info),parent=identity(os.fstat(parent),True))


def _recovery_member_pin(profile,config,item,expected,current_context):
    import re,plistlib
    from . import native_schedule as sdk
    from .native_target_request import root_for
    from .native_follow_policy import Store,digest
    from .source_setup import _confirmed_self_username
    path=Path(item['facts']['path']);unit=path.parent;state=item['state'];grant=item['grant'];snapshot=item['snapshot'];descriptor=state['descriptor']
    need(path.name=='recovery.json' and path==Path(expected['record_path']).absolute() and item['facts']['state']['sha256']==expected['record_sha256'],'scope_add_recovery_pin')
    need(unit.parent.parent==root_for(config)/'source-recovery' and re.fullmatch('[0-9a-f]{32}',unit.name) is not None
         and unit.parent.name==digest([grant.get('source_signature'),'committed_daily_only'])[:32],'scope_add_recovery_pin')
    runtime=Path(snapshot['runtime_python'])
    need(snapshot.get('mirror_root')==str(unit/'worker-cache') and runtime.is_absolute()
         and snapshot.get('window_cli')==str(runtime.parent/'wechat-local-window') and snapshot.get('reply_cli')==str(runtime.parent/'wechat-local-reply'),'scope_add_recovery_snapshot_binding')
    need(grant.get('kind')=='source_recovery' and grant.get('scope')=='committed_daily_only' and grant.get('authorized') is True
         and type(grant.get('accept')) is bool and type(state.get('accept')) is bool and state['accept']==grant['accept']
         and grant.get('nonce')==grant.get('instance_nonce')==state.get('id')==unit.name
         and grant.get('root')==grant.get('store_root')==str(unit) and grant.get('source_profile')==state.get('source_profile')==str(profile)
         and grant.get('snapshot')==state['profile']==str(unit/'source.json') and state.get('services')==str(unit/'workers')
         and descriptor.get('path')==str(unit/('grant.'+unit.name+'.json'))
         and descriptor.get('label_id')==digest([config['account_id'],config['source_generation'],'source_recovery'])[:20]+'.'+unit.name
         and all(type(grant.get(k)) is str and re.fullmatch('[0-9a-f]{64}',grant[k]) is not None for k in ('source_raw_sha256','source_signature')),'scope_add_recovery_pin')
    need(type(grant.get('auxiliary_refresh',False)) is bool and (not grant.get('auxiliary_refresh') or grant.get('auxiliary_snapshot_root')==str(unit/'auxiliary')),'scope_add_recovery_pin')
    Store(unit/'workers');Store(unit/'worker-cache');local_path=unit/'local-snapshot.json'
    need(grant.get('local_snapshot')==str(local_path),'scope_add_recovery_local_binding')
    local_raw,local_fact=read(local_path);local=json.loads(local_raw)
    need(digest(local)==grant.get('expected_local_sha256'),'scope_add_recovery_local_binding')
    anchor=dict(account_id=config['account_id'],source_generation=config['source_generation'],self_username=_confirmed_self_username(config,physical=False),
        live_db_root=config['live_db_root'],message_root=config['message_root'],scope=list(config['mirror_scope']))
    need(sdk._probe_same(local.get('anchors'),anchor) and sdk._probe_same(snapshot.get('mirror_scope'),config['mirror_scope']),'scope_add_recovery_source_binding')
    label=sdk._schedule_label(snapshot,descriptor);active=unit/'workers'/(label+'.plist');slot=sdk._slot_view(active)
    if active.exists():selected=active;suffix=''
    else:
        archives=list(active.parent.glob(active.name+'.disabled-*'));need(bool(archives),'scope_add_recovery_pin')
        def order(x):
            value=x.name[len(active.name+'.disabled-'):];need(value.isdecimal(),'scope_add_recovery_pin');return int(value)
        selected=max(archives,key=order);suffix=selected.name[len(active.name):]
    owned=active.with_suffix('.owned').with_name(active.with_suffix('.owned').name+suffix)
    need(state.get('record')==str(active.with_suffix('.owned')),'scope_add_recovery_pin')
    plist_raw,plist_fact=read(selected);record_raw,record_fact=read(owned);payload=plistlib.loads(plist_raw);record=json.loads(record_raw)
    need(record.get('operation')==state.get('operation') and type(state.get('operation')) is str and re.fullmatch('[0-9a-f]{32}',state['operation']) is not None
         and record.get('follow_grant')==descriptor['path'] and record.get('follow_grant_sha256')==descriptor['sha256']
         and record.get('config_sha256')==sdk._config_facts(snapshot) and record.get('plist_sha256')==sha(plist_raw)
         and sdk._probe_same(record.get('plist_identity'),[plist_fact['stat']['dev'],plist_fact['stat']['ino']])
         and sdk._probe_same(record.get('os_context'),grant.get('os_context')) and sdk._probe_same(state.get('os_context'),grant.get('os_context')),'scope_add_recovery_pin')
    need(sdk._probe_same(record['os_context'],expected['raw_old_context'])
         and (sdk._probe_same(current_context,expected['raw_old_context']) or sdk._probe_same(current_context,expected['raw_current_context']))
         and (sdk._probe_same(record['os_context'],current_context) or sdk._retired_context_delta(record['os_context'],current_context)),'scope_add_recovery_context')
    need(type(grant.get('round_seconds')) is int and grant['round_seconds']==30 and all(type(v) is int and v==1 for v in (grant.get('interval_seconds'),descriptor.get('interval_seconds'),record.get('interval_seconds')))
         and sdk._probe_same(grant.get('deadline'),descriptor.get('deadline')) and sdk._probe_same(grant.get('deadline'),record.get('deadline')),'scope_add_recovery_deadline')
    sdk._probe_expired(grant['deadline'],max_ns=180000000000);sdk._scope_finite_payload(record,payload)
    paths=[active]+[active.with_suffix(ext) for ext in ('.owned','.runtime','.active','.starting','.submission')]
    paths+=[selected,owned]+[active.with_suffix(ext).with_name(active.with_suffix(ext).name+suffix) for ext in ('.runtime','.active','.starting','.submission')]
    paths+=[local_path,unit.parent/'current.json',unit/'result.json',unit/'attempt.json',unit/'worker-cache/.writer.lock']
    files={str(x):_probe_file(x) for x in sorted(set(paths))}
    current_raw,_=read(unit.parent/'current.json');current=json.loads(current_raw);pointer=Path(current.get('record',''))
    need(pointer.is_absolute() and pointer.name=='recovery.json' and pointer.parent.parent==unit.parent,'scope_add_recovery_ref')
    result=None;artifacts={}
    for name in ('attempt.json','result.json'):
        try:raw,_=read(unit/name)
        except FileNotFoundError:continue
        value=json.loads(raw)
        need(value.get('operation')==state['operation'] and value.get('source_binding_digest')==grant['source_signature'] and value.get('expected_local_sha256')==grant['expected_local_sha256']
             and value.get('snapshot_digest')==grant['snapshot_sha256'] and type(value.get('accept')) is bool and value['accept']==grant['accept'],'scope_add_recovery_result_binding')
        if name=='result.json':result=value
    if result is not None and result.get('state')=='completed':
        receipt=result.get('receipt');need(type(receipt) is dict and type(result.get('accepted')) is bool and result['accepted']==grant['accept']
             and type(receipt.get('accepted')) is bool and receipt['accepted']==grant['accept'],'scope_add_recovery_receipt')
        need(receipt.get('nonce')==grant['nonce'] and receipt.get('grant_sha256')==digest(grant) and receipt.get('expected_local_sha256')==digest(local)
             and receipt.get('anchors_sha256')==digest(local['anchors']) and receipt.get('witness_sha256')==digest(receipt.get('verified_sources'))
             and [v.get('name') for v in receipt.get('verified_sources',[])]==[v.get('name') for v in local['databases']],'scope_add_recovery_receipt')
        need(receipt.get('auxiliary_refresh',False)==grant.get('auxiliary_refresh',False),'scope_add_recovery_receipt')
        if grant.get('auxiliary_refresh'):
            auxiliary=receipt.get('auxiliary_snapshots');need(type(auxiliary) is list and len(auxiliary)==1,'scope_add_recovery_receipt')
            for retained in auxiliary:
                index=retained.get('database_index');need(type(index) is int and 0<=index<len(local['databases'])
                     and local['databases'][index]['name']=='contact.db' and retained.get('mode')=='new_complete_authorized_contact_snapshot'
                     and retained['old_archive'].get('effects_sha256')==digest(local['databases'][index]['effects']),'scope_add_recovery_receipt')
                for key in ('old_archive','new_snapshot'):
                    artifact=retained[key];location=Path(artifact['path'])
                    need(location.is_absolute() and location.is_relative_to(unit/'auxiliary')
                         and all(type(artifact.get(k)) is str and re.fullmatch('[0-9a-f]{64}',artifact[k]) is not None for k in ('sha256','effects_sha256')),'scope_add_recovery_artifact')
                    artifacts[str(location)]=_recovery_artifact_fact(location)
    elif result is not None:
        need(result.get('accepted') in (None,False) and result.get('receipt') is None,'scope_add_recovery_receipt')
    need(sdk._probe_same(sdk._slot_view(active),slot) and all(_probe_file(x)==v for x,v in files.items())
         and all(_recovery_artifact_fact(x)==v for x,v in artifacts.items()),'scope_add_recovery_changed')
    return dict(record_path=str(path),record_sha256=expected['record_sha256'],state=state,grant=grant,snapshot=snapshot,record=record,payload=payload,
        local_snapshot_sha256=digest(local),files=files,auxiliary_artifacts=artifacts,slot=json.loads(json.dumps(slot)),business_phase=(result or {}).get('state','unknown'),
        historical_source_raw_sha256=grant['source_raw_sha256'],historical_source_signature=grant['source_signature'])


def _recovery_pin(profile,config,diagnostic_path,diagnostic_sha,current_context):
    from . import native_schedule as sdk
    raw,fact=read(diagnostic_path);need(sha(raw)==diagnostic_sha,'scope_add_recovery_diagnostic')
    diagnostic=json.loads(raw);expected=diagnostic.get('recoveries');need(type(expected) is list and len(expected)==7,'scope_add_recovery_diagnostic')
    paths=[v.get('record_path') for v in expected];need(len(set(paths))==7,'scope_add_recovery_diagnostic')
    for v in expected:
        need(type(v.get('record_sha256')) is str and len(v['record_sha256'])==64 and v.get('session_attributes_xor')==0x4000
             and sdk._retired_context_delta(v.get('raw_old_context'),v.get('raw_current_context')),'scope_add_recovery_diagnostic')
    cohort=_actor_metadata(profile,config);actors=[x for x in cohort if x['facts']['kind']=='source_recovery']
    need(len(actors)==7 and {x['facts']['path'] for x in actors}==set(paths),'scope_add_recovery_set')
    table={v['record_path']:v for v in expected}
    members=[_recovery_member_pin(profile,config,x,table[x['facts']['path']],current_context) for x in actors]
    authenticated={x['facts']['path']:x for x in actors}
    for member in members:
        reference_path=Path(member['record_path']).parent.parent/'current.json'
        reference_raw,reference_fact=read(reference_path);reference=json.loads(reference_raw)
        selected_path=reference.get('record');selected=authenticated.get(selected_path)
        need(selected is not None and Path(selected_path).parent.parent==reference_path.parent,'scope_add_recovery_ref')
        selected_raw,selected_fact=read(selected_path)
        need(selected_fact==selected['facts']['state'] and sha(selected_raw)==table[selected_path]['record_sha256']
             and sdk._probe_same(json.loads(selected_raw),selected['state'])
             and selected['state'].get('id')==Path(selected_path).parent.name
             and selected['state'].get('source_profile')==str(profile),'scope_add_recovery_ref')
        need(member['files'][str(reference_path)]==reference_fact,'scope_add_recovery_changed')
        member['current_reference']=dict(reference=reference_fact,record_path=selected_path,record=selected_fact)
    need(encoded([x['facts'] for x in _actor_metadata(profile,config)])==encoded([x['facts'] for x in cohort]) and read(diagnostic_path)==(raw,fact),'scope_add_recovery_changed')
    return dict(diagnostic_path=str(Path(diagnostic_path).absolute()),diagnostic_sha256=diagnostic_sha,diagnostic_fact=fact,
        current_context=current_context,members=members,cohort=[x['facts'] for x in cohort])


def _scope_recovery_authority_facts(plan_path,expected_plan_sha,current_context):
    from . import native_schedule as sdk
    p,old,common=_scope_actor_base_facts(plan_path,expected_plan_sha);prior=p.get('recoveries')
    need(type(prior) is dict and sdk._probe_same(current_context,prior['current_context']),'scope_add_recovery_authority')
    pin=_recovery_pin(Path(p['profile']),old,prior['diagnostic_path'],prior['diagnostic_sha256'],current_context)
    need(encoded(pin)==encoded(prior),'scope_add_recovery_changed');_scope_actor_facts_final(p,common)
    return dict(common,diagnostic_sha256=pin['diagnostic_sha256'],members=pin['members'],pin=pin)


def _scope_recovery_capability(p,plan_sha):
    if p.get('recoveries') is None:return None
    from .native_schedule import authorize_scope_recovery_terminal
    return authorize_scope_recovery_terminal(p['plan_path'],plan_sha)


def _scope_capability(p,plan_sha):
    if p.get('probe') is None:return None
    from .native_schedule import authorize_scope_probe_terminal
    return authorize_scope_probe_terminal(p['plan_path'],plan_sha)


def _follow(profile,config):
    from . import native_follow as f
    store=f.Store(f.default_root(profile));intent,policy=f._policy(store);runtime=f._runtime(store)
    need(policy is not None and runtime is not None and policy['profile_path']==str(profile),'scope_add_follow_binding')
    snapshot,snapshot_fact=read(policy['snapshot']);policy_raw,policy_fact=read(policy['policy_path'])
    need(f.digest(_profile(snapshot))==policy['source_signature']==f.digest(config),'scope_add_follow_binding')
    return store,dict(generation=policy['generation'],nonce=runtime['operation'],context=runtime['context'],
        snapshot=snapshot_fact,snapshot_path=policy['snapshot'],policy=policy_fact,source_signature=policy['source_signature'])


def full_stop(profile,old,expected):
    """Live original SDK only; recovery's C old/new image was authenticated separately."""
    from . import native_follow as f
    from .native_schedule import _writer_state
    store,binding=_follow(profile,old)
    need(binding==expected,'scope_add_follow_changed')
    view=f._view(store);before=f.status(profile);runtime=f._runtime(store)
    context=runtime.get('context');session=context.get('security_session') if type(context) is dict else None
    need(type(session) is int and 0<session<2**32 and context==before.get('session_context')
         and context.get('uid')==os.getuid() and context.get('domain')=='kSMDomainUserLaunchd','scope_add_context_changed')
    need(f.kernel.drained(runtime['leader']),'scope_add_group_not_drained')
    if runtime.get('segment'):
        _,policy=f._policy(store)
        segment=f._segment_status(policy,runtime['segment'],f.LaunchctlTransport(),runtime['services'])
        need(segment.get('stop_confirmed') is True,'scope_add_activity_not_stopped')
    writer=_writer_state(old);after=f.status(profile)
    need(before==after and f._view(store)==view and _follow(profile,old)[1]==binding
         and f.kernel.drained(runtime['leader']),'scope_add_stop_changed')
    need(after.get('enabled') is False and after.get('state')=='disabled' and after.get('disabled_confirmed') is True
         and after.get('activity_stop_confirmed') is True and after.get('listener_registration')=='absent'
         and after.get('worker_registration')=='absent' and after.get('writer_lock') in ('unknown','free')
         and writer=='free' and after.get('source_binding')=='configured_authorized_source'
         and after.get('gaps')==[] and after.get('policy_generation')==expected['generation']
         and after.get('instance_nonce')==expected['nonce'],'scope_add_full_stop_required')
    return dict(status=after,writer_lock=writer,runtime_context=context,group_drained=True)


def plan(profile,reference,reference_sha,path,*,probe_record=None,probe_record_sha=None,recovery_diagnostic=None,recovery_diagnostic_sha=None):
    from .source_setup import load_source_config
    from .native_target_request import target_of,validate_contact
    from .native_media_work import _binding as media_binding
    profile=Path(profile).absolute();path=Path(path).absolute();reference=Path(reference).absolute()
    config=load_source_config(profile,physical=False);raw,fact=read(profile)
    root=_daily(config)
    need(not os.path.lexists(root/'.scope-add.current') and not os.path.lexists(root/'.scope-add.pending'),'scope_add_prior_attempt')
    need(config==_profile(raw),'scope_add_config_changed')
    ref,ref_fact=read(reference);need(sha(ref)==reference_sha,'scope_add_reference_hash')
    need(json.loads(ref).get('config_sha256')==sha(raw),'scope_add_reference_changed')
    target=target_of(json.loads(ref),config);validate_contact(config,json.loads(ref))
    scope=config['mirror_scope'];need(len(scope)==1 and target not in scope,'scope_add_single_append_only')
    new=scope+[target];replacement=scope_bytes(raw,new);new_config=_profile(replacement)
    c,db_fact=_media(config)
    try:
        need(_binding(c)==media_binding(config),'scope_add_media_binding');schema=effects(c)['schema_sha256']
    finally:c.close()
    _,follow=_follow(profile,config)
    attempt=path.with_name(path.stem+'.attempt');need(not attempt.exists(),'scope_add_attempt_exists')
    value=dict(schema='walden.daily.scope-add/1',nonce=uuid.uuid4().hex,profile=str(profile),mirror_root=str(_daily(config)),profile_fact=fact,
        old_sha256=sha(raw),new_sha256=sha(replacement),old_scope=scope,new_scope=new,target=target,
        reference=str(reference),reference_fact=ref_fact,reference_sha256=reference_sha,media_fact=db_fact,
        media_schema_sha256=schema,old_binding=media_binding(config),new_binding=media_binding(new_config),
        follow=follow,attempt=str(attempt),tool_sha256=sha(Path(__file__).read_bytes()))
    from . import native_schedule as sdk
    need((probe_record is None)==(probe_record_sha is None),'scope_add_probe_pin_required')
    value['plan_path']=str(path)
    value['scope_sdk_sha256']=sha(Path(sdk.__file__).read_bytes())
    value['probe']=None if probe_record is None else _probe_pin(profile,config,probe_record,probe_record_sha,sdk._probe_context(sdk.LaunchctlTransport()))
    need((recovery_diagnostic is None)==(recovery_diagnostic_sha is None),'scope_add_recovery_diagnostic_required')
    value['recoveries']=None if recovery_diagnostic is None else _recovery_pin(profile,config,recovery_diagnostic,recovery_diagnostic_sha,sdk._probe_context(sdk.LaunchctlTransport()))
    create(path,encoded(value))
    return dict(status='scope_add_planned',plan=str(path),plan_sha256=sha(encoded(value)),old_scope_count=1,new_scope_count=2,source_opened=False,local_mutated=False)


def _plan(path,expected):
    raw,_=read(path);need(sha(raw)==expected,'scope_add_plan_hash');value=json.loads(raw)
    need(raw==encoded(value) and value.get('schema')=='walden.daily.scope-add/1'
         and value.get('tool_sha256')==sha(Path(__file__).read_bytes()),'scope_add_plan_invalid')
    need(value['new_scope']==value['old_scope']+[value['target']] and len(value['old_scope'])==1
         and value['target'] not in value['old_scope'],'scope_add_plan_invalid')
    need(value['attempt']==str(Path(path).absolute().with_name(Path(path).stem+'.attempt')),'scope_add_plan_invalid')
    return value


def _reference(p,old):
    from .native_target_request import target_of,validate_contact
    raw,fact=read(p['reference']);need(fact==p['reference_fact'] and sha(raw)==p['reference_sha256'],'scope_add_reference_changed')
    ref=json.loads(raw);need(ref.get('config_sha256')==p['old_sha256'] and target_of(ref,old)==p['target'],'scope_add_reference_changed');validate_contact(old,ref)


def _event(attempt,event,**fields):
    path=attempt/'journal.jsonl'
    fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
    with os.fdopen(fd,'ab') as stream:
        info=os.fstat(stream.fileno());need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'scope_add_journal_invalid')
        stream.write(encoded(dict(event=event,**fields)));stream.flush();os.fsync(stream.fileno())
    with directory(attempt) as parent:os.fsync(parent)


def _recorded(attempt,name):
    return any(json.loads(line).get('event')==name for line in read(attempt/'journal.jsonl')[0].splitlines())


def _archive(c,path):
    from .native_source_recovery import copy_database,freeze_artifact
    with directory(path.parent):
        copy_database(c,path)
        # Normalize only the new archive to a standalone rollback-journal file;
        # the live database's WAL mode and sidecars are never changed.
        archive=sqlite3.connect(path)
        try:need(archive.execute('PRAGMA journal_mode=DELETE').fetchone()==('delete',),'scope_add_archive_invalid')
        finally:archive.close()
        return freeze_artifact(path,effects(c))['sha256']


def archive_sha(path):
    from .native_source_recovery import artifact_hash
    with directory(Path(path).parent):return artifact_hash(path)


def _authenticate(p,plan_sha):
    """Only dedicated status/recover use this authenticated pending-C route."""
    attempt=Path(p['attempt']);meta_raw,_=read(attempt/'metadata.json');meta=json.loads(meta_raw)
    need(meta.get('plan_sha256')==plan_sha and meta.get('stage_path')==str(Path(p['profile']).with_name('.scope-add-'+p['nonce']+'.new'))
         and meta.get('stage',{}).get('sha256')==p['new_sha256'],'scope_add_journal_invalid')
    old_raw,_=read(attempt/'old-source.json');new_raw,_=read(attempt/'new-source.json')
    need(sha(old_raw)==p['old_sha256'] and sha(new_raw)==p['new_sha256']
         and scope_bytes(old_raw,p['new_scope'])==new_raw,'scope_add_backup_changed')
    old=_profile(old_raw)
    expected_marker=dict(schema='walden.scope-add.pending/1',plan_sha256=plan_sha,metadata_sha256=sha(meta_raw),attempt=p['attempt'])
    marker_fact={}
    for key,location in (('profile',marker_path(p['profile'])),('root',Path(old['mirror_root'])/'.scope-add.pending')):
        try:marker,fact=read(location)
        except FileNotFoundError:marker_fact[key]=None;continue
        need(json.loads(marker)==expected_marker,'scope_add_marker_invalid');marker_fact[key]=fact
    need(any(marker_fact.values()),'scope_add_marker_missing')
    journal,_=read(attempt/'journal.jsonl');events=[json.loads(line) for line in journal.splitlines()]
    need(events and events[0]==dict(event='prepared',metadata_sha256=sha(meta_raw)), 'scope_add_journal_invalid')
    phases=['prepared','before_media','media_committed','before_replace','profile_published','committed']
    seen=set();last=-1
    for event in events:
        name=event.get('event') if type(event) is dict else None
        if name=='recovery_started':need(event==dict(event=name),'scope_add_journal_invalid');continue
        need(name in phases and name not in seen and phases.index(name)>last,'scope_add_journal_invalid')
        if name=='before_media':
            need(event==dict(event=name,old_sha256=sha(p['old_binding'].encode()),new_sha256=sha(p['new_binding'].encode())), 'scope_add_journal_invalid')
        elif name=='before_replace':need(event==dict(event=name,stage=meta['stage']) and 'media_committed' in seen,'scope_add_journal_invalid')
        elif name=='media_committed':need(event==dict(event=name) and 'before_media' in seen,'scope_add_journal_invalid')
        elif name in ('profile_published','committed'):need(event==dict(event=name) and 'before_replace' in seen,'scope_add_journal_invalid')
        seen.add(name);last=phases.index(name)
    need(archive_sha(attempt/'media.sqlite')==meta['archive_sha256'],'scope_add_backup_changed')
    from .live_readonly import readonly_database_uri
    archive=sqlite3.connect(readonly_database_uri(attempt/'media.sqlite'),uri=True)
    try:need(effects(archive)==meta['effects'] and _binding(archive)==p['old_binding'],'scope_add_backup_changed')
    finally:archive.close()
    raw,fact=read(p['profile'])
    if sha(raw)==p['old_sha256']:
        need(fact==p['profile_fact'] and not {'profile_published','committed'}&seen,'scope_add_foreign_profile')
    else:
        need(sha(raw)==p['new_sha256'] and fact['parent']==p['profile_fact']['parent']
             and identity_from_fact(fact)==identity_from_fact(meta['stage']), 'scope_add_foreign_profile')
        need(any(e.get('event')=='before_replace' and e.get('stage')==meta['stage'] for e in events),'scope_add_journal_invalid')
    c,db_fact=_media(old)
    try:
        binding=_binding(c)
        need(db_fact==p['media_fact'] and binding in (p['old_binding'],p['new_binding'])
             and effects(c)==meta['effects'],'scope_add_media_data_changed')
        if binding==p['new_binding']:need('before_media' in seen,'scope_add_journal_invalid')
        else:need('media_committed' not in seen,'scope_add_journal_invalid')
    finally:c.close()
    return meta,marker_fact,old,raw


def identity_from_fact(fact):
    return {k:v for k,v in fact['stat'].items() if k not in ('size','mtime_ns','ctime_ns')}


def _finish(p,plan_sha,meta,marker_fact,old):
    attempt=Path(p['attempt']);profile=Path(p['profile']);stage=Path(meta['stage_path'])
    need(actor_cohort(profile,old,capability=_scope_capability(p,plan_sha),recovery_capability=_scope_recovery_capability(p,plan_sha))==meta['actors'],'scope_add_actor_changed')
    root_marker=_daily(old)/'.scope-add.pending'
    marker_raw=encoded(dict(schema='walden.scope-add.pending/1',plan_sha256=plan_sha,
                           metadata_sha256=sha(read(attempt/'metadata.json')[0]),attempt=p['attempt']))
    for key,location in (('profile',marker_path(profile)),('root',root_marker)):
        if marker_fact[key] is None:marker_fact[key]=create(location,marker_raw)
        else:need(read(location)[1]==marker_fact[key],'scope_add_marker_changed')
    c,db_fact=_media(old,True)
    try:
        need(db_fact==p['media_fact'],'scope_add_media_changed');c.execute('BEGIN IMMEDIATE')
        need(effects(c)==meta['effects'],'scope_add_media_data_changed')
        binding=_binding(c);need(binding in (p['old_binding'],p['new_binding']),'scope_add_media_binding')
        if binding==p['old_binding']:
            if not _recorded(attempt,'before_media'):
                _event(attempt,'before_media',old_sha256=sha(p['old_binding'].encode()),new_sha256=sha(p['new_binding'].encode()))
            need(c.execute('UPDATE binding SET value=? WHERE id=1 AND value=?',(p['new_binding'],p['old_binding'])).rowcount==1,'scope_add_media_binding')
        need(_binding(c)==p['new_binding'] and effects(c)==meta['effects'],'scope_add_media_data_changed')
        c.commit()
        if not _recorded(attempt,'media_committed'):_event(attempt,'media_committed')
    except BaseException:c.rollback();raise
    finally:c.close()
    raw,fact=read(profile)
    if sha(raw)==p['old_sha256']:
        need(fact==p['profile_fact'] and read(stage)[1]==meta['stage'],'scope_add_foreign_profile')
        if not _recorded(attempt,'before_replace'):_event(attempt,'before_replace',stage=meta['stage'])
        with directory(profile.parent) as parent:
            need(identity(os.fstat(parent),True)==p['profile_fact']['parent'] and read(profile)[1]==fact
                 and read(stage)[1]==meta['stage'],'scope_add_foreign_profile')
            os.replace(stage.name,profile.name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
        _event(attempt,'profile_published')
    raw,fact=read(profile)
    need(sha(raw)==p['new_sha256'] and identity_from_fact(fact)==identity_from_fact(meta['stage']),'scope_add_foreign_profile')
    c,_=_media(old)
    try:need(_binding(c)==p['new_binding'] and effects(c)==meta['effects'],'scope_add_postcondition')
    finally:c.close()
    receipt=dict(schema='walden.daily.scope-add.receipt/1',state='committed',plan_sha256=plan_sha,
        profile=fact,media_fact=p['media_fact'],preserved_effects=meta['effects'],scope_count=2,
        old_request_records='unchanged_not_rebound; profile-digest-bound refs may be stale')
    receipt_path=attempt/'receipt.json'
    try:existing,_=read(receipt_path)
    except FileNotFoundError:create(receipt_path,encoded(receipt))
    else:need(existing==encoded(receipt),'scope_add_receipt_conflict')
    pointer=encoded(dict(schema='walden.scope-add.current/1',profile_path=p['profile'],
        prior_snapshot=p['follow']['snapshot_path'],prior_signature=p['follow']['source_signature'],
        binding=json.loads(p['new_binding']),receipt=str(receipt_path),receipt_sha256=sha(encoded(receipt))))
    pointer_path=_daily(old)/'.scope-add.current'
    try:existing,_=read(pointer_path)
    except FileNotFoundError:create(pointer_path,pointer)
    else:need(existing==pointer,'scope_add_commit_invalid')
    if not _recorded(attempt,'committed'):_event(attempt,'committed')
    for key,location in (('profile',marker_path(profile)),('root',root_marker)):
        need(read(location)[1]==marker_fact[key],'scope_add_marker_changed')
        with directory(location.parent) as parent:
            os.unlink(location.name,dir_fd=parent);os.fsync(parent)
    return dict(status='scope_added',scope_count=2,receipt=str(receipt_path),source_opened=False,
                history_complete='not_observed',media_completion='separate',old_request_records='unchanged_not_rebound')


def apply(path,plan_sha):
    from .native_follow_policy import Store,default_root
    from .native_mirror_sync import writer_lock
    p=_plan(path,plan_sha);profile=Path(p['profile']);scope_guard(profile)
    raw,fact=read(profile);need(fact==p['profile_fact'],'scope_add_config_changed');old=_profile(raw);_reference(p,old)
    need(old['mirror_scope']==p['old_scope'],'scope_add_config_changed')
    store=Store(default_root(profile));attempt=Path(p['attempt'])
    with store.locked():
        stop=full_stop(profile,old,p['follow'])
        with writer_lock(_daily(old),0):
            need(read(profile)[1]==p['profile_fact'],'scope_add_config_changed');scope_guard(profile);_reference(p,old)
            probe_proofs=[]
            actors=actor_cohort(profile,old,capability=_scope_capability(p,plan_sha),recovery_capability=_scope_recovery_capability(p,plan_sha),proof_sink=probe_proofs)
            c,db_fact=_media(old)
            try:
                need(db_fact==p['media_fact'] and _binding(c)==p['old_binding'],'scope_add_media_changed')
                before=effects(c);need(before['schema_sha256']==p['media_schema_sha256'],'scope_add_media_changed')
                with directory(attempt.parent) as parent:
                    need(stat.S_IMODE(os.fstat(parent).st_mode)==0o700,'scope_add_private_artifacts_required')
                    os.mkdir(attempt.name,0o700,dir_fd=parent);os.fsync(parent)
                create(attempt/'old-source.json',raw);new=scope_bytes(raw,p['new_scope']);create(attempt/'new-source.json',new)
                archive=_archive(c,attempt/'media.sqlite')
            finally:c.close()
            stage=profile.with_name('.scope-add-'+p['nonce']+'.new');stage_fact=create(stage,new)
            meta=dict(plan_sha256=plan_sha,archive_sha256=archive,effects=before,full_stop=stop,actors=actors,stage_path=str(stage),stage=stage_fact)
            meta['actor_terminal_observations']=probe_proofs
            meta['probe_terminal_observations']=[v for v in probe_proofs if v['status']=='retired_probe_terminal_proven']
            meta_raw=encoded(meta);create(attempt/'metadata.json',meta_raw)
            create(attempt/'journal.jsonl',encoded(dict(event='prepared',metadata_sha256=sha(meta_raw))))
            marker_raw=encoded(dict(schema='walden.scope-add.pending/1',plan_sha256=plan_sha,metadata_sha256=sha(meta_raw),attempt=p['attempt']))
            marker_fact=dict(profile=create(marker_path(profile),marker_raw),root=None)
            marker_fact['root']=create(_daily(old)/'.scope-add.pending',marker_raw)
            return _finish(p,plan_sha,meta,marker_fact,old)


def recover(path,plan_sha):
    from .native_follow_policy import Store,default_root
    from .native_mirror_sync import writer_lock
    p=_plan(path,plan_sha);meta,marker_fact,old,_=_authenticate(p,plan_sha);_reference(p,old)
    with Store(default_root(p['profile'])).locked():
        full_stop(Path(p['profile']),old,p['follow'])
        with writer_lock(_daily(old),0):
            meta,marker_fact,old,_=_authenticate(p,plan_sha)
            _event(Path(p['attempt']),'recovery_started')
            return _finish(p,plan_sha,meta,marker_fact,old)


def status(path,plan_sha):
    """Local aggregate only. Commit preservation and later live progress are distinct."""
    from .native_follow_policy import Store
    from .live_readonly import readonly_database_uri
    from .common import quote_identifier as qi
    from .native_mirror_sync import mirror_root
    p=_plan(path,plan_sha);profile=Path(p['profile']);attempt=Path(p['attempt'])
    pending=False
    for location in (marker_path(profile),Path(p['mirror_root'])/'.scope-add.pending'):
        try:location.lstat()
        except FileNotFoundError:pass
        else:pending=True
    if pending:
        _authenticate(p,plan_sha)
        return dict(status='scope_add_pending',recovery_required=True,source_opened=False)
    from .source_setup import load_source_config
    config=load_source_config(profile,physical=False)
    raw,fact=read(profile);need(sha(raw)==p['new_sha256'],'scope_add_not_committed')
    receipt_raw,_=read(attempt/'receipt.json');receipt=json.loads(receipt_raw)
    need(receipt.get('state')=='committed' and receipt.get('plan_sha256')==plan_sha and fact==receipt['profile'],'scope_add_receipt_conflict')
    root=mirror_root(config,create=False);c,db_fact=_media(config)
    try:need(db_fact==p['media_fact'] and _binding(c)==p['new_binding'],'scope_add_media_binding')
    finally:c.close()
    results=[]
    with sqlite3.connect(readonly_database_uri(root/'__walden_status.db'),uri=True) as state:
        state.execute('PRAGMA query_only=ON');state.execute('BEGIN')
        for ordinal,username in enumerate(p['new_scope']):
            scope=hashlib.sha256(username.encode()).hexdigest();table='Msg_'+hashlib.md5(username.encode()).hexdigest()
            observed=state.execute('SELECT value FROM successful_observations WHERE scope=?',(scope,)).fetchone()
            gaps=state.execute('SELECT gaps FROM attempts WHERE scope=?',(scope,)).fetchone()
            proof=json.loads(observed[0]) if observed else {};roster=proof.get('source_roster',{})
            bound=(proof.get('account_id')==config['account_id'] and proof.get('source_generation')==config['source_generation']
                   and proof.get('message_root')==os.path.abspath(config['message_root']) and type(roster) is dict and bool(roster))
            shards=[]
            if bound:
                from .source_catalog import SHARD_NAME_PATTERN
                for name,present in sorted(roster.items()):
                    need(SHARD_NAME_PATTERN.fullmatch(name) is not None and type(present) is bool,'scope_add_observation_invalid')
                    if not present:shards.append(dict(shard=name,present=False));continue
                    target=root/name
                    if not target.is_file() or target.is_symlink():shards.append(dict(shard=name,present=True,status='missing'));continue
                    with sqlite3.connect(readonly_database_uri(target),uri=True) as local:
                        local.execute('PRAGMA query_only=ON');local.execute('BEGIN')
                        need(local.execute('SELECT * FROM __walden_binding').fetchall()==[(config['account_id'],config['source_generation'],name)],'source_identity_mismatch')
                        progress=local.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()
                        if not progress:shards.append(dict(shard=name,present=True,status='progress_missing'));continue
                        progress=json.loads(progress[0]);count,low,high=local.execute('SELECT count(*),min(create_time),max(create_time) FROM '+qi(table)).fetchone()
                        item=dict(shard=name,present=True,status='observed',count=count,min_create_time=low,max_create_time=high)
                        item.update({k:progress.get(k) for k in ('H','history','tail','target','history_complete','checked_at')})
                        recent=progress.get('recent_observation') or {}
                        item['observation_matches']=recent.get('observation_id')==proof.get('observation_id')
                        shards.append(item)
            present=[s for s in shards if s['present']]
            complete=bool(bound and present and gaps and json.loads(gaps[0])==[] and all(s.get('status')=='observed'
                and s.get('observation_matches') is True and s.get('history_complete') is True
                and type(s.get('history')) is int and type(s.get('H')) is int and s['history']>=s['H']
                and type(s.get('tail')) is int and type(s.get('target')) is int and s['tail']>=s['target'] for s in present))
            results.append(dict(scope_ordinal=ordinal,history_complete=complete,shards=shards,
                gaps=json.loads(gaps[0]) if gaps else ['scope_not_observed'],source_cutoff='per_shard_H_and_target; not_server_or_atomic'))
    c,_=_media(config)
    try:
        media=[dict(kind=kind,status=state,count=count) for kind,state,count in c.execute('SELECT kind,status,count(*) FROM jobs WHERE username IN (?,?) GROUP BY kind,status',tuple(p['new_scope']))]
        has_ocr=c.execute("SELECT 1 FROM sqlite_master WHERE name='image_derivations'").fetchone()
        ocr=[dict(status=state,count=count) for state,count in c.execute('SELECT d.status,count(*) FROM image_derivations d JOIN jobs j ON j.key=d.key WHERE j.username IN (?,?) GROUP BY d.status',tuple(p['new_scope']))] if has_ocr else []
        media_scopes=[]
        for ordinal,username in enumerate(p['new_scope']):
            jobs=[dict(kind=kind,status=state,count=count) for kind,state,count in c.execute('SELECT kind,status,count(*) FROM jobs WHERE username=? GROUP BY kind,status',(username,))]
            derived=[dict(status=state,count=count) for state,count in c.execute('SELECT d.status,count(*) FROM image_derivations d JOIN jobs j ON j.key=d.key WHERE j.username=? GROUP BY d.status',(username,))] if has_ocr else []
            media_scopes.append(dict(scope_ordinal=ordinal,jobs=jobs,ocr=derived))
    finally:c.close()
    return dict(status='scope_added',scopes=results,media=media,ocr=ocr,media_scopes=media_scopes,source_opened=False,
        history_complete=all(s['history_complete'] for s in results),preservation_proof='commit_receipt_not_current_database_equality',
        old_request_records='unchanged_not_rebound; profile-digest-bound refs may be stale')
