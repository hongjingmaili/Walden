"""Explicit per-request private-target windows. Local reads never admit Source work."""
import copy,hashlib,json,os,time,uuid
from pathlib import Path
from .native_mirror_store import MirrorError,MirrorStore
from .native_follow_policy import Store,digest
from .native_deadline import Deadline,check_deadline


def need(ok,reason='request_invalid'):
    if not ok:raise MirrorError(reason)
def read(path):
    from .native_schedule import _read
    return _read(Path(path))[0]
def window_spec(latest=None,since=None,until=None,timezone=None):
    if latest is not None:
        need(type(latest) is int and 1<=latest<=100 and since is None and until is None,'request_window_invalid')
        return dict(kind='latest',limit=latest)
    from zoneinfo import ZoneInfo
    need(type(since) is int and type(until) is int and 0<=since<=until and until-since<86400*2 and type(timezone) is str,'request_window_invalid')
    zone=ZoneInfo(timezone)
    from datetime import datetime
    need(datetime.fromtimestamp(since,zone).date()==datetime.fromtimestamp(until,zone).date(),'request_window_crosses_date')
    return dict(kind='date',since=since,until=until,timezone=timezone,limit=500)
def resolve(config,query):
    from .confirmed_aliases import load_alias_context,local_contact_snapshot
    from .live_identity import LiveIdentityAdapter
    aliases=load_alias_context(config)
    class Catalog:shards=()
    with local_contact_snapshot(config) as (contact,state):
        proof=state.get('source_identity');need(type(proof) is list and len(proof)==2 and all(type(v) is int and v>=0 for v in proof),'request_contact_proof_invalid')
        adapter=LiveIdentityAdapter(Catalog(),contact_connection=contact,alias_context=aliases,contact_source_identity=tuple(proof));adapter.begin_scan()
        result,_=adapter.resolve_contact(query,_kind='private')
        return dict(resolution=result,account_id=config['account_id'],source_generation=config['source_generation'],contact_source_identity=proof,contact_checked_at=state['checked_at'],alias_revision=aliases.revision)
def target_of(ref,config):
    need(type(ref) is dict and type(ref.get('resolution')) is dict,'request_reference_invalid')
    r=ref['resolution'];name=r.get('selected_username');items=r.get('candidates')
    need(ref.get('account_id')==config['account_id'] and ref.get('source_generation')==config['source_generation'],'request_source_conflict')
    need(r.get('status')=='resolved' and r.get('match_basis') in ('exact_username','exact_contact_field','confirmed_alias') and type(r.get('total_candidates')) is int and r['total_candidates']==1 and r.get('truncated') is False,'request_target_unconfirmed')
    need(type(name) is str and bool(name) and not name.endswith('@chatroom') and not name.startswith('gh_') and type(items) is list and len(items)==1 and type(items[0]) is dict and items[0].get('username')==name,'request_target_unconfirmed')
    return name
def validate_contact(config,ref):
    from .confirmed_aliases import load_alias_context,local_contact_snapshot
    need(load_alias_context(config).revision==ref['alias_revision'],'request_metadata_stale')
    with local_contact_snapshot(config) as (_,state):
        need(state.get('source_identity')==ref['contact_source_identity'] and type(ref.get('contact_checked_at')) is int and state['checked_at']>=ref['contact_checked_at'],'request_metadata_stale')
def root_for(config,base=None):
    base=Path(base) if base else Path(os.environ.get('XDG_DATA_HOME',str(Path.home()/'.local/share')))/'wechat-local/on-demand'
    need(base.is_absolute(),'request_location_invalid')
    root=base/digest([config.get(k) for k in ('account_id','source_generation','self_identity','live_db_root','message_root')])[:24]
    for key in ('live_db_root','message_root'):
        if config.get(key):
            source=Path(os.path.abspath(config[key]));need(not (root==source or source in root.parents or root in source.parents),'request_location_invalid')
    return root
def cache_profile(config,target,window,root):
    result=copy.deepcopy(config)
    for key in ('encrypted_contact_database','session_database'):
        result.pop(key,None)
    if window.get('kind') not in ('latest','date'):
        for key in ('image_database','image_attachments_root','image_key_config','image_output_root','voice_databases','voice_runtime_root','voice_python','media_transcriber_version','voice_discovery_complete','voice_discovery_status'):result.pop(key,None)
    runtime=Path(__import__('sys').executable).parent
    for key,entry in (('runtime_python','python'),('window_cli','wechat-local-window'),('reply_cli','wechat-local-reply')):
        if key in result:result[key]=str(runtime/entry)
    from .native_scope_contract import limited
    result=limited(result,[target],root/'cache'/digest(target)[:24]/digest(window)[:24])
    return result

def cache_preflight(config):
    import sqlite3,stat
    from .live_readonly import readonly_database_uri
    root=Path(config['mirror_root'])
    if not root.exists():return
    Store(root)
    table='Msg_'+hashlib.md5(config['mirror_scope'][0].encode()).hexdigest()
    try:
        for path in root.glob('*.db'):
            info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'request_cache_conflict')
            need(path.name.startswith(('message_','biz_message_')),'request_cache_conflict')
            conn=sqlite3.connect(readonly_database_uri(path),uri=True)
            try:
                conn.execute('PRAGMA query_only=ON');conn.execute('BEGIN')
                need(conn.execute('SELECT * FROM __walden_binding').fetchall()==[(config['account_id'],config['source_generation'],path.name)],'request_cache_conflict')
                need(all(name==table for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")),'request_cache_conflict')
            finally:conn.close()
    except sqlite3.Error:raise MirrorError('request_cache_conflict') from None

def _proof(config,window):
    root=Path(config['mirror_root'])
    if not root.exists():return None
    state=Store(root).read('request-window.json')
    if state:need(state.get('binding')==[config['account_id'],config['source_generation'],config['mirror_scope'][0],window],'request_cache_conflict')
    return state

def _cached_progress(config,shard):
    import sqlite3
    from .live_readonly import readonly_database_uri
    path=Path(config['mirror_root'])/shard
    if not path.is_file():return None
    table='Msg_'+hashlib.md5(config['mirror_scope'][0].encode()).hexdigest()
    conn=sqlite3.connect(readonly_database_uri(path),uri=True)
    try:
        conn.execute('PRAGMA query_only=ON');conn.execute('BEGIN')
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='__walden_progress'").fetchone():return None
        row=conn.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()
        return json.loads(row[0]) if row else None
    finally:conn.close()


def _cache_window_complete(config,proof):
    """Validate the entire declared observation, not only surviving local DBs."""
    import sqlite3
    from .source_catalog import SHARD_NAME_PATTERN
    from .live_readonly import readonly_database_uri
    table='Msg_'+hashlib.md5(config['mirror_scope'][0].encode()).hexdigest()
    try:
        shards=proof.get('shards')
        if type(shards) is not dict or not shards:return False
        for name,item in shards.items():
            if type(name) is not str or SHARD_NAME_PATTERN.fullmatch(name) is None or type(item) is not dict or type(item.get('present')) is not bool:return False
            if not item['present']:continue
            members=item.get('members')
            if type(members) is not list or len(members)>501 or any(type(v) is not int or v<=0 for v in members) or len(set(members))!=len(members):return False
            path=Path(config['mirror_root'])/name
            if not path.is_file():return False
            conn=sqlite3.connect(readonly_database_uri(path),uri=True)
            try:
                conn.execute('PRAGMA query_only=ON');conn.execute('BEGIN')
                need(conn.execute('SELECT * FROM __walden_binding').fetchall()==[(config['account_id'],config['source_generation'],name)],'request_cache_conflict')
                if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():return False
                row=conn.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()
                if not row:return False
                progress=json.loads(row[0])
                if type(progress) is not dict or any(type(progress.get(k)) is not int or progress[k]<0 for k in ('H','history','tail','target','checked_at')) or type(progress.get('history_complete')) is not bool:return False
                identity=progress.get('source_identity');header=progress.get('source_header_sha256')
                if type(identity) is not list or len(identity)!=2 or any(type(v) is not int or v<0 for v in identity) or type(header) is not str or len(header)!=64 or any(v not in '0123456789abcdef' for v in header):return False
                if any(progress.get(k)!=item.get(k) for k in ('source_identity','source_header_sha256','checked_at')):return False
                for offset in range(0,len(members),500):
                    part=members[offset:offset+500]
                    if conn.execute('SELECT count(*) FROM "'+table+'" WHERE local_id IN ('+','.join('?' for _ in part)+')',tuple(part)).fetchone()[0]!=len(part):return False
            finally:conn.close()
        return True
    except (sqlite3.Error,ValueError,TypeError,KeyError,AttributeError):return False


def local_result(config,window,*,media=True):
    """Only local cache, no resolver, Source, enqueue, codec, worker or registration."""
    cache_preflight(config)
    proof=_proof(config,window)
    if proof and window['kind']=='date' and (proof.get('reason')=='request_window_page_limit' or sum(len(v.get('members',[])) for v in proof.get('shards',{}).values())>window['limit']):
        return dict(status='pending',reason='request_window_page_limit',coverage=dict(proof,complete=False,reason='request_window_page_limit'),result=None)
    if not proof or not proof.get('complete'):return dict(status='needs_target_copy',coverage=proof or {'complete':False},result=None)
    if not _cache_window_complete(config,proof):return dict(status='needs_target_copy',coverage=dict(proof,complete=False,reason='request_cache_incomplete'),result=None)
    if not any(v['present'] for v in proof['shards'].values()):
        return dict(status='ready',coverage=proof,result=dict(messages=[],gaps=[],source_opens=0,coverage=dict(history_complete=False,request_range=dict(status='request_window_covered',window=window)),freshness='local_snapshot'))
    from .native_mirror_query import query_local
    member={shard:value['members'] for shard,value in proof['shards'].items() if value['present']}
    req=dict(username=config['mirror_scope'][0],limit=window['limit'],images=media,voice_transcripts=media)
    if window['kind']=='date':req.update(start=window['since'],end=window['until'])
    try:result=query_local(config,req,membership=member)
    except MirrorError as error:
        if str(error)!='request_cache_incomplete':raise
        return dict(status='needs_target_copy',coverage=dict(proof,complete=False,reason='request_cache_incomplete'),result=None)
    result['coverage']['history_complete']=False
    if media:
        from .native_request_media import project
        project(result,config)
    result['gaps']=[g for g in result['gaps'] if g not in ('history_incomplete','tail_incomplete')]
    result['freshness']='local_snapshot' if not result['gaps'] else 'stale'
    result['request_range']=dict(status='request_window_covered',window=window,atomic_global_snapshot=False,as_of={k:v['checked_at'] for k,v in proof['shards'].items()})
    result['coverage']['request_range']=result['request_range']
    state='ready' if not result['gaps'] else 'failed'
    if media and state=='ready' and result.get('media_completion')!='ready':state=result['media_completion']
    return dict(status=state,body_status='ready',coverage=proof,result=result)

def validate(grant):
    """Request role is never a daily-follow grant or permanent scope extension."""
    from .source_setup import load_source_config
    from .native_follow_app import matches
    from .public_service import PublicService
    need(PublicService().context==grant['os_context'],'request_context_changed')
    need(grant.get('kind')=='request' and grant.get('authorized') is True,'request_authorization_required')
    need(grant.get('round_seconds')==30 and grant.get('interval_seconds')==1 and 0<grant['deadline']['continuous_until']-grant['deadline']['continuous_start']<=180000000000,'request_budget_invalid')
    if 'media' in grant:need(grant['media']=={'images':True,'audio':True,'references':True} and all(type(v) is bool for v in grant['media'].values()),'request_media_authorization_conflict')
    w=grant['window']
    canonical=window_spec(latest=w.get('limit')) if w.get('kind')=='latest' else window_spec(since=w.get('since'),until=w.get('until'),timezone=w.get('timezone'))
    need(w==canonical,'request_window_invalid')
    Deadline(grant['deadline']).check()
    source=Path(grant['source_profile']);need(hashlib.sha256(read(source)).hexdigest()==grant['source_raw_sha256'],'request_source_conflict')
    original=load_source_config(source,physical=False);target=target_of(grant['reference'],original)
    need(target==grant['target'] and digest(original)==grant['source_signature'],'request_source_conflict')
    validate_contact(original,grant['reference'])
    state=Store(grant['store_root']).read('request.json');need(state and state.get('active_grant_sha256')==digest(grant) and state.get('window')==grant['window'] and state.get('target')==target,'request_revoked')
    snapshot=json.loads(read(grant['snapshot']));need(digest(snapshot)==grant['snapshot_sha256'] and snapshot['mirror_scope']==[target],'request_snapshot_conflict')
    need(snapshot==cache_profile(original,target,grant['window'],Path(grant['root'])),'request_snapshot_conflict')
    need(matches(grant['app_epoch'],grant['app_executable']) is True,'request_app_unavailable')
    return state

def prepare(config,config_path,*,query=None,reference=None,reference_sha=None,window,authorize=False,root=None,run=None):
    """New request/status contract. Only authorize=True may create/submit owned work."""
    if reference is not None:
        raw=read(reference);need(hashlib.sha256(raw).hexdigest()==reference_sha,'request_reference_conflict');ref=json.loads(raw)
        # Parent metadata resolver includes the same shape plus private provenance.
        need(ref.get('config_sha256')==hashlib.sha256(read(config_path)).hexdigest(),'request_metadata_stale')
    else:ref=resolve(config,query)
    if ref['resolution'].get('status')!='resolved':return dict(status='failed' if ref['resolution'].get('status')=='unavailable' else 'needs_confirmation',resolution=ref['resolution'],source_opened=False)
    target=target_of(ref,config);validate_contact(config,ref)
    root=root_for(config,root);profile=cache_profile(config,target,window,root)
    if not authorize:return _prepare_cohort(config,config_path,ref,target,window,authorize,root,profile,run)
    # One admission lock for this C/target/window, before any prior observations.
    # Worker execution claims remain in their original separate lock domain.
    media_id=digest([digest(config),target,window,'request-media-v1'])[:32]
    Store(root.parent,create=True);Store(root,create=True);Store(root/'requests',create=True)
    admission=Store(root/'requests'/media_id,create=True)
    from contextlib import ExitStack
    with ExitStack() as locks:
        try:locks.enter_context(admission.locked())
        except MirrorError:return dict(status='pending',reason='cohort_admission_unconfirmed',window=window,source_opened=False)
        return _prepare_cohort(config,config_path,ref,target,window,authorize,root,profile,run)


def _prepare_cohort(config,config_path,ref,target,window,authorize,root,profile,run):
    from .native_scope_contract import mode
    if mode(config)=='account':
        from .native_mirror_query import query_local
        try:
            request=dict(username=target,limit=window['limit'],images=True,voice_transcripts=True)
            if window['kind']=='date':request.update(start=window['since'],end=window['until'])
            result=query_local(config,request)
            return dict(status='ready' if result['coverage']['history_complete'] and not result['gaps'] else 'pending',reason='account_daily_copy',source_opened=False,result=result,window=window)
        except MirrorError as error:
            if str(error)!='scope_not_authorized':raise
            return dict(status='pending',reason='account_inventory_or_copy_pending',source_opened=False,window=window)
    from .native_request_record import candidates,cohort,inspect as inspect_record
    from .native_schedule import LaunchctlTransport
    run=run or LaunchctlTransport()
    runtime_token=digest([str(Path(__import__('sys').executable).absolute().parent),run.context])[:32]
    media_id=digest([digest(config),target,window,'request-media-v1'])[:32]
    current_path=root/'requests'/media_id/('runtime-'+runtime_token)/'request.json'
    current_lifecycle=None
    for existing in candidates(root,config,target,window):
        state,grant,old_profile=cohort(existing,config=config,config_path=config_path)
        observed=inspect_record(state,grant,old_profile,run=run)
        if observed.get('stop_confirmed') is not True:
            return dict(status='pending',phase='legacy_cleanup' if not grant.get('media') else 'prior_runtime_cleanup',reason='legacy_worker_cleanup_unconfirmed',request_record=str(existing),id=state.get('id'),window=state['window'],owned=observed,source_opened=False)
        if existing==current_path:current_lifecycle=status(existing,config=config,config_path=config_path,run=run)
    if current_lifecycle and (current_lifecycle['status']=='ready' or not authorize):return dict(current_lifecycle,source_opened=False)
    if target in config.get('mirror_scope',[]):
        from .native_mirror_query import query_local
        request=dict(username=target,limit=window['limit'],images=False,voice_transcripts=False)
        if window['kind']=='date':request.update(start=window['since'],end=window['until'])
        existing=query_local(config,request)
        if not any(i['content']['kind'] in ('image','audio') for i in existing['messages']) and not existing['gaps'] and (existing['coverage']['history_complete'] or existing['coverage']['request_range'].get('status')=='observed_vector_covered'):
            return dict(status='ready',source_opened=False,result=existing,coverage=existing['coverage'],cache_origin='existing_authorized_daily_scope')
    local=local_result(profile,window)
    progressable=bool((local.get('result') or {}).get('media_work_pending'))
    if local['status'] in ('ready','unconfigured','partial','failed') and not progressable or local['status']=='pending' and local.get('reason')=='request_window_page_limit':return dict(local,source_opened=False)
    if not authorize:return dict(local,status='needs_target_copy',source_opened=False,window=window)
    from .native_schedule import configure,LaunchctlTransport,_config_facts
    from .native_follow_app import observe
    from .native_follow_config import settings
    run=run or LaunchctlTransport();app_executable=settings(config)['executable'];app=observe(app_executable)
    need(app.get('state')=='running' and app.get('epoch'),'request_app_unavailable')
    Store(root.parent,create=True);Store(root,create=True);Store(root/'requests',create=True);Store(root/'cache',create=True)
    ident=digest([media_id,runtime_token])[:32];Store(root/'requests'/media_id,create=True);store=Store(current_path.parent,create=True)
    with store.locked():
        prior=store.read('request.json');segment_deadline=None
        if prior:
            old_grant=json.loads(read(prior['descriptor']['path']))
            from .native_schedule import inspect_status
            observed=inspect_status(profile,prior['profile'],Path(__import__('sys').executable).parent/'wechat-local-sync',prior['services'],runner=run,follow_grant=prior['descriptor'])
            if observed.get('stop_confirmed') is not True:return dict(status='pending',request_record=str(store.path('request.json')),id=ident,window=window,reason='worker_cleanup_unconfirmed')
            if Deadline(old_grant['deadline']).remaining()>0:segment_deadline=old_grant['deadline']
            configure(profile,prior['profile'],Path(__import__('sys').executable).parent/'wechat-local-sync',prior['services'],False,runner=run,follow_grant=prior['descriptor'])
        Store(profile['mirror_root'],create=True)
        from .native_mirror_sync import writer_lock
        with writer_lock(Path(profile['mirror_root']),0):pass
        snapshot=store.path('source.json')
        if snapshot.exists():need(json.loads(read(snapshot))==profile,'request_snapshot_conflict')
        else:snapshot=store.immutable('source.json',profile)
        grant=dict(kind='request',authorized=True,media={'images':True,'audio':True,'references':True},nonce=uuid.uuid4().hex,instance_nonce=ident,store_root=str(store.root),root=str(root),target=target,window=window,reference=ref,
            source_profile=str(Path(config_path).absolute()),source_raw_sha256=hashlib.sha256(read(config_path)).hexdigest(),source_signature=digest(config),snapshot=str(snapshot),snapshot_sha256=digest(profile),config_sha256=_config_facts(profile),
            deadline=segment_deadline or Deadline.create(180).facts,round_seconds=30,interval_seconds=1,consumed_hint_generation=-1,os_context=run.context,app_epoch=app['epoch'],app_executable=app_executable)
        grant_path=store.immutable('grant.'+grant['nonce']+'.json',grant)
        descriptor=dict(path=str(grant_path),sha256=digest(grant),deadline=grant['deadline'],interval_seconds=1,label_id=digest([config['account_id'],config['source_generation'],target])[:20]+'.'+ident)
        state=dict(id=ident,target=target,window=window,status='pending',profile=str(snapshot),active_grant_sha256=digest(grant),descriptor=descriptor,services=str(store.root/'workers'),source_profile=grant['source_profile'])
        store.atomic('request.json',state)
        def prepared(value):
            state.update(operation=value['operation'],record=value['record'],os_context=value['os_context']);store.atomic('request.json',state)
        configure(profile,snapshot,Path(__import__('sys').executable).parent/'wechat-local-sync',store.root/'workers',True,runner=run,follow_grant=descriptor,prepared=prepared)
        return dict(status='pending',request_record=str(store.root/'request.json'),id=ident,window=window,resolution=ref['resolution'],source_opened=None,phase='background_authorized')

def status(path,*,config=None,config_path=None,run=None,limit=100,offset=0):
    from .native_request_record import cohort,inspect as inspect_record
    state,grant,profile=cohort(path,config=config,config_path=config_path)
    observed=inspect_record(state,grant,profile,run=run)
    legacy=not bool(grant.get('media'))
    if legacy:
        from .source_setup import load_source_config
        original=load_source_config(Path(grant['source_profile']),physical=False)
        profile=cache_profile(original,grant['target'],grant['window'],Path(grant['root']))
    local=local_result(profile,state['window'])
    if observed.get('stop_confirmed') is not True:
        return dict(local,status='pending',phase='legacy_cleanup' if legacy else 'worker_cleanup',reason='legacy_worker_cleanup_unconfirmed' if legacy else 'worker_cleanup_pending',request_record=str(path),id=state.get('id'),owned=observed,source_opened=False)
    outcome=local['status'] if local['status'] in ('ready','unconfigured','failed','partial') else 'failed' if (observed.get('sync_health')=='failed' and observed.get('last_completed_exit_code')!=-14 and not observed.get('deadline_expired')) else 'pending'
    if outcome=='pending':local=dict(local,reason='legacy_retired_media_pending' if legacy else 'media_or_window_incomplete_worker_stopped')
    return dict(local,status=outcome,phase='legacy_retired' if legacy else 'request_result',next_step='repeat_authorized_request' if legacy and outcome!='ready' else None,request_record=str(path),id=state.get('id'),resolution=grant['reference']['resolution'],owned=observed,source_opened=False)


def require_source_round(facts):
    need(type(facts) is dict and 0<facts.get('continuous_until',0)-facts.get('continuous_start',0)<=30000000000,'request_budget_invalid')
    Deadline(facts).check()


def copy_window(config,record_path):
    """Source action only inside a validated request-owned child, not strictlocal."""
    from .native_follow_grant import load
    record=json.loads(read(record_path));grant=load(record['follow_grant'],record['follow_grant_sha256']);validate(grant)
    from .source_setup import load_source_config
    from .native_mirror_sync import writer_lock,mirror_root
    original=load_source_config(Path(grant['source_profile']),physical=False)
    need(load_source_config(Path(grant['snapshot']),physical=True)==config,'request_snapshot_conflict')
    try:
        with writer_lock(mirror_root(original,create=False),0):
            proof=_proof(config,grant['window'])
            copied=dict(gaps=[],request_complete=True) if proof and proof.get('complete') and _cache_window_complete(config,proof) else _copy_window(config,grant['window'])
            if copied.get('request_complete') and grant.get('media'):
                from .native_request_media import capture
                with writer_lock(mirror_root(config,create=False),0):copied['request_media_required']=capture(config,grant['window'])
            return copied
    except MirrorError as error:
        if str(error)!='sync_busy':raise
        return dict(gaps=[],request_complete=False,request_pending_reason='sync_busy')

def _copy_window(config,window,*,connection_factory=None):
    from .native_mirror_sync import mirror_root,writer_lock,_validate_message_cursor,_copy_indexes,_sender_mapping_matches
    from .live_readonly import read_private_passphrase,open_encrypted_readonly
    from .live_identity import _username_for_table
    from .source_records import SourceKey
    from .source_catalog import discover_numeric_shards
    from .common import quote_identifier as qi
    from .native_mirror_store import lossless_text_rows
    root=mirror_root(config);target=config['mirror_scope'][0];table='Msg_'+hashlib.md5(target.encode()).hexdigest()
    binding=[config['account_id'],config['source_generation'],target,window]
    proof=dict(binding=binding,complete=False,shards={},atomic_global_snapshot=False)
    try:
        with writer_lock(root,0):
            old_proof=_proof(config,window);cache_preflight(config);check_deadline()
            paths=list(discover_numeric_shards(Path(config['message_root'])))
            expected={p.name for pattern in ('message_*.db','biz_message_*.db') for p in root.glob(pattern)}|set((old_proof or {}).get('shards',{}))
            need(not expected-{p.name for p in paths},'source_shard_missing')
            need(bool(paths),'source_unavailable')
            previous={p.name:_cached_progress(config,p.name) for p in paths}
            # Discovery returns paths; exactly the same configured Source roster as native sync.
            if connection_factory is None:
                secret=read_private_passphrase(Path(config['passphrase_file']));connection_factory=lambda p:open_encrypted_readonly(p,secret)[0]
            for path in paths:
                path=Path(path);check_deadline();before=path.stat();identity=[before.st_dev,before.st_ino]
                with path.open('rb') as f:header=hashlib.sha256(f.read(16)).hexdigest()
                prior=previous[path.name];old_shard=(old_proof or {}).get('shards',{}).get(path.name,{})
                known=prior or old_shard
                if known.get('source_identity') is not None:need(known['source_identity']==identity and known.get('source_header_sha256')==header,'source_replaced')
                conn=connection_factory(path)
                try:
                    current=path.stat();need([current.st_dev,current.st_ino]==identity,'source_replaced')
                    need(conn.execute('PRAGMA query_only').fetchone()==(1,),'source_not_readonly');conn.execute('BEGIN')
                    need(conn.execute('PRAGMA encoding').fetchone()==('UTF-8',),'unsupported_auxiliary_encoding')
                    tables=dict(conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"))
                    need(not any(n.startswith('__walden_') for n in tables),'source_reserved_namespace')
                    if table not in tables:
                        need(prior is None and old_shard.get('present') is not True,'source_table_missing')
                        current=path.stat();need([current.st_dev,current.st_ino]==identity,'source_replaced')
                        with path.open('rb') as f:need(hashlib.sha256(f.read(16)).hexdigest()==header,'source_replaced')
                        proof['shards'][path.name]=dict(present=False,members=[],checked_at=int(time.time()),source_identity=identity,source_header_sha256=header)
                        continue
                    _validate_message_cursor(conn,table);need(_username_for_table(conn,table)==target,'conversation_identity_conflict')
                    key=SourceKey(config['account_id'],config['source_generation'],path.name,table);store=MirrorStore(root/path.name,key)
                    need(store.progress(table)==prior,'request_cache_conflict')
                    if prior:need(prior['source_identity']==identity and prior['source_header_sha256']==header,'source_replaced')
                    store.ensure_table(key,tables[table]);_copy_indexes(conn,store,table)
                    namekey=SourceKey(key.account_id,key.source_generation,key.shard_name,'Name2Id');store.ensure_table(namekey,tables['Name2Id'])
                    columns=[(r[1],r[2].upper()) for r in conn.execute('PRAGMA table_info(Name2Id)')]
                    names=conn.execute('SELECT rowid,* FROM Name2Id').fetchall()
                    with store.connect() as local:
                        for row in names:
                            prior_name=local.execute('SELECT rowid,* FROM Name2Id WHERE rowid=?',(row[0],)).fetchone()
                            need(prior_name is None or _sender_mapping_matches(prior_name,row,columns),'sender_identity_conflict')
                    now=int(time.time());need(conn.execute('SELECT 1 FROM '+qi(table)+" WHERE typeof(create_time)!='integer' OR create_time<0 OR create_time>? LIMIT 1",(now,)).fetchone() is None,'request_timestamp_invalid')
                    maximum=conn.execute('SELECT coalesce(max(local_id),0) FROM '+qi(table)).fetchone()[0]
                    where='';args=[];cap=window['limit'] if window['kind']=='latest' else 501
                    if window['kind']=='date':where=' WHERE create_time>=? AND create_time<=?';args=[window['since'],window['until']]
                    with lossless_text_rows(conn):rows=conn.execute('SELECT rowid,* FROM '+qi(table)+where+' ORDER BY create_time DESC,local_id DESC LIMIT ?',tuple(args+[cap])).fetchall()
                    check_deadline()
                    current=path.stat();need([current.st_dev,current.st_ino]==identity,'source_replaced')
                    with path.open('rb') as f:need(hashlib.sha256(f.read(16)).hexdigest()==header,'source_replaced')
                    store.apply_batch(namekey,'Name2Id',names,{})
                    if prior:need(maximum>=prior['H'] and maximum>=prior['tail'],'source_cursor_regression')
                    progress=dict(prior or dict(H=maximum,history=0,tail=0,history_complete=False),target=maximum,checked_at=now,source_identity=identity,source_header_sha256=header)
                    store.apply_batch(key,table,rows,progress)
                    local_index=1+[r[1] for r in conn.execute('PRAGMA table_info('+qi(table)+')')].index('local_id')
                    proof['shards'][path.name]=dict(present=True,members=[r[local_index] for r in rows],checked_at=now,complete=window['kind']=='latest' or len(rows)<501,source_identity=identity,source_header_sha256=header)
                    Store(root).atomic('request-window.json',proof)
                finally:conn.close()
            check_deadline();need([Path(p).name for p in discover_numeric_shards(Path(config['message_root']))]==[Path(p).name for p in paths],'source_shard_changed')
            proof['complete']=bool(paths) and all(v.get('complete',True) for v in proof['shards'].values())
            if window['kind']=='date' and sum(len(v['members']) for v in proof['shards'].values())>window['limit']:proof['complete']=False
            if not proof['complete']:proof['reason']='request_window_page_limit'
            Store(root).atomic('request-window.json',proof)
    except MirrorError as error:
        if str(error)!='sync_busy':raise
        return dict(gaps=[],request_complete=False,request_pending_reason='sync_busy')
    return dict(gaps=[],request_complete=proof['complete'],request_terminal_pending=proof.get('reason')=='request_window_page_limit',request_pending_reason=proof.get('reason'))


from .failure_evidence import _register
_register(window_spec,resolve,target_of,validate_contact,cache_profile,cache_preflight,_cached_progress,_cache_window_complete,local_result,validate,prepare,_prepare_cohort,status,require_source_round,copy_window,_copy_window)
