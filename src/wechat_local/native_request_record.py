"""Read-only protected request cohort and exact recorded SDK cleanup routing."""
import hashlib,json,plistlib,os,stat
from pathlib import Path
from .native_mirror_store import MirrorError
from .native_follow_policy import Store,digest


def cohort(path,*,config=None,config_path=None):
    from .native_target_request import read,need,target_of,window_spec,cache_profile
    from .source_setup import load_source_config
    from .native_schedule import _config_facts
    path=Path(path).absolute();state=Store(path.parent).read(path.name)
    need(type(state) is dict,'request_state_conflict')
    raw=read(state['descriptor']['path']);grant=json.loads(raw);profile=json.loads(read(state['profile']))
    need(digest(grant)==state['descriptor']['sha256']==state['active_grant_sha256'] and grant.get('kind')=='request' and grant.get('authorized') is True,'request_state_conflict')
    need(hashlib.sha256(read(grant['source_profile'])).hexdigest()==grant['source_raw_sha256'],'request_source_conflict')
    original=load_source_config(Path(grant['source_profile']),physical=False)
    need(digest(original)==grant['source_signature'],'request_source_conflict')
    if config is not None:need(digest(config)==grant['source_signature'] and str(Path(config_path).absolute())==grant['source_profile'],'request_source_conflict')
    target=target_of(grant['reference'],original);w=grant['window']
    canonical=window_spec(latest=w.get('limit')) if w.get('kind')=='latest' else window_spec(since=w.get('since'),until=w.get('until'),timezone=w.get('timezone'))
    need(w==canonical and state['target']==target and state['window']==w,'request_window_invalid')
    need(digest(profile)==grant['snapshot_sha256'] and _config_facts(profile)==grant['config_sha256'],'request_snapshot_conflict')
    expected=cache_profile(original,target,w,Path(grant['root']))
    if not grant.get('media'):
        for key in ('image_database','image_attachments_root','image_key_config','image_output_root','voice_databases','voice_runtime_root','voice_python','media_transcriber_version','voice_discovery_complete','voice_discovery_status'):expected.pop(key,None)
    else:need(grant['media']=={'images':True,'audio':True,'references':True} and all(type(v) is bool for v in grant['media'].values()),'request_media_authorization_conflict')
    # Immutable old profiles name their original lexical venv, not this reader's.
    runtime=profile.get('runtime_python');need(type(runtime) is str and Path(runtime).is_absolute() and Path(runtime).name=='python','request_snapshot_conflict')
    for key,entry in (('runtime_python','python'),('window_cli','wechat-local-window'),('reply_cli','wechat-local-reply')):
        need(profile.get(key)==str(Path(runtime).parent/entry),'request_snapshot_conflict');expected[key]=profile[key]
    need(profile==expected,'request_snapshot_conflict')
    return state,grant,profile


def inspect(state,grant,profile,*,run=None):
    """Never execute the recorded entry. Original SDK validates its exact argv."""
    from .native_schedule import inspect_terminal_status,_schedule_label,_slot_view,_read,_digest
    unknown=dict(state='unknown',registration='unknown',sync_health='unknown',stop_confirmed=False,record_source='none',writer_lock='unknown',group_drained=None,gaps=['schedule_state_unknown'])
    try:
        directory=Path(state['services']).absolute();label=_schedule_label(profile,state['descriptor']);active=directory/(label+'.plist');slot=_slot_view(active);path=active;suffix=''
        if slot[1][0] is None:
            archives=list(directory.glob(active.name+'.disabled-*'))
            if not archives:return dict(unknown,cleanup_reason='record_metadata_absent')
            def order(p):
                value=p.name[len(active.name+'.disabled-'):]
                if not value.isdecimal():raise MirrorError('request_record_unknown')
                return int(value)
            path=max(archives,key=order);suffix=path.name[len(active.name):]
        raw,identity=_read(path);record_path=active.with_suffix('.owned').with_name(active.with_suffix('.owned').name+suffix);record=json.loads(_read(record_path)[0]);payload=plistlib.loads(raw)
        if (record.get('plist_sha256')!=_digest(raw) or record.get('plist_identity')!=identity or record.get('follow_grant')!=state['descriptor']['path'] or record.get('follow_grant_sha256')!=state['descriptor']['sha256'] or record.get('operation')!=state.get('operation')):return dict(unknown,cleanup_reason='record_metadata_mismatch')
        args=payload.get('ProgramArguments');entry=args[0] if type(args) is list and args else None
        if type(entry) is not str or not Path(entry).is_absolute():return dict(unknown,cleanup_reason='record_entry_invalid')
        # This is metadata, not an interpreter/actor switch. SDK checks full
        # config, descriptor flags, operation, inode/hash, full context and group.
        value=inspect_terminal_status(profile,state['profile'],Path(entry),directory,runner=run,follow_grant=state['descriptor'])
        if _slot_view(active)!=slot:return dict(unknown,cleanup_reason='record_slot_changed')
        return dict(value,cleanup_reason='verified' if value.get('stop_confirmed') else 'recorded_worker_cleanup_unconfirmed',recorded_entry_matches_snapshot=entry==str(Path(profile['runtime_python']).parent/'wechat-local-sync'))
    except (MirrorError,OSError,ValueError,KeyError,TypeError,plistlib.InvalidFileException):return dict(unknown,cleanup_reason='record_metadata_unverified')


def _empty_container(path,*,runtime_dirs=False):
    entries=list(path.iterdir())
    if len(entries)>64:return False
    for entry in entries:
        info=entry.lstat()
        if entry.name=='.walden-schedule.lock':
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:return False
        elif runtime_dirs and entry.name.startswith('runtime-') and len(entry.name)==40 and all(c in '0123456789abcdef' for c in entry.name[8:]) and stat.S_ISDIR(info.st_mode):
            Store(entry)
        else:return False
    return True


def candidates(root,config,target,window):
    """Only this exact target/window cohort: legacy, media-v1, runtime children."""
    legacy=Path(root)/'requests'/digest([digest(config),target,window])[:32]
    media=Path(root)/'requests'/digest([digest(config),target,window,'request-media-v1'])[:32]
    if legacy.exists():
        Store(legacy)
        if not (legacy/'request.json').is_file():raise MirrorError('request_state_conflict')
    paths=[legacy/'request.json',media/'request.json']
    if media.exists():
        Store(media)
        if not (media/'request.json').is_file() and not _empty_container(media,runtime_dirs=True):raise MirrorError('request_state_conflict')
        children=list(media.glob('runtime-*'))
        if len(children)>32:raise MirrorError('request_runtime_slots_exceeded')
        for child in children:
            if child.is_symlink() or not child.is_dir() or len(child.name)!=40 or any(c not in '0123456789abcdef' for c in child.name[8:]):raise MirrorError('request_state_conflict')
            Store(child)
            if not (child/'request.json').is_file():
                if not _empty_container(child):raise MirrorError('request_state_conflict')
                continue
            paths.append(child/'request.json')
    return [p for p in paths if p.exists()]


from .failure_evidence import _register
_register(cohort,inspect,_empty_container,candidates)
