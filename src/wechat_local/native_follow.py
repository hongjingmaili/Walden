"""User LaunchAgent follow management. All Source work remains finite/owned."""
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import signal
import time
import uuid
from . import native_process as kernel
from .native_deadline import Deadline,continuous_ns
from .native_mirror_store import MirrorError
from .native_schedule import (_read,_create,_sync_dir,_observe,_writer_state,_schedule_label,_lock,
                              configure,inspect_status,LaunchctlTransport)
from .native_follow_policy import Store,default_root,profile_id,encoded,digest,local_environment
from .native_follow_config import settings
from .native_follow_app import observe
from .native_follow_events import VnodeHints
from .native_follow_schedule import plan
from .native_follow_state import transition
from .source_setup import load_source_config


def _preparation_fact(trace, outcome, operation=None, error=None):
    from .native_schedule import _PREPARATION_PHASES
    phase=trace.get('phase') if type(trace) is dict else None
    phase=phase if type(phase)is str and phase in _PREPARATION_PHASES else 'unknown'
    disposition='unknown'
    if outcome!='in_progress' and type(trace) is dict:
        if trace.get('submit_returned') is True:disposition='api_returned'
        elif trace.get('submit_attempted') is True:disposition='attempted_unknown'
        elif outcome=='returned' and phase=='existing_owned':disposition='existing_owned'
        elif outcome=='failed' and phase!='unknown' and trace.get('submit_attempted') is False:
            disposition='not_attempted_by_this_call'
    types={MirrorError:'MirrorError',OSError:'OSError',PermissionError:'PermissionError',
        FileNotFoundError:'FileNotFoundError',ValueError:'ValueError',TypeError:'TypeError',
        RuntimeError:'RuntimeError',TimeoutError:'TimeoutError',KeyboardInterrupt:'KeyboardInterrupt',SystemExit:'SystemExit'}
    return dict(phase=phase,outcome=outcome,submit_disposition=disposition,
        operation=operation if type(operation)is str and re.fullmatch('[0-9a-f]{32}',operation) else None,
        error_type=types.get(type(error),'other') if error is not None else None)


def preparation_diagnostic(runtime):
    """Bounded optional diagnostics; never used to authorize work or prove stop."""
    from .native_schedule import _PREPARATION_PHASES
    if type(runtime)is not dict:return None
    value=runtime.get('worker_preparation')
    if type(value)is not dict or set(value)!={'phase','outcome','submit_disposition','operation','error_type'}:return None
    if any(type(value[k])is not str for k in ('phase','outcome','submit_disposition')):return None
    if value['phase'] not in _PREPARATION_PHASES|{'unknown'} or value['outcome'] not in ('in_progress','failed','returned'):return None
    if value['submit_disposition'] not in ('unknown','api_returned','attempted_unknown','existing_owned','not_attempted_by_this_call'):return None
    if value['operation'] is not None and (type(value['operation'])is not str or re.fullmatch('[0-9a-f]{32}',value['operation'])is None):return None
    if value['error_type'] not in (None,'MirrorError','OSError','PermissionError','FileNotFoundError','ValueError','TypeError','RuntimeError','TimeoutError','KeyboardInterrupt','SystemExit','other'):return None
    return dict(value)


def _home():return Path(pwd.getpwuid(os.getuid()).pw_dir)


def _payload(policy,policy_path):
    return dict(Label=policy['label'],ProgramArguments=[policy['executable'],'follow-run',
        '--source-config',policy['snapshot'],'--policy-record',str(policy_path),
        '--policy-sha256',digest(policy),'--operation-token',policy['generation']],
        EnvironmentVariables=policy['environment'],RunAtLoad=True,KeepAlive=False,
        ThrottleInterval=30,ExitTimeOut=2,AbandonProcessGroup=False,ProcessType='Background')


def _legacy_payload(policy,policy_path):
    return dict(_payload(policy,policy_path),KeepAlive=True,ThrottleInterval=5)


def _target(run,label):
    ctx=run.context
    if ctx.get('uid')!=os.getuid() or ctx.get('domain')!='kSMDomainUserLaunchd':
        raise MirrorError('follow_context_unknown')
    return ctx['domain']+'/'+str(ctx['uid'])+'/'+str(ctx['security_session'])+'/'+label


def _policy(store):
    intent=store.read('intent.json')
    if intent is None:return None,None
    if type(intent.get('enabled')) is not bool:raise MirrorError('follow_state_unknown')
    policy=store.read('policy.'+intent['generation']+'.json')
    if not policy or policy['generation']!=intent['generation']:raise MirrorError('follow_state_unknown')
    return intent,policy


def _listener_revoked(store, policy):
    # Revocation permits only leaving the listener loop. Original finally still
    # proves ownership before worker control; this is never a stop/strict proof.
    intent, observed_policy = _policy(store)
    return intent == dict(enabled=False, generation=policy['generation']) and observed_policy == policy


def _runtime(store):
    current=store.read('current.json')
    if current is None:return None
    value=store.read('instance.'+current['nonce']+'.json')
    if not value or value.get('operation')!=current['nonce']:raise MirrorError('follow_state_unknown')
    return value


def _material(policy,*,allow_legacy=False):
    path=Path(policy['agent_path']);expected=plistlib.dumps(_payload(policy,policy['policy_path']))
    try:raw,_=_read(path)
    except FileNotFoundError:return 'absent'
    if raw==expected:
        return 'installed'
    if allow_legacy and raw==plistlib.dumps(_legacy_payload(policy,policy['policy_path'])):
        return 'legacy'
    return 'unknown'


def _segment_status(policy,segment,run,services):
    config=load_source_config(Path(policy['snapshot']),physical=False)
    until=time.monotonic()+2.;trace=None
    for attempt in range(3):
        result=inspect_status(config,policy['snapshot'],policy['executable'],services,
                              runner=run,follow_grant=segment['descriptor'])
        if result.get('runtime_snapshot_changed') is True:trace=result
        if result.get('runtime_snapshot_changed') is not True or time.monotonic()>=until:break
    diagnostic=result if result.get('gaps') else trace
    if diagnostic is not None:
        result['observation_diagnostic']=dict(reason=diagnostic.get('observation_reason','guard_or_read_unknown'),
            stage=diagnostic.get('observation_stage','guards'),attempt=diagnostic.get('observation_attempt',0),
            status_before=diagnostic.get('status_before','unknown'),status_after=diagnostic.get('status_after','unknown'),
            runtime_file_replaced=diagnostic.get('runtime_file_replaced',False),retries=attempt,recovered=not bool(result.get('gaps')))
    return result


def _stop_segment(policy,segment,run,services):
    config=load_source_config(Path(policy['snapshot']),physical=False)
    configure(config,policy['snapshot'],policy['executable'],services,False,
              runner=run,follow_grant=segment['descriptor'])
    return _segment_status(policy,segment,run,services)['stop_confirmed']


_WORKER_OBSERVATION_REASONS=frozenset(('runtime_ordinary_change','runtime_cleanup_change','runtime_authority_change','runtime_nonordinary_change',
    'runtime_unpublished_change','slot_changed','registration_changed','configuration_changed','plist_changed',
    'record_changed','guard_or_read_unknown','listener_stop'))
_WORKER_OBSERVATION_STAGES=frozenset(('guards','final','handoff','decision'))
_WORKER_STOP_CONTEXTS=frozenset(('none','disabled','source_conflict','application_changed','source_backoff','worker_unknown','segment_mismatch','other'))
_WORKER_RUNTIME_STATUSES=frozenset(('running','stopping','forcing_group_exit','stopped','stop_unconfirmed','cleanup_pending','unknown'))


def worker_observations(runtime):
    """Validate only the bounded fixed worker-observation diagnostic."""
    if type(runtime) is not dict:return []
    values=runtime.get('worker_observations',[])
    keys={'operation','at_ns','reason','stage','attempt','retries','recovered','status_before','status_after','runtime_file_replaced','stop_context'}
    if type(values) is not list or len(values)>8:return []
    for value in values:
        if type(value) is not dict or set(value)!=keys:return []
        if type(value['operation']) is not str or re.fullmatch('[0-9a-f]{32}',value['operation']) is None:return []
        if type(value['at_ns']) is not int or not 0<value['at_ns']<10**30:return []
        for key,maximum in (('attempt',2147483647),('retries',2)):
            if type(value[key]) is not int or not 0<=value[key]<=maximum:return []
        for key in ('recovered','runtime_file_replaced'):
            if type(value[key]) is not bool:return []
        for key,allowed in (('reason',_WORKER_OBSERVATION_REASONS),('stage',_WORKER_OBSERVATION_STAGES),
                            ('stop_context',_WORKER_STOP_CONTEXTS),('status_before',_WORKER_RUNTIME_STATUSES),('status_after',_WORKER_RUNTIME_STATUSES)):
            if type(value[key]) is not str or value[key] not in allowed:return []
    return [dict(value) for value in values]


def _record_worker_observation(runtime,segment,info,*,stop_context='none'):
    diagnostic=info.get('observation_diagnostic')
    if type(diagnostic) is not dict and stop_context=='none':return
    diagnostic=diagnostic if type(diagnostic) is dict else {}
    operation=segment.get('operation')
    if type(operation) is not str or re.fullmatch('[0-9a-f]{32}',operation) is None:return
    def enum(key,allowed,fallback):
        value=diagnostic.get(key)
        return value if type(value) is str and value in allowed else fallback
    value=dict(operation=operation,at_ns=time.time_ns(),
        reason=enum('reason',_WORKER_OBSERVATION_REASONS,'listener_stop' if stop_context!='none' else 'guard_or_read_unknown'),
        stage=enum('stage',_WORKER_OBSERVATION_STAGES,'decision'),
        attempt=diagnostic.get('attempt',0),retries=diagnostic.get('retries',0),recovered=diagnostic.get('recovered',False),
        status_before=enum('status_before',_WORKER_RUNTIME_STATUSES,'unknown'),
        status_after=enum('status_after',_WORKER_RUNTIME_STATUSES,'unknown'),
        runtime_file_replaced=diagnostic.get('runtime_file_replaced',False),stop_context=stop_context)
    if not worker_observations(dict(worker_observations=[value])):return
    rows=worker_observations(runtime)
    if any(all(prior[key]==value[key] for key in value if key!='at_ns') for prior in rows):return
    runtime['worker_observations']=(rows+[value])[-8:]


def _prune_disabled_agents(store, agent):
    """The three newest native archives are the bounded rollback copies."""
    archive_name = re.compile(re.escape(agent.name) + r'\.disabled-([0-9]+)\Z')
    candidates = []
    for path in agent.parent.glob(agent.name + '.disabled-*'):
        match = archive_name.fullmatch(path.name)
        if not match:
            continue
        try:
            raw, identity = _read(path)
            payload = plistlib.loads(raw)
        except (OSError, ValueError, MirrorError, plistlib.InvalidFileException):
            continue  # Unrecognized files are outside this profile's retention set.
        if type(payload) is not dict:
            continue
        args = payload.get('ProgramArguments', [])
        if type(args) is not list or len(args) < 2 or args[1] != 'follow-run' or args.count('--policy-record') != 1:
            continue
        index = args.index('--policy-record') + 1
        if index >= len(args) or type(args[index]) is not str:
            continue
        policy_path = Path(args[index])
        if policy_path.parent != store.root or not re.fullmatch(r'policy\.[0-9a-f]{32}\.json',policy_path.name):
            continue
        policy = store.read(policy_path.name)
        if type(policy) is not dict or policy.get('agent_path') != str(agent):
            continue
        expected = _payload(policy, policy_path)
        if payload not in (expected,_legacy_payload(policy,policy_path)):
            continue
        candidates.append((int(match[1]),path,raw,identity))
    candidates.sort(reverse=True)
    removed = 0
    for _,path,raw,identity in candidates[3:]:
        # Record each retirement before deleting; the last record is overwritten.
        store.atomic('listener-retirement.json',dict(at_ns=time.time_ns(),archive=path.name,
                     sha256=hashlib.sha256(raw).hexdigest(),preserved=3))
        if _read(path) != (raw,identity):
            raise MirrorError('follow_retirement_unconfirmed')
        path.unlink()
        removed += 1
    if removed:
        _sync_dir(agent.parent)
    return removed


def _retire_stopped_worker(store, segment, services, *, terminal=None):
    """Retire a proved, detached worker. An exact backup resumes partial removal."""
    services = Path(services)
    record_path = Path(segment['record'])
    descriptor = segment['descriptor']
    grant_path = Path(descriptor['path'])
    if (services.parent != store.root or not re.fullmatch(r'workers\.[0-9a-f]{32}',services.name)
            or record_path.parent != services or record_path.suffix != '.owned'
            or grant_path.parent != store.root or not re.fullmatch(r'grant\.[0-9a-f]{32}\.json',grant_path.name)):
        raise MirrorError('follow_retirement_unconfirmed')
    owner = services.name.rsplit('.',1)[1]
    key = digest(dict(segment=segment,services=str(services)))
    with store.locked(), _lock(services):
        current = _runtime(store) or {}
        pending = current.get('retirement_pending') or {}
        transferred = pending.get('segment') == segment and pending.get('services') == str(services)
        owns = current.get('operation') == owner and current.get('services') == str(services)
        if (not (owns or transferred) or current.get('segment') or current.get('unsettled_activity')
                or current.get('grant_nonce')):
            raise MirrorError('follow_retirement_active_reference')
        generation = pending.get('policy_generation') if transferred else current.get('policy_generation')
        context = pending.get('context') if transferred else current.get('context')
        backup = store.read('worker-retirement.json') or {}
        resumed = backup.get('descriptor_sha256') == key
        if resumed:
            suffix = backup['suffix']
        else:
            matches = []
            for archive in services.glob(record_path.name + '.disabled-*'):
                candidate = archive.name[len(record_path.name):]
                if re.fullmatch(r'\.disabled-[0-9]+',candidate) and json.loads(_read(archive)[0]).get('operation')==segment['operation']:
                    matches.append(candidate)
            if len(matches) != 1:
                raise MirrorError('follow_retirement_unconfirmed')
            suffix = matches[0]
        if not re.fullmatch(r'\.disabled-[0-9]+',suffix):
            raise MirrorError('follow_retirement_unconfirmed')
        files = {}
        for extension in ('.plist','.owned','.runtime','.active','.starting','.submission'):
            live = record_path.with_suffix(extension)
            if live.exists() or live.is_symlink():
                raise MirrorError('follow_retirement_active_reference')
            archived = live.with_name(live.name + suffix)
            if resumed:
                if archived.name in backup['files']:
                    files[archived] = (base64.b64decode(backup['files'][archived.name],validate=True),
                                       backup['identities'][archived.name])
            else:
                try:files[archived] = _read(archived)
                except FileNotFoundError:
                    if extension in ('.plist','.owned'):raise
        if resumed:
            files[grant_path] = (base64.b64decode(backup['files'][grant_path.name],validate=True),
                                 backup['identities'][grant_path.name])
        else:
            files[grant_path] = _read(grant_path)
        grant_raw, _ = files[grant_path]
        grant = json.loads(grant_raw)
        archived_record = record_path.with_name(record_path.name+suffix)
        record = json.loads(files[archived_record][0])
        archived_plist = record_path.with_suffix('.plist')
        plist_raw, plist_id = files[archived_plist.with_name(archived_plist.name+suffix)]
        if (hashlib.sha256(grant_raw).hexdigest() != descriptor['sha256']
                or grant.get('kind') not in ('active','drain') or grant.get('instance_nonce') != owner
                or grant.get('policy_generation') != generation or grant.get('store_root') != str(store.root)
                or grant_path.name != 'grant.'+grant.get('nonce','')+'.json'
                or record.get('operation') != segment['operation']
                or record.get('follow_grant') != str(grant_path)
                or record.get('follow_grant_sha256') != descriptor['sha256']
                or record.get('plist_identity') != plist_id
                or record.get('plist_sha256') != hashlib.sha256(plist_raw).hexdigest()):
            raise MirrorError('follow_retirement_unconfirmed')
        if not resumed:
            backup = dict(at_ns=time.time_ns(),operation=segment['operation'],descriptor_sha256=key,suffix=suffix,
                          files={p.name:base64.b64encode(raw).decode('ascii') for p,(raw,_) in files.items()},
                          identities={p.name:identity for p,(_,identity) in files.items()})
            if len(encoded(backup)) > 65536:
                raise MirrorError('follow_retirement_unconfirmed')
            store.atomic('worker-retirement.json',backup)
        present = []
        for path, before in files.items():
            try:actual = _read(path)
            except FileNotFoundError:
                if resumed:continue
                raise
            if actual != before:
                raise MirrorError('follow_retirement_unconfirmed')
            present.append(path)
        runtime_path = record_path.with_suffix('.runtime')
        runtime_path = runtime_path.with_name(runtime_path.name+suffix)
        if terminal is not None and runtime_path in files:
            final = json.loads(files[runtime_path][0])
            if final.get('operation') != segment['operation'] or final.get('os_context') != context:
                raise MirrorError('follow_retirement_unconfirmed')
            terminal(final)
        for path in present:
            path.unlink()
        _sync_dir(services)
        _sync_dir(store.root)
        return len(present)


def _adopt_worker_cadence(runtime, segment, report, *, interval):
    if segment.get('kind') == 'active' and type(report.get('source_schedule')) is dict:
        cadence = dict(report['source_schedule'])
        prior = runtime.get('source_schedule') or {}
        if 'media' in prior:
            cadence.setdefault('media',prior['media'])
        runtime['source_schedule'] = cadence
    # A failed admission has no child completion. Apply its outcome even for
    # drain, whose successful cadence does not carry into an active grant.
    failure = report.get('admission_failure')
    attempt = report.get('attempt_record') or {}
    if (type(failure) is not dict or failure.get('kind') != 'source_spawn'
            or failure.get('operation') != segment.get('operation')
            or failure.get('attempt') != report.get('attempts')
            or attempt.get('phase') != 'spawn_failed' or attempt.get('attempt') != failure.get('attempt')):
        return False
    runtime['source_schedule'] = plan(runtime.get('source_schedule'), wall=time.time(),
        continuous=continuous_ns(), interval=interval, completion=dict(failure,exit_code=2))
    return True


def enable(config,profile_path,executable,*,run=None,root=None,agents=None):
    opts=settings(config);profile_path=Path(profile_path).absolute();executable=Path(executable).absolute()
    from .native_scope_contract import mode
    mode(config)
    if not config.get('mirror_root') or not config.get('self_identity'):
        raise MirrorError('follow_bound_native_source_required')
    if (Path(config['runtime_python']).parent!=executable.parent or
        Path(config['window_cli'])!=executable.parent/'wechat-local-window' or
        Path(config['reply_cli'])!=executable.parent/'wechat-local-reply'):
        raise MirrorError('follow_installed_environment_mismatch')
    run=run or LaunchctlTransport();store=Store(root or default_root(profile_path),create=True)
    agent_dir=Path(agents) if agents is not None else _home()/'Library/LaunchAgents'
    agent_dir.mkdir(parents=True,mode=0o700,exist_ok=True)
    with store.locked():
        intent,previous=_policy(store)
        if intent and intent['enabled']:
            if previous['source_signature']!=digest(config) or previous['executable']!=str(executable):
                raise MirrorError('follow_existing_policy_conflict')
            policy=previous
        else:
            generation=uuid.uuid4().hex
            snapshot=store.immutable('source.'+generation+'.json',config)
            policy=dict(schema_version=1,generation=generation,profile_path=str(profile_path),
                source_signature=digest(config),snapshot=str(snapshot),executable=str(executable),
                settings=opts,label='org.walden.native.follow.'+profile_id(profile_path),
                store_root=str(store.root),environment=local_environment(_home()))
            policy['policy_path']=str(store.path('policy.'+generation+'.json'))
            policy['agent_path']=str(agent_dir/(policy['label']+'.plist'))
            store.immutable('policy.'+generation+'.json',policy)
            store.atomic('intent.json',dict(enabled=True,generation=generation))
        payload=_payload(policy,policy['policy_path']);target=_target(run,policy['label'])
        material=_material(policy)
        if material=='unknown':raise MirrorError('follow_login_material_unknown')
        if material=='absent':_create(Path(policy['agent_path']),plistlib.dumps(payload));_sync_dir(agent_dir)
        observation=_observe(run,target,payload)
        if observation=='absent':run.submit(payload)
        elif observation!='owned':raise MirrorError('follow_listener_unknown')
        if _observe(run,target,payload)!='owned':raise MirrorError('follow_listener_unknown')
    return status(profile_path,run=run,root=store.root)


def disable(profile_path,*,run=None,root=None):
    store=Store(root or default_root(profile_path));run=run or LaunchctlTransport()
    intent,policy=_policy(store)
    if policy is None:return status(profile_path,run=run,root=store.root)
    # Durable revocation always precedes any stop/API operation.
    with store.locked():store.atomic('intent.json',dict(enabled=False,generation=intent['generation']))
    current=_runtime(store)
    if current and current.get('segment'):
        _stop_segment(policy,current['segment'],run,current['services'])
    material = _material(policy,allow_legacy=True)
    payload = (_legacy_payload if material=='legacy' else _payload)(policy,policy['policy_path'])
    target=_target(run,policy['label'])
    registration=_observe(run,target,payload)
    if registration=='owned':run.remove(target,wait=True)
    elif registration!='absent':raise MirrorError('follow_listener_unknown')
    if _observe(run,target,payload)!='absent':raise MirrorError('follow_listener_unknown')
    if current and (current.get('legacy_retirement') or current.get('current_recovery')) and current.get('segment') is None:
        if current.get('current_recovery'):
            from .native_follow_current_recovery import current_status
        else:
            from .native_follow_legacy import current_status
        if current_status(store,current,run,**({'profile_path':profile_path}if current.get('current_recovery')else{}))!='free':
            raise MirrorError('follow_listener_stop_unconfirmed')
    elif current and not kernel.drained(current['leader']):raise MirrorError('follow_listener_stop_unconfirmed')
    if material in ('installed','legacy'):
        path=Path(policy['agent_path']);before=_read(path)
        if before[0]!=plistlib.dumps(payload):raise MirrorError('follow_login_material_unknown')
        archive=path.with_name(path.name+'.disabled-'+str(time.time_ns()))
        if path.parent!=archive.parent or _read(path)!=before:raise MirrorError('follow_login_material_unknown')
        os.replace(path,archive);_sync_dir(path.parent)
        with store.locked():
            _prune_disabled_agents(store,path)
    return status(profile_path,run=run,root=store.root)


def _view(store):
    values=[]
    for name in ('intent.json','current.json'):
        try:values.append(_read(store.path(name)))
        except FileNotFoundError:values.append(None)
    current=store.read('current.json')
    if current is not None:
        try:values.append(_read(store.path('instance.'+current['nonce']+'.json')))
        except FileNotFoundError:values.append(None)
    return values


def status(profile_path,*,run=None,root=None):
    store=Store(root or default_root(profile_path));run=run or LaunchctlTransport()
    before_view=_view(store)
    intent,policy=_policy(store)
    result=dict(schema_version=1,mode='follow',enabled=False,state='disabled',policy_generation=None,
        instance_nonce=None,app_epoch=None,gui_login_identity='unobservable',source_binding='unknown',
        listener_registration='unknown',worker_registration='absent',round=dict(operation=None,attempt=None,last_completed=None),
        drain=None,activity_stop_confirmed=None,disabled_confirmed=False,observed_catchup_complete=None,
        observed_as_of=None,catchup_pending=True,pending_reasons=[],final_completeness='not_promised',
        writer_lock='unknown',gaps=[],login_registration=dict(state='absent',enabled=False,verified_user_home=None),
        session_context=run.context,source_schedule=dict(mode='normal',next_due_at_ns=None,next_due_continuous_ns=None))
    if policy is None:
        label='org.walden.native.follow.'+profile_id(profile_path)
        result['listener_registration']=_observe(run,_target(run,label))
        result['disabled_confirmed']=result['listener_registration']=='absent'
        if _view(store)!=before_view:
            result.update(state='unknown',disabled_confirmed=False,gaps=['follow_state_changed'])
        elif not result['disabled_confirmed']:result.update(state='unknown',gaps=['follow_state_unknown'])
        return result
    result.update(enabled=intent['enabled'],policy_generation=policy['generation'])
    result['login_registration']=dict(state=_material(policy),enabled=intent['enabled'],
        verified_user_home=Path(policy['agent_path']).parent==_home()/'Library/LaunchAgents')
    registration=_observe(run,_target(run,policy['label']),_payload(policy,policy['policy_path']))
    result['listener_registration']=registration
    runtime=_runtime(store)
    if runtime and runtime.get('policy_generation')==policy['generation']:
        for key in ('state','app_epoch','drain','observed_catchup_complete','observed_as_of','catchup_pending','pending_reasons','source_schedule','retention'):
            if key in runtime:result[key]=runtime[key]
        result['instance_nonce']=runtime['operation']
        result['source_binding']='configured_authorized_source' if runtime.get('binding_valid') else 'conflict'
        if runtime.get('segment'):
            info=_segment_status(policy,runtime['segment'],run,runtime['services'])
            result.update(worker_registration=info['registration'],writer_lock=info['writer_lock'],
                activity_stop_confirmed=info['stop_confirmed'],cleanup_handoff=info.get('cleanup_handoff'))
            raw=Store(runtime['store_root']).read('instance.'+runtime['operation']+'.json')
            result['round']=raw.get('round',result['round'])
        else:
            result['activity_stop_confirmed']=runtime.get('activity_stop_confirmed')
            if runtime.get('legacy_retirement') or runtime.get('current_recovery'):
                if runtime.get('current_recovery'):
                    from .native_follow_current_recovery import current_status
                else:
                    from .native_follow_legacy import current_status
                try:
                    result['writer_lock']=current_status(store,runtime,run,**({'profile_path':profile_path}if runtime.get('current_recovery')else{}))
                    if result['writer_lock']!='free':result['activity_stop_confirmed']=False
                except (MirrorError,OSError,KeyError,TypeError,ValueError):
                    result['activity_stop_confirmed']=False
                    result['worker_registration']='unknown'
        leader=runtime.get('leader');actual=kernel.identity(leader['pid']) if leader else None
        if (registration!='owned' or not kernel.same_generation(actual,leader)
                or run.pid(_target(run,policy['label']))!=leader['pid']):
            if intent['enabled']:result.update(state='unknown',gaps=['follow_listener_unknown'])
    elif intent['enabled']:
        result.update(state='starting',gaps=[])
    if not intent['enabled']:
        result['disabled_confirmed']=registration=='absent' and (runtime is None or result['activity_stop_confirmed'] is True)
        result['state']='disabled' if result['disabled_confirmed'] else 'stopping'
        if not result['disabled_confirmed']:result['gaps']=['follow_stop_unconfirmed']
    if intent['enabled'] and runtime:
        try:
            if digest(load_source_config(Path(policy['profile_path']),physical=False))!=policy['source_signature']:
                result.update(state='source_conflict',source_binding='conflict',catchup_pending=True,gaps=['follow_source_conflict'])
            else:
                app=observe(policy['settings']['executable'])
                if app['state']=='unknown':
                    result.update(state='unknown',observed_catchup_complete=None,catchup_pending=True,gaps=['follow_app_unknown'])
                elif app['state']=='running' and app['epoch']!=runtime.get('app_epoch'):
                    result.update(state='starting',observed_catchup_complete=None,catchup_pending=True)
                elif app['state']=='absent' and result['state'] not in ('finishing','waiting_app','source_conflict'):
                    result.update(state='stopping',observed_catchup_complete=None,catchup_pending=True)
        except (OSError,ValueError,MirrorError):
            result.update(state='source_conflict',source_binding='unknown',catchup_pending=True,gaps=['follow_source_conflict'])
    if result['state']=='source_conflict' and not result['gaps']:result['gaps']=['follow_source_conflict']
    if result['state']=='partial_source' and not result['gaps']:
        from .native_table_cursor import PENDING
        reasons = result['pending_reasons']
        gaps = [PENDING] if PENDING in reasons else []
        if 'source_shard_retry_pending' in reasons or not gaps:
            gaps.append('follow_shard_retry_pending')
        result.update(gaps=gaps,observed_catchup_complete=None,catchup_pending=True)
    if result['state']=='waiting_source' and not result['gaps']:
        done=(result.get('round') or {}).get('last_completed') or {};ended=done.get('termination') or {}
        result['gaps']=['follow_child_reaped_after_deadline' if ended.get('raw_signal') and ended.get('round_deadline_expired') is True
                        else 'follow_child_signaled' if ended.get('raw_signal') else 'follow_source_unavailable']
    handoff=result.get('cleanup_handoff') or {}
    if handoff.get('gaps'):
        result['gaps']=sorted(set(result['gaps']+handoff['gaps']));result['catchup_pending']=True;result['observed_catchup_complete']=None
    if result['login_registration']['state']=='unknown':result['gaps'].append('follow_login_material_unknown')
    completed=(runtime or {}).get('round',{}).get('last_completed') or {}
    prior_unknown=(completed.get('observation') or {}).get('prior_coverage_unknown') is True
    try:
        from .native_account_reconcile import read as reconcile_request
        from .native_scope_contract import mode
        source=json.loads(_read(Path(policy['snapshot']))[0])
        if mode(source)=='account':prior_unknown=prior_unknown or reconcile_request(source) is not None
    except (MirrorError,OSError,ValueError,KeyError,TypeError):
        result.update(state='unknown',observed_catchup_complete=None)
        result['gaps'].append('account_reconcile_request_invalid')
    if prior_unknown:
        result.update(prior_coverage_unknown=True,current_snapshot_complete=result.get('observed_catchup_complete'),observed_catchup_complete=None)
    if _view(store)!=before_view:
        result.update(state='unknown',disabled_confirmed=False,activity_stop_confirmed=None,
                      observed_catchup_complete=None,gaps=['follow_state_changed'])
    ident=(runtime or {}).get('listener_task_id')
    if type(ident)is str and re.fullmatch('[0-9a-f]{32}',ident):result['listener_task_id']=ident
    diagnostic=preparation_diagnostic(runtime)
    if diagnostic is not None:result['worker_preparation']=diagnostic
    return result


def _settle_cleanup_handoff(policy,segment,run,services,parent,info):
    """Record same-receiver accounting only after the original SDK proves stop."""
    handoff=info.get('cleanup_handoff')
    if handoff is None:return info
    allowed={'cleanup_handoff_expired'}
    if (info.get('stop_confirmed') is not True or info.get('registration')!='absent'
        or info.get('group_drained') is not True or info.get('writer_lock')!='free'
        or set(info.get('gaps',[]))-allowed):return info
    path=Path(segment['record']).with_suffix('.runtime');original_runtime=_read(path)[0];child=json.loads(original_runtime);pending=child.get('cleanup_pending') or {}
    context=hashlib.sha256(json.dumps(run.context,sort_keys=True).encode()).hexdigest()
    if (child.get('operation')!=segment['operation'] or pending.get('operation')!=segment['operation']
        or pending.get('receiver_instance')!=parent.get('operation') or pending.get('receiver_generation')!=policy['generation']
        or pending.get('receiver_context')!=context or parent.get('context')!=run.context):
        return dict(info,cleanup_handoff=dict(state='receiver_mismatch',source_authority=False,gaps=['cleanup_handoff_receiver_mismatch']),gaps=sorted(set(info.get('gaps',[])+['cleanup_handoff_receiver_mismatch'])),stop_confirmed=False)
    fresh=_segment_status(policy,segment,run,services)
    if (fresh.get('stop_confirmed') is not True or fresh.get('registration')!='absent'
        or fresh.get('group_drained') is not True or fresh.get('writer_lock')!='free'
        or set(fresh.get('gaps',[]))-allowed):return fresh
    from .native_background import _runtime_write
    expired=Deadline(pending['expires']).remaining()<=0
    child['cleanup_settlement']=dict(operation=segment['operation'],receiver_instance=parent['operation'],receiver_generation=policy['generation'],receiver_context=context,state='confirmed_after_expiry' if expired else 'confirmed',observed_at_ns=time.time_ns(),historical_gap='cleanup_handoff_expired' if expired else None,source_authority=False)
    if _read(path)[0]!=original_runtime:raise MirrorError('follow_worker_preparation_unknown')
    _runtime_write(path,child)
    return _segment_status(policy,segment,run,services)


def run_listener(policy_path,policy_sha256,*,operation_token,run=None,process=kernel,sleep=time.sleep,app_observer=observe,event_factory=VnodeHints):
    """Persistent login authorization, fresh per-instance context/birth; no model."""
    raw,_=_read(Path(policy_path))
    if hashlib.sha256(raw).hexdigest()!=policy_sha256:raise MirrorError('follow_policy_unknown')
    policy=json.loads(raw);store=Store(policy['store_root']);run=run or LaunchctlTransport()
    payload=_payload(policy,policy_path);target=_target(run,policy['label'])
    if (operation_token!=policy['generation'] or _material(policy)!='installed'
            or _observe(run,target,payload)!='owned' or run.pid(target)!=os.getpid()):
        raise MirrorError('follow_listener_unknown')
    leader=process.identity(os.getpid());process.require_own_leader(leader)
    intent,_=_policy(store)
    if not intent['enabled']:
        run.remove(target,wait=False)
        return dict(enabled=False,gaps=[])
    previous=_runtime(store);nonce=uuid.uuid4().hex
    services=store.root/('workers.'+nonce);services.mkdir(mode=0o700)
    old_state=previous if previous and previous.get('context')==run.context and previous.get('policy_generation')==policy['generation'] else {}
    runtime=dict(old_state,operation=nonce,policy_generation=policy['generation'],leader=leader,
        context=run.context,listener_argv=payload['ProgramArguments'],store_root=str(store.root),services=str(services),
        admission=False,grant_nonce=None,segment=None,binding_valid=True,activity_stop_confirmed=None)
    runtime.pop('legacy_retirement',None)
    runtime.pop('current_recovery',None)
    runtime['observed_catchup_complete']=None
    from .failure_evidence import current_task_id
    runtime['listener_task_id']=current_task_id()
    runtime['worker_preparation']=None
    runtime['observed_as_of']=None
    runtime['consumed_hint_generation']=-1
    runtime['source_schedule'] = old_state.get('source_schedule') or dict(
        mode='normal',next_due_at_ns=time.time_ns(),next_due_continuous_ns=continuous_ns())
    pending=previous.get('unsettled_activity') if previous else None
    if pending is None and previous and previous.get('segment'):
        pending=dict(segment=previous['segment'],services=previous['services'],context=previous['context'],
                     policy_generation=previous['policy_generation'])
    runtime['unsettled_activity']=pending
    runtime['retirement_pending'] = previous.get('retirement_pending') if previous else None
    store.immutable('instance.'+nonce+'.json',runtime)
    store.atomic('current.json',dict(nonce=nonce))
    stop=[False];previous_handler=signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM,lambda *_:stop.__setitem__(0,True))
    config=load_source_config(Path(policy['snapshot']),physical=False)
    recovered=True;last_serialized=None;last_completion=None
    hint_generation=runtime.get('hint_generation',0)+1
    events=None
    event_attempt = 0
    def event_failed(error):
        nonlocal events, event_attempt, hint_generation
        event_attempt += 1
        hint_generation += 1
        wall, tick = time.time(), continuous_ns()
        permanent = isinstance(error,MirrorError) and str(error) in (
            'follow_event_root_conflict','follow_native_events_unsupported')
        done = dict(operation=nonce,attempt=event_attempt,exit_code=2,
                    failure_class='permanent' if permanent else 'retryable',
                    completed_at_ns=int(wall*1e9),completed_at_continuous_ns=tick)
        runtime.update(hint_generation=hint_generation,event_state='failed',binding_valid=False,admission=False,
                       state='source_conflict' if permanent else 'waiting_source',
                       pending_reasons=['event_root_conflict' if permanent else 'event_watch_retry'],
                       event_schedule=plan(runtime.get('event_schedule'),wall=wall,continuous=tick,
                                           interval=policy['settings']['interval'],completion=done))
        save()
        if events is not None:
            old, events = events, None
            old.close()
        if permanent:
            raise error
    def wait_events(seconds):
        nonlocal hint_generation
        try:
            generation=events.wait(seconds)
            hint_generation=event_origin+generation
        except (OSError,MirrorError) as error:
            event_failed(error)
            return
        runtime.pop('event_schedule', None)
        runtime['hint_generation']=hint_generation
        runtime['shard_hints'] = dict(root_identity=list(events.identity),
            shards={name:event_origin+value for name,value in getattr(events,'shard_generations',{}).items()},
            coverage_version=1,uncertain_generation=event_origin+getattr(events,'uncertain_generation',events.generation),
            fallback=bool(getattr(events,'fallback_generation',0)))
        save()  # Even after drain expiry, late hints are durable; no admission here.
    def save():
        nonlocal last_serialized
        serial=encoded(runtime)
        if serial!=last_serialized:
            store.atomic('instance.'+nonce+'.json',runtime);last_serialized=serial
    def retry_retirement():
        retired = runtime.get('retirement_pending')
        if retired is None:
            return True
        wall,tick = time.time(),continuous_ns()
        interval = policy['settings']['interval']
        retry = runtime.get('retirement_schedule')
        if retry is not None and not plan(retry,wall=wall,continuous=tick,interval=interval)['due']:
            return False
        segment = retired['segment']
        def preserve_terminal_schedule(report):
            if retired['policy_generation'] != policy['generation'] or retired['context'] != run.context:
                return
            admission_failed = _adopt_worker_cadence(runtime, segment, report, interval=interval)
            done = report.get('last_completed')
            if admission_failed:
                runtime['round'] = dict(operation=segment['operation'],attempt=report['attempts'],
                                        last_completed=done,admission_failure=report['admission_failure'])
            if type(done) is dict and done.get('operation') == segment['operation']:
                if not admission_failed:
                    runtime['round'] = dict(operation=segment['operation'],attempt=report['attempts'],
                                            last_completed=done)
                if done.get('source_conflicts'):
                    runtime.update(source_conflict_seen=True,binding_valid=False,admission=False)
                if not admission_failed and done.get('exit_code') not in (None,0,-signal.SIGTERM,-signal.SIGKILL):
                    runtime['source_schedule'] = plan(
                        runtime.get('source_schedule'),wall=time.time(),continuous=continuous_ns(),
                        interval=policy['settings']['interval'],completion=done)
            save()
        try:
            removed = _retire_stopped_worker(store,segment,retired['services'],terminal=preserve_terminal_schedule)
        except (OSError,ValueError,MirrorError,TypeError,KeyError):
            attempt = runtime.get('retirement_attempt',0)+1
            runtime.update(admission=False,state='waiting_source',pending_reasons=['worker_retirement_pending'],
                           retention=dict(status='pending'),retirement_attempt=attempt,
                           retirement_schedule=plan(retry,wall=wall,continuous=tick,interval=interval,
                               completion=dict(operation=segment['operation'],attempt=attempt,exit_code=2)))
            save()
            return False
        runtime.update(retirement_pending=None,retention=dict(status='retired',worker_files=removed))
        runtime.pop('retirement_schedule',None)
        runtime.pop('retirement_attempt',None)
        save()
        return True
    def finish_segment(segment):
        # Atomically detach active authority and preserve the location until retirement is durable.
        if runtime.get('retirement_pending') is not None:
            raise MirrorError('follow_retirement_unconfirmed')
        runtime.update(segment=None,grant_nonce=None,activity_stop_confirmed=True,
                       retirement_pending=dict(segment=segment,services=str(services),
                                               policy_generation=policy['generation'],context=run.context))
        save()
        return retry_retirement()
    def settle_segment(segment, *, exiting=False):
        runtime['admission'] = False
        save()
        wall,tick = time.time(),continuous_ns()
        interval = policy['settings']['interval']
        prior = runtime.get('stop_schedule')
        if not exiting and prior is not None and not plan(prior,wall=wall,continuous=tick,interval=interval)['due']:
            return False
        try:
            if not _stop_segment(policy,segment,run,services):
                raise MirrorError('follow_activity_stop_unconfirmed')
        except (OSError,ValueError,MirrorError):
            attempt = runtime.get('stop_attempt',0)+1
            runtime.update(activity_stop_confirmed=False,state='stopping',
                           pending_reasons=['worker_stop_unconfirmed'],stop_attempt=attempt,
                           stop_schedule=plan(prior,wall=wall,continuous=tick,interval=interval,
                               completion=dict(operation=segment['operation'],attempt=attempt,exit_code=2)))
            save()
            if exiting:
                raise
            return False
        runtime.pop('stop_schedule',None)
        runtime.pop('stop_attempt',None)
        return finish_segment(segment)
    # Old instances never become this instance. Only passive old-group evidence
    # or exact old-owned cancellation may clear their activity before new work.
    if pending:
        try:
            prior_policy=store.read('policy.'+pending['policy_generation']+'.json')
            prior_config=load_source_config(Path(prior_policy['snapshot']),physical=False)
            if pending['context']==run.context:
                if not _stop_segment(prior_policy,pending['segment'],run,pending['services']):
                    raise MirrorError('follow_previous_activity_unconfirmed')
                if runtime.get('retirement_pending') is not None:
                    raise MirrorError('follow_retirement_unconfirmed')
                runtime['retirement_pending'] = dict(segment=pending['segment'],services=pending['services'],
                    policy_generation=pending['policy_generation'], context=pending['context'])
            else:
                info=json.loads(_read(Path(pending['segment']['record']).with_suffix('.runtime'))[0])
                if not process.drained(info['leader']) or _writer_state(prior_config)!='free':
                    raise MirrorError('follow_previous_activity_unconfirmed')
                runtime.update(drain=None,app_was_running=False,verified_app_epoch=None)
            runtime['unsettled_activity']=None;runtime['activity_stop_confirmed']=True
            save()
        except (OSError,MirrorError,ValueError,KeyError):
            runtime.update(state='unknown',pending_reasons=['follow_previous_activity_unconfirmed'],admission=False)
            save();raise MirrorError('follow_previous_activity_unconfirmed') from None
    primary_failure=None
    try:
        while not stop[0]:
            if _listener_revoked(store, policy):
                break
            if (_observe(run,target,payload)!='owned' or run.pid(target)!=os.getpid()
                    or not process.same_generation(process.identity(os.getpid()),leader)):
                if _listener_revoked(store, policy):
                    break
                raise MirrorError('follow_listener_unknown')
            intent,_=_policy(store)
            if not retry_retirement():
                if not intent['enabled']:
                    break
                sleep(policy['settings']['poll'])
                continue
            if not intent['enabled']:
                break
            if runtime.get('stop_schedule') is not None and runtime.get('segment'):
                if not settle_segment(runtime['segment']):
                    sleep(policy['settings']['poll'])
                continue
            binding=True
            try:binding=digest(load_source_config(Path(policy['profile_path']),physical=False))==policy['source_signature'] and not runtime.get('source_conflict_seen',False)
            except (ValueError,OSError):binding=False
            if events is None:
                runtime['admission'] = False
                if runtime.get('segment'):
                    if not settle_segment(runtime['segment']):
                        sleep(policy['settings']['poll'])
                    continue
                if not binding:
                    runtime.update(state='source_conflict',binding_valid=False)
                    save()
                    sleep(policy['settings']['poll'])
                    continue
                retry = runtime.get('event_schedule')
                if retry is not None and not plan(retry,wall=time.time(),continuous=continuous_ns(),
                                                  interval=policy['settings']['interval'])['due']:
                    sleep(policy['settings']['poll'])
                    continue
                try:
                    events=event_factory(config['message_root'])
                    pinned=store.read('event-root.'+policy['generation']+'.json')
                    if pinned is not None and pinned.get('identity')!=events.identity:
                        raise MirrorError('follow_event_root_conflict')
                    if pinned is None:
                        store.immutable('event-root.'+policy['generation']+'.json',dict(identity=events.identity))
                except (OSError,MirrorError) as error:
                    event_failed(error)
                    continue
                event_origin=hint_generation
                hint_generation=event_origin+events.generation
                runtime.update(hint_generation=hint_generation,event_state='native_vnode')
                save()
            app=app_observer(policy['settings']['executable'])
            worker=dict(active=False,stop_confirmed=True)
            segment=runtime.get('segment')
            if segment:
                info=_segment_status(policy,segment,run,services)
                _record_worker_observation(runtime,segment,info)
                info=_settle_cleanup_handoff(policy,segment,run,services,runtime,info)
                runtime['cleanup_handoff']=info.get('cleanup_handoff')
                worker.update(active=info['registration']=='owned' and not info['stop_confirmed'],stop_confirmed=info['stop_confirmed'])
                try:
                    child=json.loads(_read(Path(segment['record']).with_suffix('.runtime'))[0])
                    if not info['gaps'] and child['operation']==segment['operation']:
                        done=child.get('last_completed')
                        if done and done.get('source_conflicts'):
                            runtime['source_conflict_seen']=True;binding=False
                        observation=done.get('observation') if done else None
                        admission_failed = _adopt_worker_cadence(
                            runtime,segment,child,interval=policy['settings']['interval'])
                        worker.update(kind=segment['kind'],app_epoch=segment['app_epoch'],policy_generation=policy['generation'],
                            operation=segment['operation'],last_completed=None if admission_failed else done,
                            observed_complete=observation.get('complete') if type(observation) is dict else None)
                        runtime['round']=dict(operation=segment['operation'],attempt=child['attempts'],last_completed=done)
                        if admission_failed:
                            runtime['round']['admission_failure'] = child['admission_failure']
                        consumed=child.get('consumed_hint_generation',-1)
                        if (segment['kind']=='active' and segment['app_epoch']==runtime.get('app_epoch')
                                and type(consumed) is int and consumed>=-1):
                            runtime['consumed_hint_generation']=consumed
                        if done and [done['operation'],done['attempt']]!=last_completion:
                            last_completion=[done['operation'],done['attempt']]
                            if type(observation) is dict:
                                runtime['observed_as_of']=dict(observation_id=observation['observation_id'],
                                    completed_at_ns=done['completed_at_ns'],watermarks=observation['watermarks'])
                except FileNotFoundError:pass
            from .native_reconcile_current import schedule_admission
            admission=schedule_admission(config,runtime,policy)
            if admission is not None:
                runtime.update(admission);save()  # Token and finite cadence publish before configure/submit.
            previous_epoch=runtime.get('app_epoch')
            next_=transition(runtime,enabled=intent['enabled'],policy_generation=policy['generation'],app=app,worker=worker,
                wall=time.time(),continuous=continuous_ns(),drain_seconds=policy['settings']['drain'],
                retry_seconds=policy['settings']['interval'],binding_valid=binding,recovering=recovered)
            recovered=False
            runtime.update(next_,binding_valid=binding)
            if app['state']=='running' and app['epoch']!=previous_epoch:
                runtime['consumed_hint_generation']=-1
                if runtime['source_schedule'].get('mode') not in ('backoff','blocked'):
                    runtime['source_schedule'].update(mode='normal',next_due_at_ns=time.time_ns(),
                                                      next_due_continuous_ns=continuous_ns())
            if runtime.get('segment') is None:
                runtime['activity_stop_confirmed']=True
            action=runtime['action']
            if runtime.get('drain'):runtime['drain']['source_sha256']=policy['source_signature']
            runtime['admission']=(action!='stop' and intent['enabled'] and binding
                and runtime['state'] in ('starting','catching_up','healthy','partial_source','finishing') and app['state']!='unknown')
            runtime['hint_generation']=hint_generation
            save()
            if segment and action=='stop':
                stop_context=('disabled' if not intent['enabled'] else 'source_conflict' if not binding else
                         'application_changed' if app['state']!='running' or segment.get('app_epoch')!=app.get('epoch') else
                         'source_backoff' if runtime['state']=='waiting_source' else
                         'worker_unknown' if info.get('gaps') else 'segment_mismatch')
                _record_worker_observation(runtime,segment,info,stop_context=stop_context);save()
            if segment and (action=='stop' or info['stop_confirmed']):
                if not settle_segment(segment):
                    wait_events(policy['settings']['poll'])
                continue  # Terminal cadence and app state may have superseded this action.
            elif action in ('start_active','start_drain'):
                if segment:
                    wait_events(policy['settings']['poll'])
                    continue
                if _writer_state(config)!='free':
                    runtime.update(state='waiting_source',pending_reasons=['sync_busy']);save()
                    wait_events(policy['settings']['poll']);continue
                kind='drain' if action=='start_drain' else 'active'
                deadline=Deadline.create(policy['settings']['segment'])
                if kind=='drain':
                    parent=Deadline(runtime['drain']['deadline'])
                    if parent.remaining()<2:wait_events(min(policy['settings']['poll'],parent.remaining()+.01));continue
                    facts=deadline.facts
                    facts['wall_until']=min(facts['wall_until'],parent.facts['wall_until'])
                    facts['continuous_until']=min(facts['continuous_until'],parent.facts['continuous_until'])
                    deadline=Deadline(facts)
                grant=dict(nonce=uuid.uuid4().hex,kind=kind,instance_nonce=nonce,policy_generation=policy['generation'],
                    app_epoch=runtime['app_epoch'],source_sha256=policy['source_signature'],store_root=str(store.root),
                    os_context=run.context,deadline=deadline.facts,drain=runtime.get('drain'),
                    schedule=runtime.get('source_schedule') if kind=='active' else None,
                    consumed_hint_generation=runtime.get('consumed_hint_generation',-1) if kind=='active' else -1,
                    round_seconds=policy['settings']['round'])
                path=store.immutable('grant.'+grant['nonce']+'.json',grant)
                descriptor=dict(path=str(path),sha256=digest(grant),deadline=deadline.facts,
                    interval_seconds=policy['settings']['drain_interval'] if kind=='drain' else policy['settings']['interval'],
                    label_id=profile_id(policy['profile_path'])+'.'+nonce)
                expected_plist=services/(_schedule_label(config,descriptor)+'.plist')
                runtime.update(admission=True,grant_nonce=grant['nonce'],activity_stop_confirmed=False,
                    segment=dict(descriptor=descriptor,record=str(expected_plist.with_suffix('.owned')),operation=None,
                                 kind=kind,app_epoch=runtime['app_epoch'],submission='pending'))
                trace={}
                runtime['worker_preparation']=_preparation_fact(trace,'in_progress')
                save()  # Durable exact slot/grant reference precedes any OS acceptance.
                def prepared_segment(value):
                    operation=value.get('operation')
                    if (set(value)!= {'operation','record','grant','os_context'}
                        or type(operation) is not str or len(operation)!=32 or any(c not in '0123456789abcdef' for c in operation)
                        or value['record']!=str(expected_plist.with_suffix('.owned'))
                        or value['grant']!=descriptor or value['os_context']!=run.context):
                        raise MirrorError('follow_worker_preparation_unknown')
                    runtime['segment'].update(operation=operation,record=value['record'],descriptor=value['grant'],os_context=value['os_context'])
                    runtime['worker_preparation']=_preparation_fact(trace,'in_progress',operation)
                    save()  # Exact operation reaches the listener durably before submit.
                try:
                    plist=configure(config,policy['snapshot'],policy['executable'],services,True,runner=run,follow_grant=descriptor,prepared=prepared_segment,_prepare_trace=trace)
                except BaseException as error:
                    # Existing finally revokes admission and saves this image;
                    # no new I/O, recovery decision, or exception replacement.
                    try:runtime['worker_preparation']=_preparation_fact(trace,'failed',(runtime.get('segment')or{}).get('operation'),error)
                    except BaseException:pass
                    raise
                record=json.loads(_read(plist.with_suffix('.owned'))[0])
                runtime['worker_preparation']=_preparation_fact(trace,'returned',record['operation'])
                runtime['segment'].update(descriptor=descriptor,record=str(plist.with_suffix('.owned')),operation=record['operation'],
                    kind=kind,app_epoch=runtime['app_epoch'],submission='accepted')
                runtime['activity_stop_confirmed']=False;save()
            if not intent['enabled']:break
            wait_events(policy['settings']['poll'])
    except BaseException as error:
        primary_failure=error
        raise
    finally:
        try:
            try:
                runtime['admission']=False;save()
                if runtime.get('segment'):
                    settle_segment(runtime['segment'],exiting=True)
            except BaseException as cleanup_failure:
                if primary_failure is None:raise
                # Keep the initiating failure primary; retain cleanup as explicit evidence.
                # Avoid the automatic cleanup -> primary -> cleanup context cycle.
                if cleanup_failure.__context__ is primary_failure:cleanup_failure.__context__=None
                raise primary_failure from cleanup_failure
        finally:
            if events is not None:events.close()
            signal.signal(signal.SIGTERM,previous_handler)
    return dict(enabled=False,gaps=[])


from .failure_evidence import _register
_register(_preparation_fact,preparation_diagnostic,worker_observations, _record_worker_observation, _home,_payload,_target,_policy,_runtime,_material,_segment_status,_stop_segment,
          _prune_disabled_agents,_retire_stopped_worker,enable,disable,_view,status,run_listener)

from .failure_evidence import _register
_register(_settle_cleanup_handoff)
