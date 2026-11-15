"""User LaunchAgent follow management. All Source work remains finite/owned."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import signal
import time
import uuid
from . import native_process as kernel
from .native_deadline import Deadline,continuous_ns
from .native_mirror_store import MirrorError
from .native_schedule import (_read,_create,_sync_dir,_observe,_writer_state,_schedule_label,
                              configure,inspect_status,LaunchctlTransport)
from .native_follow_policy import Store,default_root,profile_id,encoded,digest,local_environment
from .native_follow_config import settings
from .native_follow_app import observe
from .native_follow_events import VnodeHints
from .native_follow_state import transition
from .source_setup import load_source_config


def _home():return Path(pwd.getpwuid(os.getuid()).pw_dir)


def _payload(policy,policy_path):
    return dict(Label=policy['label'],ProgramArguments=[policy['executable'],'follow-run',
        '--source-config',policy['snapshot'],'--policy-record',str(policy_path),
        '--policy-sha256',digest(policy),'--operation-token',policy['generation']],
        EnvironmentVariables=policy['environment'],RunAtLoad=True,KeepAlive=True,
        ThrottleInterval=5,ExitTimeOut=2,AbandonProcessGroup=False,ProcessType='Background')


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


def _runtime(store):
    current=store.read('current.json')
    if current is None:return None
    value=store.read('instance.'+current['nonce']+'.json')
    if not value or value.get('operation')!=current['nonce']:raise MirrorError('follow_state_unknown')
    return value


def _material(policy):
    path=Path(policy['agent_path']);expected=plistlib.dumps(_payload(policy,policy['policy_path']))
    try:raw,_=_read(path)
    except FileNotFoundError:return 'absent'
    return 'installed' if raw==expected else 'unknown'


def _segment_status(policy,segment,run,services):
    config=load_source_config(Path(policy['snapshot']),physical=False)
    return inspect_status(config,policy['snapshot'],policy['executable'],services,
                          runner=run,follow_grant=segment['descriptor'])


def _stop_segment(policy,segment,run,services):
    config=load_source_config(Path(policy['snapshot']),physical=False)
    configure(config,policy['snapshot'],policy['executable'],services,False,
              runner=run,follow_grant=segment['descriptor'])
    return _segment_status(policy,segment,run,services)['stop_confirmed']


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
    payload=_payload(policy,policy['policy_path']);target=_target(run,policy['label'])
    registration=_observe(run,target,payload)
    if registration=='owned':run.remove(target,wait=True)
    elif registration!='absent':raise MirrorError('follow_listener_unknown')
    if _observe(run,target,payload)!='absent':raise MirrorError('follow_listener_unknown')
    if current and not kernel.drained(current['leader']):raise MirrorError('follow_listener_stop_unconfirmed')
    if _material(policy)=='installed':
        path=Path(policy['agent_path']);before=_read(path)
        if before[0]!=plistlib.dumps(payload):raise MirrorError('follow_login_material_unknown')
        archive=path.with_name(path.name+'.disabled-'+str(time.time_ns()))
        if path.parent!=archive.parent or _read(path)!=before:raise MirrorError('follow_login_material_unknown')
        os.replace(path,archive);_sync_dir(path.parent)
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
        for key in ('state','app_epoch','drain','observed_catchup_complete','observed_as_of','catchup_pending','pending_reasons','source_schedule'):
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
    if result['state']=='waiting_source' and not result['gaps']:
        done=(result.get('round') or {}).get('last_completed') or {};ended=done.get('termination') or {}
        result['gaps']=['follow_child_reaped_after_deadline' if ended.get('raw_signal') and ended.get('round_deadline_expired') is True
                        else 'follow_child_signaled' if ended.get('raw_signal') else 'follow_source_unavailable']
    handoff=result.get('cleanup_handoff') or {}
    if handoff.get('gaps'):
        result['gaps']=sorted(set(result['gaps']+handoff['gaps']));result['catchup_pending']=True;result['observed_catchup_complete']=None
    if result['login_registration']['state']=='unknown':result['gaps'].append('follow_login_material_unknown')
    if _view(store)!=before_view:
        result.update(state='unknown',disabled_confirmed=False,activity_stop_confirmed=None,
                      observed_catchup_complete=None,gaps=['follow_state_changed'])
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
    runtime['observed_catchup_complete']=None
    runtime['observed_as_of']=None
    runtime['consumed_hint_generation']=-1
    runtime['source_schedule']=dict(mode='normal',next_due_at_ns=time.time_ns(),next_due_continuous_ns=continuous_ns())
    pending=previous.get('unsettled_activity') if previous else None
    if pending is None and previous and previous.get('segment'):
        pending=dict(segment=previous['segment'],services=previous['services'],context=previous['context'],
                     policy_generation=previous['policy_generation'])
    runtime['unsettled_activity']=pending
    store.immutable('instance.'+nonce+'.json',runtime)
    store.atomic('current.json',dict(nonce=nonce))
    stop=[False];previous_handler=signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM,lambda *_:stop.__setitem__(0,True))
    config=load_source_config(Path(policy['snapshot']),physical=False)
    recovered=True;last_serialized=None;last_completion=None
    hint_generation=runtime.get('hint_generation',0)+1
    events=None
    def wait_events(seconds):
        nonlocal hint_generation
        try:
            generation=events.wait(seconds)
            hint_generation=event_origin+generation
        except (OSError,MirrorError):
            runtime.update(hint_generation=hint_generation+1,event_state='failed',binding_valid=False,admission=False)
            save()
            raise
        runtime['hint_generation']=hint_generation
        save()  # Even after drain expiry, late hints are durable; no admission here.
    def save():
        nonlocal last_serialized
        serial=encoded(runtime)
        if serial!=last_serialized:
            store.atomic('instance.'+nonce+'.json',runtime);last_serialized=serial
    # Old instances never become this instance. Only passive old-group evidence
    # or exact old-owned cancellation may clear their activity before new work.
    if pending:
        try:
            prior_policy=store.read('policy.'+pending['policy_generation']+'.json')
            prior_config=load_source_config(Path(prior_policy['snapshot']),physical=False)
            if pending['context']==run.context:
                if not _stop_segment(prior_policy,pending['segment'],run,pending['services']):
                    raise MirrorError('follow_previous_activity_unconfirmed')
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
        events=event_factory(config['message_root'])
        pinned=store.read('event-root.'+policy['generation']+'.json')
        if pinned is not None and pinned.get('identity')!=events.identity:
            raise MirrorError('follow_event_root_conflict')
        if pinned is None:
            store.immutable('event-root.'+policy['generation']+'.json',dict(identity=events.identity))
        event_origin=hint_generation
        hint_generation=event_origin+events.generation
        runtime.update(hint_generation=hint_generation,event_state='native_vnode')
        save()
        while not stop[0]:
            if (_observe(run,target,payload)!='owned' or run.pid(target)!=os.getpid()
                    or not process.same_generation(process.identity(os.getpid()),leader)):
                raise MirrorError('follow_listener_unknown')
            intent,_=_policy(store)
            binding=True
            try:binding=digest(load_source_config(Path(policy['profile_path']),physical=False))==policy['source_signature'] and not runtime.get('source_conflict_seen',False)
            except (ValueError,OSError):binding=False
            app=app_observer(policy['settings']['executable'])
            worker=dict(active=False,stop_confirmed=True)
            segment=runtime.get('segment')
            if segment:
                info=_segment_status(policy,segment,run,services)
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
                        worker.update(kind=segment['kind'],app_epoch=segment['app_epoch'],policy_generation=policy['generation'],
                            operation=segment['operation'],last_completed=done,
                            observed_complete=observation.get('complete') if type(observation) is dict else None)
                        runtime['round']=dict(operation=segment['operation'],attempt=child['attempts'],last_completed=done)
                        runtime['source_schedule']=child.get('source_schedule',runtime.get('source_schedule',{}))
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
            previous_epoch=runtime.get('app_epoch')
            next_=transition(runtime,enabled=intent['enabled'],policy_generation=policy['generation'],app=app,worker=worker,
                wall=time.time(),continuous=continuous_ns(),drain_seconds=policy['settings']['drain'],
                retry_seconds=policy['settings']['interval'],binding_valid=binding,recovering=recovered)
            recovered=False
            runtime.update(next_,binding_valid=binding)
            if app['state']=='running' and app['epoch']!=previous_epoch:
                runtime['consumed_hint_generation']=-1
                runtime['source_schedule']=dict(mode='normal',next_due_at_ns=time.time_ns(),next_due_continuous_ns=continuous_ns())
            if runtime.get('segment') is None:
                runtime['activity_stop_confirmed']=True
            action=runtime['action']
            if runtime.get('drain'):runtime['drain']['source_sha256']=policy['source_signature']
            runtime['admission']=(action!='stop' and intent['enabled'] and binding
                and runtime['state'] in ('starting','catching_up','healthy','finishing') and app['state']!='unknown')
            runtime['hint_generation']=hint_generation
            save()
            if action=='stop' and segment:
                runtime['admission']=False;save()
                runtime['activity_stop_confirmed']=_stop_segment(policy,segment,run,services)
                if runtime['activity_stop_confirmed']:runtime['segment']=None
                save()
            elif action in ('start_active','start_drain'):
                if segment:
                    if not info['stop_confirmed']:wait_events(policy['settings']['poll']);continue
                    if not _stop_segment(policy,segment,run,services):raise MirrorError('follow_activity_stop_unconfirmed')
                    runtime['segment']=None
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
                save()  # Durable exact slot/grant reference precedes any OS acceptance.
                def prepared_segment(value):
                    operation=value.get('operation')
                    if (set(value)!= {'operation','record','grant','os_context'}
                        or type(operation) is not str or len(operation)!=32 or any(c not in '0123456789abcdef' for c in operation)
                        or value['record']!=str(expected_plist.with_suffix('.owned'))
                        or value['grant']!=descriptor or value['os_context']!=run.context):
                        raise MirrorError('follow_worker_preparation_unknown')
                    runtime['segment'].update(operation=operation,record=value['record'],descriptor=value['grant'],os_context=value['os_context'])
                    save()  # Exact operation reaches the listener durably before submit.
                plist=configure(config,policy['snapshot'],policy['executable'],services,True,runner=run,follow_grant=descriptor,prepared=prepared_segment)
                record=json.loads(_read(plist.with_suffix('.owned'))[0])
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
                    runtime['activity_stop_confirmed']=_stop_segment(policy,runtime['segment'],run,services);save()
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
_register(_home,_payload,_target,_policy,_runtime,_material,_segment_status,_stop_segment,
          enable,disable,_view,status,run_listener)

from .failure_evidence import _register
_register(_settle_cleanup_handoff)
