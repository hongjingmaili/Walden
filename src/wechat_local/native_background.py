"""Finite launchd-owned sync runner. No resident supervisor or DSH dependency."""
import json
import hashlib
import plistlib
import os
import signal
import select
import re
import subprocess
import time
import uuid
from pathlib import Path
from .native_deadline import Deadline, activate_deadline, continuous_ns, arm_fatal
from .native_mirror_store import MirrorError
from . import native_process as kernel
from .failure_evidence import child_result, _register


def _control(config,config_path,record_path,transport,operation_token,*,cleanup_only=False):
    from .native_schedule import _read,_digest,_config_facts,_config_digest,_observe,_argv_operation
    record_path=Path(record_path).absolute();record=json.loads(_read(record_path)[0])
    data,identity=_read(record_path.with_suffix('.plist'));payload=plistlib.loads(data)
    if (record.get('os_context')!=transport.context or record.get('preflight')!='absent'
        or record.get('plist_identity')!=identity or record.get('plist_sha256')!=_digest(data)
        or record.get('config_sha256')!=_config_facts(config) or _config_digest(config_path)!=record.get('config_sha256')
        or record.get('operation')!=_argv_operation(payload.get('ProgramArguments'))
        or operation_token!=record.get('operation')
        or _observe(transport,record.get('target',''),payload)!='owned'):
        raise MirrorError('schedule_state_unknown')
    deadline = Deadline(record.get('deadline'))
    if record.get('follow_grant'):
        argv = payload['ProgramArguments']
        for flag, expected in (('--follow-grant',record['follow_grant']),('--follow-grant-sha256',record.get('follow_grant_sha256'))):
            if argv.count(flag)!=1 or argv.index(flag)+1>=len(argv) or argv[argv.index(flag)+1]!=expected:
                raise MirrorError('follow_grant_unknown')
        if cleanup_only:
            _cleanup_grant_metadata(record) # No Source authority; returns ordinary expired Deadline.
        else:
            from .native_follow_grant import from_record
            deadline = from_record(record,deadline)
    elif '--follow-grant' in payload['ProgramArguments']:
        raise MirrorError('follow_grant_unknown')
    return record,payload,deadline


def _runtime_write(path,value,*,first=False):
    from .native_schedule import _read,_create,_sync_dir
    if first:
        _create(path,json.dumps(value,sort_keys=True).encode());_sync_dir(path.parent);return
    prior=json.loads(_read(path)[0])
    if prior.get('operation')!=value['operation']:raise MirrorError('schedule_state_unknown')
    temp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    _create(temp,json.dumps(value,sort_keys=True).encode())
    if path.is_symlink():raise MirrorError('schedule_state_unknown')
    os.replace(temp,path);_sync_dir(path.parent)


def bootstrap(record_path,operation_token,*,process=kernel,argv=None):
    """Persist self identity before config/SM admission. This receipt grants no Source access."""
    import sys
    from .native_schedule import _read,_create,_sync_dir,_digest,_argv_operation
    path=Path(record_path).absolute();raw,_=_read(path);record=json.loads(raw)
    plist_raw,_=_read(path.with_suffix('.plist'));payload=plistlib.loads(plist_raw)
    expected=payload.get('ProgramArguments');actual=list(sys.argv if argv is None else argv)
    if (record.get('operation')!=operation_token or _argv_operation(expected)!=operation_token
            or expected!=actual or record.get('plist_sha256')!=_digest(plist_raw)):
        raise MirrorError('schedule_state_unknown')
    # Same absolute original segment guard; writing a receipt cannot renew it.
    deadline=Deadline(record['deadline']);arm_fatal(deadline,3)
    leader=process.identity(os.getpid())
    if not leader or leader['uid']!=os.getuid() or leader['pid']!=leader['pgid']:
        raise MirrorError('schedule_process_unknown')
    value=dict(schema_version=1,operation=operation_token,leader=leader,status='starting',admitted=False,
        os_context=record['os_context'],context_verified=False,argv=actual,record_sha256=_digest(raw),
        plist_sha256=_digest(plist_raw),deadline=record['deadline'])
    target=path.with_suffix('.starting')
    try:_create(target,json.dumps(value,sort_keys=True).encode());_sync_dir(target.parent)
    except FileExistsError:
        saved=json.loads(_read(target)[0])
        if any(saved.get(k)!=value[k] for k in ('operation','leader','record_sha256','plist_sha256','argv','os_context')):
            raise MirrorError('schedule_process_unknown')
    return value


def starting_leader(record_path,record,payload,*,context,process=kernel,receipt_path=None):
    """Consume only an exact current-operation starting receipt, never a guessed PID."""
    from .native_schedule import _read,_digest
    path=Path(record_path)
    try:raw,_=_read(Path(receipt_path) if receipt_path is not None else path.with_suffix('.starting'))
    except FileNotFoundError:return None
    value=json.loads(raw);record_raw,_=_read(path)
    if (value.get('operation')!=record.get('operation') or value.get('record_sha256')!=_digest(record_raw)
            or value.get('plist_sha256')!=record.get('plist_sha256') or value.get('argv')!=payload.get('ProgramArguments')
            or value.get('os_context')!=context or value.get('admitted') is not False or value.get('status')!='starting'):
        raise MirrorError('schedule_process_unknown')
    leader=value.get('leader')
    if not leader or leader.get('uid')!=os.getuid() or leader.get('pid')!=leader.get('pgid'):
        raise MirrorError('schedule_process_unknown')
    current=process.identity(leader['pid'])
    if current is not None and not process.same_generation(current,leader):raise MirrorError('schedule_process_unknown')
    return leader


def _drain_output(child,buffer):
    if child is None or child.stdout is None:return
    while True:
        try:data=os.read(child.stdout.fileno(),4096)
        except BlockingIOError:return
        if not data:return
        if len(buffer)+len(data)<=65536:buffer.extend(data)
        else:buffer.clear();buffer.extend(b'!oversize!')


def _child_error_id(buffer):
    try:value=json.loads(buffer)
    except (ValueError,UnicodeError):return None
    ident=value.get('error_id') if type(value) is dict else None
    return ident if type(ident) is str and re.fullmatch('[0-9a-f]{32}',ident) else None


def _completed_attempt(runtime, code, output=None):
    """Set only after actual exit; count only the existing sync result's scope."""
    count = None
    observation = None
    conflicts = []
    if output is not None:
        try:
            value = json.loads(output)
            allowed = {'source_replaced','auxiliary_source_replaced','source_cursor_regression',
                       'conversation_identity_conflict','sender_identity_conflict','source_identity_mismatch',
                       'source_table_missing','source_shard_missing'}
            if type(value.get('gaps')) is list:
                conflicts = sorted({gap for gap in value['gaps'] if type(gap) is str and gap in allowed})
            candidate = value.get('source_opens')
            if code == 0 and value.get('gaps') == [] and type(candidate) is int and candidate >= 0:
                count = candidate
                observation = value.get('follow_observation')
        except (ValueError, UnicodeError, AttributeError):
            pass
    attempted=runtime.get('attempt_record') or {}
    ended_wall=time.time_ns();ended_continuous=continuous_ns();facts=attempted.get('round_deadline')
    expired=bool(facts and (ended_wall>=int(facts['wall_until']*1e9) or ended_continuous>=facts['continuous_until']))
    raw_signal=-code if type(code) is int and code<0 else None
    termination=dict(raw_signal=raw_signal,round_deadline_expired=expired,clock_basis='parent_reap_observation_not_signal_time',
        classification=('signal_reaped_at_or_after_round_deadline' if expired else 'signal_reaped_before_round_deadline') if raw_signal else 'exit',
        timer_origin='not_independently_proven' if raw_signal else None)
    runtime['last_completed'] = dict(operation=runtime['operation'], attempt=runtime['attempts'],
        exit_code=code, completed_at_ns=time.time_ns(), completed_at_continuous_ns=continuous_ns(),
        source_db_connections=count, source_db_connections_scope='sync_once_connection_factory_success_v1',
        observation=observation, source_conflicts=conflicts,child_pid=attempted.get('child_pid'),
        attempt_record=attempted,termination=termination)


def _idle_delay(deadline, cadence, next_run, poll):
    if cadence is None:
        due = next_run-time.monotonic()
    else:
        due = min((cadence['next_due_at_ns']-time.time_ns())/1e9,
                  (cadence['next_due_continuous_ns']-continuous_ns())/1e9)
    return max(0.,min(poll,deadline.remaining(),due))


def _idle_wait(read_fd, seconds, sleep):
    if sleep is not time.sleep:
        sleep(seconds)  # Existing injected clock boundary for deterministic tests.
    else:
        select.select([read_fd],[],[],seconds)


def _record_media_exit(runtime,code):
    runtime['media_child_exit']=code
    if code!=0:
        runtime['media_failure_seen']=True
        counts=runtime.setdefault('media_failed_exits',{})
        label=str(code) if type(code) is int and -255<=code<=255 else 'unknown'
        counts[label]=counts.get(label,0)+1


class CleanupPending(dict):
    """Internal control handoff only; never a stop or Source authorization proof."""


def _cleanup_grant_metadata(record):
    from .native_schedule import _read,_digest
    path=Path(record['follow_grant']).absolute();raw,_=_read(path);grant=json.loads(raw)
    if (_digest(raw)!=record['follow_grant_sha256'] or grant.get('kind')!='active'
        or path.parent!=Path(grant.get('store_root','')) or path.name!='grant.'+grant.get('nonce','')+'.json'):raise MirrorError('follow_grant_unknown')
    parent=Deadline(grant['deadline']);child=Deadline(record['deadline'])
    if any(child.facts[k]>parent.facts[k] for k in ('wall_until','continuous_until')):raise MirrorError('follow_grant_unknown')
    return grant


def cleanup_handoff_status(runtime,record,context,*,stop_verified=False):
    value=runtime.get('cleanup_pending')
    if value is None:return None
    from .native_follow_grant import load
    try:
        grant=_cleanup_grant_metadata(record)
        import hashlib
        expected=hashlib.sha256(json.dumps(context,sort_keys=True).encode()).hexdigest()
        if (value.get('operation')!=record['operation'] or value.get('receiver_instance')!=grant['instance_nonce']
            or value.get('receiver_generation')!=grant['policy_generation'] or value.get('receiver_context')!=expected
            or value.get('source_authority') is not False or value.get('stop_confirmed') is not False):raise ValueError()
        expires=Deadline(value['expires'])
        if (expires.facts['continuous_until']-expires.facts['continuous_start']!=10000000000
            or type(value.get('created_at_ns')) is not int or value['created_at_ns']>time.time_ns()
            or abs(expires.facts['wall_until']-10-value['created_at_ns']/1000000000)>1
            or continuous_ns()<expires.facts['continuous_start']):raise ValueError()
        expired=expires.remaining()<=0
        settled=runtime.get('cleanup_settlement') or {}
        if (settled.get('operation')==record['operation'] and settled.get('receiver_instance')==value['receiver_instance']
            and settled.get('receiver_generation')==value['receiver_generation'] and settled.get('receiver_context')==expected
            and settled.get('state') in ('confirmed','confirmed_after_expiry')):
            return dict(state=settled['state'],source_authority=False,gaps=[]) if stop_verified else dict(state='unknown',source_authority=False,gaps=['cleanup_handoff_stop_unverified'])
        from .native_follow_grant import _enabled_intent,_instance_runtime
        from .native_follow_policy import Store
        store=Store(grant['store_root']);_enabled_intent(store,grant);parent=_instance_runtime(store,grant)
        if parent.get('context')!=context or (parent.get('segment') or {}).get('operation')!=record['operation']:raise ValueError()
        return dict(state='unsettled' if expired else 'pending',source_authority=False,gaps=['cleanup_handoff_expired'] if expired else [],created_at_ns=value['created_at_ns'],expires=value['expires'])
    except (KeyError,TypeError,ValueError,OSError,MirrorError):return dict(state='unknown',source_authority=False,gaps=['cleanup_handoff_unknown'])


def _verify_cleanup_owner(config,config_path,record_path,record,payload,follow,transport,process,worker):
    from .native_follow_grant import _enabled_intent,_instance_runtime
    from .native_follow_policy import Store
    fresh,plist,_=_control(config,config_path,record_path,transport,record['operation'],cleanup_only=True)
    if fresh!=record or plist!=payload or follow.get('kind')!='active':raise MirrorError('schedule_state_unknown')
    if transport.pid(record['target'])!=os.getpid() or not process.same_generation(process.identity(os.getpid()),worker):raise MirrorError('schedule_process_unknown')
    store=Store(follow['store_root']);_enabled_intent(store,follow);parent=_instance_runtime(store,follow)
    policy=store.read('policy.'+follow['policy_generation']+'.json');segment=parent.get('segment') or {}
    api=getattr(transport,'api',None);leader=parent.get('leader');actual=process.identity(leader['pid']) if leader else None
    if (not policy or policy.get('source_signature')!=follow.get('source_sha256') or not api or api.current_context()!=record['os_context'] or parent.get('context')!=record['os_context']
        or follow.get('os_context')!=record['os_context'] or segment.get('operation')!=record['operation'] or segment.get('kind')!='active'
        or not leader or not actual or not process.same_generation(actual,leader) or actual.get('status')==5):raise MirrorError('follow_instance_changed')
    from .native_schedule import _read
    from .native_follow_policy import digest
    if (digest(json.loads(_read(Path(policy['profile_path']))[0]))!=follow['source_sha256']
        or parent.get('binding_valid') is False or parent.get('source_conflict_seen') is True):raise MirrorError('follow_source_conflict')
    public=api.get(policy['label'])
    if not public or public.get('ProgramArguments')!=parent.get('listener_argv') or public.get('PID')!=leader['pid']:raise MirrorError('follow_instance_changed')
    _enabled_intent(store,follow);latest=_instance_runtime(store,follow)
    if (any(latest.get(k)!=parent.get(k) for k in ('leader','context','segment','listener_argv'))
        or api.current_context()!=record['os_context']):raise MirrorError('follow_instance_changed')


def run_bounded(config,config_path,record_path,*,operation_token=None,transport=None,process=kernel,spawn=subprocess.Popen,sleep=time.sleep):
    from .native_schedule import LaunchctlTransport,_config_digest,_observe,_read
    record_path=Path(record_path).absolute();config_path=Path(config_path).absolute()
    initial_deadline=Deadline(json.loads(_read(record_path)[0]).get('deadline'))
    arm_fatal(initial_deadline,3)
    transport=transport or LaunchctlTransport()
    record,payload,deadline=_control(config,config_path,record_path,transport,operation_token)
    if deadline.facts!=initial_deadline.facts:raise MirrorError('schedule_state_unknown')
    leader=process.identity(os.getpid())
    if (not leader or leader['uid']!=os.getuid() or leader['pid']!=leader['pgid']
        or transport.pid(record['target'])!=os.getpid()):
        raise MirrorError('schedule_process_unknown')
    process.require_own_leader(leader)
    from .failure_evidence import bind_operation,phase
    bind_operation(record['operation'],deadline.facts);phase('owned_control')
    runtime_path=record_path.with_suffix('.runtime')
    runtime=dict(operation=record['operation'],os_context=record['os_context'],leader=leader,
                 status='running',attempts=0,child_exit=None,deadline=record['deadline'],group_drained=False,registration_absent=False)
    stop=[False];previous=signal.getsignal(signal.SIGTERM)
    child=None;media_child=None;media_next=0.;failure=None;output=bytearray();remove_accepted=False
    def persist_cleanup():
        nonlocal failure
        try:_runtime_write(runtime_path,runtime)
        except (OSError,MirrorError,ValueError) as error:
            if failure is None:failure=error
    interval=record['interval_seconds'];next_run=time.monotonic()+(0 if record.get('follow_grant') else interval)
    follow = None
    cadence = None
    consumed_hint = -1
    idle_poll = 2.
    if record.get('follow_grant'):
        from .native_follow_config import settings
        idle_poll = min(2.,settings(config)['poll'])
        from .native_follow_grant import load
        from .native_follow_schedule import plan
        from .native_follow_policy import Store
        follow = load(record['follow_grant'],record['follow_grant_sha256'])
        consumed_hint = follow.get('consumed_hint_generation',-1)
        if type(consumed_hint) is not int or consumed_hint < -1:
            raise MirrorError('follow_grant_unknown')
        runtime['consumed_hint_generation']=consumed_hint
        attempt_hint = consumed_hint
        cadence = follow.get('schedule') or None
        cadence = plan(cadence,wall=time.time(),continuous=continuous_ns(),interval=interval,draining=follow['kind']=='drain')
        runtime['source_schedule']=cadence
    read_fd,write_fd=os.pipe()
    os.set_blocking(read_fd,False);os.set_blocking(write_fd,False)
    def request_stop(*_):
        stop[0]=True
        try:os.write(write_fd,b'x')
        except OSError:pass
    signal.signal(signal.SIGTERM,request_stop)
    try:
        _runtime_write(runtime_path,runtime,first=True)
        while not stop[0] and deadline.remaining()>0:
            if follow is not None and follow['kind'] in ('active','drain'):
                deadline.check_revocation(process=process)
            if _config_digest(config_path)!=record['config_sha256']:raise MirrorError('schedule_configuration_conflict')
            if media_child is not None and media_child.poll() is not None:
                _record_media_exit(runtime,media_child.returncode);media_child=None
                _runtime_write(runtime_path,runtime)
                if follow is not None and follow['kind']=='request' and runtime.get('request_source_complete'):
                    if runtime['media_child_exit']!=0:raise MirrorError('request_media_child_failed')
                    runtime['request_complete']=True;runtime['request_media_complete']=True
                    break
            if child is not None:
                _drain_output(child,output)
                code=child.poll()
                if code is not None:
                    _drain_output(child,output)
                    runtime['child_error_id']=_child_error_id(output)
                    runtime['child_exit']=code;child_result(code,None);child=None
                    _completed_attempt(runtime,code,output)
                    if follow is not None:
                        done=runtime['last_completed'];observation=done.get('observation') or {}
                        if code==0 and type(observation.get('complete')) is bool:
                            consumed_hint=attempt_hint
                            runtime['consumed_hint_generation']=consumed_hint
                        completion=dict(done,observed_complete=observation.get('complete'),known_backlog=observation.get('known_backlog',False))
                        cadence=plan(cadence,wall=time.time(),continuous=continuous_ns(),interval=interval,
                                     completion=completion,draining=follow['kind']=='drain')
                        runtime['source_schedule']=cadence
                    _runtime_write(runtime_path,runtime)
                    if code:raise MirrorError('schedule_child_failed')
                    if follow is not None and follow['kind']=='source_recovery':
                        try:recovery_response=json.loads(output)
                        except (ValueError,AttributeError):recovery_response={}
                        if recovery_response.get('source_recovery_complete') is not True:raise MirrorError('recovery_result_unavailable')
                        runtime['source_recovery_complete']=True
                        break
                    if follow is not None and follow['kind']=='directory_probe':
                        try:probe_response=json.loads(output)
                        except (ValueError,AttributeError):probe_response={}
                        if probe_response.get('directory_probe_complete') is not True:raise MirrorError('probe_result_unavailable')
                        runtime['directory_probe_complete']=True
                        break
                    if follow is not None and follow['kind']=='request':
                        try:
                            response=json.loads(output)
                            request_done=response.get('request_complete') is True or response.get('request_terminal_pending') is True
                        except (ValueError,AttributeError):request_done=False
                        if request_done and response.get('request_media_required') is True:
                            runtime['request_source_complete']=True
                            request_done=False
                        if request_done:
                            runtime['request_complete']=response.get('request_complete') is True
                            runtime['request_terminal_pending']=response.get('request_terminal_pending') is True
                            break
                    next_run=time.monotonic()+interval
            ready=time.monotonic()>=next_run
            parent_hint=consumed_hint
            if follow is not None and child is None:
                owner=Store(follow['store_root']).read('instance.'+follow['instance_nonce']+'.json')
                parent_hint=owner.get('hint_generation',0) if owner else 0
                newer=plan(cadence,wall=time.time(),continuous=continuous_ns(),interval=interval,
                           dirty=parent_hint>consumed_hint,draining=follow['kind']=='drain')
                if newer!=cadence:
                    cadence=newer;runtime['source_schedule']=cadence;_runtime_write(runtime_path,runtime)
                ready=cadence['due']
            active_tail = follow is not None and follow['kind']=='active' and deadline.remaining()<follow['round_seconds']
            if child is None and ready and not active_tail and not runtime.get('request_source_complete'):
                deadline.check()
                if _config_digest(config_path)!=record['config_sha256']:raise MirrorError('schedule_configuration_conflict')
                # Recheck immediately before spawn, including after a system sleep.
                if stop[0]:break
                args=[payload['ProgramArguments'][0],'once','--source-config',str(config_path),'--operation-record',str(record_path),'--operation-token',record['operation']]
                output=bytearray()
                extra={};facts=dict(deadline.facts)
                if follow is not None:
                    if deadline.remaining()<1:break
                    tick=continuous_ns();facts=dict(deadline.facts)
                    facts.update(continuous_start=tick,
                        continuous_until=min(facts['continuous_until'],tick+int(follow['round_seconds']*1e9)),
                        wall_until=min(facts['wall_until'],time.time()+follow['round_seconds']))
                    args += ['--round-deadline',json.dumps(facts,sort_keys=True)]
                    attempt_hint=parent_hint
                    extra['env']=dict(payload['EnvironmentVariables'])
                runtime['attempt_record']=dict(operation=runtime['operation'],attempt=runtime['attempts']+1,
                    round_deadline=dict(facts),spawn_wall_ns=time.time_ns(),spawn_continuous_ns=continuous_ns(),
                    phase='spawning',child_pid=None,child_identity=None)
                _runtime_write(runtime_path,runtime)
                child=spawn(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,**extra)
                runtime['attempt_record'].update(phase='spawned',child_pid=child.pid)
                try:
                    identity=process.identity(child.pid)
                    if identity and identity['pid']==child.pid and identity['uid']==leader['uid'] and identity['pgid']==leader['pgid']:
                        runtime['attempt_record']['child_identity']=identity
                except (OSError,MirrorError):pass

                if child.stdout is not None:os.set_blocking(child.stdout.fileno(),False)
                runtime['attempts']+=1;runtime['child_pid']=child.pid
                _runtime_write(runtime_path,runtime)
            # A separate ordinary child shares this owned group and the unchanged parent deadline.
            # No media starts in drain; expensive codecs/ASR never occupy the message child.
            media_configured=bool(follow is not None and (config.get('voice_databases') or config.get('image_database') or
                                  config.get('mirror_root') and (Path(config['mirror_root'])/'media-work.sqlite').is_file()))
            if (follow is not None and (follow['kind']=='active' or follow['kind']=='request' and runtime.get('request_source_complete')) and media_configured and media_child is None
                    and runtime.get('child_exit')==0 and time.monotonic()>=media_next and deadline.remaining()>2 and not stop[0]):
                tick=continuous_ns();facts=dict(deadline.facts)
                facts.update(continuous_start=tick,continuous_until=min(facts['continuous_until'],tick+120000000000),
                             wall_until=min(facts['wall_until'],time.time()+120))
                media_args=[payload['ProgramArguments'][0],'media','--source-config',str(config_path),
                    '--operation-record',str(record_path),'--operation-token',record['operation'],'--round-deadline',json.dumps(facts,sort_keys=True)]
                media_next=time.monotonic()+30
                try:
                    media_child=spawn(media_args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                      close_fds=True,env=dict(payload['EnvironmentVariables']))
                    runtime['media_child_pid']=media_child.pid;runtime['media_error']=None
                except (OSError,subprocess.SubprocessError):
                    runtime['media_error']='media_spawn_unavailable';runtime['media_failure_seen']=True
                    if follow['kind']=='request':raise MirrorError('request_media_spawn_unavailable')
                _runtime_write(runtime_path,runtime)
            if child is None:
                delay=min(1.,deadline.remaining()) if active_tail or runtime.get('request_source_complete') else _idle_delay(deadline,cadence,next_run,idle_poll)
                _idle_wait(read_fd,min(delay,2.) if media_child is not None else delay,sleep)
            else:
                sleep(min(0.05,deadline.remaining()))
    except BaseException as error:
        failure=error
    finally:
        try:
            runtime['status']='stopping';runtime['stop_reason']='failure' if failure else 'requested' if stop[0] else 'source_recovery_complete' if runtime.get('source_recovery_complete') else 'directory_probe_complete' if runtime.get('directory_probe_complete') else 'request_window_complete' if runtime.get('request_complete') else 'request_window_pending' if runtime.get('request_terminal_pending') else 'deadline'
            persist_cleanup()
            # Unregister first: this one-shot job has no KeepAlive/StartInterval, and
            # cannot create a later child while stopping. wait=False avoids self-wait.
            try:
                if _observe(transport,record['target'],payload)=='owned':
                    transport.remove(record['target'],wait=False);remove_accepted=True
                runtime['registration_absent']=_observe(transport,record['target'],payload)=='absent'
            except (OSError,MirrorError,ValueError,subprocess.SubprocessError) as error:
                if isinstance(error,subprocess.CalledProcessError):child_result(error.returncode,error.stderr)
                runtime['registration_absent']=False
            members=[v for v in process.group_members(leader['pgid'],leader['uid']) if v['pid']!=leader['pid']]
            if members:
                process.signal_own_group(leader,signal.SIGTERM)
                grace=continuous_ns()+2000000000
                while members and continuous_ns()<grace:
                    if child is not None:child.poll()
                    if media_child is not None:media_child.poll()
                    sleep(0.02)
                    members=[v for v in process.group_members(leader['pgid'],leader['uid']) if v['pid']!=leader['pid']]
                if members:
                    runtime['status']='forcing_group_exit';persist_cleanup()
                    # Last resort includes the live owned leader, so no descendant is
                    # orphaned into a different group and no fictitious final is saved.
                    process.signal_own_group(leader,signal.SIGKILL)
                    raise MirrorError('schedule_process_unknown')
            if child is not None:
                runtime['child_exit']=child.wait(timeout=0.1)
                _drain_output(child,output);runtime['child_error_id']=_child_error_id(output)
                _completed_attempt(runtime,runtime['child_exit'],output)
                child_result(runtime['child_exit'],None)
            if media_child is not None:
                _record_media_exit(runtime,media_child.wait(timeout=0.1))
            runtime['group_drained']=True
            final_observation=_observe(transport,record['target'],payload)
            runtime['registration_absent']=final_observation=='absent'
            runtime['cleanup_observation']=dict(remove_accepted=remove_accepted,registration=final_observation)
            runtime['status']='stopped' if runtime['registration_absent'] else 'stop_unconfirmed'
            body_ok=runtime.get('child_exit')==0 and runtime.get('media_child_exit') in (None,0) and runtime.get('media_error') is None and runtime.get('media_failure_seen') is not True
            if (failure is None and body_ok and not stop[0] and follow is not None and follow.get('kind')=='active'
                and remove_accepted and final_observation=='owned'):
                _verify_cleanup_owner(config,config_path,record_path,record,payload,follow,transport,process,leader)
                runtime['status']='cleanup_pending'
                runtime['cleanup_pending']=dict(source_authority=False,stop_confirmed=False,body_status='succeeded',operation=record['operation'],receiver_instance=follow['instance_nonce'],receiver_generation=follow['policy_generation'],receiver_context=hashlib.sha256(json.dumps(record['os_context'],sort_keys=True).encode()).hexdigest(),created_at_ns=time.time_ns(),expires=Deadline.create(10).facts)
            persist_cleanup()
        finally:
            signal.signal(signal.SIGTERM,previous)
            os.close(read_fd);os.close(write_fd)
    if failure:raise failure
    if runtime.get('child_exit') not in (None,0):raise MirrorError('schedule_child_failed')
    if runtime.get('media_child_exit') not in (None,0) or runtime.get('media_error') or runtime.get('media_failure_seen') is True:raise MirrorError('schedule_media_child_failed')
    if runtime['status']=='cleanup_pending':
        return CleanupPending(status='cleanup_pending',enabled=False,stopped=False,registration_absent=False,source_authority=False,body_status='succeeded',operation=record['operation'],handoff=dict(created_at_ns=runtime['cleanup_pending']['created_at_ns'],expires=runtime['cleanup_pending']['expires'],source_authority=False))
    if not runtime['registration_absent']:raise MirrorError('schedule_state_unknown')
    return dict(enabled=False,stopped=True,deadline_expired=runtime['stop_reason']=='deadline',attempts=runtime['attempts'])


def run_owned_once(config,config_path,record_path,action,*,operation_token=None,transport=None,process=kernel,round_deadline=None,follow_action=None,owned_media=False,request_media_devices=None):
    from .native_schedule import LaunchctlTransport,_read
    record_path=Path(record_path).absolute()
    parent_deadline=Deadline(json.loads(_read(record_path)[0]).get('deadline'))
    initial_deadline=Deadline(round_deadline) if round_deadline is not None else parent_deadline
    if (initial_deadline.facts['wall_until']>parent_deadline.facts['wall_until']
            or initial_deadline.facts['continuous_until']>parent_deadline.facts['continuous_until']
            or initial_deadline.facts['continuous_start']<parent_deadline.facts['continuous_start']):
        raise MirrorError('schedule_deadline_invalid')
    initial_deadline.check()
    arm_fatal(initial_deadline,0)
    transport=transport or LaunchctlTransport()
    record,payload,deadline=_control(config,config_path,record_path,transport,operation_token)
    if deadline.facts!=parent_deadline.facts:raise MirrorError('schedule_state_unknown')
    if round_deadline is not None:
        from .native_follow_grant import from_record
        deadline=from_record(record,initial_deadline)
    if record.get('follow_grant'):
        from .native_follow_grant import load
        role=load(record['follow_grant'],record['follow_grant_sha256'])
        if role.get('kind') in ('request','directory_probe','source_recovery') and not (role.get('kind')=='request' and owned_media):
            from .native_target_request import require_source_round
            require_source_round(round_deadline)
    runtime=json.loads(_read(record_path.with_suffix('.runtime'))[0]);current=process.identity(os.getpid())
    if (runtime.get('operation')!=record['operation'] or runtime.get('status')!='running'
        or not current or current['uid']!=os.getuid() or current['pgid']!=runtime['leader']['pgid']
        or not process.same_generation(process.identity(runtime['leader']['pid']),runtime['leader'])):
        raise MirrorError('schedule_process_unknown')
    from .failure_evidence import bind_operation,phase
    bind_operation(record['operation'],deadline.facts);phase('owned_control')
    with activate_deadline(deadline):
        deadline.check()
        if record.get('follow_grant') and role.get('kind')=='request' and owned_media:
            if round_deadline is None or round_deadline['continuous_until']-round_deadline['continuous_start']>120000000000:raise MirrorError('request_budget_invalid')
            from .native_request_media import run
            result=run(config,record_path,**(request_media_devices or {}))
        elif record.get('follow_grant') and role.get('kind')=='source_recovery':
            from .native_recovery_role import execute
            result=execute(config,record_path,**(request_media_devices or {}))
        elif record.get('follow_grant') and role.get('kind')=='directory_probe':
            from .native_directory_probe import execute
            result=execute(config,record_path)
        else:
            result=follow_action() if record.get('follow_grant') and follow_action is not None else action()
        phase('action_returned')
        return result


_register(_record_media_exit,_cleanup_grant_metadata,cleanup_handoff_status,_verify_cleanup_owner,bootstrap,starting_leader,_control,_runtime_write,_drain_output,_child_error_id,_completed_attempt,_idle_delay,_idle_wait,run_bounded,run_owned_once)
