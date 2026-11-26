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
from . import native_media_segment as media_segment
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


def _reap_child(child, output=None):
    code = child.wait(timeout=.1)
    if child.stdout is not None:
        try:
            if output is not None:
                _drain_output(child, output)
        finally:
            child.stdout.close()
    return code


def _group_children(process, leader):
    return [member for member in process.group_members(leader['pgid'],leader['uid'])
            if member['pid'] != leader['pid']]


def _kill_and_reap_children(children):
    # Only unreaped Popen handles created by this worker may be signaled here.
    for child in children:
        if child is not None and child.poll() is None:
            child.kill()
    for child in children:
        if child is not None:
            try:
                child.wait(timeout=.1)
            except subprocess.TimeoutExpired:
                pass  # The caller independently checks the whole owned group.


def _update_media_cadence(cadence, runtime, code, output):
    from .native_follow_schedule import failure_details, plan
    try:
        value = json.loads(output)
    except (ValueError, UnicodeError):
        value = {}
    if type(value) is not dict:
        value = {}
    detail = failure_details([value.get('failure_reason')]) if code else {}
    wall, tick = time.time(), continuous_ns()
    done = dict(operation=runtime['operation'], attempt=runtime['media_attempts'], exit_code=code,
                completed_at_ns=int(wall*1e9), completed_at_continuous_ns=tick, **detail)
    return dict(cadence, media=plan(cadence.get('media'), wall=wall, continuous=tick,
                                    interval=30, completion=done))


def _child_error_id(buffer):
    try:value=json.loads(buffer)
    except (ValueError,UnicodeError):return None
    ident=value.get('error_id') if type(value) is dict else None
    return ident if type(ident) is str and re.fullmatch('[0-9a-f]{32}',ident) else None


def _round_expiration(attempt, wall, continuous):
    """Return unknown when the recorded round or its clock ordering is unproven."""
    try:
        facts = Deadline(attempt.get('round_deadline')).facts
    except (MirrorError, OverflowError):
        return None
    spawn_wall = attempt.get('spawn_wall_ns')
    spawn_continuous = attempt.get('spawn_continuous_ns')
    if (any(type(value) is not int for value in (wall, continuous, spawn_wall, spawn_continuous))
            or not 0 < spawn_wall <= wall
            or not facts['continuous_start'] <= spawn_continuous <= continuous):
        return None
    return wall / 1e9 >= facts['wall_until'] or continuous >= facts['continuous_until']


def _completed_attempt(runtime, code, output=None):
    """Set only after actual exit; count only the existing sync result's scope."""
    from .native_follow_schedule import SOURCE_CONFLICTS, failure_details, partial_source, partial_media_sources, shard_diagnostics, round_diagnostics
    count = None
    observation = None
    conflicts = []
    detail = failure_details(()) if code else {}
    if output is not None:
        try:
            value = json.loads(output)
            if type(value.get('gaps')) is list:
                conflicts = sorted({gap for gap in value['gaps'] if type(gap) is str and gap in SOURCE_CONFLICTS})
            if code or value.get('failure_reason') is not None or value.get('failure_class') is not None or conflicts:
                detail = failure_details([value.get('failure_reason'), *conflicts])
            if code:
                partial=partial_source(value) if code==1 and not conflicts else None
                if partial is not None:
                    detail=dict(failure_class='partial_retryable',partial_source=partial)
                    sources = partial_media_sources(value)
                    if sources is not None:
                        detail['media_sources'] = sources
                        detail['media_source_opens'] = value['source_opens']
                diagnostics=shard_diagnostics(value)
                if diagnostics:detail['shard_diagnostics']=diagnostics
            if 'image_preview_hint' in value:
                from .native_image_preview import hint
                preview = hint(value['image_preview_hint'])
                if preview is not None:
                    detail['image_preview_hint'] = preview
            candidate = value.get('source_opens')
            diagnostics=round_diagnostics(value)
            if diagnostics is not None:detail['round_diagnostics']=diagnostics
            if (code == 0 and value.get('gaps') == [] and not detail.get('failure_class')
                    and value.get('source_conflicts') in (None, [])
                    and value.get('partial_source') is None and value.get('media_sources') is None
                    and type(candidate) is int and candidate >= 0):
                count = candidate
                observation = value.get('follow_observation')
        except (ValueError, UnicodeError, AttributeError):
            pass
    attempted = runtime.get('attempt_record')
    if type(attempted) is not dict:
        attempted = {}
    ended_wall = time.time_ns()
    ended_continuous = continuous_ns()
    expired = _round_expiration(attempted, ended_wall, ended_continuous)
    raw_signal=-code if type(code) is int and code<0 else None
    termination=dict(raw_signal=raw_signal,round_deadline_expired=expired,clock_basis='parent_reap_observation_not_signal_time',
        classification=(('signal_reaped_at_or_after_round_deadline' if expired else 'signal_reaped_before_round_deadline')
                        if expired is not None else 'signal_reaped_with_unknown_round_deadline') if raw_signal else 'exit',
        timer_origin='not_independently_proven' if raw_signal else None)
    runtime['last_completed'] = dict(operation=runtime['operation'], attempt=runtime['attempts'],
        exit_code=code, completed_at_ns=ended_wall, completed_at_continuous_ns=ended_continuous,
        source_db_connections=count, source_db_connections_scope='sync_once_connection_factory_success_v1',
        observation=observation, source_conflicts=conflicts,child_pid=attempted.get('child_pid'),
        attempt_record=attempted,termination=termination,**detail)


def _active_media_sources(runtime):
    """False defers; None is a full success; a mapping limits a verified partial."""
    from .native_follow_schedule import partial_completion, partial_media_sources
    done = runtime.get('last_completed')
    attempt = runtime.get('attempt_record')
    if type(done) is not dict or type(attempt) is not dict:
        return False
    termination = done.get('termination')
    code = runtime.get('child_exit')
    operation = runtime.get('operation')
    number = runtime.get('attempts')
    if (type(termination) is not dict or runtime.get('admission_failure')
            or type(code) is not int or type(done.get('exit_code')) is not int or done['exit_code'] != code
            or type(operation) is not str or not operation or type(number) is not int or number <= 0
            or done.get('operation') != operation or type(done.get('attempt')) is not int or done['attempt'] != number
            or attempt.get('operation') != operation or type(attempt.get('attempt')) is not int or attempt['attempt'] != number
            or attempt != done.get('attempt_record') or attempt.get('phase') != 'spawned'
            or type(attempt.get('child_pid')) is not int or attempt['child_pid'] <= 0
            or type(done.get('child_pid')) is not int or type(runtime.get('child_pid')) is not int
            or attempt['child_pid'] != done['child_pid'] or attempt['child_pid'] != runtime['child_pid']
            or done.get('source_conflicts') != [] or 'raw_signal' not in termination or termination['raw_signal'] is not None
            or termination.get('round_deadline_expired') is not False
            or _round_expiration(attempt, done.get('completed_at_ns'), done.get('completed_at_continuous_ns')) is not False):
        return False
    if code == 0:
        opens = done.get('source_db_connections')
        return None if (type(opens) is int and opens > 0
                        and done.get('source_db_connections_scope') == 'sync_once_connection_factory_success_v1'
                        and done.get('failure_class') is None and done.get('failure_reason') is None) else False
    if not partial_completion(done):
        return False
    partial = done['partial_source']
    gaps = []
    if partial['retrying_shards']:
        gaps.append('source_shard_retry_pending')
    if 'paused_tables' in partial:
        from .native_table_cursor import PENDING
        gaps.append(PENDING)
    return partial_media_sources(dict(done, gaps=gaps, source_opens=done.get('media_source_opens'))) or False


def _preview_reference(runtime):
    from .native_image_preview import hint
    options = _active_media_sources(runtime)
    if options is False:
        return None
    ref = hint(runtime['last_completed'].get('image_preview_hint'))
    if ref is None or options is not None and options.get(ref['shard'])!=ref['anchor']:
        return None
    return ref


def _preview_deadline(cadence, runtime, parent, interval, wall, tick):
    """Fit between ordinary admissions, including the earliest dirty idle poll."""
    from .native_image_preview import MAX_AGE, MAX_SECONDS
    media = cadence.get('media')
    done = runtime.get('last_completed')
    checked = done.get('completed_at_continuous_ns') if type(done) is dict else None
    if (cadence.get('mode') not in ('normal','idle') or cadence.get('due') is not False
            or type(media) is not dict or media.get('mode')!='normal' or media.get('last_completion') is None
            or type(checked) is not int or not 0<=tick-checked<=MAX_AGE*10**9):
        return None
    required = [cadence.get('next_due_at_ns'),cadence.get('next_due_continuous_ns'),
                media.get('next_due_at_ns'),media.get('next_due_continuous_ns')]
    if cadence['mode']=='idle':
        required += [cadence.get('last_checked_at_ns'),cadence.get('last_checked_continuous_ns')]
    if any(type(value) is not int or value <= 0 for value in required):
        return None
    source_wall, source_tick = required[:2]
    if cadence['mode']=='idle':
        source_wall = min(source_wall,cadence['last_checked_at_ns']+interval*10**9)
        source_tick = min(source_tick,cadence['last_checked_continuous_ns']+interval*10**9)
    # Leave time for parent polling/reaping before the first regular deadline.
    margin = 2*10**9
    wall_end = min(parent['wall_until'], wall/1e9+MAX_SECONDS,
                   (source_wall-margin)/1e9,(media['next_due_at_ns']-margin)/1e9)
    tick_end = min(parent['continuous_until'],tick+MAX_SECONDS*10**9,
                   source_tick-margin,media['next_due_continuous_ns']-margin)
    if wall_end-wall/1e9<4 or tick_end-tick<4*10**9:
        return None
    return dict(wall_until=wall_end,continuous_start=tick,continuous_until=tick_end)


def _record_preview_exit(runtime, code, buffer):
    plan = runtime.pop('early_preview_plan')
    result = dict(attempt=plan['attempt'],started_at_ns=plan['started_at_ns'],reaped_at_ns=time.time_ns(),exit_code=code,
                  deadline=plan['deadline'])
    try:
        parsed = json.loads(buffer)
        for name in ('preview_attempted','preview_published','resource_opens','preview_started_at_ns','preview_published_at_ns'):
            if type(parsed.get(name)) is int:
                result[name]=parsed[name]
        reason=parsed.get('preview_reason')
        if type(reason) is str and re.fullmatch('[a-z_]{1,64}',reason):
            result['reason']=reason
    except (ValueError,AttributeError):
        pass
    runtime['last_early_preview']=result


def _idle_delay(deadline, cadence, next_run, poll):
    if cadence is None:
        due = next_run-time.monotonic()
    elif cadence['mode'] == 'blocked':
        due = poll
    elif cadence['mode'] == 'backoff':
        due = (cadence['next_due_continuous_ns']-continuous_ns())/1e9
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
    child=None;media_child=None;media_early=False;media_preempted=False;preview_seen=0;media_next=0.;failure=None;output=bytearray();media_output=bytearray();remove_accepted=False
    group_sigterm_sent=False;group_sigkill_sent=False;signal_before_cleanup=False
    reap_pending = False
    def finish_regular_media(child_process, code, buffer, *, cleaning=False):
        nonlocal cadence
        plan = runtime.pop('media_segment_plan', None)
        proof = media_segment.verified(plan, child_process.pid, code, buffer,
                                       wall=time.time_ns(), tick=continuous_ns()) if plan else None
        if proof is not None:
            runtime['media_child_exit'] = code
            runtime['media_segment_yield'] = dict(proof, attempt=plan['attempt'], deadline=plan['child_deadline'])
            return
        _record_media_exit(runtime, code)
        if follow is not None and follow['kind']=='active' and (not cleaning
                or code not in (-signal.SIGTERM,-signal.SIGKILL)):
            cadence = _update_media_cadence(cadence, runtime, code, buffer)
            runtime['source_schedule'] = cadence

    def preempt_preview():
        nonlocal media_preempted
        if not media_preempted:
            media_preempted = True
            try:media_child.kill()
            except ProcessLookupError:pass

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
            if media_child is not None:
                _drain_output(media_child, media_output)
            if media_child is not None and media_child.poll() is not None:
                media_code = _reap_child(media_child, media_output)
                if media_early:
                    _record_preview_exit(runtime, media_code, media_output)
                    media_early = False
                else:
                    finish_regular_media(media_child, media_code, media_output)
                media_child = None
                media_preempted = False
                reap_pending = True
                _runtime_write(runtime_path,runtime)
                if follow is not None and follow['kind']=='request' and runtime.get('request_source_complete'):
                    if runtime['media_child_exit']!=0:raise MirrorError('request_media_child_failed')
                    runtime['request_complete']=True;runtime['request_media_complete']=True
                    break
            if child is not None:
                _drain_output(child,output)
                code=child.poll()
                if code is not None:
                    code = _reap_child(child, output)
                    runtime['child_error_id']=_child_error_id(output)
                    runtime['child_exit']=code;child_result(code,None);child=None
                    reap_pending = True
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
                    if code and runtime['last_completed'].get('failure_class')!='partial_retryable':raise MirrorError('schedule_child_failed')
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
            if reap_pending and child is None and media_child is None:
                if _group_children(process, leader):
                    raise MirrorError('owned_descendants_unsettled')
                reap_pending = False
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
            if child is None and ready and media_early and media_child is not None:
                # A clock/hint change can make Source due sooner than planned.
                # Stop this optional child without waiting before normal Source.
                preempt_preview()
            if child is None and ready and not reap_pending and not active_tail and not runtime.get('request_source_complete'):
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
                    if follow['kind'] in ('active','drain'):
                        extra['env']['WALDEN_FOLLOW_CONTROL_RESULT'] = '1'
                runtime['attempt_record']=dict(operation=runtime['operation'],attempt=runtime['attempts']+1,
                    round_deadline=dict(facts),spawn_wall_ns=time.time_ns(),spawn_continuous_ns=continuous_ns(),
                    phase='spawning',child_pid=None,child_identity=None)
                _runtime_write(runtime_path,runtime)
                try:
                    child=spawn(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,**extra)
                except (OSError,subprocess.SubprocessError) as error:
                    from .native_follow_schedule import failure_details
                    unavailable = isinstance(error,(FileNotFoundError,PermissionError))
                    detail = failure_details(['source_runner_unavailable'] if unavailable else [])
                    runtime['attempts'] += 1
                    runtime['attempt_record']['phase'] = 'spawn_failed'
                    runtime['admission_failure'] = dict(operation=runtime['operation'],attempt=runtime['attempts'],
                        kind='source_spawn',completed_at_ns=time.time_ns(),
                        completed_at_continuous_ns=continuous_ns(),**detail)
                    if cadence is not None:
                        outcome = dict(runtime['admission_failure'],exit_code=2)
                        cadence = plan(cadence,wall=time.time(),continuous=continuous_ns(),interval=interval,
                                       completion=outcome,draining=follow['kind']=='drain')
                        runtime['source_schedule'] = cadence
                    _runtime_write(runtime_path,runtime)
                    raise MirrorError('schedule_child_spawn_failed') from error
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
            media_ready = time.monotonic() >= media_next
            if media_configured and follow['kind'] == 'active' and cadence.get('media'):
                media_ready = plan(cadence['media'],wall=time.time(),continuous=continuous_ns(),interval=30)['due']
            media_source_ready = (follow is not None and
                (_active_media_sources(runtime) is not False if follow['kind']=='active' else
                 follow['kind']=='request' and runtime.get('request_source_complete') and runtime.get('child_exit')==0))
            if media_ready and media_early and media_child is not None:
                preempt_preview()
                if media_child.poll() is not None:
                    continue  # Reap through the same slot before any idle wait.
            ordinary_ready = (media_source_ready and media_configured and media_child is None
                              and media_ready and not reap_pending and not stop[0]
                              and not runtime.get('media_segment_yield'))
            remaining = deadline.remaining()
            min_start = (media_segment.CLEANUP_SECONDS+media_segment.STAGE_SECONDS['claim']
                         if follow is not None and follow['kind']=='active' else 2)
            if ordinary_ready and remaining<=min_start and min_start>2 and not runtime.get('media_segment_deferred'):
                runtime['media_segment_deferred'] = dict(remaining_seconds=remaining, at_ns=time.time_ns())
                _runtime_write(runtime_path,runtime)
            if ordinary_ready and remaining>min_start:
                tick=continuous_ns();facts=dict(deadline.facts)
                facts.update(continuous_start=tick,continuous_until=min(facts['continuous_until'],tick+120000000000),
                             wall_until=min(facts['wall_until'],time.time()+120))
                media_args=[payload['ProgramArguments'][0],'media','--source-config',str(config_path),
                    '--operation-record',str(record_path),'--operation-token',record['operation'],'--round-deadline',json.dumps(facts,sort_keys=True)]
                media_next=time.monotonic()+30
                preview_seen=runtime['attempts']  # A normal admission already won this turn.
                media_output = bytearray()
                runtime['media_attempts'] = runtime.get('media_attempts', 0) + 1
                if follow['kind']=='active' and media_segment.segment_limited(deadline.facts, facts):
                    token = uuid.uuid4().hex
                    runtime['media_segment_plan'] = dict(
                        token=token, operation=record['operation'], grant_sha256=record['follow_grant_sha256'],
                        attempt=runtime['media_attempts'], child_deadline=facts, started_wall_ns=time.time_ns())
                    media_args.extend(('--media-segment-token', token))
                    _runtime_write(runtime_path,runtime)
                try:
                    media_child=spawn(media_args,stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE if follow['kind']=='active' else subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, close_fds=True,env=dict(payload['EnvironmentVariables']))
                    if media_child.stdout is not None:
                        os.set_blocking(media_child.stdout.fileno(), False)
                    runtime['media_child_pid']=media_child.pid;runtime['media_error']=None
                except (OSError,subprocess.SubprocessError):
                    runtime.pop('media_segment_plan', None)
                    runtime['media_error']='media_spawn_unavailable';runtime['media_failure_seen']=True
                    if follow['kind']=='request':raise MirrorError('request_media_spawn_unavailable')
                    cadence = _update_media_cadence(cadence, runtime, 1, media_output)
                    runtime['source_schedule'] = cadence
                _runtime_write(runtime_path,runtime)
            if (follow is not None and follow['kind']=='active' and not active_tail
                    and child is None and media_child is None and not reap_pending and not stop[0]
                    and not ready and not media_ready and runtime['attempts']>preview_seen):
                preview_seen=runtime['attempts']
                if (media_source_ready and owner and owner.get('admission') is True
                        and not (owner.get('retirement_pending') or owner.get('unsettled_activity'))
                        and _preview_reference(runtime) is not None):
                    facts = _preview_deadline(cadence,runtime,deadline.facts,interval,time.time_ns(),continuous_ns())
                    if facts is not None:
                        media_args=[payload['ProgramArguments'][0],'media','--source-config',str(config_path),
                            '--operation-record',str(record_path),'--operation-token',record['operation'],
                            '--round-deadline',json.dumps(facts,sort_keys=True),'--early-preview']
                        media_output=bytearray()
                        runtime['early_preview_plan']=dict(attempt=preview_seen,deadline=facts,started_at_ns=time.time_ns())
                        _runtime_write(runtime_path,runtime)
                        try:
                            media_child=spawn(media_args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                              stderr=subprocess.DEVNULL,close_fds=True,env=dict(payload['EnvironmentVariables']))
                        except (OSError,subprocess.SubprocessError):
                            _record_preview_exit(runtime,2,b'{"preview_reason":"preview_spawn_unavailable"}')
                            _runtime_write(runtime_path,runtime)
                        else:
                            media_early=True
                            if media_child.stdout is not None:
                                os.set_blocking(media_child.stdout.fileno(),False)
            if child is None:
                if reap_pending or active_tail or runtime.get('request_source_complete'):
                    delay = min(1.,deadline.remaining())
                else:
                    delay = _idle_delay(deadline,cadence,next_run,idle_poll)
                if media_preempted:
                    delay = min(delay,.05)
                elif media_child is not None:
                    delay = min(delay,2.)
                _idle_wait(read_fd,delay,sleep)
            else:
                sleep(min(0.05,deadline.remaining()))
    except BaseException as error:
        failure=error
    finally:
        try:
            signal_before_cleanup=stop[0]
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
            members = _group_children(process, leader)
            if members:
                process.signal_own_group(leader,signal.SIGTERM)
                group_sigterm_sent=True
                grace=continuous_ns()+2000000000
                while members and continuous_ns()<grace:
                    if child is not None:child.poll()
                    if media_child is not None:media_child.poll()
                    sleep(0.02)
                    members = _group_children(process, leader)
                if members:
                    _kill_and_reap_children((child, media_child))
                    members = _group_children(process, leader)
                if members:
                    runtime['status']='forcing_group_exit';persist_cleanup()
                    # Last resort includes the live owned leader, so no descendant is
                    # orphaned into a different group and no fictitious final is saved.
                    group_sigkill_sent=True
                    process.signal_own_group(leader,signal.SIGKILL)
                    raise MirrorError('schedule_process_unknown')
            if child is not None:
                runtime['child_exit']=_reap_child(child, output)
                runtime['child_error_id']=_child_error_id(output)
                _completed_attempt(runtime,runtime['child_exit'],output)
                child_result(runtime['child_exit'],None)
            if media_child is not None:
                media_code = _reap_child(media_child, media_output)
                if media_early:
                    _record_preview_exit(runtime, media_code, media_output)
                else:
                    finish_regular_media(media_child, media_code, media_output, cleaning=True)
            runtime['group_drained']=True
            final_observation=_observe(transport,record['target'],payload)
            runtime['registration_absent']=final_observation=='absent'
            runtime['cleanup_observation']=dict(remove_accepted=remove_accepted,registration=final_observation)
            from .failure_evidence import bounded_terminal
            bounded_terminal(stop_reason=runtime['stop_reason'],remove_accepted=remove_accepted,final_registration=final_observation,
                signal_received_before_cleanup=signal_before_cleanup,group_sigterm_sent=group_sigterm_sent,group_sigkill_sent=group_sigkill_sent,
                parent_deadline_expired=deadline.remaining()<=0,child_exit=runtime.get('child_exit'),attempts=runtime['attempts'])
            runtime['status']='stopped' if runtime['registration_absent'] else 'stop_unconfirmed'
            media_failed = runtime.get('media_child_exit') not in (None,0) or runtime.get('media_error') or runtime.get('media_failure_seen') is True
            body_ok = runtime.get('child_exit') == 0 and (follow is not None and follow['kind']=='active' or not media_failed)
            # Self-removal can deliver SIGTERM. The saved cause precedes it.
            # The receiver still has to prove intent, ownership, and final stop.
            if (failure is None and body_ok and runtime['stop_reason']=='deadline' and follow is not None and follow.get('kind')=='active'
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
    if (follow is None or follow['kind']!='active') and media_failed:raise MirrorError('schedule_media_child_failed')
    if runtime['status']=='cleanup_pending':
        return CleanupPending(status='cleanup_pending',enabled=False,stopped=False,registration_absent=False,source_authority=False,body_status='succeeded',operation=record['operation'],handoff=dict(created_at_ns=runtime['cleanup_pending']['created_at_ns'],expires=runtime['cleanup_pending']['expires'],source_authority=False))
    if not runtime['registration_absent']:raise MirrorError('schedule_state_unknown')
    return dict(enabled=False,stopped=True,deadline_expired=runtime['stop_reason']=='deadline',attempts=runtime['attempts'])


def run_owned_once(config,config_path,record_path,action,*,operation_token=None,transport=None,process=kernel,round_deadline=None,follow_action=None,owned_media=False,request_media_devices=None,early_preview=None,media_segment_token=None):
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
        plan = None
        if media_segment_token is not None:
            if (not record.get('follow_grant') or role.get('kind')!='active'
                    or not owned_media or early_preview is not None):
                raise MirrorError('media_segment_binding')
            plan = media_segment.bind(runtime.get('media_segment_plan'), media_segment_token,
                                      record, runtime, round_deadline)
        if early_preview is not None:
            from .native_follow_policy import Store
            from .native_image_preview import MAX_SECONDS
            plan = runtime.get('early_preview_plan') or {}
            ref = _preview_reference(runtime)
            if (not record.get('follow_grant') or role.get('kind')!='active' or not owned_media or ref is None
                    or plan.get('attempt')!=runtime.get('attempts') or plan.get('deadline')!=round_deadline
                    or round_deadline is None or round_deadline['continuous_until']-round_deadline['continuous_start']>MAX_SECONDS*10**9):
                raise MirrorError('media_source_round_changed')
            def validate_preview():
                deadline.check()
                live = json.loads(_read(record_path.with_suffix('.runtime'))[0])
                owner = Store(role['store_root']).read('instance.'+role['instance_nonce']+'.json')
                if (live.get('operation')!=record['operation'] or live.get('status')!='running'
                        or live.get('early_preview_plan')!=plan or _preview_reference(live)!=ref
                        or live.get('last_completed')!=runtime['last_completed']
                        or not owner or owner.get('admission') is not True
                        or owner.get('retirement_pending') or owner.get('unsettled_activity')):
                    raise MirrorError('media_source_round_changed')
            result = early_preview(ref,validate=validate_preview)
        elif record.get('follow_grant') and role.get('kind')=='active' and owned_media:
            sources = _active_media_sources(runtime)
            if sources is False:
                result = dict(gaps=[], media_dispatch_reason='source_round_pending', media_attempted=0)
            else:
                def current_media_source(shard):
                    deadline.check()
                    live = json.loads(_read(record_path.with_suffix('.runtime'))[0])
                    if live.get('operation')!=record['operation'] or live.get('status')!='running' or live.get('admission_failure'):
                        raise MirrorError('media_source_round_changed')
                    if live.get('last_completed') == runtime['last_completed']:
                        return True
                    latest = _active_media_sources(live)
                    if latest is False:
                        raise MirrorError('media_source_round_changed')
                    return latest is None or latest.get(shard)==sources.get(shard)
                media_options = dict(media_sources=sources,media_validate=current_media_source) if sources is not None else {}
                try:
                    with media_segment.activate(plan):
                        result = (follow_action or action)(**media_options)
                except media_segment.SegmentYield as yielded:
                    deadline.check()
                    live=json.loads(_read(record_path.with_suffix('.runtime'))[0])
                    if (not plan or live.get('operation')!=record['operation'] or live.get('status')!='running'
                            or live.get('media_segment_plan')!=plan or live.get('leader')!=runtime['leader']
                            or not process.same_generation(process.identity(runtime['leader']['pid']),runtime['leader'])):
                        raise MirrorError('media_segment_binding') from None
                    result=media_segment.receipt(plan, os.getpid(), yielded)
        elif record.get('follow_grant') and role.get('kind')=='request' and owned_media:
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


_register(_reap_child,_group_children,_kill_and_reap_children,_update_media_cadence,_record_media_exit,_cleanup_grant_metadata,cleanup_handoff_status,_verify_cleanup_owner,bootstrap,starting_leader,_control,_runtime_write,_drain_output,_child_error_id,_completed_attempt,_idle_delay,_idle_wait,run_bounded,run_owned_once)
