"""Follow decision rules; OS facts and Source I/O stay at their existing edges."""
from copy import deepcopy
import uuid
from .native_follow_schedule import plan,partial_completion


def _completed(worker, policy_generation, epoch):
    done = worker.get('last_completed')
    return (type(done) is dict and worker.get('policy_generation') == policy_generation
        and worker.get('app_epoch') == epoch and done.get('operation') == worker.get('operation')
        and type(done.get('attempt')) is int and done['attempt'] > 0
        and type(done.get('exit_code')) is int)


def transition(previous, *, enabled, policy_generation, app, worker, wall, continuous,
               drain_seconds=30, retry_seconds=30, binding_valid=True, recovering=False):
    """Return next metadata/action; never open Source or infer GUI login identity.

    An exit drain is a fixed subgrant from prior verified activity, not a fresh
    positive app observation. Recovery cannot manufacture a missing exit clock.
    """
    r = deepcopy(previous)
    r.setdefault('app_epoch', None)
    r.setdefault('verified_app_epoch', None)
    r.setdefault('app_was_running', False)
    r.setdefault('drain', None)
    r.setdefault('observed_catchup_complete', None)
    r.update(enabled=bool(enabled), action='wait', final_completeness='not_promised',
             gui_login_identity='unobservable', catchup_pending=True,
             pending_reasons=['final_writer_unobservable'])
    active = worker.get('active') is True
    stopped = worker.get('stop_confirmed') is True
    stop = 'stop' if active else 'wait'
    if r.get('policy_generation') not in (None, policy_generation):
        r.update(app_epoch=None, verified_app_epoch=None, app_was_running=False, drain=None,
                 observed_catchup_complete=None, observed_as_of=None, source_schedule=None)
        if active:
            r.update(policy_generation=policy_generation, state='stopping', action='stop')
            return r
    r['policy_generation'] = policy_generation
    if not enabled:
        r.update(drain=None, app_was_running=False, state='stopping' if active or not stopped else 'disabled', action=stop)
        return r
    if not binding_valid or app.get('state') not in ('running', 'absent'):
        r.update(drain=None, verified_app_epoch=None, app_was_running=False,
                 state='source_conflict' if not binding_valid else 'unknown', action=stop)
        return r
    old_epoch = r['app_epoch']
    if old_epoch and _completed(worker, policy_generation, old_epoch):
        done = worker['last_completed']
        if done['exit_code'] == 0:
            r['verified_app_epoch'] = deepcopy(old_epoch)
            r['observed_catchup_complete'] = worker.get('observed_complete')
        else:
            r['source_schedule'] = plan(r.get('source_schedule'), wall=wall, continuous=continuous,
                                        interval=retry_seconds, completion=done)
    schedule = r.get('source_schedule') or {}
    if schedule.get('mode') in ('backoff','blocked'):
        schedule = plan(schedule, wall=wall, continuous=continuous, interval=retry_seconds)
        r['source_schedule'] = schedule
        if not schedule['due']:
            if app['state'] == 'absent':
                # An exit observed during cooldown cannot become a later drain grant.
                r.update(app_was_running=False, drain=None)
            reason = schedule.get('failure_reason') if schedule['mode'] == 'blocked' else 'source_retry_backoff'
            r.update(state='waiting_source', action=stop, pending_reasons=[reason or 'source_contract_blocked'])
            return r
    if app['state'] == 'running':
        epoch = app['epoch']
        if epoch != old_epoch:
            r.update(app_epoch=deepcopy(epoch), verified_app_epoch=None,
                     observed_catchup_complete=None, observed_as_of=None, drain=None)
        r['app_was_running'] = True
        if active and (worker.get('kind') != 'active' or worker.get('app_epoch') != epoch
                       or worker.get('policy_generation') != policy_generation):
            r.update(state='starting', action='stop')
            return r
        if _completed(worker, policy_generation, epoch):
            done = worker['last_completed']
            if partial_completion(done) and active:
                from .native_table_cursor import PENDING
                source = done['partial_source']
                reasons = []
                if source['retrying_shards']:reasons.append('source_shard_retry_pending')
                if 'paused_tables' in source:reasons.append(PENDING)
                r.update(state='partial_source',observed_catchup_complete=None,
                         pending_reasons=reasons,catchup_pending=True)
                return r
            if done['exit_code']==0:
                r['verified_app_epoch'] = deepcopy(epoch)
                r['observed_catchup_complete'] = worker.get('observed_complete')
                if active:
                    r.update(state='healthy' if worker.get('observed_complete') is True else 'catching_up',
                             catchup_pending=True)
                    return r
        if active:
            r['state'] = 'starting'
        elif stopped:
            r.update(state='starting', action='start_active')
        else:
            r['state'] = 'unknown'
        return r
    # Complete OS absence is distinct from an unobservable app/source identity.
    if (r['drain'] is None and r['app_was_running'] and not recovering
            and old_epoch is not None and r['verified_app_epoch'] == old_epoch):
        r['drain'] = dict(nonce=uuid.uuid4().hex, app_epoch=deepcopy(old_epoch),
            policy_generation=policy_generation, observed_exit_at_ns=int(wall*1e9),
            deadline=dict(wall_until=wall+drain_seconds, continuous_start=continuous,
                          continuous_until=continuous+int(drain_seconds*1e9)))
    r['app_was_running'] = False
    drain = r['drain']
    if drain is not None:
        d = drain['deadline']
        live = (drain['policy_generation'] == policy_generation and
                d['continuous_start'] <= continuous < d['continuous_until'] and wall < d['wall_until'])
        if live:
            r['state'] = 'finishing'
            if active:
                r['action'] = 'wait' if worker.get('kind') == 'drain' else 'stop'
            elif stopped:
                r['action'] = 'start_drain'
            return r
    r.update(state='waiting_app' if stopped or active else 'unknown', action=stop,
             pending_reasons=['drain_deadline_or_no_final_writer_protocol'])
    return r


from .failure_evidence import _register
_register(_completed, transition)
