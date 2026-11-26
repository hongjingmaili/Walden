"""Completion-relative Source cadence; metadata hints never prove catchup."""
from copy import deepcopy
import json

from .native_table_cursor import PENDING as TABLE_CURSOR_PENDING


_PERMANENT_FAILURES = frozenset({
    'invalid_source_configuration', 'source_runner_unavailable', 'schedule_configuration_conflict', 'follow_source_conflict',
    'follow_installed_environment_mismatch', 'scope_mode_stale', 'scope_mode_ambiguous',
    'scope_registry_binding', 'scope_registry_schema', 'scope_registry_replaced',
    'scope_source_conflict', 'scope_member_proof', 'scope_copy_proof',
    'account_scope_receipt_invalid', 'source_identity_mismatch', 'source_replaced',
    'source_cursor_regression',
    'sender_identity_conflict', 'conversation_identity_conflict', 'media_store_binding',
    'source_retry_binding','account_fairness_invalid',
    'account_copy_init_invalid', 'account_copy_init_conflict',
    'account_copy_init_unknown', 'account_copy_init_unowned_local',
    'account_copy_init_uncommitted_stage', 'account_copy_init_shell_changed',
    'account_copy_init_source_changed', 'account_copy_init_local_replaced',
    'account_copy_init_local_missing', 'account_copy_init_progress_lost',
    'account_reconcile_request_invalid', 'account_reconcile_request_conflict',
    'account_reconcile_source_conflict', 'account_reconcile_copy_not_absent',
    'account_reconcile_local_invalid', 'account_reconcile_existing_initialization',
    'account_reconcile_current_unproven',
})
SOURCE_CONFLICTS = frozenset({
    'source_replaced', 'auxiliary_source_replaced', 'source_cursor_regression',
    'conversation_identity_conflict', 'sender_identity_conflict', 'source_identity_mismatch',
})


def failure_details(reasons):
    for reason in reasons:
        if type(reason) is str and reason in _PERMANENT_FAILURES:
            return dict(failure_class='permanent', failure_reason=reason)
    return dict(failure_class='retryable')


def partial_source(value):
    info=value.get('partial_source')
    gaps=value.get('gaps')
    allowed = {'source_shard_retry_pending', TABLE_CURSOR_PENDING}
    if (value.get('failure_reason') is not None or value.get('failure_class') not in (None,'partial_retryable')
            or value.get('source_conflicts') or type(gaps) is not list or not gaps
            or any(type(gap) is not str or gap not in allowed for gap in gaps) or type(info) is not dict):
        return None
    held = TABLE_CURSOR_PENDING in gaps
    expected = {'successful_shards','retrying_shards'} | ({'paused_tables'} if held else set())
    if set(info) != expected:
        return None
    successful,retrying=info['successful_shards'],info['retrying_shards']
    if (type(successful) is not int or type(retrying) is not int or min(successful,retrying)<0
            or successful+retrying>64 or ('source_shard_retry_pending' in gaps)!=(retrying>0)):
        return None
    if held:
        if type(info['paused_tables']) is not int or not 0<info['paused_tables']<2**31:
            return None
    elif not successful:
        return None
    return dict(info)


def partial_media_sources(value):
    """Internal bounded source receipt from a terminally authorized account round."""
    import re
    partial = partial_source(value)
    sources = value.get('media_sources')
    opens = value.get('source_opens')
    if (partial is None or type(sources) is not dict or not sources
            or len(sources) != partial['successful_shards'] or type(opens) is not int or opens < len(sources)):
        return None
    for shard, anchor in sources.items():
        if (type(shard) is not str or not re.fullmatch(r'(?:biz_)?message_[0-9]{1,20}\.db', shard)
                or type(anchor) is not dict or set(anchor) != {'source_identity','header'}
                or type(anchor['source_identity']) is not list or len(anchor['source_identity']) != 2
                or any(type(n) is not int or not 0 <= n < 2**64 for n in anchor['source_identity'])
                or type(anchor['header']) is not str or not re.fullmatch('[0-9a-f]{64}', anchor['header'])):
            return None
    return sources


def partial_completion(done):
    info = done.get('partial_source')
    gaps = []
    if type(info) is dict:
        if info.get('retrying_shards'):
            gaps.append('source_shard_retry_pending')
        if 'paused_tables' in info:
            gaps.append(TABLE_CURSOR_PENDING)
    return (type(done.get('exit_code')) is int and done['exit_code']==1 and done.get('failure_class')=='partial_retryable'
            and not done.get('source_conflicts') and partial_source(dict(done,gaps=gaps)) is not None)


def shard_diagnostics(value):
    rows=value.get('shard_diagnostics')
    if type(rows) is not list or len(rows)>64:return []
    stages={'source_open','source_probe','source_copy','inventory','registry','mirror','stat','unknown'}
    families={'sqlite_operational','sqlite_database','os_error','guard','python_name','python_type','python_value','unexpected'}
    result=[]
    for row in rows:
        required={'stage','exception_family','sqlite_primary_code','errno'}
        extra={'operation_phase','commit_state','sqlite_extended_code'}
        if type(row) is not dict or not required<=set(row) or set(row)-required-extra:return []
        if 'operation_phase' in row and (type(row['operation_phase']) is not str or row['operation_phase'] not in {'source_max','source_columns','source_candidates','source_rows','source_indexes','sender_schema','sender_rows','local_open','local_schema','local_progress','local_prepare','local_write','local_commit_prepare','local_commit','local_commit_revalidate','registry_commit_prepare','registry_commit','registry_commit_revalidate','copy_guard'}):return []
        if 'commit_state' in row and row['commit_state'] not in ('unknown','physical_commit_returned'):return []
        if 'sqlite_extended_code' in row and (type(row['sqlite_extended_code']) is not int or not 0<row['sqlite_extended_code']<=2147483647):return []
        if type(row['stage']) is not str or row['stage'] not in stages:return []
        if type(row['exception_family']) is not str or row['exception_family'] not in families:return []
        for key,maximum in (('sqlite_primary_code',255),('errno',2147483647)):
            if row[key] is not None and (type(row[key]) is not int or not 0<=row[key]<=maximum):return []
        result.append(dict(row))
    return result


def round_diagnostics(value):
    """A small technical frame, never Source proof/message/progress objects."""
    import re
    frame=value.get('round_diagnostics')
    if type(frame) is not dict or set(frame)!={'version','events','dropped'} or frame.get('version')!=1:return None
    events=frame['events']
    if (type(events) is not list or len(events)>64 or type(frame['dropped']) is not int
            or not 0<=frame['dropped']<=2147483647):return None
    reasons={'recovered_debt','discovery_origin_pending','discovery_page_deferred','recovered_history_commit','round_start','fair_history_due','history_source_retry_wait','history_metadata_reserved','work_proof_not_current','fair_history_next','tail_priority','no_verified_history','hint_changed','unowned_copy_withheld','current_qualification_reserved','initial_suffix_metadata_reserved',
        'fair_history','ordinary','history','tail','suffix','recent','cursor_generation','cursor_recovery','authorization_checked','authorization_failed','independent_status_not_run',
        'status_returned','status_failed','status_budget_or_timeout','probe_time_limit_unknown','prior_probe_limit_unknown','probe_member_unverified','probe_schema_unverified','probe_interrupted_unknown','deferred_page','deferred_queue','deferred_metadata','deferred_metadata_or_witness','deferred_rows','deferred_bytes','deferred_time','deferred_tables'}
    stages={'selection','source_read','local_commit','budget','terminal','independent_status'}
    numbers={'elapsed_ms','tail_streak','history_heads','metadata_used','metadata_limit','rows_used','rows_limit',
        'rows','written','H','history','tail','duration_ms','committed_rows','committed_message_rows','limit','used','required'}
    for row in events:
        if (type(row) is not dict or not {'stage','reason','elapsed_ms'}<=set(row)
                or set(row)-numbers-{'stage','reason','target','stop_kind','at_stage'} or type(row['stage']) is not str or type(row['reason']) is not str or row['stage'] not in stages or row['reason'] not in reasons):return None
        if any(type(v) is not int or not 0<=v<2**63 for k,v in row.items() if k in numbers):return None
        if 'at_stage' in row and row['at_stage'] not in ('pending_request','pending_init','management','source_open','inventory','copy_rows','history_import','tail_probe','hint_recovery'):return None
        if 'stop_kind' in row and row['stop_kind'] not in ('metadata_bytes','metadata_ms','source_ms','rows','row_bytes','tables','metadata_tables','tail_queue'):return None
        if 'target' in row and (type(row['target']) is not str or re.fullmatch('[0-9a-f]{64}',row['target']) is None):return None
    if len(json.dumps(frame).encode())>16384:return None
    return dict(version=1,events=[dict(row) for row in events],dropped=frame['dropped'])


def control_result(result):
    """An internal once-result, small enough for the owned worker pipe."""
    gaps = result.get('gaps') or []
    known = SOURCE_CONFLICTS | _PERMANENT_FAILURES | {
        'unsupported_message_schema','source_schema_changed','source_table_missing','source_shard_missing',
        'source_shard_retry_pending',TABLE_CURSOR_PENDING}
    safe_gaps = sorted({gap for gap in gaps if type(gap) is str and gap in known})
    if gaps and not safe_gaps:
        safe_gaps = ['reported_gap']
    frame = dict(gaps=safe_gaps, source_opens=result.get('source_opens'))
    diagnostics=shard_diagnostics(result)
    if diagnostics:frame['shard_diagnostics']=diagnostics
    diagnostics=round_diagnostics(result)
    if diagnostics is not None:frame['round_diagnostics']=diagnostics
    if gaps or result.get('failure_reason') is not None or result.get('failure_class') is not None:
        details=failure_details([*gaps,result.get('failure_reason')])
        frame.update(details)
    partial=partial_source(result)
    if partial is not None:
        frame.update(partial_source=partial,failure_class='partial_retryable')
        sources = partial_media_sources(result)
        if sources is not None:
            frame['media_sources'] = sources
    if 'image_preview_hint' in result and (not gaps or frame.get('media_sources')):
        from .native_image_preview import hint
        preview = hint(result['image_preview_hint'])
        if preview is not None:
            frame['image_preview_hint'] = preview
    observation = result.get('follow_observation')
    if partial is None and type(observation) is dict:
        if len(json.dumps(observation).encode()) <= 32*1024:
            frame['follow_observation'] = observation
        else:
            frame['observation_scope'] = 'oversized'
    return frame


def plan(previous, *, wall, continuous, interval, completion=None, dirty=False,
         restart=False, draining=False):
    r=deepcopy(previous) if previous and not restart else {}
    normal=min(interval,5) if draining else interval
    if not r:
        r=dict(mode='normal',next_due_at_ns=int(wall*1e9),next_due_continuous_ns=continuous,
               last_completion=None,backoff=0,dirty=False)
    r.setdefault('last_completion',None)
    r.setdefault('backoff',0)
    r.setdefault('dirty',False)
    if draining and r.get('draining') is not True and r['mode'] not in ('backoff', 'blocked'):
        r.update(mode='normal',next_due_at_ns=int(wall*1e9),next_due_continuous_ns=continuous)
    r['draining']=draining
    if completion is not None:
        key=[completion.get('operation'),completion.get('attempt')]
        if key!=r.get('last_completion'):
            r['last_completion']=key
            failed=completion.get('exit_code')!=0
            permanent=(completion.get('failure_class')=='permanent' or
                       failure_details([completion.get('failure_reason')])['failure_class']=='permanent')
            if failed and permanent:
                delay=None;mode='blocked'
            elif partial_completion(completion):
                delay=normal;mode='normal';r['backoff']=0
            elif failed:
                floor = max(300, interval)
                delay = min(max(floor, r['backoff']*2), max(3600, floor))
                mode = 'backoff'
                r['backoff'] = delay
            elif not draining and completion.get('observed_complete') is True and not completion.get('known_backlog',False):
                delay=max(300,interval);mode='idle';r['backoff']=0
            else:
                delay=normal;mode='normal';r['backoff']=0
            at=completion.get('completed_at_ns',int(wall*1e9))
            tick=completion.get('completed_at_continuous_ns',continuous)
            delay_ns = int(delay*1e9) if delay is not None else None
            r.pop('failure_reason', None)
            reason = completion.get('failure_reason')
            if failed and type(reason) is str and reason in _PERMANENT_FAILURES:
                r['failure_reason'] = reason
            r.update(mode=mode,next_due_at_ns=at+delay_ns if delay_ns is not None else None,
                     next_due_continuous_ns=tick+delay_ns if delay_ns is not None else None,dirty=False,
                     last_checked_at_ns=at,last_checked_continuous_ns=tick)
    r['dirty']=r['dirty'] or bool(dirty)
    if r['dirty'] and r['mode']=='idle' and not draining:
        # Hints only shorten a fixed due date, never reset it into the future.
        earliest=r.get('last_checked_continuous_ns',continuous)+int(interval*1e9)
        due=max(continuous,earliest)
        r['next_due_continuous_ns']=min(r['next_due_continuous_ns'],due)
        wall_due=int(wall*1e9)+max(0,due-continuous)
        r['next_due_at_ns']=min(r['next_due_at_ns'],wall_due)
    # A wall-clock adjustment must not make a failed round retry early.
    r['due'] = r['mode'] != 'blocked' and (
        continuous >= r['next_due_continuous_ns']
        or r['mode'] != 'backoff' and int(wall*1e9) >= r['next_due_at_ns'])
    return r


from .failure_evidence import _register
_register(plan, failure_details, partial_source, partial_completion, shard_diagnostics, round_diagnostics, control_result)
