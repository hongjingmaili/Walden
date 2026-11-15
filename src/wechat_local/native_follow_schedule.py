"""Completion-relative Source cadence; metadata hints never prove catchup."""
from copy import deepcopy


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
    if draining and r.get('draining') is not True:
        r.update(mode='normal',next_due_at_ns=int(wall*1e9),next_due_continuous_ns=continuous)
    r['draining']=draining
    if completion is not None:
        key=[completion.get('operation'),completion.get('attempt')]
        if key!=r.get('last_completion'):
            r['last_completion']=key
            failed=completion.get('exit_code')!=0
            if failed:
                delay=normal if draining else min(max(interval,r.get('backoff',0)*2),max(300,interval))
                mode='backoff';r['backoff']=delay
            elif not draining and completion.get('observed_complete') is True and not completion.get('known_backlog',False):
                delay=max(300,interval);mode='idle';r['backoff']=0
            else:
                delay=normal;mode='normal';r['backoff']=0
            at=completion.get('completed_at_ns',int(wall*1e9))
            tick=completion.get('completed_at_continuous_ns',continuous)
            r.update(mode=mode,next_due_at_ns=at+int(delay*1e9),
                     next_due_continuous_ns=tick+int(delay*1e9),dirty=False,
                     last_checked_at_ns=at,last_checked_continuous_ns=tick)
    r['dirty']=r['dirty'] or bool(dirty)
    if r['dirty'] and r['mode']=='idle' and not draining:
        # Hints only shorten a fixed due date, never reset it into the future.
        earliest=r.get('last_checked_continuous_ns',continuous)+int(interval*1e9)
        due=max(continuous,earliest)
        r['next_due_continuous_ns']=min(r['next_due_continuous_ns'],due)
        wall_due=int(wall*1e9)+max(0,due-continuous)
        r['next_due_at_ns']=min(r['next_due_at_ns'],wall_due)
    r['due']=continuous>=r['next_due_continuous_ns'] or int(wall*1e9)>=r['next_due_at_ns']
    return r


from .failure_evidence import _register
_register(plan)
