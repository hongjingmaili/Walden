"""Validated local follow settings; no Source or application file probes."""
import math
from pathlib import Path
from .native_follow_app import DEFAULT_EXECUTABLE

FIELDS={'follow_application_executable','follow_poll_seconds','follow_segment_seconds',
        'follow_round_seconds','follow_drain_seconds'}


def settings(profile):
    exe=profile.get('follow_application_executable',DEFAULT_EXECUTABLE)
    if (type(exe) is not str or not exe or not Path(exe).is_absolute()
            or '..' in Path(exe).parts or str(Path(exe))!=exe):
        raise ValueError('follow_application_invalid')
    try:exe.encode('utf-8')
    except UnicodeError:raise ValueError('follow_application_invalid') from None
    out=dict(executable=exe)
    for name,default,lower,upper,integer in [
        ('poll',2,.05,30,False),('segment',180,5,3600,True),
        ('round',30,1,3600,True),('drain',30,1,180,True)]:
        value=profile.get('follow_'+name+'_seconds',min(default,out['segment']) if name=='round' else default)
        if (type(value) not in ((int,) if integer else (int,float))
                or not math.isfinite(value) or not lower<=value<=upper):
            raise ValueError('follow_budget_invalid')
        out[name]=value
    if out['round']>out['segment']:raise ValueError('follow_budget_invalid')
    interval=profile.get('mirror_interval',60)
    if type(interval) is not int or interval<1:raise ValueError('follow_interval_invalid')
    out.update(interval=interval,drain_interval=min(interval,5),idle_interval=max(300,interval))
    return out


from .failure_evidence import _register
_register(settings)
