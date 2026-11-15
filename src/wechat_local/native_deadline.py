"""Finite owned-operation deadline; continuous macOS time includes sleep."""
import contextvars
import ctypes as C
import math
import signal
import sys
import time
from contextlib import contextmanager
from .native_mirror_store import MirrorError

_clock=None

def continuous_ns():
    global _clock
    if _clock is None:
        if sys.platform!='darwin':raise MirrorError('schedule_clock_unavailable')
        lib=C.CDLL('/usr/lib/libSystem.B.dylib')
        class Timebase(C.Structure):_fields_=[('numer',C.c_uint32),('denom',C.c_uint32)]
        lib.mach_timebase_info.argtypes=[C.POINTER(Timebase)];lib.mach_timebase_info.restype=C.c_int
        lib.mach_continuous_time.argtypes=[];lib.mach_continuous_time.restype=C.c_uint64
        value=Timebase()
        if lib.mach_timebase_info(C.byref(value)) or not value.denom:raise MirrorError('schedule_clock_unavailable')
        _clock=(lib.mach_continuous_time,value.numer,value.denom)
    fn,numer,denom=_clock
    return fn()*numer//denom


class Deadline:
    def __init__(self,facts,*,wall=time.time,continuous=continuous_ns):
        if (type(facts) is not dict or set(facts)!={'wall_until','continuous_start','continuous_until'}
            or type(facts['wall_until']) not in (int,float) or not math.isfinite(facts['wall_until'])
            or type(facts['continuous_start']) is not int or type(facts['continuous_until']) is not int
            or not 0<=facts['continuous_start']<facts['continuous_until']
            or facts['continuous_until']-facts['continuous_start']>3600000000000):
            raise MirrorError('schedule_deadline_invalid')
        self.facts=dict(facts);self.wall=wall;self.continuous=continuous

    @classmethod
    def create(cls,seconds,*,wall=time.time,continuous=continuous_ns):
        if type(seconds) not in (int,float) or not math.isfinite(seconds) or not 1<=seconds<=3600:
            raise MirrorError('schedule_duration_invalid')
        start=continuous()
        return cls(dict(wall_until=wall()+seconds,continuous_start=start,continuous_until=start+int(seconds*1000000000)),wall=wall,continuous=continuous)

    def remaining(self):
        now=self.continuous()
        if now<self.facts['continuous_start']:return 0.
        return max(0.,min(self.facts['wall_until']-self.wall(),(self.facts['continuous_until']-now)/1000000000))

    def check(self):
        if self.remaining()<=0:raise MirrorError('schedule_deadline_expired')


def arm_fatal(deadline,grace=0):
    # This process is an owned one-shot child or validated launchd wrapper.
    # Default SIGALRM is kernel-fatal even if Python is inside a blocking C call.
    if grace not in (0,3):raise MirrorError('schedule_deadline_invalid')
    signal.signal(signal.SIGALRM,signal.SIG_DFL)
    signal.setitimer(signal.ITIMER_REAL,max(0.001,deadline.remaining()+grace))


_current=contextvars.ContextVar('walden_owned_deadline',default=None)

@contextmanager
def activate_deadline(deadline):
    token=_current.set(deadline)
    try:yield
    finally:_current.reset(token)


def check_deadline():
    deadline=_current.get()
    if deadline is not None:deadline.check()


from .failure_evidence import _register
_register(continuous_ns, Deadline.__init__, Deadline.create.__func__, Deadline.remaining, Deadline.check, arm_fatal, check_deadline)
