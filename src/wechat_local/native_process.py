"""Public libproc identity and bounded control of the current owned job group."""
import ctypes as C
import errno
import os
import signal
import subprocess
import re
import time
from .native_mirror_store import MirrorError
from .native_deadline import continuous_ns


def boot_session():
    """Public kernel generation; not a process/RSS observation or user input."""
    try:
        result=subprocess.run(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],
                              capture_output=True,timeout=2,check=False)
        value=result.stdout.decode('ascii').strip()
    except (OSError,subprocess.SubprocessError,UnicodeError):
        raise MirrorError('follow_boot_generation_unknown') from None
    if result.returncode or len(result.stdout)>128 or not re.fullmatch(
            r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',value):
        raise MirrorError('follow_boot_generation_unknown')
    return value.lower()

class _BSDInfo(C.Structure):
    _fields_=[(name,C.c_uint32) for name in ('flags','status','xstatus','pid','ppid','uid','gid','ruid','rgid','svuid','svgid','reserved')]+[('comm',C.c_char*16),('name',C.c_char*32)]+[(name,C.c_uint32) for name in ('nfiles','pgid','pjobc','tdev','tpgid')]+[('nice',C.c_int32),('start_sec',C.c_uint64),('start_usec',C.c_uint64)]


def _lib():
    lib=C.CDLL('/usr/lib/libproc.dylib',use_errno=True)
    lib.proc_pidinfo.argtypes=[C.c_int,C.c_int,C.c_uint64,C.c_void_p,C.c_int];lib.proc_pidinfo.restype=C.c_int
    lib.proc_listpgrppids.argtypes=[C.c_int,C.c_void_p,C.c_int];lib.proc_listpgrppids.restype=C.c_int
    return lib


def identity(pid):
    if type(pid) is not int or pid<=0:raise MirrorError('schedule_process_unknown')
    lib=_lib();value=_BSDInfo();C.set_errno(0)
    count=lib.proc_pidinfo(pid,3,0,C.byref(value),C.sizeof(value))
    if count==0 and C.get_errno()==errno.ESRCH:return None
    if count!=C.sizeof(value):raise MirrorError('schedule_process_unknown')
    return dict(pid=value.pid,uid=value.uid,pgid=value.pgid,start=[value.start_sec,value.start_usec],status=value.status)


def same_generation(current,expected):
    return bool(current and type(expected) is dict and all(current.get(k)==expected.get(k) for k in ('pid','uid','pgid','start')))


def group_members(pgid,uid):
    lib=_lib();buffer=(C.c_int*256)();C.set_errno(0)
    count=lib.proc_listpgrppids(int(pgid),buffer,C.sizeof(buffer))
    # proc_listpgrppids returns PID count, unlike proc_pidinfo's byte count.
    if count<0 or count>=len(buffer) or C.get_errno():raise MirrorError('schedule_process_unknown')
    values=[]
    for pid in buffer[:count]:
        if pid<=0:continue
        value=identity(pid)
        if value is None:continue
        if value['uid']!=uid or value['pgid']!=pgid:raise MirrorError('schedule_process_unknown')
        if value['status']!=5:values.append(value)
    return values


def require_own_leader(expected):
    current=identity(os.getpid())
    if not same_generation(current,expected) or current['uid']!=os.getuid() or current['pid']!=current['pgid']:
        raise MirrorError('schedule_process_unknown')
    return current


def signal_own_group(expected,signum):
    # The live wrapper is its group leader: its PID/PGID cannot be reused while
    # this check and operation execute. Never signal a caller-selected other group.
    current=require_own_leader(expected)
    group_members(current['pgid'],current['uid'])
    os.killpg(current['pgid'],signum)


def drained(expected):
    current=identity(expected['pid'])
    if current is not None and not same_generation(current,expected):
        raise MirrorError('schedule_process_unknown')
    return not group_members(expected['pgid'],expected['uid'])


from .failure_evidence import _register
_register(boot_session, _lib, identity, same_generation, group_members, require_own_leader, signal_own_group, drained)
