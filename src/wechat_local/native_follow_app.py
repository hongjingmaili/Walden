"""Exact same-user main-executable observation via public libproc only."""
import ctypes as C
import errno
import os
from pathlib import Path
from . import native_process as kernel
from .native_mirror_store import MirrorError

DEFAULT_EXECUTABLE = '/Applications/WeChat.app/Contents/MacOS/WeChat'


def _collect(executable, pids, identity, image_path, uid):
    matches=[]
    try:
        for pid in pids:
            before=identity(pid)
            if before is None or before['uid']!=uid or before['status']==5:
                continue
            try:
                path=image_path(pid)
            except OSError:
                after=identity(pid)
                if after is None or after['status']==5:continue
                raise
            if path!=executable:continue
            after=identity(pid)
            if after is None or after['status']==5:continue
            if not kernel.same_generation(after,before):
                raise MirrorError('follow_app_unknown')
            matches.append(dict(pid=after['pid'],uid=after['uid'],start=after['start']))
        if len(matches)>1:raise MirrorError('follow_app_ambiguous')
        return dict(state='running' if matches else 'absent',epoch=matches[0] if matches else None,
                    gui_login_identity='unobservable')
    except (OSError,MirrorError,KeyError,TypeError,ValueError):
        return dict(state='unknown',epoch=None,gui_login_identity='unobservable')


def observe(executable=DEFAULT_EXECUTABLE):
    """No Source paths, FD enumeration, UI, sockets or model calls."""
    try:
        executable=str(Path(executable).absolute())
        lib=kernel._lib()
        lib.proc_listpids.argtypes=[C.c_uint32,C.c_uint32,C.c_void_p,C.c_int]
        lib.proc_listpids.restype=C.c_int
        lib.proc_pidpath.argtypes=[C.c_int,C.c_void_p,C.c_uint32]
        lib.proc_pidpath.restype=C.c_int
        # PROC_UID_ONLY=4; proc_listpids returns bytes, not PID count.
        buffer=(C.c_int*16384)();C.set_errno(0)
        count=lib.proc_listpids(4,os.getuid(),buffer,C.sizeof(buffer))
        if count<=0 or count>=C.sizeof(buffer) or count%C.sizeof(C.c_int) or C.get_errno():
            raise MirrorError('follow_app_unknown')
        def image(pid):
            value=C.create_string_buffer(4096);C.set_errno(0)
            size=lib.proc_pidpath(pid,value,C.sizeof(value))
            if size<=0 or size>=C.sizeof(value) or not value.value:
                raise OSError(C.get_errno() or errno.EIO,'follow_app_unknown')
            return os.fsdecode(value.value)
        return _collect(executable,[p for p in buffer[:count//C.sizeof(C.c_int)] if p>0],kernel.identity,image,os.getuid())
    except (OSError,MirrorError,TypeError,ValueError,AttributeError):
        return dict(state='unknown',epoch=None,gui_login_identity='unobservable')


def matches(epoch,executable):
    try:
        before=kernel.identity(epoch['pid'])
        if not before or before['status']==5 or any(before[k]!=epoch[k] for k in ('pid','uid','start')):
            return False
        lib=kernel._lib()
        lib.proc_pidpath.argtypes=[C.c_int,C.c_void_p,C.c_uint32];lib.proc_pidpath.restype=C.c_int
        value=C.create_string_buffer(4096);C.set_errno(0)
        count=lib.proc_pidpath(epoch['pid'],value,C.sizeof(value))
        if count<=0 or count>=C.sizeof(value) or not value.value:return None
        after=kernel.identity(epoch['pid'])
        return bool(kernel.same_generation(after,before) and after['status']!=5 and os.fsdecode(value.value)==executable)
    except (OSError,MirrorError,KeyError,TypeError,ValueError,AttributeError):
        return None


from .failure_evidence import _register
_register(_collect,observe,matches)
