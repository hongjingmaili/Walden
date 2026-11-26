"""Prospective local volume/object pins using the public macOS FD metadata API.

Same-Mac/non-migration is an operator precondition, not a hardware attestation.
No current volume fact can repair an older plan lacking this identity.
"""
import ctypes as C
import hashlib
import math
import os
from pathlib import Path
import stat
from .native_mirror_store import MirrorError

class _Attributes(C.Structure):
    _fields_=[('bitmapcount',C.c_uint16),('reserved',C.c_uint16),('common',C.c_uint32),
              ('volume',C.c_uint32),('directory',C.c_uint32),('file',C.c_uint32),('fork',C.c_uint32)]

def _need(ok):
    if not ok:raise MirrorError('follow_stable_identity_unknown')

def _volume(fd):
    # Public SDK sys/attr.h: ATTR_BIT_MAP_COUNT=5, ATTR_VOL_INFO|ATTR_VOL_UUID.
    lib=C.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    get=lib.fgetattrlist;get.argtypes=[C.c_int,C.POINTER(_Attributes),C.c_void_p,C.c_size_t,C.c_uint];get.restype=C.c_int
    attrs=_Attributes(5,0,0,0x80040000,0,0,0);value=C.create_string_buffer(20)
    _need(C.sizeof(_Attributes)==24 and get(fd,C.byref(attrs),value,20,0)==0)
    raw=value.raw;_need(int.from_bytes(raw[:4],'little')==20 and any(raw[4:]))
    return raw[4:].hex()

def _stamp(st):
    return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns,
            getattr(st,'st_birthtime',None))

def pin(path,*,directory=False):
    """Hash and volume identity from one FD; recheck its named object before return."""
    path=Path(path)
    try:
        _need(path.is_absolute() and path.resolve()==path)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd);birth=getattr(before,'st_birthtime',None)
            _need(before.st_uid==os.getuid() and type(birth) is float and math.isfinite(birth) and birth>0)
            if directory:_need(stat.S_ISDIR(before.st_mode) and not before.st_mode&0o022)
            else:_need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode)==0o600
                       and before.st_nlink==1 and before.st_size<=65536)
            volume=_volume(fd);raw=None if directory else os.read(fd,65537)
            if not directory:_need(len(raw)==before.st_size and len(raw)<=65536)
            identity=dict(volume_uuid=volume,inode=before.st_ino,birthtime_hex=birth.hex(),
                          kind=stat.S_IFMT(before.st_mode),uid=before.st_uid,mode=stat.S_IMODE(before.st_mode))
            _need(_volume(fd)==volume and _stamp(before)==_stamp(os.fstat(fd))
                  and _stamp(before)==_stamp(path.lstat()))
            return identity if directory else dict(identity=identity,sha256=hashlib.sha256(raw).hexdigest())
        finally:os.close(fd)
    except (OSError,ValueError,AttributeError):
        raise MirrorError('follow_stable_identity_unknown') from None

from .failure_evidence import _register
_register(_need,_volume,_stamp,pin)
