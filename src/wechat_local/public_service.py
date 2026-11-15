"""Narrow public ServiceManagement/CoreFoundation bridge for this user's jobs.

Uses the same documented user-domain API for read/submit/remove. No list/print
parsing or private XPC. Other jobs are inspected only for CF Label equality. A unique exact target
may supply the same selected identity fields when exact lookup returns null.
Deprecated API/key availability is
checked at runtime; unexpected dictionaries fail at the ownership consumer.
"""
import ctypes as C
import os
import plistlib
import re
import sys


class PublicService:
    DOMAIN = 'kSMDomainUserLaunchd'

    def __init__(self):
        if sys.platform != 'darwin' or os.getuid() != os.geteuid() or os.getuid() == 0:
            raise OSError('user service context required')
        self.cf = C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        self.sm = C.CDLL('/System/Library/Frameworks/ServiceManagement.framework/ServiceManagement')
        self.security = C.CDLL('/System/Library/Frameworks/Security.framework/Security')
        def fn(lib, name, result, args):
            value = getattr(lib, name); value.restype = result; value.argtypes = args; return value
        P=C.c_void_p; U=C.c_uint32
        self.string=fn(self.cf,'CFStringCreateWithCString',P,[P,C.c_char_p,U])
        self.release=fn(self.cf,'CFRelease',None,[P])
        self.data=fn(self.cf,'CFDataCreate',P,[P,P,C.c_long])
        self.length=fn(self.cf,'CFDataGetLength',C.c_long,[P])
        self.bytes=fn(self.cf,'CFDataGetBytePtr',P,[P])
        self.parse=fn(self.cf,'CFPropertyListCreateWithData',P,[P,P,C.c_long,P,C.POINTER(P)])
        self.encode=fn(self.cf,'CFPropertyListCreateData',P,[P,P,C.c_long,C.c_long,C.POINTER(P)])
        self.copy=fn(self.sm,'SMJobCopyDictionary',P,[P,P])
        self.copy_all=fn(self.sm,'SMCopyAllJobDictionaries',P,[P])
        self.type_id=fn(self.cf,'CFGetTypeID',C.c_ulong,[P])
        self.array_type=fn(self.cf,'CFArrayGetTypeID',C.c_ulong,[])
        self.dict_type=fn(self.cf,'CFDictionaryGetTypeID',C.c_ulong,[])
        self.string_type=fn(self.cf,'CFStringGetTypeID',C.c_ulong,[])
        self.number_type=fn(self.cf,'CFNumberGetTypeID',C.c_ulong,[])
        self.array_count=fn(self.cf,'CFArrayGetCount',C.c_long,[P])
        self.array_item=fn(self.cf,'CFArrayGetValueAtIndex',P,[P,C.c_long])
        self.dict_value=fn(self.cf,'CFDictionaryGetValue',P,[P,P])
        self.equal=fn(self.cf,'CFEqual',C.c_bool,[P,P])
        self.last_absence=None
        self.submit_job=fn(self.sm,'SMJobSubmit',C.c_bool,[P,P,P,C.POINTER(P)])
        self.remove_job=fn(self.sm,'SMJobRemove',C.c_bool,[P,P,P,C.c_bool,C.POINTER(P)])
        self.error_code=fn(self.cf,'CFErrorGetCode',C.c_long,[P])
        self.session_info=fn(self.security,'SessionGetInfo',C.c_int32,[U,C.POINTER(U),C.POINTER(U)])
        self.domain=P.in_dll(self.sm,self.DOMAIN).value
        if not self.domain:
            raise OSError('public user domain unavailable')
        self.context=self.current_context()

    def current_context(self):
        session=C.c_uint32(); attrs=C.c_uint32()
        status=self.session_info(C.c_uint32(0xffffffff),C.byref(session),C.byref(attrs))
        if status or not session.value:
            raise OSError(int(status),'public caller session unavailable')
        return dict(domain=self.DOMAIN,uid=os.getuid(),security_session=session.value,session_attributes=attrs.value)

    def _label(self,label):
        if type(label) is not str or not re.fullmatch(r'org\.walden\.(?:native|fixture|probe)\.[a-zA-Z0-9.-]{1,100}',label):
            raise ValueError('exact owned label required')
        p=self.string(None,label.encode(),0x08000100)
        if not p: raise OSError('label allocation failed')
        return p

    def _check(self):
        if self.current_context()!=self.context:
            raise OSError('caller context changed')

    def _to_cf(self,value):
        raw=plistlib.dumps(value); buffer=C.create_string_buffer(raw)
        data=self.data(None,buffer,len(raw));error=C.c_void_p()
        if not data: raise OSError('plist allocation failed')
        try:
            result=self.parse(None,data,0,None,C.byref(error))
            if not result: raise OSError('public plist conversion failed')
            return result
        finally:
            self.release(data)
            if error.value:self.release(error.value)

    def _from_cf(self,value):
        error=C.c_void_p();data=self.encode(None,value,100,0,C.byref(error))
        try:
            if not data:raise OSError('public dictionary conversion failed')
            length=self.length(data)
            if not 0<length<=65536:raise OSError('public dictionary size unsupported')
            return plistlib.loads(C.string_at(self.bytes(data),length))
        finally:
            if data:self.release(data)
            if error.value:self.release(error.value)

    def _selected_job(self,value):
        if self.type_id(value)!=self.dict_type():raise OSError('public job container invalid')
        result={}
        for name,kind in [('Label','string'),('ProgramArguments','argv'),('PID','number')]:
            key=self.string(None,name.encode(),0x08000100)
            if not key:raise OSError('field allocation failed')
            try:field=self.dict_value(value,key)
            finally:self.release(key)
            if not field:
                if name in ('Label','ProgramArguments'):raise OSError('public job identity unavailable')
                continue
            expected=self.array_type() if kind=='argv' else self.string_type() if kind=='string' else self.number_type()
            if self.type_id(field)!=expected:raise OSError('public job field type invalid')
            if kind=='argv':
                count=self.array_count(field)
                if not 1<=count<=256:raise OSError('public argv invalid')
                for index in range(count):
                    item=self.array_item(field,index)
                    if not item or self.type_id(item)!=self.string_type():raise OSError('public argv invalid')
            decoded=self._from_cf(field)
            if kind=='number' and type(decoded) is not int:raise OSError('public numeric field invalid')
            result[name]=decoded
        return result

    def _domain_job(self,name,*,require_absent=False):
        # Never serialize the container or decode any non-target job.
        # Validate every Label and uniqueness before decoding the exact target.
        array=self.copy_all(self.domain)
        if not array:raise OSError('public service domain query failed')
        key=None
        try:
            if self.type_id(array)!=self.array_type():raise OSError('public domain container invalid')
            count=self.array_count(array)
            if not 0<=count<=100000:raise OSError('public domain container invalid')
            key=self.string(None,b'Label',0x08000100)
            if not key:raise OSError('label allocation failed')
            matched=None
            for index in range(count):
                job=self.array_item(array,index)
                if not job or self.type_id(job)!=self.dict_type():raise OSError('public job container invalid')
                label=self.dict_value(job,key)
                if not label or self.type_id(label)!=self.string_type():raise OSError('public label metadata invalid')
                if self.equal(label,name):
                    if matched is not None:raise OSError('duplicate exact public job')
                    matched=job
            self._check()
            if matched is not None:
                if require_absent:raise OSError('exact job query inconsistent')
                result=self._selected_job(matched)
                self._check()
                return result
            self.last_absence=dict(valid_container=True,target_absent=True,fields_accessed=['Label'])
            return None
        finally:
            try:
                if key:self.release(key)
            finally:self.release(array)

    def _confirmed_absent(self,name):
        self._domain_job(name,require_absent=True)
        return True

    def get(self,label):
        self.last_absence=None
        self._check();name=self._label(label)
        try:
            result=self.copy(self.domain,name)
            if not result:
                return self._domain_job(name)
            try:return self._selected_job(result)
            finally:self.release(result)
        finally:self.release(name)

    def submit(self,payload):
        self._check();name=self._label(payload.get('Label'));self.release(name)
        job=self._to_cf(payload);error=C.c_void_p()
        try:
            if not self.submit_job(self.domain,job,None,C.byref(error)):
                raise OSError(int(self.error_code(error)) if error.value else 0,'public job submit failed')
        finally:
            self.release(job)
            if error.value:self.release(error.value)

    def remove(self,label,wait=True):
        self._check();name=self._label(label);error=C.c_void_p()
        try:
            if not self.remove_job(self.domain,name,None,bool(wait),C.byref(error)):
                raise OSError(int(self.error_code(error)) if error.value else 0,'public job remove failed')
        finally:
            self.release(name)
            if error.value:self.release(error.value)


from .failure_evidence import _register
_register(PublicService.__init__, PublicService.current_context, PublicService._label, PublicService._check, PublicService._to_cf, PublicService._from_cf, PublicService._selected_job, PublicService._domain_job, PublicService._confirmed_absent, PublicService.get, PublicService.submit, PublicService.remove)
