"""Private CLI lifecycle evidence. Never serialize exception values or locals."""
from __future__ import annotations

import contextvars
import fcntl
import functools
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import types
import uuid
from datetime import datetime, timezone

_current = contextvars.ContextVar('failure_task', default=None)
_KINDS = {'window', 'sync', 'reply', 'setup', 'external'}
_STAGES = {'entry', 'configuration', 'query', 'synchronize', 'schedule', '[redacted]'}
_LIMIT = 1024 * 1024
_TYPES = {ValueError: 'ValueError', TypeError: 'TypeError', RuntimeError: 'RuntimeError',
          OSError: 'OSError', PermissionError: 'PermissionError', FileNotFoundError: 'FileNotFoundError',
          KeyboardInterrupt: 'KeyboardInterrupt', SystemExit: 'SystemExit', sqlite3.Error: 'Error',
          sqlite3.OperationalError: 'OperationalError', subprocess.CalledProcessError: 'CalledProcessError'}
_CODES = {}


def _register(*functions, exception_types=None):
    """Snapshot actual entry code identities at import, never frame-supplied names."""
    if exception_types:
        _TYPES.update(exception_types)
    def add(code):
        _CODES[id(code)] = (code, Path(code.co_filename).name, code.co_name)
        for child in code.co_consts:
            if isinstance(child, types.CodeType):
                add(child)
    for function in functions:
        add(function.__code__)
        if hasattr(function, '__wrapped__'):
            add(function.__wrapped__.__code__)


def _directory(*, create=True):
    root = Path(os.path.abspath(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local/state')))) / 'walden/failures'
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = root.parts[1:]
        for index, part in enumerate(parts):
            try:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode):
                raise OSError('unsafe evidence directory')
            if index >= len(parts) - 2 and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                raise OSError('unsafe evidence directory')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _file_safe(info):
    return (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600)


def _write(record):
    encoded = json.dumps(record).encode()
    if len(encoded) > _LIMIT:
        raise OSError('evidence unavailable: oversized')
    directory = _directory()
    name, temp, lock = record['task_id'] + '.json', uuid.uuid4().hex + '.tmp', None
    try:
        lock = os.open('.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        if not _file_safe(os.fstat(lock)):
            raise OSError('unsafe lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as out:
            out.write(encoded)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temp, dir_fd=directory)
        except FileNotFoundError:
            pass
        if lock is not None:
            os.close(lock)
        os.close(directory)


def _now():
    return datetime.now(timezone.utc).isoformat()


def begin(kind):
    record = dict(schema_version=2, task_id=uuid.uuid4().hex,
                  kind=kind if kind in _KINDS else 'external', status='started', stage='entry',
                  started_at=_now(), content_redacted=True, missing_events=[],
                   process=dict(pid=os.getpid(),uid=os.getuid(),operation_id=None,operation_verified=False))
    token=os.environ.get('WALDEN_OPERATION_ID','')
    if re.fullmatch('[0-9a-f]{32}',token):record['process']['operation_id']=token
    _write(record)
    return record


def _frames(error):
    result, tb = [], error.__traceback__
    while tb:
        code = tb.tb_frame.f_code
        known = _CODES.get(id(code))
        trusted = known is not None and known[0] is code
        result.append(dict(file=known[1] if trusted else '[external]',
                           function=known[2] if trusted else '[redacted]', line=tb.tb_lineno,
                           metadata='trusted_code' if trusted else 'redacted'))
        tb = tb.tb_next
    return result


def record_failure(task, stage, error):
    if task.get('status')=='failed':return task['task_id']
    # Keep both real edges, even when Python's display suppresses context. Indexes
    # preserve shared nodes and cycles without recursion or arbitrary object serialization.
    pending, indexes, exceptions = [error], {id(error): 0}, []
    for item in pending:
        edges = {}
        for name in ('cause', 'context'):
            linked = getattr(item, '__' + name + '__')
            if linked is not None and id(linked) not in indexes:
                indexes[id(linked)] = len(pending)
                pending.append(linked)
            edges[name] = indexes[id(linked)] if linked is not None else None
        frames = _frames(item)
        exceptions.append(dict(type=_TYPES.get(type(item), '[external type redacted]'), frames=frames,
                               traceback_status='available' if frames else 'unavailable',
                               context_suppressed=bool(item.__suppress_context__), **edges,
                               relation='cause' if item.__cause__ is not None else
                               'context' if item.__context__ is not None else None))
    task.pop('cleanup',None)
    task.update(status='failed', failure_boundary=stage if stage in ('cli', 'entry', 'child') else '[redacted]',
                exceptions=exceptions, finished_at=_now())
    _write(task)
    return task['task_id']


def _missing(task, event):
    if event not in task['missing_events']:
        task['missing_events'].append(event)


def _persist(task, event):
    try:
        _write(task)
        return True
    except Exception:
        _missing(task, event)
        print('failure evidence unavailable (' + event + ')', file=sys.stderr)
        return False


def stage(name):
    task = _current.get()
    if task is not None:
        task.update(stage=name if name in _STAGES else '[redacted]', stage_at=_now())
        if name in ('query', 'synchronize', 'schedule'):
            _persist(task, 'stage')


_PHASES={'owned_control','source_open','source_read','mirror_commit','action_returned','output_started','output_returned'}

def bind_operation(operation,round_facts):
    task=_current.get()
    if task is None or task.get('status')!='started':return
    if type(operation) is not str or re.fullmatch('[0-9a-f]{32}',operation) is None:return
    from .native_deadline import Deadline
    facts=Deadline(round_facts).facts
    task['process'].update(operation_id=operation,operation_verified=True)
    task['round_deadline']=dict(facts)
    _persist(task,'phase')


def phase(name,alias='native'):
    task=_current.get()
    if task is None or name not in _PHASES or alias not in ('native','message_source','auxiliary_source'):return
    prior=task.get('phase') or {}
    if prior.get('name')==name and prior.get('alias')==alias:return
    # At most twelve coarse plus three terminal writes, never per row/guard.
    count=task.get('phase_writes',0)
    if count>=12 and name not in ('action_returned','output_started','output_returned'):return
    if count>=15:return
    task['phase']=dict(name=name,alias=alias,at=_now());task['phase_writes']=count+1
    _persist(task,'phase')


_SERVICE_REASONS=frozenset(('observer_unavailable','observer_exception','result_not_dictionary','target_mismatch','result_shape','operation_mismatch'))
_SERVICE_TYPES={OSError:'OSError',PermissionError:'PermissionError',FileNotFoundError:'FileNotFoundError',
    ValueError:'ValueError',subprocess.SubprocessError:'SubprocessError',subprocess.CalledProcessError:'CalledProcessError',subprocess.TimeoutExpired:'TimeoutExpired'}
_SERVICE_TYPE_CODES=frozenset(_SERVICE_TYPES.values())|{'none','external_type_redacted'}


def service_observation_unknown(reason,exception_type=None):
    """Fixed type/reason only. No exception object, values, argv or locals."""
    task=_current.get()
    if task is None or reason not in _SERVICE_REASONS:return
    code='none' if exception_type is None else _SERVICE_TYPES.get(exception_type,'external_type_redacted')
    entry=dict(reason=reason,exception_type=code)
    entries=task.setdefault('service_observations',[])
    if entry in entries or len(entries)>=8:return
    entries.append(entry)
    _persist(task,'service_observation')


def child_result(returncode, stderr):
    """Only for the existing owned runner; output content is never retained."""
    task = _current.get()
    if task is not None:
        task['child'] = dict(returncode=returncode if type(returncode) is int else None,
                             stderr='[redacted]', stderr_length=len(stderr) if type(stderr) in (str, bytes) else None)
        _persist(task, 'child')


def capture(error, *, exit_code=None):
    task = _current.get()
    if task is None:
        return None
    if task.get('status')=='failed':return task['task_id']
    if task.get('status')=='pending' and exit_code is None:task.pop('exit_code',None)
    if exit_code is not None:
        task['exit_code'] = exit_code
    try:
        return record_failure(task, 'cli', error)
    except Exception:
        _missing(task, 'failure')
        return None


def error_fields(error):
    # Existing catch callers return 2. Persist that terminal fact before claiming
    # saved; boundary does not issue a second, fallible terminal write afterward.
    ident = capture(error, exit_code=2)
    task = _current.get()
    return dict(error_id=ident, evidence_status='unavailable' if not ident else
                'partial' if task['missing_events'] else 'saved')


def mark_cleanup_pending(result):
    from .native_background import CleanupPending
    task=_current.get()
    if task is not None and task.get('status')!='started':return
    if not isinstance(result,CleanupPending) or result.get('status')!='cleanup_pending' or result.get('body_status')!='succeeded' or any(result.get(k) is not False for k in ('stopped','registration_absent','source_authority')):raise ValueError('invalid cleanup handoff')
    if task is None:return
    process=task.get('process') or {}
    if process.get('operation_verified') is not True or process.get('operation_id')!=result.get('operation'):raise ValueError('unverified cleanup handoff')
    task.update(status='pending',exit_code=75,finished_at=_now(),cleanup=dict(state='pending',source_authority=False,stop_confirmed=False))


def boundary(kind):
    def decorate(fn):
        @functools.wraps(fn)
        def run(*args, **kwargs):
            try:
                task = begin(kind)
            except Exception:
                task = None
                print('failure evidence unavailable (begin)', file=sys.stderr)
            token = _current.set(task)
            try:
                result = fn(*args, **kwargs)
                if task is not None and task['status']=='pending' and not (type(result) is int and result==75):
                    raise RuntimeError('cleanup_pending_exit_required')
                if task is not None and task['status']=='failed':
                    code=task.get('exit_code')
                    return code if type(code) is int and code!=0 else 1
                if task is not None and not (task['status'] == 'failed' and task.get('exit_code') == 2):
                    if not (type(result) is int and result==75 and task['status']=='pending'):task.pop('cleanup',None)
                    task['exit_code'] = result if type(result) is int else None
                    if task['status'] != 'failed':
                        task.update(status='pending' if type(result) is int and result==75 and task['status']=='pending' else 'completed' if result == 0 else 'ended', finished_at=_now())
                    _persist(task, 'final')
                return result
            except BaseException as error:
                if task is not None and task['status']=='failed':
                    saved=task.get('exit_code')
                    return saved if type(saved) is int and saved!=0 else 1
                if isinstance(error, SystemExit):
                    code = error.code if type(error.code) is int else 0 if error.code is None else 1
                    if code==0 and task is not None and task['status']=='pending':
                        refusal=RuntimeError('cleanup_pending_exit_required')
                        refusal.__cause__=error
                        capture(refusal,exit_code=1)
                        raise refusal from error
                    if code == 0:
                        if task is not None:
                            task.pop('cleanup',None)
                            task.update(status='completed', exit_code=0, finished_at=_now())
                            _persist(task, 'final')
                        raise
                else:
                    code = None
                ident = capture(error, exit_code=code)
                reason = 'native_interrupted' if isinstance(error, KeyboardInterrupt) else 'native_unhandled_failure'
                print(reason + ': failure evidence ' + (ident or 'unavailable'), file=sys.stderr)
                raise
            finally:
                _current.reset(token)
        return run
    return decorate


def console(fn, *args, **kwargs):
    """Only installed native console presentation; library APIs still propagate."""
    try:
        return fn(*args, **kwargs)
    except SystemExit as error:
        return error.code if type(error.code) is int else 0 if error.code is None else 1
    except KeyboardInterrupt:
        # Preserve actual SIGINT termination without Python printing traceback,
        # source lines or an arbitrary KeyboardInterrupt value.
        import signal
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        os.kill(os.getpid(), signal.SIGINT)
        return 130
    except BaseException:
        return 1


def _validate(record, ident):
    """Reject untrusted JSON. Every emitted string is a fixed enum or timestamp."""
    def require(condition):
        if not condition:
            raise ValueError('invalid evidence record')
    def keys(value, required, optional=()):
        require(type(value) is dict and set(required) <= value.keys() <= set(required) | set(optional))
    def integer(value):
        return type(value) is int
    def timestamp(value):
        require(type(value) is str and len(value) <= 40)
        parsed = datetime.fromisoformat(value)
        require(parsed.tzinfo is not None and parsed.isoformat() == value)
    keys(record, ('schema_version', 'task_id', 'kind', 'status', 'stage', 'started_at', 'content_redacted', 'missing_events'),
         ('stage_at', 'finished_at', 'failure_boundary', 'exceptions', 'exit_code', 'child','process','round_deadline','phase','phase_writes','service_observations','cleanup'))
    require(type(record['schema_version']) is int and record['schema_version'] == 2 and record['task_id'] == ident)
    require(record['kind'] in _KINDS and record['status'] in ('started', 'failed', 'completed', 'ended', 'pending'))
    if 'cleanup' in record:
        value=record['cleanup'];keys(value,('state','source_authority','stop_confirmed'))
        require(type(value['state']) is str and value['state']=='pending')
        require(value['source_authority'] is False and value['stop_confirmed'] is False)
        require(record['status']=='pending' and type(record.get('exit_code')) is int and record['exit_code']==75)
    if record['status']=='pending':
        require('cleanup' in record and 'finished_at' in record)
        require((record.get('process') or {}).get('operation_verified') is True)
    require(record['stage'] in _STAGES and record['content_redacted'] is True)
    require(type(record['missing_events']) is list and all(x in ('stage', 'child', 'failure', 'final','phase','service_observation') for x in record['missing_events']))
    for name in ('started_at', 'stage_at', 'finished_at'):
        if name in record:
            timestamp(record[name])
    if 'service_observations' in record:
        entries=record['service_observations'];require(type(entries) is list and 1<=len(entries)<=8)
        for entry in entries:
            keys(entry,('reason','exception_type'))
            require(entry['reason'] in _SERVICE_REASONS and entry['exception_type'] in _SERVICE_TYPE_CODES)
            require((entry['reason']=='observer_exception')==(entry['exception_type']!='none'))
    if 'process' in record:
        value=record['process'];keys(value,('pid','uid','operation_id','operation_verified'))
        require(integer(value['pid']) and value['pid']>0 and integer(value['uid']) and value['uid']>=0)
        require(value['operation_id'] is None or type(value['operation_id']) is str and re.fullmatch('[0-9a-f]{32}',value['operation_id']) is not None)
        require(type(value['operation_verified']) is bool and (not value['operation_verified'] or value['operation_id'] is not None))
    if 'round_deadline' in record:
        from .native_deadline import Deadline
        Deadline(record['round_deadline'])
    if 'phase' in record:
        value=record['phase'];keys(value,('name','alias','at'))
        require(value['name'] in _PHASES and value['alias'] in ('native','message_source','auxiliary_source'));timestamp(value['at'])
        require(integer(record.get('phase_writes')) and 1<=record['phase_writes']<=15)
    if 'exit_code' in record:
        require(record['exit_code'] is None or integer(record['exit_code']))
    if 'failure_boundary' in record:
        require(record['failure_boundary'] in ('cli', 'entry', 'child', '[redacted]'))
    if 'child' in record:
        child = record['child']
        keys(child, ('returncode', 'stderr', 'stderr_length'))
        require(child['returncode'] is None or integer(child['returncode']))
        require(child['stderr'] == '[redacted]')
        require(child['stderr_length'] is None or integer(child['stderr_length']) and child['stderr_length'] >= 0)
    if 'exceptions' in record:
        # Import fixed entry/request modules to obtain their real code names
        # when lookup runs in a fresh process. No CLI or source operation runs.
        from . import native_mirror_cli, native_window, native_target_request, native_directory_probe, native_request_media, native_request_record, native_follow, native_follow_grant, native_background, native_scope_contract, native_scope_migrate
        locations = {(item[1], item[2]) for item in _CODES.values()}
        nodes = record['exceptions']
        require(type(nodes) is list and bool(nodes))
        for item in nodes:
            keys(item, ('type', 'frames', 'traceback_status', 'context_suppressed', 'cause', 'context', 'relation'))
            require(item['type'] in set(_TYPES.values()) | {'[external type redacted]'})
            require(type(item['context_suppressed']) is bool and item['relation'] in (None, 'cause', 'context'))
            for edge in ('cause', 'context'):
                require(item[edge] is None or integer(item[edge]) and 0 <= item[edge] < len(nodes))
            require(type(item['frames']) is list)
            require(item['traceback_status'] == ('available' if item['frames'] else 'unavailable'))
            for frame in item['frames']:
                keys(frame, ('file', 'function', 'line', 'metadata'))
                require(integer(frame['line']) and frame['line'] >= 0)
                require((frame['metadata'] == 'redacted' and frame['file'] == '[external]' and frame['function'] == '[redacted]')
                        or (frame['metadata'] == 'trusted_code' and (frame['file'], frame['function']) in locations))
    require((record['status'] == 'failed') == ('exceptions' in record and 'failure_boundary' in record))
    require(record['status'] == 'started' or 'finished_at' in record)
    return record


def lookup(ident):
    if type(ident) is not str or re.fullmatch('[0-9a-f]{32}', ident) is None:
        raise ValueError('invalid evidence id')
    directory = _directory(create=False)
    try:
        fd = os.open(ident + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not _file_safe(info) or not 0 < info.st_size <= _LIMIT:
            raise OSError('unsafe evidence file')
        data = handle.read(_LIMIT + 1)
        if len(data) > _LIMIT:
            raise OSError('oversized evidence file')
    try:
        return _validate(json.loads(data), ident)
    except (TypeError, KeyError, RecursionError, UnicodeError) as error:
        raise ValueError('invalid evidence record') from None


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('id')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(lookup(args.id)))
        return 0
    except (OSError, ValueError):
        print('{"error":"evidence_unavailable"}')
        return 2


_register(_frames, record_failure, capture, error_fields, boundary, console)
