"""Narrow launchd ownership checks. Unknown observations never authorize mutation.

Only the OS transport is injectable. The operation nonce is installed in the
frozen plist and must be observed by a supported OS collector, with exact argv
and target. The public user ServiceManagement domain is bound to caller context.
The local record also binds pre-bootstrap absence, plist inode/bytes and config.
This does not make OS observation + removal atomic against external same-user replacement.
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
import time
import uuid
from xml.parsers.expat import ExpatError
from pathlib import Path
from contextlib import contextmanager
from .native_mirror_store import MirrorError
from . import public_service  # Register safe bridge frames for fresh error-ID lookup.
from .failure_evidence import child_result, _register


def _unknown():
    raise MirrorError('schedule_state_unknown')


def _read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            _unknown()
        data = handle.read(65537)
        if len(data) > 65536:
            _unknown()
        return data, [info.st_dev, info.st_ino]


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _config_facts(value):
    # One loaded semantic snapshot; never adopt later file contents.
    # Interval does not change source/scope ownership and must not prevent stop.
    if not isinstance(value, dict):
        _unknown()
    value = dict(value)
    value.pop('mirror_interval', None)
    return _digest(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode())


def _config_digest(path):
    return _config_facts(json.loads(_read(path)[0]))


def _create(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _sync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def _lock(directory):
    # Never follow a replaced service directory or lock file.
    if directory.is_symlink():
        _unknown()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(directory / '.walden-schedule.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            _unknown()
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MirrorError('schedule_state_unknown') from None
        yield
    finally:
        os.close(fd)


class LaunchctlTransport:
    """Legacy type name; actual backend is the public user ServiceManagement API.

    Exact API domain/UID/security session is recorded; never equated with gui/UID.
    Dictionary fields are validated for this observed OS and fail closed if the
    deprecated public API or required keys cease to be available. Only Label comparisons authorize exact absence.
    """
    def __init__(self):
        from .public_service import PublicService
        self.api = PublicService()
        self.context = dict(self.api.context)
        from . import native_process
        self.process = native_process

    def _label(self, target):
        prefix = self.context['domain'] + '/' + str(self.context['uid']) + '/' + str(self.context['security_session']) + '/'
        if not target.startswith(prefix) or '/' in target[len(prefix):] or self.api.current_context() != self.context:
            raise OSError('service context mismatch')
        return target[len(prefix):]

    def observe(self, target):
        value = self.api.get(self._label(target))
        if value is None:
            return dict(target=target, state='absent')
        if value.get('Label') != self._label(target) or type(value.get('ProgramArguments')) is not list or _argv_operation(value.get('ProgramArguments')) is None:
            return None
        return dict(target=target, state='present', argv=value['ProgramArguments'], operation=_argv_operation(value['ProgramArguments']))

    def submit(self, payload):
        self.api.submit(payload)

    def remove(self, target, wait=True):
        self.api.remove(self._label(target), wait=wait)

    def pid(self, target):
        value = self.api.get(self._label(target))
        if value is None:return None
        pid = value.get('PID')
        if pid is None:return None
        if type(pid) is not int or pid <= 0:raise OSError('public job PID invalid')
        return pid


def _argv_operation(argv):
    if type(argv) is not list or not all(type(value) is str for value in argv) or argv.count('--operation-token')!=1:
        return None
    index=argv.index('--operation-token')+1
    if index>=len(argv) or not re.fullmatch('[0-9a-f]{32}',argv[index]):return None
    return argv[index]


def _observation_unknown(reason,exception_type=None):
    from .failure_evidence import service_observation_unknown
    service_observation_unknown(reason,exception_type)
    return 'unknown'


def _observe(transport, target, payload=None):
    """Original trust boundary; only fixed redacted failure metadata is added."""
    try:
        collect = getattr(transport, 'observe', None)
        if not callable(collect):return _observation_unknown('observer_unavailable')
        value = collect(target)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        return _observation_unknown('observer_exception',type(error))
    if type(value) is not dict:
        return _observation_unknown('result_not_dictionary')
    if value.get('target') != target:
        return _observation_unknown('target_mismatch')
    if value == dict(target=target, state='absent'):
        return 'absent'
    if set(value) != {'target', 'state', 'argv', 'operation'} or value['state'] != 'present' or payload is None:
        return _observation_unknown('result_shape')
    nonce = _argv_operation(payload.get('ProgramArguments'))
    if value['argv'] != payload['ProgramArguments'] or not nonce or value['operation'] != nonce:
        return _observation_unknown('operation_mismatch')
    return 'owned'


def _schedule_label(config, spec=None):
    if spec is not None:
        value = spec.get('label_id', '')
        if type(value) is not str or re.fullmatch('[0-9a-f]{20}\\.[0-9a-f]{32}', value) is None:
            _unknown()
        return 'org.walden.native.follow-worker.' + value
    return 'org.walden.native.' + _digest((config['account_id'] + '\0' + config['source_generation']).encode())[:20]


def _follow_args(args, spec):
    if spec is None:
        return args
    if (type(spec) is not dict or type(spec.get('path')) is not str
            or not Path(spec['path']).is_absolute()
            or re.fullmatch('[0-9a-f]{64}', spec.get('sha256', '')) is None
            or type(spec.get('interval_seconds')) is not int or spec['interval_seconds'] < 1):
        _unknown()
    return args + ['--follow-grant', spec['path'], '--follow-grant-sha256', spec['sha256']]


def _submission(path,record,*,status=None,leader=None,receipt_path=None,observation=None):
    """Disposition is durable independently of optional external identity visibility."""
    target=Path(receipt_path) if receipt_path is not None else Path(path).with_suffix('.submission')
    raw,_=_read(path)
    if status is None:
        try:value=json.loads(_read(target)[0])
        except FileNotFoundError:return None
        if (value.get('operation')!=record.get('operation') or value.get('record_sha256')!=_digest(raw)
            or value.get('os_context')!=record.get('os_context') or value.get('status') not in ('not_submitted','pending','accepted')):_unknown()
        return value
    if status not in ('not_submitted','pending','accepted'):_unknown()
    prior=_submission(path,record)
    if prior:
        allowed={'not_submitted':('pending',),'pending':('pending','accepted'),'accepted':('accepted',)}
        if status not in allowed[prior['status']]:_unknown()
        if leader and prior.get('leader'):
            from .native_process import same_generation
            if not same_generation(leader,prior['leader']):_unknown()
    elif status!='not_submitted':
        # Legacy missing receipt may gain only exact currently verified stop evidence.
        if status!='pending' or not leader or not observation or observation.get('state')!='verified':_unknown()
    value=dict(prior or {},operation=record['operation'],record_sha256=_digest(raw),os_context=record['os_context'],status=status,
               leader=leader if leader is not None else (prior or {}).get('leader'))
    if observation is not None:value['identity_observation']=observation
    data=json.dumps(value,sort_keys=True).encode()
    if prior is None:_create(target,data)
    else:
        temporary=target.with_name(target.name+'.'+uuid.uuid4().hex+'.tmp');_create(temporary,data)
        if target.is_symlink() or _submission(path,record)!=prior:_unknown()
        os.replace(temporary,target)
    _sync_dir(target.parent)
    return value


def _optional_submit_identity(run,target):
    """A short/failed external read is unobservable, never gone or Source admission."""
    observation=dict(state='unobservable',provider='sm_pid_and_libproc_identity_v1',public_job_pid=None)
    try:
        pid=run.pid(target)
        if pid is None:return None,observation
        if type(pid) is not int or pid<=0:return None,observation
        observation['public_job_pid']=pid
        leader=run.process.identity(pid)
        if (not leader or leader['pid']!=pid or leader['uid']!=os.getuid() or leader['pid']!=leader['pgid']):return None,observation
        observation['state']='verified';return leader,observation
    except (OSError,MirrorError,ValueError,KeyError,AttributeError):
        return None,observation


def configure(config, config_path, executable, service_dir, enabled, *, runner=None, duration_seconds=600, follow_grant=None, prepared=None):
    from .native_deadline import Deadline, continuous_ns
    expected_config = _config_facts(config)
    requested_deadline = (Deadline(follow_grant['deadline']) if follow_grant is not None else Deadline.create(duration_seconds)) if enabled else None
    expected_interval = follow_grant['interval_seconds'] if follow_grant is not None else int(config.get('mirror_interval', 60))
    run = runner or LaunchctlTransport()
    config_path, executable, directory = (Path(p).absolute() for p in (config_path, executable, service_dir))
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise MirrorError('installed_sync_entry_required')
    label = _schedule_label(config, follow_grant)
    context = getattr(run, 'context', None)
    if (type(context) is not dict or context.get('domain') != 'kSMDomainUserLaunchd'
            or context.get('uid') != os.getuid() or type(context.get('security_session')) is not int):
        _unknown()
    target = context['domain'] + '/' + str(context['uid']) + '/' + str(context['security_session']) + '/' + label
    path = directory / (label + '.plist')
    record_path = path.with_suffix('.owned')
    active = path.with_suffix('.active')
    runtime_path = path.with_suffix('.runtime')
    args = _follow_args([str(executable), 'bounded', '--source-config', str(config_path), '--operation-record', str(record_path)], follow_grant)
    with _lock(directory):
        if _config_digest(config_path) != expected_config:
            _unknown()
        for item in (path, record_path, active, runtime_path,path.with_suffix('.starting'),path.with_suffix('.submission')):
            if item.is_symlink():
                _unknown()
        if path.exists():
            try:
                data, identity = _read(path)
                record_data, _ = _read(record_path)
                record = json.loads(record_data)
                payload = plistlib.loads(data)
                if not isinstance(record, dict) or not isinstance(payload, dict):
                    _unknown()
                if active.exists() and _read(active) != (b'unknown\n', record.get('active_identity')):
                    _unknown()
                if (record.get('target') != target or record.get('os_context') != context or record.get('preflight') != 'absent'
                    or record.get('plist_identity') != identity or record.get('plist_sha256') != _digest(data)
                    or record.get('config_sha256') != expected_config
                    or payload.get('Label') != label or payload.get('ProgramArguments') != args + ['--operation-token', record.get('operation')]
                    or record.get('operation') != payload.get('EnvironmentVariables', {}).get('WALDEN_OPERATION_ID')
                    or not re.fullmatch('[0-9a-f]{32}', record.get('operation', ''))):
                    _unknown()
            except (OSError, ValueError, TypeError, AttributeError, plistlib.InvalidFileException, ExpatError):
                raise MirrorError('schedule_state_unknown') from None
            recorded_deadline = Deadline(record.get('deadline'))
            runtime = json.loads(_read(runtime_path)[0]) if runtime_path.exists() else None
            if runtime is not None and (type(runtime) is not dict or runtime.get('operation') != record['operation'] or runtime.get('os_context') != context):
                _unknown()
            state = _observe(run, target, payload)
            if _config_digest(config_path) != expected_config:
                _unknown()
            if enabled:
                recorded_deadline.check()
                if state != 'owned' or record.get('interval_seconds') != expected_interval:
                    _unknown()
                return path
            if state not in ('owned', 'absent'):
                _unknown()
            def check_active():
                if active.exists() and _read(active) != (b'unknown\n', record.get('active_identity')):
                    _unknown()
            check_active()
            # Revalidate files and service inside the product lock immediately before mutation.
            if _read(path) != (data, identity) or _read(record_path)[0] != record_data or _config_digest(config_path) != expected_config:
                _unknown()
            if _observe(run, target, payload) != state or _config_digest(config_path) != expected_config:
                _unknown()
            process = getattr(run, 'process', None)
            if process is None:
                _unknown()
            leader = runtime.get('leader') if runtime else None
            from .native_background import starting_leader
            early=starting_leader(record_path,record,payload,context=context,process=process)
            submitted=_submission(record_path,record)
            receipt_leader=submitted.get('leader') if submitted else None
            for candidate in (early,receipt_leader):
                if candidate:
                    if leader and not process.same_generation(candidate,leader):_unknown()
                    leader=candidate
            pid = run.pid(target) if state == 'owned' else None
            if pid is not None:
                observed_leader = process.identity(pid)
                if (not observed_leader or observed_leader['uid'] != os.getuid() or observed_leader['pid'] != observed_leader['pgid']
                    or (leader and not process.same_generation(observed_leader, leader))):
                    _unknown()
                leader = observed_leader
                prior=_submission(record_path,record)
                _submission(record_path,record,status=prior['status'] if prior else 'pending',leader=leader,
                    observation=dict(state='verified',provider='sm_pid_and_libproc_identity_v1',public_job_pid=pid))
            elif leader:
                current = process.identity(leader['pid'])
                if current and not process.same_generation(current, leader):
                    _unknown()
            if state == 'owned':
                try:
                    run.remove(target)
                except (OSError, subprocess.SubprocessError) as error:
                    if isinstance(error, subprocess.CalledProcessError):
                        child_result(error.returncode, error.stderr)
                    raise MirrorError('schedule_state_unknown') from None
                if _observe(run, target, payload) != 'absent':
                    _unknown()
            if not leader and not (submitted and submitted['status']=='not_submitted'):
                _unknown()  # Preserve every pending descriptor/handshake for later exact recovery.
            if leader:
                until = continuous_ns() + 3000000000
                while not process.drained(leader):
                    if continuous_ns() >= until:
                        _unknown()
                    time.sleep(0.02)
            # No cleanup until exact absence and this operation's files remain proven.
            if _read(path) != (data, identity) or _read(record_path)[0] != record_data:
                _unknown()
            check_active()
            suffix = '.disabled-' + str(time.time_ns())
            for item in (path, record_path, active, runtime_path,path.with_suffix('.starting'),path.with_suffix('.submission')):
                if item.exists():
                    if item.is_symlink():
                        _unknown()
                    item.rename(item.with_name(item.name + suffix))
            _sync_dir(directory)
            return path
        if any(item.exists() for item in (record_path,active,runtime_path,path.with_suffix('.starting'),path.with_suffix('.submission'))):
            _unknown()
        if _observe(run, target) != 'absent' or _config_digest(config_path) != expected_config:
            _unknown()
        if not enabled:
            return path
        operation = uuid.uuid4().hex
        args = args + ['--operation-token', operation]
        requested_deadline.check()
        environment = dict(WALDEN_OPERATION_ID=operation, HOME=str(Path.home()), PYTHONDONTWRITEBYTECODE='1')
        for key in ('XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME'):
            if os.environ.get(key):
                environment[key] = os.environ[key]
        payload = dict(Label=label, ProgramArguments=args, RunAtLoad=True, KeepAlive=False,
                       ExitTimeOut=2, AbandonProcessGroup=False, EnvironmentVariables=environment)
        data = plistlib.dumps(payload)
        config_hash = expected_config
        _create(path, data)
        _, identity = _read(path)
        _create(active, b'unknown\n')
        _, active_identity = _read(active)
        record = dict(deadline=requested_deadline.facts, interval_seconds=expected_interval, os_context=context, active_identity=active_identity, target=target, preflight='absent', operation=operation, plist_identity=identity,
                      plist_sha256=_digest(data), config_sha256=config_hash)
        if follow_grant is not None:
            record.update(follow_grant=follow_grant['path'], follow_grant_sha256=follow_grant['sha256'])
        _create(record_path, json.dumps(record, sort_keys=True).encode())
        _submission(record_path,record,status='not_submitted')
        _sync_dir(directory)
        if _observe(run, target) != 'absent' or _config_digest(config_path) != expected_config or _read(path) != (data, identity):
            _unknown()
        if prepared is not None:
            prepared(dict(operation=operation,record=str(record_path),grant=json.loads(json.dumps(follow_grant)),os_context=dict(context)))
        requested_deadline.check()
        _submission(record_path,record,status='pending')
        try:
            run.submit(payload)
            # Successful submit is committed before any optional SM/libproc read.
            _submission(record_path,record,status='accepted',observation=dict(state='not_sampled',provider='sm_pid_and_libproc_identity_v1',public_job_pid=None))
            receipt_leader,observation=_optional_submit_identity(run,target)
            _submission(record_path,record,status='accepted',leader=receipt_leader,observation=observation)
        except (OSError, subprocess.SubprocessError) as error:
            if isinstance(error, subprocess.CalledProcessError):
                child_result(error.returncode, error.stderr)
            raise MirrorError('schedule_state_unknown') from None
        if _observe(run, target, payload) != 'owned' or _config_digest(config_path) != expected_config:
            _unknown()
        # active is advisory only; ownership always comes from record + live OS.
        return path


def _writer_state(config):
    """Probe the existing local writer lock without creating files or reading source."""
    from .native_mirror_sync import mirror_root
    path = mirror_root(config, create=False) / '.writer.lock'
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            _unknown()
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 'busy'
        fcntl.flock(fd, fcntl.LOCK_UN)
        return 'free'
    finally:
        os.close(fd)


def _slot_view(path, *, archives=None):
    """Bind current slot; enumerate history only for an archive fallback view."""
    items = (path, path.with_suffix('.owned'), path.with_suffix('.runtime'), path.with_suffix('.active'),path.with_suffix('.starting'),path.with_suffix('.submission'))
    def stamp(item):
        try:
            info = item.lstat()
        except FileNotFoundError:
            return None
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    directory = stamp(path.parent)
    if directory is not None and not stat.S_ISDIR(directory[2]):
        _unknown()
    current = tuple(stamp(item) for item in items)
    include_archives = current[0] is None if archives is None else archives
    names = {item.name for item in items}
    inventory = tuple(sorted((item.name, stamp(item))
        for item in path.parent.glob(path.stem + '.*.disabled-*')
        if item.name.rsplit('.disabled-', 1)[0] in names)) if include_archives else None
    # Unrelated jobs may update the directory; only its own identity is bound.
    return directory[:4] if directory else None, current, inventory


def _retired_context_delta(old,current):
    if type(old) is not dict or type(current) is not dict or set(old)!=set(current):return False
    a=old.get('session_attributes');b=current.get('session_attributes')
    if type(a) is not int or type(b) is not int or not 0<=a<2**32 or not 0<=b<2**32 or a^b!=0x4000:return False
    return all(old[k]==current[k] and type(old[k]) is type(current[k]) for k in old if k!='session_attributes')


def inspect_terminal_status(config,config_path,executable,service_dir,*,runner=None,follow_grant=None):
    """Read-only retired request proof. Never authorizes control/stop/Source."""
    return inspect_status(config,config_path,executable,service_dir,runner=runner,follow_grant=follow_grant,_terminal_only=True)


_MAINTENANCE_SEAL=object()

class _MaintenanceTerminalAuthority:
    pass


def authorize_terminal_maintenance(config,config_path,recovery,*,expected_source_sha256,runner=None):
    """Mint only read-only maintenance authority from exact accepted recovery/retention."""
    from .native_follow_policy import digest
    from . import native_source_recovery as core
    pins={}
    def load(path):
        raw,info=_read(Path(path));pins[str(Path(path))]=(_digest(raw),info);return json.loads(raw)
    state=load(recovery['record']);grant=load(state['descriptor']['path']);frozen=load(grant['local_snapshot']);profile=load(state['profile'])
    if (grant.get('kind')!='source_recovery' or grant.get('authorized') is not True or grant.get('accept') is not True
        or state.get('operation')!=recovery['operation'] or grant.get('nonce')!=recovery['nonce']
        or digest(grant)!=state['descriptor']['sha256'] or digest(grant)!=state['active_grant_sha256'] or digest(grant)!=recovery['grant_sha256']
        or grant.get('source_profile')!=str(Path(config_path).absolute()) or grant.get('source_raw_sha256')!=expected_source_sha256
        or grant.get('source_signature')!=digest(config) or frozen.get('anchors')!=core.anchors(config)
        or digest(frozen)!=grant.get('expected_local_sha256') or digest(frozen)!=recovery['expected_local_sha256']
        or digest(profile)!=grant.get('snapshot_sha256') or _config_facts(profile)!=grant.get('config_sha256')):_unknown()
    current=load(Path(recovery['record']).parent.parent/'current.json')
    if current.get('record')!=recovery['record']:_unknown()
    receipt=core.committed_receipt(frozen,grant['nonce'],digest(grant))
    if not receipt or receipt.get('accepted') is not True or digest(receipt)!=recovery['receipt_sha256']:_unknown()
    value=_MaintenanceTerminalAuthority();value._seal=_MAINTENANCE_SEAL;value.config_path=str(Path(config_path).absolute());value.source_signature=digest(config);value.grant_sha256=digest(grant);value.nonce=grant['nonce'];value.expected_local_sha256=digest(frozen);value.receipt_sha256=digest(receipt);value.pins=pins
    paths=[frozen['databases'][0]['path']]+[item[key]['path'] for item in receipt.get('auxiliary_snapshots',[]) for key in ('old_archive','new_snapshot')]
    stamp=lambda path:(lambda st:(st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns))(os.stat(path,follow_symlinks=False))
    value.file_tags={path:stamp(path) for path in paths}
    source=inspect_maintenance_terminal_status(profile,state['profile'],Path(profile['runtime_python']).parent/'wechat-local-sync',state['services'],authority=value,runner=runner,follow_grant=state['descriptor'])
    if source.get('registration')!='absent' or source.get('group_drained') is not True or source.get('writer_lock')!='free' or source.get('stop_confirmed') is not True:_unknown()
    value.recovery_stopped=True
    return value


def _maintenance_terminal_grant(authority,grant,descriptor,record,expected,config,config_path,context):
    from .native_follow_policy import Store,default_root,digest
    from . import native_follow as follow
    if type(authority) is not _MaintenanceTerminalAuthority or authority._seal is not _MAINTENANCE_SEAL:_unknown()
    for path,(hashed,identity) in authority.pins.items():
        raw,now=_read(Path(path))
        if (_digest(raw),now)!=(hashed,identity):_unknown()
    if (digest(grant)!=descriptor['sha256'] or record.get('follow_grant')!=descriptor['path'] or record.get('follow_grant_sha256')!=descriptor['sha256'] or grant.get('os_context')!=record.get('os_context')):_unknown()
    for path,expected_tag in authority.file_tags.items():
        st=os.stat(path,follow_symlinks=False);now=(st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        if now!=expected_tag:_unknown()
    kind=grant.get('kind')
    if kind=='source_recovery':
        if (digest(grant)!=authority.grant_sha256 or grant.get('nonce')!=authority.nonce or grant.get('expected_local_sha256')!=authority.expected_local_sha256 or grant.get('authorized') is not True or grant.get('accept') is not True or grant.get('config_sha256')!=expected):_unknown()
    elif kind in ('active','drain'):
        if getattr(authority,'recovery_stopped',False) is not True:_unknown()
        store=Store(default_root(Path(authority.config_path)));intent,policy=follow._policy(store);runtime=follow._runtime(store)
        if (not intent or intent.get('enabled') is not False or not policy or not runtime or runtime.get('unsettled_activity')
            or policy['snapshot']!=str(config_path) or digest(config)!=policy['source_signature'] or policy['source_signature']!=authority.source_signature
            or grant.get('source_sha256')!=policy['source_signature'] or grant.get('policy_generation')!=policy['generation'] or runtime.get('policy_generation')!=policy['generation']
            or grant.get('instance_nonce')!=runtime.get('operation') or grant.get('store_root')!=str(store.root) or runtime.get('store_root')!=str(store.root)
            or runtime.get('context')!=record.get('os_context') or not runtime.get('segment') or runtime['segment'].get('descriptor')!=descriptor or runtime['segment'].get('operation')!=record.get('operation')):_unknown()
    else:_unknown()
    old=record.get('os_context')
    exact=lambda a,b:type(a) is dict and type(b) is dict and set(a)==set(b) and all(type(a[k]) is type(b[k]) and a[k]==b[k] for k in a)
    if not exact(grant.get('os_context'),old) or type(old.get('session_attributes')) is not int or type(context.get('session_attributes')) is not int or not (exact(old,context) or _retired_context_delta(old,context)):_unknown()
    return kind


def inspect_maintenance_terminal_status(config,config_path,executable,service_dir,*,authority,runner=None,follow_grant=None):
    """Explicit maintenance facts only; busy is never reported as Stop/free."""
    return inspect_status(config,config_path,executable,service_dir,runner=runner,follow_grant=follow_grant,_terminal_only=True,_maintenance=authority)



_SCOPE_PROBE_SEAL=object()

class _ScopeProbeAuthority:
    pass


def _probe_same(a,b):
    # Canonical JSON preserves bool/int and all original context field types.
    return json.dumps(a,sort_keys=True,separators=(',',':'),allow_nan=False)==json.dumps(b,sort_keys=True,separators=(',',':'),allow_nan=False)


def _probe_context(run):
    api=getattr(run,'api',None);current=getattr(api,'current_context',None)
    if not callable(current):_unknown()
    value=current()
    if (type(value) is not dict or not _probe_same(value,getattr(run,'context',None))
        or value.get('domain')!='kSMDomainUserLaunchd' or type(value.get('uid')) is not int or value['uid']!=os.getuid()
        or type(value.get('security_session')) is not int or not 0<value['security_session']<2**32
        or type(value.get('session_attributes')) is not int or not 0<=value['session_attributes']<2**32):_unknown()
    return json.loads(json.dumps(value))


def _probe_expired(facts,lower=None,*,max_ns=60000000000):
    import math
    from .native_deadline import Deadline,continuous_ns
    deadline=Deadline(facts);wall=time.time();continuous=continuous_ns()
    if (facts['continuous_until']-facts['continuous_start']>max_ns
        or type(continuous) is not int or continuous<=facts['continuous_until']
        or type(wall) not in (int,float) or not math.isfinite(wall) or wall<=facts['wall_until']):_unknown()
    if lower is not None and (wall<lower['wall'] or continuous<lower['continuous']):_unknown()
    return dict(wall=wall,continuous=continuous)


def authorize_scope_probe_terminal(plan_path,expected_plan_sha,*,runner=None):
    # This mints no control or Source authority. Only the dedicated scope plan
    # validator can return the exact pinned, current old/new-C metadata cohort.
    from .native_scope_add import _scope_probe_authority_facts
    if type(expected_plan_sha) is not str or re.fullmatch('[0-9a-f]{64}',expected_plan_sha) is None:_unknown()
    run=runner or LaunchctlTransport();context=_probe_context(run)
    path=str(Path(plan_path).absolute())
    facts=_scope_probe_authority_facts(path,expected_plan_sha,context)
    now=_probe_expired(facts['grant']['deadline'])
    value=_ScopeProbeAuthority();value._seal=_SCOPE_PROBE_SEAL
    value._run=run;value.plan_path=path;value.plan_sha256=expected_plan_sha
    value._facts=json.loads(json.dumps(facts));value._facts_json=json.dumps(facts,sort_keys=True,separators=(',',':'),allow_nan=False)
    value.issued_now=now;value.last_now=now
    _scope_probe_authority_check(value,run)
    return value


def _scope_probe_authority_check(authority,run):
    from .native_scope_add import _scope_probe_authority_facts
    if type(authority) is not _ScopeProbeAuthority or getattr(authority,'_seal',None) is not _SCOPE_PROBE_SEAL or authority._run is not run:_unknown()
    context=_probe_context(run)
    facts=_scope_probe_authority_facts(authority.plan_path,authority.plan_sha256,context)
    if json.dumps(facts,sort_keys=True,separators=(',',':'),allow_nan=False)!=authority._facts_json:_unknown()
    authority.last_now=_probe_expired(facts['grant']['deadline'],authority.last_now)
    return facts


def _scope_probe_terminal_grant(authority,grant,descriptor,record,payload,config,config_path,context,run):
    facts=_scope_probe_authority_check(authority,run)
    if (not _probe_same(context,_probe_context(run)) or not _retired_context_delta(record.get('os_context'),context)
        or not _probe_same(grant,facts['grant']) or not _probe_same(descriptor,facts['state']['descriptor'])
        or not _probe_same(record,facts['record']) or not _probe_same(payload,facts['payload'])
        or not _probe_same(config,facts['snapshot']) or str(Path(config_path).absolute())!=facts['state']['profile']
        or grant.get('kind')!='directory_probe' or grant.get('authorized') is not True
        or grant.get('scope')!='directory_discovery_once' or not _probe_same(grant.get('os_context'),record.get('os_context'))
        or type(grant.get('round_seconds')) is not int or grant['round_seconds']!=30
        or any(type(v) is not int or v!=1 for v in (grant.get('interval_seconds'),descriptor.get('interval_seconds'),record.get('interval_seconds')))
        or not _probe_same(grant.get('deadline'),descriptor.get('deadline')) or not _probe_same(grant.get('deadline'),record.get('deadline'))):_unknown()
    _scope_finite_payload(record,payload)
    authority.last_now=_probe_expired(record['deadline'],authority.last_now)


def inspect_scope_probe_terminal_status(authority,*,runner=None):
    # Independent namespace; never returned as normal/control/Source admission.
    normal_before=None;normal_after=None
    try:
        if type(authority) is not _ScopeProbeAuthority or getattr(authority,'_seal',None) is not _SCOPE_PROBE_SEAL:_unknown()
        run=authority._run if runner is None else runner
        facts=_scope_probe_authority_check(authority,run);state=facts['state'];snapshot=facts['snapshot']
        entry=Path(snapshot['runtime_python']).parent/'wechat-local-sync'
        normal_before=inspect_status(snapshot,state['profile'],entry,state['services'],runner=run,follow_grant=state['descriptor'])
        if normal_before.get('state')!='unknown':return dict(status='normal',proof=normal_before,normal_before=normal_before)
        if not _retired_context_delta(facts['record'].get('os_context'),_probe_context(run)):_unknown()
        proof=inspect_status(snapshot,state['profile'],entry,state['services'],runner=run,follow_grant=state['descriptor'],_terminal_only=True,_scope_probe=authority)
        normal_after=inspect_status(snapshot,state['profile'],entry,state['services'],runner=run,follow_grant=state['descriptor'])
        fresh=_scope_probe_authority_check(authority,run)
        if (normal_after.get('state')!='unknown' or not _probe_same(normal_before,normal_after)
            or proof.get('stop_confirmed') is not True or proof.get('registration')!='absent'
            or proof.get('group_drained') is not True or proof.get('writer_lock')!='free' or proof.get('gaps')!=[]
            or proof.get('operation_id')!=state['operation']):_unknown()
        return dict(status='retired_probe_terminal_proven',plan_sha256=authority.plan_sha256,
            record_sha256=fresh['record_sha256'],record_path=fresh['pin']['record_path'],normal_before=normal_before,normal_after=normal_after,proof=proof,
            raw_old_context=fresh['record']['os_context'],raw_current_context=_probe_context(run),
            session_attributes_xor=0x4000,deadline=fresh['grant']['deadline'],issued_now=authority.issued_now,observed_now=authority.last_now)
    except (OSError,MirrorError,ValueError,TypeError,KeyError,AttributeError,ExpatError,subprocess.SubprocessError):
        return dict(status='unknown',normal_before=normal_before,normal_after=normal_after)


def _scope_finite_payload(record,payload):
    expected_keys={'Label','ProgramArguments','RunAtLoad','KeepAlive','ExitTimeOut','AbandonProcessGroup','EnvironmentVariables'}
    env=payload.get('EnvironmentVariables')
    if (set(payload)!=expected_keys or type(payload.get('RunAtLoad')) is not bool or payload['RunAtLoad'] is not True
        or type(payload.get('KeepAlive')) is not bool or payload['KeepAlive'] is not False
        or type(payload.get('ExitTimeOut')) is not int or payload['ExitTimeOut']!=2
        or type(payload.get('AbandonProcessGroup')) is not bool or payload['AbandonProcessGroup'] is not False
        or type(env) is not dict or not {'WALDEN_OPERATION_ID','HOME','PYTHONDONTWRITEBYTECODE'}<=set(env)
        or set(env)-{'WALDEN_OPERATION_ID','HOME','PYTHONDONTWRITEBYTECODE','XDG_CONFIG_HOME','XDG_DATA_HOME','XDG_CACHE_HOME','XDG_STATE_HOME'}
        or any(type(k) is not str or type(v) is not str for k,v in env.items())
        or env.get('WALDEN_OPERATION_ID')!=record.get('operation') or env.get('PYTHONDONTWRITEBYTECODE')!='1'
        or not Path(env['HOME']).is_absolute()):_unknown()



_SCOPE_RECOVERY_SEAL=object()

class _ScopeRecoveryAuthority:
    pass

class _ScopeRecoverySelection:
    pass


def _recovery_expired(facts,lower=None):
    if len(facts['members'])!=7:_unknown()
    for member in facts['members']:
        lower=_probe_expired(member['grant']['deadline'],lower,max_ns=180000000000)
    return lower


def authorize_scope_recovery_terminal(plan_path,expected_plan_sha,*,runner=None):
    from .native_scope_add import _scope_recovery_authority_facts
    if type(expected_plan_sha) is not str or re.fullmatch('[0-9a-f]{64}',expected_plan_sha) is None:_unknown()
    run=runner or LaunchctlTransport();context=_probe_context(run)
    path=str(Path(plan_path).absolute());facts=_scope_recovery_authority_facts(path,expected_plan_sha,context)
    now=_recovery_expired(facts)
    value=_ScopeRecoveryAuthority();value._seal=_SCOPE_RECOVERY_SEAL;value._run=run
    value.plan_path=path;value.plan_sha256=expected_plan_sha
    value._facts_json=json.dumps(facts,sort_keys=True,separators=(',',':'),allow_nan=False)
    value.issued_now=now;value.last_now=now
    _scope_recovery_authority_check(value,run)
    return value


def _scope_recovery_authority_check(authority,run):
    from .native_scope_add import _scope_recovery_authority_facts
    if type(authority) is not _ScopeRecoveryAuthority or getattr(authority,'_seal',None) is not _SCOPE_RECOVERY_SEAL or authority._run is not run:_unknown()
    facts=_scope_recovery_authority_facts(authority.plan_path,authority.plan_sha256,_probe_context(run))
    if json.dumps(facts,sort_keys=True,separators=(',',':'),allow_nan=False)!=authority._facts_json:_unknown()
    authority.last_now=_recovery_expired(facts,authority.last_now)
    return facts


def _scope_recovery_member(facts,record_path,expected_record_sha):
    members=[m for m in facts['members'] if m['record_path']==str(Path(record_path).absolute()) and m['record_sha256']==expected_record_sha]
    if len(members)!=1:_unknown()
    return members[0]


def _scope_recovery_terminal_grant(selection,grant,descriptor,record,payload,config,config_path,context,run):
    if type(selection) is not _ScopeRecoverySelection or getattr(selection,'_seal',None) is not _SCOPE_RECOVERY_SEAL:_unknown()
    authority=selection.authority;facts=_scope_recovery_authority_check(authority,run)
    member=_scope_recovery_member(facts,selection.record_path,selection.record_sha256)
    if (not _probe_same(context,_probe_context(run)) or not _retired_context_delta(record.get('os_context'),context)
        or not _probe_same(grant,member['grant']) or not _probe_same(descriptor,member['state']['descriptor'])
        or not _probe_same(record,member['record']) or not _probe_same(payload,member['payload'])
        or not _probe_same(config,member['snapshot']) or str(Path(config_path).absolute())!=member['state']['profile']
        or grant.get('kind')!='source_recovery' or grant.get('scope')!='committed_daily_only'
        or grant.get('authorized') is not True or type(grant.get('accept')) is not bool
        or type(grant.get('round_seconds')) is not int or grant['round_seconds']!=30
        or any(type(v) is not int or v!=1 for v in (grant.get('interval_seconds'),descriptor.get('interval_seconds'),record.get('interval_seconds')))
        or not _probe_same(grant.get('deadline'),descriptor.get('deadline')) or not _probe_same(grant.get('deadline'),record.get('deadline'))):_unknown()
    _scope_finite_payload(record,payload)
    authority.last_now=_probe_expired(record['deadline'],authority.last_now,max_ns=180000000000)


def inspect_scope_recovery_terminal_status(authority,record_path,expected_record_sha,*,runner=None):
    normal_before=None;normal_after=None
    try:
        if type(authority) is not _ScopeRecoveryAuthority or getattr(authority,'_seal',None) is not _SCOPE_RECOVERY_SEAL:_unknown()
        run=authority._run if runner is None else runner
        facts=_scope_recovery_authority_check(authority,run);member=_scope_recovery_member(facts,record_path,expected_record_sha)
        state=member['state'];snapshot=member['snapshot'];entry=Path(snapshot['runtime_python']).parent/'wechat-local-sync'
        normal_before=inspect_status(snapshot,state['profile'],entry,state['services'],runner=run,follow_grant=state['descriptor'])
        if normal_before.get('state')!='unknown':
            _scope_recovery_authority_check(authority,run)
            return dict(status='normal',proof=normal_before,normal_before=normal_before)
        if not _retired_context_delta(member['record'].get('os_context'),_probe_context(run)):_unknown()
        selected=_ScopeRecoverySelection();selected._seal=_SCOPE_RECOVERY_SEAL
        selected.authority=authority;selected.record_path=str(Path(record_path).absolute());selected.record_sha256=expected_record_sha
        proof=inspect_status(snapshot,state['profile'],entry,state['services'],runner=run,follow_grant=state['descriptor'],_terminal_only=True,_scope_recovery=selected)
        normal_after=inspect_status(snapshot,state['profile'],entry,state['services'],runner=run,follow_grant=state['descriptor'])
        fresh=_scope_recovery_authority_check(authority,run);member=_scope_recovery_member(fresh,record_path,expected_record_sha)
        if (normal_after.get('state')!='unknown' or not _probe_same(normal_before,normal_after)
            or proof.get('registration')!='absent' or proof.get('group_drained') is not True
            or proof.get('writer_lock')!='free' or proof.get('stop_confirmed') is not True
            or proof.get('gaps')!=[] or proof.get('operation_id')!=state['operation']):_unknown()
        return dict(status='retired_recovery_terminal_proven',plan_sha256=authority.plan_sha256,
            diagnostic_sha256=fresh['diagnostic_sha256'],record_path=member['record_path'],record_sha256=member['record_sha256'],
            normal_before=normal_before,normal_after=normal_after,proof=proof,
            raw_old_context=member['record']['os_context'],raw_current_context=_probe_context(run),session_attributes_xor=0x4000,
            deadline=member['grant']['deadline'],issued_now=authority.issued_now,observed_now=authority.last_now,
            business_phase=member['business_phase'],business_acceptance='not_newly_verified_by_terminal_proof')
    except (OSError,MirrorError,ValueError,TypeError,KeyError,AttributeError,ExpatError,subprocess.SubprocessError):
        return dict(status='unknown',normal_before=normal_before,normal_after=normal_after)


def inspect_status(config, config_path, executable, service_dir, *, runner=None, follow_grant=None, _terminal_only=False, _maintenance=None, _scope_probe=None, _scope_recovery=None):
    """Independent point-in-time observation; never repair or rewrite runtime."""
    from .native_deadline import Deadline
    result = dict(state='unknown', registration='unknown', sync_health='unknown',
                  first_sync_completed=False, last_completed_attempt=None, last_completed_exit_code=None,
                  group_drained=None, writer_lock='unknown', stop_confirmed=False,
                  runtime_self_report=None, record_source='none', gaps=['schedule_state_unknown'])
    try:
        if _scope_recovery is not None and (_terminal_only is not True or _scope_probe is not None or _maintenance is not None):_unknown()
        if _scope_probe is not None and (_terminal_only is not True or _maintenance is not None):_unknown()
        run = runner or LaunchctlTransport()
        context = getattr(run, 'context', None)
        if (type(context) is not dict or context.get('domain') != 'kSMDomainUserLaunchd'
                or context.get('uid') != os.getuid() or type(context.get('security_session')) is not int):
            _unknown()
        config_path, executable, directory = (Path(p).absolute() for p in (config_path, executable, service_dir))
        expected = _config_facts(config)
        if _config_digest(config_path) != expected or directory.is_symlink():
            _unknown()
        label = _schedule_label(config, follow_grant)
        target = context['domain'] + '/' + str(context['uid']) + '/' + str(context['security_session']) + '/' + label
        active_path = directory / (label + '.plist')
        selected_slot = _slot_view(active_path)
        selected_active = selected_slot[1][0] is not None
        active_record = active_path.with_suffix('.owned')
        active_items = (active_path, active_record, active_path.with_suffix('.runtime'), active_path.with_suffix('.active'),active_path.with_suffix('.starting'),active_path.with_suffix('.submission'))
        if any(item.is_symlink() for item in active_items):
            _unknown()
        if active_path.exists() != selected_active:
            _unknown()
        if not selected_active and any(item.exists() for item in active_items[1:]):
            _unknown()
        path, record_path, suffix = active_path, active_record, ''
        if not selected_active:
            # Read only the latest archive of this exact slot; never adopt another
            # profile, older valid record, service, or guessed process group.
            archives = list(directory.glob(active_path.name + '.disabled-*'))
            if not archives:
                result['registration'] = _observe(run, target)
                result['writer_lock'] = _writer_state(config)
                if _slot_view(active_path, archives=True) != selected_slot:
                    _unknown()
                return result
            def archive_order(item):
                value = item.name[len(active_path.name + '.disabled-'):]
                if not value.isdecimal():
                    _unknown()
                return int(value)
            path = max(archives, key=archive_order)
            suffix = path.name[len(active_path.name):]
            record_path = active_record.with_name(active_record.name + suffix)
        runtime_path = active_path.with_suffix('.runtime').with_name(active_path.with_suffix('.runtime').name + suffix)
        for item in (path, record_path, runtime_path):
            if item.is_symlink():
                _unknown()
        data, identity = _read(path)
        raw, _ = _read(record_path)
        record, payload = json.loads(raw), plistlib.loads(data)
        operation = record.get('operation')
        args = _follow_args([str(executable), 'bounded', '--source-config', str(config_path), '--operation-record', str(active_record)], follow_grant)
        record_context=record.get('os_context');context_equal=record_context==context
        if _terminal_only:
            from .native_follow_policy import digest as grant_digest
            if type(follow_grant) is not dict:_unknown()
            retired_grant=json.loads(_read(Path(follow_grant['path']))[0])
            if _maintenance is not None:
                _maintenance_terminal_grant(_maintenance,retired_grant,follow_grant,record,expected,config,config_path,context)
            elif _scope_probe is not None:
                _scope_probe_terminal_grant(_scope_probe,retired_grant,follow_grant,record,payload,config,config_path,context,run)
            elif _scope_recovery is not None:
                _scope_recovery_terminal_grant(_scope_recovery,retired_grant,follow_grant,record,payload,config,config_path,context,run)
            else:
                if (grant_digest(retired_grant)!=follow_grant['sha256'] or retired_grant.get('kind')!='request' or retired_grant.get('authorized') is not True or retired_grant.get('round_seconds')!=30 or retired_grant.get('os_context')!=record_context or retired_grant.get('config_sha256')!=expected or record.get('follow_grant')!=follow_grant['path'] or record.get('follow_grant_sha256')!=follow_grant['sha256']):_unknown()
        retired_delta=_terminal_only and not context_equal and _retired_context_delta(record_context,context)
        if (type(operation) is not str or re.fullmatch('[0-9a-f]{32}', operation) is None
                or record.get('target') != target or (not context_equal and not retired_delta) or record.get('preflight') != 'absent'
                or record.get('plist_identity') != identity or record.get('plist_sha256') != _digest(data)
                or record.get('config_sha256') != expected or payload.get('Label') != label
                or payload.get('ProgramArguments') != args + ['--operation-token', operation]
                or payload.get('EnvironmentVariables', {}).get('WALDEN_OPERATION_ID') != operation):
            _unknown()
        expired = Deadline(record.get('deadline')).remaining() <= 0
        observation = _observe(run, target, payload)
        if observation not in ('owned', 'absent') or retired_delta and observation!='absent':
            _unknown()
        result.update(registration=observation, record_source='archived' if suffix else 'active', operation_id=operation)
        runtime = None
        runtime_bytes = None
        if runtime_path.exists():
            runtime_bytes = _read(runtime_path)[0]
            runtime = json.loads(runtime_bytes)
            if runtime.get('operation') != operation or runtime.get('os_context') != record_context:
                _unknown()
        leader = runtime.get('leader') if runtime else None
        if runtime is not None and leader is None:
            _unknown()
        process = getattr(run, 'process', None)
        if process is None:
            _unknown()
        from .native_background import starting_leader
        early_path=active_path.with_suffix('.starting');early_path=early_path.with_name(early_path.name+suffix)
        early=starting_leader(record_path,record,payload,context=record_context,process=process,receipt_path=early_path)
        submit_path=active_path.with_suffix('.submission');submit_path=submit_path.with_name(submit_path.name+suffix)
        submitted=_submission(record_path,record,receipt_path=submit_path)
        for candidate in (early,submitted.get('leader') if submitted else None):
            if candidate:
                if leader and not process.same_generation(candidate,leader):_unknown()
                leader=candidate
        if retired_delta and leader is None:_unknown()
        if leader is None and submitted and submitted['status']=='not_submitted' and observation=='absent':
            result['group_drained']=True
        pid = run.pid(target)
        if observation == 'absent' and pid is not None:
            _unknown()
        current = process.identity(pid) if pid is not None else None
        if current and (current['uid'] != os.getuid() or current['pid'] != current['pgid']):
            _unknown()
        if leader is not None:
            if (type(leader) is not dict or leader.get('uid') != os.getuid()
                    or type(leader.get('pid')) is not int or leader['pid'] <= 0 or leader.get('pgid') != leader['pid']
                    or type(leader.get('start')) is not list or len(leader['start']) != 2
                    or any(type(n) is not int or n < 0 for n in leader['start'])):
                _unknown()
            live = process.identity(leader['pid'])
            if (live and not process.same_generation(live, leader)) or (current and not process.same_generation(current, leader)):
                _unknown()
            result['group_drained'] = process.drained(leader)
        result['writer_lock'] = _writer_state(config)
        if runtime is None:
            health = 'waiting_first_sync'
        else:
            attempts = runtime.get('attempts')
            if type(attempts) is not int or attempts < 0:
                _unknown()
            completed = runtime.get('last_completed')
            health = 'waiting_first_sync' if attempts == 0 else 'unknown'
            if completed is not None:
                if (type(completed) is not dict or completed.get('operation') != operation
                        or type(completed.get('attempt')) is not int or not 1 <= completed['attempt'] <= attempts
                        or type(completed.get('exit_code')) is not int
                        or type(completed.get('completed_at_ns')) is not int or completed['completed_at_ns'] <= 0):
                    _unknown()
                result.update(first_sync_completed=True, last_completed_attempt=completed['attempt'],
                              last_completed_exit_code=completed['exit_code'])
                health = 'syncing' if attempts > completed['attempt'] else 'failed' if completed['exit_code'] else 'healthy'
            if runtime.get('stop_reason') == 'failure':
                health = 'failed'
            status = runtime.get('status')
            result['runtime_self_report'] = dict(status=status if status in ('running', 'stopping', 'forcing_group_exit', 'stopped', 'stop_unconfirmed', 'cleanup_pending') else 'unknown',
                registration_absent=runtime.get('registration_absent') if type(runtime.get('registration_absent')) is bool else None,
                group_drained=runtime.get('group_drained') if type(runtime.get('group_drained')) is bool else None)
        # Revalidate observations and files. This is a bounded snapshot, not a
        # promise about future intervals and never an OS mutation or self-report.
        if (_observe(run, target, payload) != observation or _config_digest(config_path) != expected
                or _read(path) != (data, identity) or _read(record_path)[0] != raw
                or (runtime_bytes is not None and _read(runtime_path)[0] != runtime_bytes)
                or _slot_view(active_path, archives=not selected_active) != selected_slot):
            _unknown()
        stopped = observation == 'absent' and result['group_drained'] is True and result['writer_lock'] == 'free'
        if retired_delta and not stopped and not (_maintenance is not None and observation=='absent' and result['group_drained'] is True and result['writer_lock']=='busy'):_unknown()
        if _terminal_only and _maintenance is not None:result.update(maintenance_terminal=True,actual_grant_kind=retired_grant['kind'],authority_receipt_sha256=_maintenance.receipt_sha256)
        if _terminal_only:
            result.update(context_equal=context_equal,recorded_os_context=record_context,current_os_context=context,session_attributes_xor=(record_context.get('session_attributes',0)^context.get('session_attributes',0)),terminal_only=True,terminal_proof=dict(registration_absent=observation=='absent',generation_group_drained=result['group_drained'] is True,writer_free=result['writer_lock']=='free'),legacy_terminal=stopped)
        state = 'stopped' if stopped else 'expired_stopping' if expired and observation == 'owned' else 'running' if current else 'enabled' if observation == 'owned' and runtime is None else 'stopping'
        if observation == 'owned' and leader is not None and current is None:
            health = 'unknown'
        if expired and observation == 'owned':
            health = 'unknown' if health == 'healthy' else health
        result.update(state=state, sync_health=health, stop_confirmed=stopped, deadline_expired=expired, gaps=[])
        if runtime is not None:
            from .native_background import cleanup_handoff_status
            handoff=cleanup_handoff_status(runtime,record,context,stop_verified=stopped)
            if handoff is not None:
                result['cleanup_handoff']=handoff
                result['gaps']+=handoff['gaps']
                if handoff['state'] not in ('confirmed','confirmed_after_expiry'):result['sync_health']='unknown'
                if (_observe(run,target,payload)!=observation or _read(runtime_path)[0]!=runtime_bytes
                    or _slot_view(active_path,archives=not selected_active)!=selected_slot):_unknown()
        if observation == 'absent' and not stopped:
            result.update(state='unknown', gaps=['schedule_stop_unconfirmed'])
        if _scope_probe is not None:
            _scope_probe_terminal_grant(_scope_probe,retired_grant,follow_grant,record,payload,config,config_path,_probe_context(run),run)
            if not stopped:_unknown()
        if _scope_recovery is not None:
            _scope_recovery_terminal_grant(_scope_recovery,retired_grant,follow_grant,record,payload,config,config_path,_probe_context(run),run)
            if not stopped:_unknown()
        return result
    except (OSError, MirrorError, ValueError, TypeError, KeyError, AttributeError, ExpatError, subprocess.SubprocessError):
        # A partially observed old completion never survives failed ownership or
        # unknown OS evidence as a successful health/stop declaration.
        result.update(state='unknown', sync_health='unknown', first_sync_completed=False,
                      last_completed_attempt=None, last_completed_exit_code=None,
                      stop_confirmed=False, gaps=['schedule_state_unknown'])
        return result


_register(_unknown, _read, _digest, _config_facts, _config_digest, _create, _sync_dir, _argv_operation, _observe, _schedule_label, _follow_args, _submission, _optional_submit_identity, configure, _writer_state, _slot_view, _retired_context_delta, inspect_terminal_status, inspect_status)
