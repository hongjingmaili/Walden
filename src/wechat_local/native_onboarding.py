"""Confirmed first-use wiring; existing sync and follow own copying and scheduling."""
from contextlib import contextmanager
import ctypes
import fcntl
import os
import re
from pathlib import Path
import stat
import sqlite3
import json
import sys
import tempfile
import uuid

from .native_mirror_store import MirrorError
from . import native_scope_contract as scope
from .source_setup import load_source_config, SourceSetupError, _confirmed_self_username, _validate_self_username


def _private_parents(path):
    missing = []
    for parent in (path, *path.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            missing.append(parent)
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise MirrorError('onboarding_unsafe_directory')
    for parent in reversed(missing):
        parent.mkdir(mode=0o700)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise MirrorError('onboarding_directory_not_private')


@contextmanager
def _exclusive(profile):
    _private_parents(profile.parent)
    lock = profile.with_name('.' + profile.name + '.onboarding.lock')
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise MirrorError('onboarding_lock_invalid')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MirrorError('onboarding_busy') from None
        yield
    finally:
        os.close(fd)


def _publish_directory(staged, destination):
    """Kernel exclusive rename: never replace an existing file, link or directory."""
    lib = ctypes.CDLL(None, use_errno=True)
    from .native_scope_add import directory
    with directory(destination.parent) as parent:
        if sys.platform == 'darwin':
            rename = lib.renameatx_np
            flag = 4  # RENAME_EXCL
        elif hasattr(lib, 'renameat2'):
            rename = lib.renameat2
            flag = 1  # RENAME_NOREPLACE
        else:
            raise MirrorError('onboarding_atomic_publish_unavailable')
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        if rename(parent, os.fsencode(staged.name), parent, os.fsencode(destination.name), flag):
            raise OSError(ctypes.get_errno(), 'onboarding_publish_failed')
        os.fsync(parent)


def _account_creation(args, profile, output_data, *, create=False):
    """Bind a fresh account profile to this confirmed onboarding before capture."""
    path = profile.with_name('.' + profile.name + '.account-creation.json')
    expected = dict(schema='walden.first-account-creation/1', profile=str(profile),
        account_root=str(args.account_root.expanduser().resolve()),
        self_username=args.confirm_self_username, data_home=str(output_data), timezone=args.timezone)
    try:
        value = json.loads(scope.read(path)[0])
    except FileNotFoundError:
        if not create:
            return None
        value = dict(expected, scope_contract_id=uuid.uuid4().hex)
        scope.create(path, scope.encoded(value))
    if (not isinstance(value, dict) or set(value) != set(expected) | {'scope_contract_id'}
            or any(value.get(key) != wanted for key, wanted in expected.items())
            or not isinstance(value['scope_contract_id'], str)
            or re.fullmatch('[0-9a-f]{32}', value['scope_contract_id']) is None):
        raise MirrorError('onboarding_profile_provenance_invalid')
    return value['scope_contract_id']


def _directory_identity(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        raise MirrorError('onboarding_publication_identity_invalid')
    return [info.st_dev, info.st_ino, info.st_uid]


def _publication(config, profile):
    path = profile.with_name('.' + profile.name + '.account-publication.json')
    try:
        raw, _ = scope.read(path)
    except FileNotFoundError:
        return path, None
    value = json.loads(raw)
    expected = {'schema', 'profile', 'config_sha256', 'mirror_root', 'stage', 'directory_identity', 'files'}
    if (not isinstance(value, dict) or set(value) != expected
            or value['schema'] != 'walden.first-account-publication/1'
            or value['profile'] != str(profile) or value['config_sha256'] != scope.digest(config)
            or value['mirror_root'] != config['mirror_root']):
        raise MirrorError('onboarding_publication_binding_invalid')
    if type(value['files']) is dict and set(value['files']) == {scope.REGISTRY, '.first-install-receipt.json', scope.CURRENT}:
        raise MirrorError('onboarding_writer_lock_missing')
    if (not isinstance(value['stage'], str)
            or type(value['directory_identity']) is not list or len(value['directory_identity']) != 3
            or any(type(part) is not int or part < 0 for part in value['directory_identity'])
            or type(value['files']) is not dict
            or set(value['files']) != {scope.REGISTRY, '.first-install-receipt.json', scope.CURRENT, '.writer.lock'}
            or any(not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None
                   for digest in value['files'].values())):
        raise MirrorError('onboarding_publication_binding_invalid')
    staged, root = Path(value['stage']), Path(config['mirror_root'])
    if staged.parent != root.parent or not staged.name.startswith('.onboarding-'):
        raise MirrorError('onboarding_publication_binding_invalid')
    return path, value


def initialize_account(config, profile, *, progress=None, previously_configured=False, created_by_onboarding=False):
    """Publish one empty contract, remembering the operation outside its mirror.

    A durable immutable witness binds the completed private stage before rename.
    A consumed stage with a missing destination is a lost committed copy, never
    permission to recreate it. Only the exact unconsumed stage may resume rename.
    """
    progress = progress if progress is not None else {}
    progress.update(status='preparing', stage='destination_check', source_opened=False, copy_pending=True)
    scope.fixed(config)
    root = Path(config['mirror_root'])
    record_path, publication = _publication(config, profile)
    if root.exists() or root.is_symlink():
        if publication is not None and _directory_identity(root) != publication['directory_identity']:
            raise MirrorError('onboarding_initialized_copy_replaced')
        scope.query_scope_guard(config)
        from .native_registry_migrate import migrate
        from .native_follow_policy import digest
        migrate(config,profile,confirmed=True,expected_source_sha256=digest(config))
        with scope.registry(config):
            pass
        try:
            scope.read(root / '.writer.lock')
        except FileNotFoundError:
            raise MirrorError('onboarding_writer_lock_missing') from None
        return dict(status='preserved_existing_copy', source_opened=False)
    if publication is None:
        if previously_configured:
            raise MirrorError('onboarding_initialized_copy_missing')
        if not created_by_onboarding:
            raise MirrorError('onboarding_profile_provenance_required')
    if publication is not None:
        staged = Path(publication['stage'])
        if not staged.exists() or staged.is_symlink():
            raise MirrorError('onboarding_initialized_copy_missing')
        if (_directory_identity(staged) != publication['directory_identity']
                or {path.name for path in staged.iterdir()} != set(publication['files'])
                or any(scope.sha(scope.read(staged / name)[0]) != digest for name, digest in publication['files'].items())):
            raise MirrorError('onboarding_publication_stage_changed')
        progress.update(stage='publication', staging_directory=str(staged))
        _unchanged(profile, config)
        _publish_directory(staged, root)
    else:
        source = Path(config['live_db_root']).resolve()
        if root.resolve() == source or source in root.resolve().parents or root.resolve() in source.parents:
            raise MirrorError('mirror_source_overlap')
        _private_parents(root.parent)
        staged = Path(tempfile.mkdtemp(prefix='.onboarding-', dir=root.parent))
        progress.update(stage='registry', staging_directory=str(staged))
        # Reuse protected creation, without manufacturing source observations.
        temporary = dict(config, mirror_root=str(staged))
        with scope.registry(temporary, write=True, initialize=True) as conn:
            conn.execute('UPDATE binding SET value=?', (json.dumps(scope.fixed(config), sort_keys=True),))
            conn.commit()
        progress['stage'] = 'writer_lock'
        scope.create(staged / '.writer.lock', b'')
        receipt = dict(state='committed', kind='first_install', contract=scope.fixed(config),
                       new_config_sha256=scope.digest(config), legacy_current_sha256=None,
                       profile=str(profile))
        receipt_name = '.first-install-receipt.json'
        raw = scope.encoded(receipt)
        progress['stage'] = 'receipt'
        scope.create(staged / receipt_name, raw)
        progress['stage'] = 'current'
        scope.create(staged / scope.CURRENT, scope.encoded(dict(schema='walden.account.scope.current/1',
            contract=scope.fixed(config), receipt=str(root / receipt_name), receipt_sha256=scope.sha(raw))))
        _unchanged(profile, config)
        progress['stage'] = 'publication_record'
        publication = dict(schema='walden.first-account-publication/1', profile=str(profile),
            config_sha256=scope.digest(config), mirror_root=str(root), stage=str(staged),
            directory_identity=_directory_identity(staged),
            files={name: scope.sha(scope.read(staged / name)[0]) for name in
                   (scope.REGISTRY, receipt_name, scope.CURRENT, '.writer.lock')})
        scope.create(record_path, scope.encoded(publication))
        progress['stage'] = 'publication'
        _publish_directory(staged, root)
    if _directory_identity(root) != publication['directory_identity']:
        raise MirrorError('onboarding_initialized_copy_replaced')
    from .native_registry_migrate import migrate
    from .native_follow_policy import digest
    migrate(config,profile,confirmed=True,expected_source_sha256=digest(config))
    with scope.registry(config):
        pass
    return dict(status='initialized', copy_pending=True, source_opened=False)


def _validate_credentials(config):
    """Recheck the saved credential against this bound source, metadata only."""
    from .source_setup import read_private_passphrase, _metadata_connection, _database_stamp
    from .source_catalog import discover_numeric_shards, LiveCatalogError
    from .live_readonly import LiveReadonlyError
    root = Path(config['live_db_root'])
    try:
        secret = read_private_passphrase(Path(config['passphrase_file']))
        shards = discover_numeric_shards(Path(config['message_root']))
        if not shards:
            raise MirrorError('onboarding_credential_source_unavailable')
        for shard in shards:
            before = _database_stamp(shard, root)
            if before is None:
                raise MirrorError('onboarding_credential_source_changed')
            connection = _metadata_connection(shard, secret)
            connection.close()
            if _database_stamp(shard, root) != before:
                raise MirrorError('onboarding_credential_source_changed')
        if discover_numeric_shards(Path(config['message_root'])) != shards:
            raise MirrorError('onboarding_credential_source_changed')
    except (OSError, LiveReadonlyError, LiveCatalogError):
        raise MirrorError('onboarding_credentials_unavailable') from None


def _unchanged(profile, config):
    if scope.digest(load_source_config(profile, physical=False)) != scope.digest(config):
        raise MirrorError('onboarding_configuration_changed')


def _matches(args, config):
    from .source_setup import _db_storage_for
    storage, _ = _db_storage_for(args.account_root)
    if storage is None or str(storage.resolve()) != config['live_db_root']:
        raise MirrorError('onboarding_source_conflict')
    if _confirmed_self_username(config) != args.confirm_self_username:
        raise MirrorError('onboarding_identity_conflict')
    expected_mode = 'account' if args.account_scope else 'selected'
    if scope.mode(config) != expected_mode or (expected_mode == 'selected' and set(config['mirror_scope']) != set(args.mirror_scope)):
        raise MirrorError('onboarding_scope_conflict')
    if args.timezone is not None and config.get('query_timezone') != args.timezone:
        raise MirrorError('onboarding_timezone_conflict')
    if args.passphrase_file is not None and str(args.passphrase_file.expanduser().resolve()) != config['passphrase_file']:
        raise MirrorError('onboarding_credential_conflict')
    if args.data_home is not None:
        expected = args.data_home.expanduser().resolve() / 'wechat-local' / 'native-mirrors' / config['account_id'] / config['source_generation']
        if str(expected) != config['mirror_root']:
            raise MirrorError('onboarding_destination_conflict')


def start(args, *, configure):
    phase = 'confirmation'
    report = dict(status='onboarding_failed', stage=phase, background_enabled=None, background_enable_attempted=False,
                  sync_health='not_observed', history_complete=None)
    if not args.confirmed:
        return dict(report, status='onboarding_confirmation_required')
    if (args.account_root is None or not args.confirm_self_username or args.replace_self_identity
            or (args.account_scope and args.mirror_scope) or (not args.account_scope and not args.mirror_scope)):
        return dict(report, status='onboarding_arguments_invalid')
    try:
        _validate_self_username(args.confirm_self_username)
        if args.mirror_scope:
            from .source_setup import _validate_mirror_username
            if len(set(args.mirror_scope)) != len(args.mirror_scope):
                raise MirrorError('mirror_scope_invalid')
            for username in args.mirror_scope:
                _validate_mirror_username(username)
                if username == '*':
                    raise MirrorError('mirror_scope_invalid')
        profile = (args.config or Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'wechat-local/current-source.json').expanduser().absolute()
        phase = 'configuration'
        # Reject source-contained output before creating even the setup lock.
        from .source_setup import _db_storage_for, _contained
        storage, error = _db_storage_for(args.account_root)
        if storage is None:
            return dict(report, stage=phase, configuration=error)
        source_root = storage.parent
        output_data = (args.data_home or Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local/share'))).expanduser().resolve()
        if _contained(profile.resolve(), source_root):
            raise MirrorError('config_must_be_outside_account_root')
        if _contained(output_data, source_root):
            raise MirrorError('data_home_must_be_outside_account_root')
        with _exclusive(profile):
            phase = 'configuration'
            if profile.exists() or profile.is_symlink():
                config = load_source_config(profile)
                _matches(args, config)
                creation_id = _account_creation(args, profile, output_data) if args.account_scope else None
                created_by_onboarding = creation_id is not None and creation_id == config.get('scope_contract_id')
                report['configuration'] = dict(status='reused')
                phase = 'credential_validation'
                _validate_credentials(config)
                report['credential_validation'] = dict(status='verified')
            else:
                creation_id = _account_creation(args, profile, output_data, create=True) if args.account_scope else None
                args._onboarding_contract_id = creation_id
                created_by_onboarding = creation_id is not None
                if args.passphrase_file is None:
                    args.acquire_passphrase = True
                result = configure()
                report['configuration'] = result
                if result['status'] not in ('configured', 'configured_with_voice_incomplete'):
                    return dict(report, stage=phase)
                config = load_source_config(profile)
                _matches(args, config)
            phase = 'initialization'
            _unchanged(profile, config)
            from . import native_follow
            # An enabled policy must be inspected by the original enable path;
            # never run a concurrent foreground init against its active writer.
            prior = native_follow.status(profile)
            report['background_enabled'] = prior.get('enabled')
            if scope.mode(config) == 'account':
                report['initialization'] = {}
                result = initialize_account(config, profile, progress=report['initialization'],
                    previously_configured=prior.get('policy_generation') is not None,
                    created_by_onboarding=created_by_onboarding)
                report['initialization'] = result
            elif not prior.get('enabled'):
                from .native_deadline import Deadline, activate_deadline
                from .native_mirror_sync import sync_once
                with activate_deadline(Deadline.create(30)):
                    result = sync_once(config, config['mirror_scope'], initialize=True, capture_media=False)
                report['initialization'] = result
                if result.get('gaps'):
                    return dict(report, stage=phase)
            else:
                report['initialization'] = dict(status='preserved_existing_copy')
            phase = 'background_enable'
            _unchanged(profile, config)
            executable = Path(sys.executable).parent / 'wechat-local-sync'
            report['background_enable_attempted'] = True
            report['background_enabled'] = None  # enable may partially register before failing
            report['background'] = native_follow.enable(config, profile, executable)
            phase = 'observation'
            report['background_enabled'] = report['background'].get('enabled', False)
            report['sync_health'] = report['background'].get('state', 'unknown')
            from .native_mirror_cli import mirror_status
            report['coverage'] = mirror_status(config)
            report['history_complete'] = report['background'].get('observed_catchup_complete')
            if report['coverage'].get('prior_coverage_unknown'):
                report.update(prior_coverage_unknown=True,history_complete=None)
            if not report['background_enabled'] or report['background'].get('listener_registration') != 'owned':
                return dict(report, stage=phase)
            return dict(report, status='onboarding_complete', stage='background_registered',
                        next_step='follow-status', final_completeness='not_promised')
    except KeyboardInterrupt:
        return dict(report, status='onboarding_cancelled', stage=phase)
    except (ValueError, OSError, MirrorError, sqlite3.Error, KeyError, TypeError) as error:
        if phase == 'background_enable':
            try:
                report['background'] = native_follow.status(profile)
                report['background_enabled'] = report['background'].get('enabled')
                report['sync_health'] = report['background'].get('state', 'unknown')
            except (ValueError, OSError, MirrorError, sqlite3.Error, KeyError, TypeError):
                report['background_enabled'] = None
        return dict(report, stage=phase, error=str(error) if isinstance(error, (SourceSetupError, MirrorError)) else type(error).__name__)
