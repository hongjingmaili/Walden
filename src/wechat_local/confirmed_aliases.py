"""Small private confirmed-target registry, independent of chat/event stores."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .contact_matching import normalize
from .live_readonly import readonly_database_uri

MAX_BYTES = 65536
MAX_ALIASES = 128
PENDING_SECONDS = 900


class AliasError(ValueError):
    """Fixed public reason only; never include private values or OS errors."""
    REASONS = frozenset(('alias_invalid', 'alias_target_invalid', 'alias_source_binding_unavailable',
        'alias_registry_location_invalid', 'alias_registry_unsafe', 'alias_registry_invalid',
        'alias_source_identity_unavailable', 'alias_source_binding_mismatch', 'alias_registry_unavailable',
        'alias_registry_full', 'alias_registry_changed', 'alias_commit_uncertain', 'alias_save_failed',
        'local_contacts_unavailable', 'contact_source_identity_mismatch', 'contact_snapshot_incomplete',
        'alias_target_type_mismatch', 'alias_target_unavailable', 'alias_pending_full',
        'explicit_confirmation_required', 'alias_confirmation_binding_invalid', 'alias_proposal_stale',
        'alias_source_identity_mismatch', 'alias_replace_required'))

    def __init__(self, reason):
        self.reason = reason if reason in self.REASONS else 'alias_registry_unavailable'
        super().__init__(self.reason)


def _alias(value):
    if (not isinstance(value, str) or not value.strip()
            or any(c in value for c in ('\n', '\r', '\x00'))
            or any(0xD800 <= ord(c) <= 0xDFFF for c in value)
            or len(value.encode('utf-8')) > 256 or len(normalize(value).encode('utf-8')) > 256):
        raise AliasError('alias_invalid')
    return normalize(value)


def _username(value):
    if (not isinstance(value, str) or not value or value.strip() != value
            or any(c.isspace() or ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
            or len(value.encode('utf-8')) > 512):
        raise AliasError('alias_target_invalid')
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def _absolute(value):
    if not isinstance(value, str) or not os.path.isabs(value):
        raise AliasError('alias_source_binding_unavailable')
    return os.path.normpath(value)


def source_binding(profile):
    return _digest([profile['account_id'], profile['source_generation'],
                    _absolute(str(profile.get('live_db_root', profile['message_root']))),
                    _absolute(str(profile['message_root']))])


def _location(profile):
    account = profile.get('account_id')
    if not isinstance(account, str) or not account:
        raise AliasError('alias_source_binding_unavailable')
    base = Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share')))
    if not base.is_absolute():
        raise AliasError('alias_registry_location_invalid')
    root = Path(os.path.normpath(str(base))) / 'wechat-local/confirmed-aliases'
    for key in ('live_db_root', 'message_root'):
        value = profile.get(key)
        if value:
            source = Path(_absolute(str(value)))
            if source == root or source in root.parents or root in source.parents:
                raise AliasError('alias_registry_location_invalid')
    return root, hashlib.sha256(account.encode()).hexdigest()


def _check_parents(root, *, private=True):
    for parent in (root, *root.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise AliasError('alias_registry_unsafe')
    if private and root.exists():
        info = root.lstat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise AliasError('alias_registry_unsafe')


def _private(fd):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise AliasError('alias_registry_unsafe')
    return info


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise AliasError('alias_registry_invalid')
        result[key] = value
    return result


def _identity(value):
    if not isinstance(value, (list, tuple)) or len(value) != 2 or any(type(v) is not int or v < 0 for v in value):
        raise AliasError('alias_source_identity_unavailable')
    return tuple(value)


def _validate(state, account):
    if (not isinstance(state, dict) or type(state.get('version')) is not int or state['version'] != 1
            or state.get('account') != account or type(state.get('revision')) is not int or state['revision'] < 0
            or not isinstance(state.get('aliases'), dict) or len(state['aliases']) > MAX_ALIASES
            or not isinstance(state.get('pending'), dict) or len(state['pending']) > 16):
        raise AliasError('alias_registry_invalid')
    for key, entry in state['aliases'].items():
        if not isinstance(entry, dict) or _alias(entry.get('alias')) != key:
            raise AliasError('alias_registry_invalid')
        _entry(entry)
        if type(entry.get('confirmed_at')) is not int or entry['confirmed_at'] < 1:
            raise AliasError('alias_registry_invalid')
    for key, entry in state['pending'].items():
        if (not isinstance(key, str) or len(key) != 32 or any(c not in '0123456789abcdef' for c in key)
                or not isinstance(entry, dict) or type(entry.get('created_at')) is not int
                or type(entry.get('revision')) is not int):
            raise AliasError('alias_registry_invalid')
        _alias(entry.get('alias')); _entry(entry)
    return state


def _entry(entry):
    _username(entry.get('username'))
    if (entry.get('kind') not in ('private', 'group') or not isinstance(entry.get('source'), str)
            or len(entry['source']) != 64 or any(c not in '0123456789abcdef' for c in entry['source'])):
        raise AliasError('alias_registry_invalid')
    _identity(entry.get('source_identity'))


def _read(fd, filename, account):
    try:
        opened = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return dict(version=1, account=account, revision=0, aliases={}, pending={}), None
    try:
        if _private(opened).st_size > MAX_BYTES:
            raise AliasError('alias_registry_invalid')
        with os.fdopen(opened, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise AliasError('alias_registry_invalid')
        try:
            state = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)
        except (ValueError, UnicodeError, RecursionError):
            raise AliasError('alias_registry_invalid') from None
        return _validate(state, account), raw
    finally:
        os.close(opened)


@dataclass(frozen=True)
class AliasBinding:
    alias: str
    username: str
    kind: str
    source: str
    source_identity: tuple


@dataclass(frozen=True)
class AliasContext:
    revision: int
    source: str
    entries: tuple

    def lookup(self, query):
        key = normalize(query)
        for normalized, entry in self.entries:
            if normalized == key:
                if entry.source != self.source:
                    raise AliasError('alias_source_binding_mismatch')
                return entry
        return None


def load_alias_context(profile):
    root, account = _location(profile)
    try:
        _check_parents(root)
        if not root.exists():
            return AliasContext(0, source_binding(profile), ())
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            state, _ = _read(fd, account + '.json', account)
        finally:
            os.close(fd)
        entries = tuple((key, AliasBinding(e['alias'], e['username'], e['kind'], e['source'], _identity(e['source_identity']))) for key, e in state['aliases'].items())
        return AliasContext(state['revision'], source_binding(profile), entries)
    except OSError:
        raise AliasError('alias_registry_unavailable') from None


@contextmanager
def _locked(profile):
    root, account = _location(profile)
    directory = lock = None
    try:
        _check_parents(root)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _check_parents(root)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        lock = os.open(account + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        _private(lock)
        fcntl.flock(lock, fcntl.LOCK_EX)
        state, original = _read(directory, account + '.json', account)
        def commit():
            nonlocal original
            _validate(state, account)
            raw = (json.dumps(state, ensure_ascii=False, sort_keys=True) + '\n').encode()
            if len(raw) > MAX_BYTES:
                raise AliasError('alias_registry_full')
            temporary = '.alias-' + secrets.token_hex(16) + '.tmp'
            replaced = False
            temporary_identity = None
            try:
                opened = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                with os.fdopen(opened, 'wb') as stream:
                    info = os.fstat(stream.fileno())
                    temporary_identity = (info.st_dev, info.st_ino)
                    _private(stream.fileno()); stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                if _read(directory, account + '.json', account)[1] != original:
                    raise AliasError('alias_registry_changed')
                if (root.lstat().st_dev, root.lstat().st_ino) != (os.fstat(directory).st_dev, os.fstat(directory).st_ino):
                    raise AliasError('alias_registry_changed')
                info = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != temporary_identity:
                    raise AliasError('alias_registry_changed')
                os.replace(temporary, account + '.json', src_dir_fd=directory, dst_dir_fd=directory)
                replaced = True
                original = raw
                os.fsync(directory)
            except OSError:
                raise AliasError('alias_commit_uncertain' if replaced else 'alias_save_failed') from None
            finally:
                if not replaced and temporary_identity is not None:
                    try:
                        info = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
                        if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == temporary_identity:
                            os.unlink(temporary, dir_fd=directory)
                    except OSError:
                        pass
        yield state, commit
    except OSError:
        raise AliasError('alias_registry_unavailable') from None
    finally:
        if lock is not None: os.close(lock)
        if directory is not None: os.close(directory)


@contextmanager
def local_contact_snapshot(profile):
    """Read only committed native contacts, never the original source/key."""
    root = Path(os.path.abspath(str(profile.get('mirror_root', ''))))
    path = root / 'contact.db'
    connection = None
    try:
        for key in ('live_db_root', 'message_root'):
            if profile.get(key):
                source = Path(_absolute(str(profile[key])))
                if root == source or source in root.parents or root in source.parents:
                    raise AliasError('local_contacts_unavailable')
        try:
            _check_parents(root, private=False)
        except AliasError:
            raise AliasError('local_contacts_unavailable') from None
        if not profile.get('mirror_root') or path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise AliasError('local_contacts_unavailable')
        connection = sqlite3.connect(readonly_database_uri(path), uri=True)
        connection.execute('PRAGMA query_only=ON'); connection.execute('BEGIN')
        if connection.execute('SELECT * FROM __walden_binding').fetchall() != [(profile['account_id'], profile['source_generation'], 'contact.db')]:
            raise AliasError('contact_source_identity_mismatch')
        progress = connection.execute("SELECT value FROM __walden_progress WHERE table_name='contact'").fetchone()
        state = json.loads(progress[0]) if progress else {}
        if not isinstance(state, dict) or type(state.get('checked_at')) is not int or state['checked_at'] < 1:
            raise AliasError('contact_snapshot_incomplete')
        yield connection, state
    except (sqlite3.Error, OSError, ValueError, TypeError) as error:
        if isinstance(error, AliasError): raise
        raise AliasError('contact_snapshot_incomplete') from None
    finally:
        if connection is not None: connection.close()


def _target(connection, username, kind, alias):
    _username(username)
    if kind not in ('private', 'group') or (kind == 'group') != username.endswith('@chatroom') or username.startswith('gh_'):
        raise AliasError('alias_target_type_mismatch')
    try:
        rows = connection.execute('SELECT username,alias,remark,nick_name FROM contact WHERE username=? LIMIT 2', (username,)).fetchall()
        shadow = connection.execute('SELECT username FROM contact WHERE username COLLATE NOCASE IN (?,?) LIMIT 2', (alias, normalize(alias))).fetchall()
    except sqlite3.Error:
        raise AliasError('alias_target_unavailable') from None
    if len(rows) != 1 or rows[0][0] != username or any(r[0] != username for r in shadow):
        raise AliasError('alias_target_invalid')
    return next((v.strip() for v in (rows[0][2], rows[0][3], rows[0][1]) if isinstance(v, str) and v.strip()), username)


def propose_alias(profile, alias, username, kind='private'):
    key = _alias(alias)
    with local_contact_snapshot(profile) as (connection, progress):
        label = _target(connection, username, kind, alias)
        identity = _identity(progress.get('source_identity'))
        with _locked(profile) as (state, commit):
            now = int(time.time())
            state['pending'] = {k:v for k,v in state['pending'].items() if 0 <= now - v['created_at'] <= PENDING_SECONDS and normalize(v['alias']) != key}
            if len(state['pending']) >= 16:
                raise AliasError('alias_pending_full')
            token = secrets.token_hex(16)
            state['pending'][token] = dict(alias=alias, username=username, kind=kind, source=source_binding(profile), source_identity=list(identity), created_at=now, revision=state['revision'], label=label)
            commit()
    return dict(status='awaiting_confirmation', proposal_id=token, alias=alias, username=username, target_label=label)


def confirm_alias(profile, alias, username, proposal_id, *, confirmed=False, replace=False, expected_username=None):
    key = _alias(alias)
    if not confirmed:
        raise AliasError('explicit_confirmation_required')
    with local_contact_snapshot(profile) as (connection, progress):
        with _locked(profile) as (state, commit):
            existing = state['aliases'].get(key)
            if (existing and existing.get('confirmation_id') == proposal_id
                    and existing['username'] == username and existing['source'] == source_binding(profile)
                    and _identity(existing['source_identity']) == _identity(progress.get('source_identity'))):
                _target(connection, username, existing['kind'], alias)
                # Verify actual state before retrying durability, not the old
                # operation blindly. No mapping/revision change is replayed.
                commit()
                return dict(status='confirmed', revision=state['revision'])
            pending = state['pending'].get(proposal_id)
            if not pending or normalize(pending['alias']) != key or pending['username'] != username or pending['source'] != source_binding(profile):
                raise AliasError('alias_confirmation_binding_invalid')
            if pending['revision'] != state['revision'] or not 0 <= int(time.time()) - pending['created_at'] <= PENDING_SECONDS:
                raise AliasError('alias_proposal_stale')
            if _identity(progress.get('source_identity')) != _identity(pending['source_identity']):
                raise AliasError('alias_source_identity_mismatch')
            if _target(connection, username, pending['kind'], alias) != pending['label']:
                raise AliasError('alias_proposal_stale')
            previous = state['aliases'].get(key)
            changed = previous is not None and any(previous[field] != pending[field] for field in ('username', 'source', 'kind', 'source_identity'))
            if changed and (not replace or expected_username != previous['username']):
                raise AliasError('alias_replace_required')
            if previous is None and len(state['aliases']) >= MAX_ALIASES:
                raise AliasError('alias_registry_full')
            state['aliases'][key] = {field:pending[field] for field in ('alias', 'username', 'kind', 'source', 'source_identity')}
            state['aliases'][key]['confirmed_at'] = int(time.time())
            state['aliases'][key]['confirmation_id'] = proposal_id
            state['revision'] += 1
            del state['pending'][proposal_id]
            commit()
    return dict(status='confirmed', revision=state['revision'])


def list_aliases(profile):
    context = load_alias_context(profile)
    return dict(status='ok', revision=context.revision, aliases=[dict(alias=e.alias, username=e.username, target_kind=e.kind, source_matches=e.source == context.source) for _, e in context.entries])


def remove_alias(profile, alias, *, expected_revision, confirmed=False):
    key = _alias(alias)
    if not confirmed: raise AliasError('explicit_confirmation_required')
    with _locked(profile) as (state, commit):
        if state['revision'] != expected_revision:
            raise AliasError('alias_registry_changed')
        if key in state['aliases']:
            if state['aliases'][key]['source'] != source_binding(profile):
                raise AliasError('alias_source_binding_mismatch')
            del state['aliases'][key]; state['revision'] += 1
        state['pending'] = {k:v for k,v in state['pending'].items() if normalize(v['alias']) != key}
        commit()
    return dict(status='removed', revision=state['revision'])
