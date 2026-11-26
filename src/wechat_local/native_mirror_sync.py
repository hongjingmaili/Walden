"""Bounded native history/tail synchronizer shared by foreground and scheduler."""
from __future__ import annotations

import fcntl
import hashlib
import os
import sqlite3
import time
from contextlib import contextmanager, closing
from pathlib import Path

from .common import quote_identifier as qi
from .source_records import SourceKey
from .source_catalog import discover_numeric_shards
from .live_identity import _username_for_table
from .live_readonly import open_encrypted_readonly, read_private_passphrase
from .source_schema import _table_columns
from .native_mirror_store import MirrorError, MirrorStore, lossless_text_rows
from . import native_table_cursor as cursor_recovery
from .native_deadline import check_deadline
from .failure_evidence import phase


def _validate_message_cursor(conn, table):
    """Only the verified positive INTEGER rowid alias supports this keyset."""
    columns = conn.execute('PRAGMA table_info(' + qi(table) + ')').fetchall()
    primary = [column for column in columns if column[5]]
    if (len(primary) != 1 or primary[0][1] != 'local_id'
            or primary[0][2].strip().upper() != 'INTEGER'
            or any(index[3] == 'pk' for index in conn.execute('PRAGMA index_list(' + qi(table) + ')'))):
        # INTEGER PRIMARY KEY DESC has a separate PK index and is not a rowid alias.
        raise MirrorError('unsupported_message_cursor')
    _table_columns(conn, table)
    minimum = conn.execute('SELECT min(local_id) FROM ' + qi(table)).fetchone()[0]
    if minimum is not None and (type(minimum) is not int or minimum <= 0):
        raise MirrorError('invalid_message_cursor_value')


def mirror_root(config, *, create=True):
    value = config.get('mirror_root')
    if not value:
        raise MirrorError('mirror_root_required')
    root = Path(value).resolve()
    source_value = config.get('live_db_root', config['message_root'])
    # Sync verifies physical separation. Offline reads must not inspect the
    # original source even to resolve symlinks; retain a lexical overlap guard.
    source = Path(source_value).resolve() if create else Path(os.path.abspath(source_value))
    if root == source or source in root.parents or root in source.parents:
        raise MirrorError('mirror_source_overlap')
    if create:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root, 0o700)
    return root


@contextmanager
def writer_lock(root, timeout=10):
    fd = os.open(root / '.writer.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    deadline = time.monotonic() + timeout
    try:
        while True:
            check_deadline()
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise MirrorError('sync_busy')
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        yield
    finally:
        os.close(fd)


def _persist_status(root, scope, gaps, *, observations=None):
    import json
    state_path = root / '__walden_status.db'
    descriptor = os.open(state_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)
    with sqlite3.connect(state_path) as status:
        status.execute('CREATE TABLE IF NOT EXISTS attempts(scope TEXT PRIMARY KEY,gaps TEXT)')
        for username in scope:
            status.execute('INSERT OR REPLACE INTO attempts VALUES(?,?)', (hashlib.sha256(username.encode()).hexdigest(), json.dumps(gaps)))
        if observations:
            status.execute('CREATE TABLE IF NOT EXISTS successful_observations(scope TEXT PRIMARY KEY,value TEXT NOT NULL)')
            for username, observation in observations.items():
                status.execute('INSERT OR REPLACE INTO successful_observations VALUES(?,?)', (hashlib.sha256(username.encode()).hexdigest(), json.dumps(observation, sort_keys=True)))


def _copy_indexes(connection, store, table):
    indexes = connection.execute("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL", (table,)).fetchall()
    for name, sql in indexes:
        if name.startswith('__walden_'):
            raise MirrorError('source_reserved_namespace')
        # Source SQLite has already parsed this one CREATE INDEX statement.
        # Verify it in a disposable clone of this table before applying it.
        with store.connect() as local:
            prior = local.execute('SELECT sql FROM sqlite_master WHERE name=?', (name,)).fetchone()
            if prior is not None:
                if prior != (sql,):
                    raise MirrorError('index_schema_changed')
                continue
            ddl = local.execute('SELECT sql FROM sqlite_master WHERE name=?', (table,)).fetchone()[0]
            with sqlite3.connect(':memory:') as probe:
                probe.execute(ddl)
                probe.execute(sql)
                if probe.execute("SELECT tbl_name FROM sqlite_master WHERE type='index' AND name=?", (name,)).fetchone() != (table,):
                    raise MirrorError('unsupported_index')
            local.execute(sql)


def _auxiliary_diagnostic(source_kind, stage, error):
    # Map both sqlite3 and SQLCipher exception hierarchies to fixed public
    # constants. Never serialize arbitrary class names or exception messages.
    allowed = frozenset(('PermissionError', 'FileNotFoundError', 'NotADirectoryError',
                         'OSError', 'MirrorError', 'OperationalError', 'IntegrityError',
                         'DatabaseError', 'InterfaceError', 'ProgrammingError',
                         'DataError', 'NotSupportedError', 'KeyError', 'ValueError',
                         'TypeError', 'LiveReadonlyError', 'SourceKeyVerificationError'))
    kind = next((cls.__name__ for cls in type(error).__mro__ if cls.__name__ in allowed), 'OtherError')
    try:
        code = getattr(error, 'sqlite_errorcode', None)
    except Exception:
        code = None
    if type(code) is not int or not 0 <= code <= 2147483647:
        code = None
    return dict(source_kind=source_kind, stage=stage, exception_type=kind, sqlite_errorcode=code)


def _os_failure(result, stage, object_alias, error):
    """Public metadata only; neither paths nor exception values are retained."""
    if not isinstance(error, OSError):
        return
    from .failure_evidence import capture, _current
    allowed_stages = {'writer_lock', 'read_credential', 'stat', 'discover', 'read_header',
        'open_database', 'read_database', 'write_mirror', 'close_database', 'persist_status',
        'capture_media', 'resolve', 'open', 'readonly', 'begin', 'read_rows', 'schema_list',
        'schema_guard', 'store_bind', 'ensure_table', 'copy_indexes', 'apply_rows', 'commit'}
    aliases = {'mirror_writer', 'credential', 'message_root', 'message_shard', 'mirror_status',
               'contact_source', 'session_source', 'image_source', 'media_source'}
    try:
        code = error.errno
    except Exception:
        code = None
    code = code if type(code) is int and 0 <= code <= 2147483647 else None
    # Every caught OSError adds a gap: both formal sync/window entries return 1.
    # Persist that known terminal fact before any diagnostic can claim saved.
    ident = capture(error, exit_code=1)
    task = _current.get()
    event = dict(stage=stage if stage in allowed_stages else 'unknown',
                 object_alias=object_alias if object_alias in aliases else 'unknown', errno=code,
                 error_id=ident, evidence_status='unavailable' if not ident else
                 'partial' if task['missing_events'] else 'saved',
                 next_step='check_os_access_for_actual_runtime' if code in (1, 13) else
                 'check_bound_source_location' if code == 2 else 'inspect_error_id')
    result.setdefault('failure_diagnostics', []).append(event)
    if ident:
        result['error_id'] = ident


def _sender_mapping_matches(old, row, columns):
    """Keep exact typed identities; only known is_session int/NULL is mutable."""
    if len(old) != len(row) or len(row) != len(columns) + 1:
        return False
    metadata_index = 2 if columns == [('user_name', 'TEXT'), ('is_session', 'INTEGER')] else None
    for index, (prior, current) in enumerate(zip(old, row)):
        if type(prior) is type(current) and prior == current:
            continue
        if index == metadata_index and all(value is None or type(value) is int for value in (prior, current)):
            continue
        return False
    return True


def sync_once(config, scope, *, initialize=False, connection_factory=None, media_request=None, capture_media=True):
    check_deadline()
    started = time.monotonic()
    from .native_scope_contract import mode,query_scope_guard
    scope_token=query_scope_guard(config)
    if mode(config)=='account':return _account_sync(config,connection_factory=connection_factory)
    authorized = config.get('mirror_scope', [])
    if not scope or not set(scope).issubset(authorized):
        raise MirrorError('scope_not_authorized')
    root = mirror_root(config)
    result = dict(sources=[], gaps=[], source_opens=0, rows_read=0, rows_written=0, elapsed_seconds=0)
    failure_stage, failure_object = 'writer_lock', 'mirror_writer'
    try:
        with writer_lock(root, float(config.get('mirror_lock_timeout', 10))):
            query_scope_guard(config,scope_token)
            if connection_factory is None:
                check_deadline()
                failure_stage, failure_object = 'read_credential', 'credential'
                secret = read_private_passphrase(Path(config['passphrase_file']))
                connection_factory = lambda path: open_encrypted_readonly(path, secret)[0]
            for field, filename, source_kind in (('encrypted_contact_database', 'contact.db', 'contact'), ('session_database', 'session.db', 'session'), ('image_database', 'image-resources.db', 'image')):
                if field == 'image_database' or not config.get(field):
                    continue
                check_deadline()
                auxiliary = None
                auxiliary_stage = 'resolve'
                try:
                    auxiliary_path = Path(config[field]).resolve()
                    source_root = Path(config.get('live_db_root', config['message_root'])).resolve()
                    if source_root not in auxiliary_path.parents:
                        raise MirrorError('auxiliary_source_outside_root')
                    auxiliary_stage = 'stat'
                    auxiliary_stamp = auxiliary_path.stat()
                    auxiliary_identity = [auxiliary_stamp.st_dev, auxiliary_stamp.st_ino]
                    auxiliary_stage = 'open'
                    check_deadline()
                    phase('source_open','auxiliary_source')
                    auxiliary = connection_factory(auxiliary_path)
                    check_deadline()
                    result['source_opens'] += 1
                    phase('source_read','auxiliary_source')
                    auxiliary_stage = 'readonly'
                    if auxiliary.execute('PRAGMA query_only').fetchone() != (1,):
                        raise MirrorError('source_not_readonly')
                    auxiliary_stage = 'begin'
                    auxiliary.execute('BEGIN')
                    # A UTF-16 database can transcode TEXT before text_factory
                    # sees it. Reject it before creating any target tables;
                    # decoded strings alone cannot prove original byte identity.
                    auxiliary_stage = 'read_rows'
                    if auxiliary.execute('PRAGMA encoding').fetchone() != ('UTF-8',):
                        raise MirrorError('unsupported_auxiliary_encoding')
                    auxiliary_stage = 'schema_list'
                    tables = auxiliary.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
                    auxiliary_stage = 'schema_guard'
                    if any(name.startswith('__walden_') for name, _ in tables):
                        raise MirrorError('source_reserved_namespace')
                    snapshots = []
                    for name, ddl in tables:
                        auxiliary_stage = 'store_bind'
                        source = SourceKey(config['account_id'], config['source_generation'], filename, name)
                        store = MirrorStore(root / filename, source)
                        previous = store.progress(name)
                        auxiliary_stage = 'stat'
                        current_stamp = auxiliary_path.stat()
                        if (previous is not None and previous.get('source_identity') != auxiliary_identity) or [current_stamp.st_dev, current_stamp.st_ino] != auxiliary_identity:
                            raise MirrorError('auxiliary_source_replaced')
                        auxiliary_stage = 'ensure_table'
                        store.ensure_table(source, ddl)
                        auxiliary_stage = 'copy_indexes'
                        _copy_indexes(auxiliary, store, name)
                        auxiliary_stage = 'read_rows'
                        with lossless_text_rows(auxiliary):
                            rows = auxiliary.execute('SELECT rowid,* FROM ' + qi(name)).fetchall()
                        result['rows_read'] += len(rows)
                        snapshots.append((source, name, rows))
                    if snapshots:
                        auxiliary_written = 0
                        auxiliary_stage = 'apply_rows'
                        with store.connect() as transaction:
                            for source, name, rows in snapshots:
                                auxiliary_written += store.apply_batch(source, name, rows, {'checked_at': int(time.time()), 'source_identity': auxiliary_identity}, replace_snapshot=True, _connection=transaction)
                            auxiliary_stage = 'commit'
                        result['rows_written'] += auxiliary_written
                except Exception as error:
                    check_deadline()
                    result['gaps'].append('auxiliary_source_replaced' if isinstance(error,MirrorError)
                        and str(error)=='auxiliary_source_replaced' else 'auxiliary_source_unavailable_or_unsupported')
                    result.setdefault('auxiliary_diagnostics', []).append(_auxiliary_diagnostic(source_kind, auxiliary_stage, error))
                    _os_failure(result, auxiliary_stage, source_kind + '_source', error)
                finally:
                    if auxiliary is not None:
                        failure_stage, failure_object = 'close_database', source_kind + '_source'
                        auxiliary.close()
            check_deadline()
            observation_id = os.urandom(16).hex()
            source_roster = {username: {} for username in scope}
            message_gap_start = len(result['gaps'])
            failure_stage, failure_object = 'stat', 'message_root'
            roster_stamp = Path(config['message_root']).stat()
            failure_stage = 'discover'
            paths = discover_numeric_shards(Path(config['message_root']))
            if not paths:
                result['gaps'].append('source_unavailable')
            expected_shards = {p.name for p in root.glob('message_*.db')} | {p.name for p in root.glob('biz_message_*.db')}
            if expected_shards - {p.name for p in paths}:
                result['gaps'].append('source_shard_missing')
            for path in paths:
                check_deadline()
                conn = None
                try:
                    failure_stage, failure_object = 'stat', 'message_shard'
                    stamp = path.stat()
                    identity = [stamp.st_dev, stamp.st_ino]
                    check_deadline()
                    failure_stage = 'read_header'
                    with path.open('rb') as header:
                        header_hash = hashlib.sha256(header.read(16)).hexdigest()
                    if (root / path.name).is_file():
                        for username in scope:
                            old_table = 'Msg_' + hashlib.md5(username.encode()).hexdigest()
                            old_key = SourceKey(config['account_id'], config['source_generation'], path.name, old_table)
                            previous = MirrorStore(root / path.name, old_key).progress(old_table)
                            if previous and previous.get('source_header_sha256') != header_hash:
                                raise MirrorError('source_replaced')
                    check_deadline()
                    failure_stage = 'open_database'
                    phase('source_open','message_source')
                    conn = connection_factory(path)
                    check_deadline()
                    result['source_opens'] += 1
                    failure_stage = 'stat'
                    current = path.stat()
                    if [current.st_dev, current.st_ino] != identity:
                        raise MirrorError('source_replaced')
                    failure_stage = 'read_database'
                    phase('source_read','message_source')
                    if conn.execute('PRAGMA query_only').fetchone() != (1,):
                        raise MirrorError('source_not_readonly')
                    conn.execute('BEGIN')
                    schema = dict(conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"))
                    if any(name.startswith('__walden_') for name in schema):
                        raise MirrorError('source_reserved_namespace')
                    for username in scope:
                        check_deadline()
                        table = 'Msg_' + hashlib.md5(username.encode()).hexdigest()
                        source_roster[username][path.name] = table in schema
                        if table not in schema:
                            if (root / path.name).is_file():
                                missing_key = SourceKey(config['account_id'], config['source_generation'], path.name, table)
                                if MirrorStore(root / path.name, missing_key).progress(table) is not None:
                                    raise MirrorError('source_table_missing')
                            continue
                        _validate_message_cursor(conn, table)
                        if _username_for_table(conn, table) != username:
                            raise MirrorError('conversation_identity_conflict')
                        key = SourceKey(config['account_id'], config['source_generation'], path.name, table)
                        failure_stage = 'write_mirror'
                        store = MirrorStore(root / path.name, key)
                        store.ensure_table(key, schema[table])
                        _copy_indexes(conn, store, table)
                        failure_stage = 'read_database'
                        maximum = conn.execute('SELECT coalesce(max(local_id),0) FROM ' + qi(table)).fetchone()[0]
                        progress = store.progress(table)
                        media_prior = dict(progress) if progress is not None else None
                        if progress is None:
                            if not initialize and not (root / '__walden_status.db').is_file():
                                raise MirrorError('initialization_required')
                            progress = dict(H=maximum, history=0, tail=maximum, source_identity=identity, source_header_sha256=header_hash)
                        if progress['source_identity'] != identity:
                            raise MirrorError('source_replaced')
                        if maximum < progress['tail'] or maximum < progress['H']:
                            raise MirrorError('source_cursor_regression')
                        # Identity row numbers are immutable within this source generation.
                        namekey = SourceKey(key.account_id, key.source_generation, key.shard_name, 'Name2Id')
                        store.ensure_table(namekey, schema['Name2Id'])
                        name_columns = [(item[1], item[2].upper()) for item in conn.execute('PRAGMA table_info(Name2Id)')]
                        names = conn.execute('SELECT rowid,* FROM Name2Id').fetchall()
                        with store.connect() as local:
                            for row in names:
                                old = local.execute('SELECT rowid,* FROM Name2Id WHERE rowid=?', (row[0],)).fetchone()
                                if old is not None and not _sender_mapping_matches(old, row, name_columns):
                                    raise MirrorError('sender_identity_conflict')
                        phase('mirror_commit')
                        result['rows_written'] += store.apply_batch(namekey, 'Name2Id', names, {})
                        batch = int(config.get('mirror_batch_size', 500))
                        if batch < 1:
                            raise MirrorError('invalid_batch_size')
                        phase('source_read','message_source')
                        history = conn.execute('SELECT rowid,* FROM ' + qi(table) + ' WHERE local_id>? AND local_id<=? ORDER BY local_id LIMIT ?', (progress['history'], progress['H'], batch)).fetchall()
                        columns = [r[1] for r in conn.execute('PRAGMA table_info(' + qi(table) + ')')]
                        local_index = columns.index('local_id') + 1
                        if history:
                            progress['history'] = history[-1][local_index]
                        tail = conn.execute('SELECT rowid,* FROM ' + qi(table) + ' WHERE local_id>? AND local_id<=? ORDER BY local_id LIMIT ?', (progress['tail'], maximum, batch)).fetchall()
                        if tail:
                            progress['tail'] = tail[-1][local_index]
                        now = int(config.get('mirror_now', time.time()))
                        recent = conn.execute('SELECT rowid,* FROM ' + qi(table) + ' WHERE create_time>=? AND local_id<=?', (now - 86400, maximum)).fetchall()
                        progress.update(history_complete=progress['history'] >= progress['H'], checked_at=now, rechecked_since=now - 86400, target=maximum)
                        # Validate the whole supported time domain, not only rows that
                        # happened to pass the recent predicate (NULL sorts outside it).
                        bad_time = conn.execute('SELECT 1 FROM ' + qi(table) + " WHERE local_id<=? AND (typeof(create_time)!='integer' OR create_time<0 OR create_time>?) LIMIT 1", (maximum, now)).fetchone()
                        members = [row[local_index] for row in recent]
                        progress['recent_observation'] = dict(version=1, observation_id=observation_id, since=now-86400, through=now, timestamp_integrity=bad_time is None, member_local_ids=members if len(members)<=20000 else None)
                        rows = history + tail + recent
                        result['rows_read'] += len(rows) + len(names)
                        failure_stage = 'stat'
                        current = path.stat()
                        if [current.st_dev, current.st_ino] != identity:
                            raise MirrorError('source_replaced')
                        failure_stage = 'write_mirror'
                        phase('mirror_commit')
                        result['rows_written'] += store.apply_batch(key, table, rows, progress)
                        # Persist only small local queue records; media failures do not turn a completed message observation into failure.
                        try:
                            from .native_media_work import enqueue_rows
                            arrival=None
                            if (media_prior is not None and type(media_prior.get('target'))is int
                                    and media_prior['tail']==media_prior['target'] and tail
                                    and type(media_prior.get('checked_at'))is int
                                    and 0<=media_prior['checked_at']<now):
                                arrival=dict(kind='tail_increment',before_tail=media_prior['tail'],prior_max=media_prior['target'],
                                             through_tail=progress['tail'],prior_checked_at=media_prior['checked_at'],observed_at=now)
                            enqueue_rows(config,path.name,table,username,columns,rows,**({'arrival':arrival}if arrival else{}))
                        except Exception:
                            check_deadline();result.setdefault('media_gaps',[]).append('media_enqueue_pending')
                            try:
                                from .native_media_work import mark_enqueue_repair
                                mark_enqueue_repair(config,path.name,table,min(row[0] for row in rows)-1)
                            except Exception:check_deadline()
                        result['sources'].append(dict(shard=path.name, table=table, **{name: value for name, value in progress.items() if name != 'recent_observation'}))
                except Exception as error:
                    check_deadline()
                    result['gaps'].append(str(error) if isinstance(error, MirrorError) else 'source_unavailable_or_unsupported')
                    _os_failure(result, failure_stage, failure_object, error)
                finally:
                    if conn is not None:
                        failure_stage = 'close_database'
                        conn.close()
            observations = None
            failure_stage, failure_object = 'discover', 'message_root'
            final_paths = discover_numeric_shards(Path(config['message_root']))
            failure_stage = 'stat'
            final_stamp = Path(config['message_root']).stat()
            roster_identity = lambda stamp: (stamp.st_dev, stamp.st_ino, stamp.st_mtime_ns, stamp.st_ctime_ns)
            if [p.name for p in paths] != [p.name for p in final_paths] or roster_identity(roster_stamp) != roster_identity(final_stamp):
                result['gaps'].append('source_roster_changed')
            if paths and not result['gaps'][message_gap_start:]:
                observations = {username: dict(version=1, observation_id=observation_id,
                    account_id=config['account_id'], source_generation=config['source_generation'],
                    message_root=str(Path(config['message_root']).resolve()),
                    source_roster=source_roster[username], atomic_global_snapshot=False)
                    for username in scope}
            # Publish this attempt before freezing its one selected window, so an
            # old failure cannot contaminate the successful refresh's response.
            query_scope_guard(config,scope_token)
            failure_stage, failure_object = 'persist_status', 'mirror_status'
            _persist_status(root, scope, result['gaps'], observations=observations)
            if not capture_media:
                watermarks = [{key: source[key] for key in ('shard','table','H','history','tail','target')} for source in result['sources']]
                roster_count = sum(sum(bool(found) for found in tables.values()) for tables in source_roster.values())
                covered = all(any(tables.values()) for tables in source_roster.values())
                reliable = bool(observations and covered and not result['gaps'] and len(watermarks) == roster_count)
                backlog = any(row['history'] < row['H'] or row['tail'] < row['target'] for row in watermarks)
                result['follow_observation'] = dict(observation_id=observation_id,
                    complete=(not backlog) if reliable else None, known_backlog=backlog,
                    watermarks=watermarks if reliable else [], atomic_global_snapshot=False,
                    final_completeness='not_promised')
            check_deadline()
            failure_stage, failure_object = 'capture_media', 'media_source'
            # Media capture/decode/transcription belongs to the separate owned worker.
            # Explicit refresh returns currently cached local results, including pending.
            if media_request is not None:
                from .native_mirror_query import query_local
                result['media_window']=query_local(config,media_request)
            query_scope_guard(config,scope_token)
            failure_stage, failure_object = 'persist_status', 'mirror_status'
            _persist_status(root, scope, result['gaps'])
    except (MirrorError, OSError) as error:
        _os_failure(result, failure_stage, failure_object, error)
        result['gaps'].append(str(error) if isinstance(error, MirrorError) else 'source_unavailable')
        if str(error) != 'sync_busy':
            repair_stage, repair_object = 'writer_lock', 'mirror_writer'
            try:
                with writer_lock(root, 0):
                    query_scope_guard(config,scope_token)
                    repair_stage, repair_object = 'persist_status', 'mirror_status'
                    _persist_status(root, scope, result['gaps'])
            except (MirrorError, OSError) as repair_error:
                _os_failure(result, repair_stage, repair_object, repair_error)
                pass  # A current writer owns the next authoritative attempt state.
    if not result['sources'] and not result['gaps']:
        result['gaps'].append('scope_not_found')
    query_scope_guard(config,scope_token)
    result['elapsed_seconds'] = time.monotonic() - started
    return result


from .failure_evidence import _register
_register(_os_failure, _sender_mapping_matches, sync_once)


def _account_budget(config):
    limits={}
    for key,default,maximum in [('tables',256,2048),('rows',2000,50000),('bytes',8*1024*1024,64*1024*1024),('shards',4,64),('inventory',256,4096)]:
        value=config.get('mirror_account_'+key,default)
        if type(value) is not int or not 1<=value<=maximum:raise MirrorError('account_budget_invalid')
        limits[key]=value
    started=time.monotonic()
    limits.update(started=started,until=started+20.,used_rows=0,used_bytes=0,used_tables=0)
    return limits


def _account_registry_commit(conn,*,config=None,budget=None):
    """Classify only this exact local registry operation; never Source errors."""
    try:
        if config is None:conn.commit()
        else:
            from .native_registry_reuse import commit
            commit(config,conn,budget=budget)
    except sqlite3.Error as error:
        if isinstance(error,sqlite3.OperationalError) and str(error) in ('database is locked','database table is locked'):raise MirrorError('local_registry_commit_busy') from None
        raise MirrorError('local_registry_commit_failed') from None


def _account_sqlite_types():
    errors=[sqlite3.Error];operational=[sqlite3.OperationalError]
    try:
        from sqlcipher3 import dbapi2 as cipher
    except ImportError:
        pass
    else:
        errors.append(cipher.Error);operational.append(cipher.OperationalError)
    return tuple(errors),tuple(operational)


def _account_error_info(error,stage):
    """Fixed metadata only: no exception strings, args, SQL or object paths."""
    errors,operational=_account_sqlite_types()
    family=('sqlite_operational' if isinstance(error,operational) else
            'sqlite_database' if isinstance(error,errors) else
            'os_error' if isinstance(error,OSError) else
            'guard' if isinstance(error,MirrorError) else
            'python_name' if isinstance(error,NameError) else
            'python_type' if isinstance(error,TypeError) else
            'python_value' if isinstance(error,ValueError) else 'unexpected')
    primary=None;extended=None;errno=None;seen=set();current=error;phase='unknown';commit_state='unknown'
    phases={'source_max','source_columns','source_candidates','source_rows','source_indexes','sender_schema','sender_rows','local_open','local_schema','local_progress','local_prepare','local_write','local_commit_prepare','local_commit','local_commit_revalidate','registry_commit_prepare','registry_commit','registry_commit_revalidate','copy_guard'}
    # Only fixed enums from the actual known copy/transaction code. No frame
    # text, SQL, parameters, filenames or exception strings enter the evidence.
    modules={'native_mirror_sync','native_mirror_store','native_account_witness'}
    functions={'_account_sync','_account_copy_table','_account_source_read','apply_batch','commit'}
    for _ in range(4):
        if not isinstance(current,BaseException) or id(current) in seen:break
        seen.add(id(current))
        if isinstance(current,errors):
            value=getattr(current,'sqlite_errorcode',None)
            if primary is None and type(value) is int and 0<value<=0x7fffffff:
                primary=value&255;extended=value
        if isinstance(current,OSError):
            value=current.errno
            if errno is None and type(value) is int and 0<=value<=2147483647:errno=value
        try:
            tb=current.__traceback__
            for index in range(32):
                if tb is None:break
                frame=tb.tb_frame
                if frame.f_globals.get('__name__') in {__package__+'.'+name for name in modules} and frame.f_code.co_name in functions:
                    value=frame.f_locals.get('_diagnostic_stage')
                    if type(value) is str and value in phases:phase=value
                    if frame.f_locals.get('_diagnostic_committed') is True:commit_state='physical_commit_returned'
                tb=tb.tb_next
        except Exception:pass  # A diagnostic must never replace the error.
        current=current.__cause__
    stages={'source_open','source_probe','source_copy','inventory','registry','mirror','stat','unknown'}
    result=dict(stage=stage if stage in stages else 'unknown',exception_family=family,sqlite_primary_code=primary,errno=errno)
    if phase!='unknown':result.update(operation_phase=phase,commit_state=commit_state)
    if extended is not None:result['sqlite_extended_code']=extended
    return result


def _account_busy(error):
    errors,_=_account_sqlite_types();seen=set()
    for _ in range(4):
        if not isinstance(error,errors) or id(error) in seen:return False
        seen.add(id(error));code=getattr(error,'sqlite_errorcode',None)
        if type(code) is not int or not 0<code<=0x7fffffff or code&255 not in (5,6):return False
        if error.__cause__ is None:return True
        error=error.__cause__
    return False


class _AccountShardBusy(MirrorError):
    """Raised only around a verified Source read, never a local registry write."""
    def __init__(self,error,stage):
        super().__init__('source_shard_retry_pending')
        self.diagnostic=_account_error_info(error,stage)


def _account_source_read(conn,sql,args=(),*,stage,phase='unknown'):
    _diagnostic_stage=phase
    # Call sites follow the original anchor/proof/query_only/BEGIN guards.
    try:return conn.execute(sql,args)
    except Exception as error:
        if conn.in_transaction and _account_busy(error):
            raise _AccountShardBusy(error,stage) from error
        raise


def _account_retry_clock():
    from .native_deadline import continuous_ns
    return time.time(),continuous_ns()


def _account_retry_state(config,registry,shard,grant):
    from . import native_scope_contract as sc
    value=sc.state(registry,'source_retry:'+shard)
    if value is None:return None
    expected=dict(source_sha256=grant['source_sha256'],anchor=sc.state(registry,'shard_anchor:'+shard))
    if (type(value) is not dict or value.get('schema')!='walden.source.shard.retry/1'
            or value.get('binding')!=expected or type(value.get('primary_code')) is not int
            or value['primary_code'] not in (5,6) or type(value.get('attempt')) is not int or value['attempt']<1
            or type(value.get('schedule')) is not dict or value['schedule'].get('mode')!='backoff'):
        raise MirrorError('source_retry_binding')
    schedule=value['schedule']
    if any(type(schedule.get(key)) is not int or schedule[key]<0
           for key in ('next_due_at_ns','next_due_continuous_ns','backoff')):
        raise MirrorError('source_retry_binding')
    if value.get('policy_generation')!=grant.get('policy_generation'):
        from .native_follow_policy import Store
        generation=value.get('policy_generation')
        if type(generation) is not str or len(generation)!=32 or any(ch not in '0123456789abcdef' for ch in generation):
            raise MirrorError('source_retry_binding')
        store=Store(grant['store_root']);old=store.read('policy.'+generation+'.json')
        if (type(old) is not dict or old.get('generation')!=generation
                or old.get('store_root')!=str(store.root) or old.get('source_signature')!=grant['source_sha256']):
            raise MirrorError('source_retry_binding')
    return value


def _account_retry_ready(config,registry,shard,grant):
    from .native_follow_schedule import plan
    value=_account_retry_state(config,registry,shard,grant)
    if value is None:return True
    wall,tick=_account_retry_clock()
    return plan(value['schedule'],wall=wall,continuous=tick,interval=30)['due']


def _account_record_retry(config,registry,shard,grant,diagnostic):
    from . import native_scope_contract as sc
    from .native_follow_schedule import plan
    if any(type(grant.get(key)) is not str for key in ('source_sha256','policy_generation','instance_nonce','store_root')):
        raise MirrorError('source_retry_binding')
    prior=_account_retry_state(config,registry,shard,grant)
    attempt=1 if prior is None else prior['attempt']+1
    wall,tick=_account_retry_clock()
    done=dict(operation=grant['instance_nonce'],attempt=attempt,exit_code=1,
              completed_at_ns=int(wall*1e9),completed_at_continuous_ns=tick)
    schedule=plan(prior['schedule'] if prior else None,wall=wall,continuous=tick,interval=30,completion=done)
    sc.save(registry,'source_retry:'+shard,dict(schema='walden.source.shard.retry/1',
        binding=dict(source_sha256=grant['source_sha256'],anchor=sc.state(registry,'shard_anchor:'+shard)),
        policy_generation=grant['policy_generation'],primary_code=diagnostic['sqlite_primary_code'],
        attempt=attempt,schedule=schedule))


def _st_dev_renumber_proof(anchor, identity, header_hash):
    """Hard same-source proof, identical to native_scope_contract.stale_shards
    'renumber' classification: inode equal, header equal, ONLY st_dev differs.

    Also requires the exact canonical anchor shape so a malformed/None anchor is
    rejected (the caller still raises scope_source_conflict), never tolerated.
    Returns a bool; never raises on malformed input. Never weakens the proof:
    a differing inode or header is a real source change and returns False.
    """
    if not (isinstance(anchor, dict) and set(anchor) == {'source_identity', 'header'}):
        return False
    prior = anchor['source_identity']
    if (type(prior) is not list or len(prior) != 2
            or any(type(v) is not int for v in prior)):
        return False
    return (prior[1] == identity[1]              # inode unchanged
            and anchor['header'] == header_hash  # header unchanged
            and prior[0] != identity[0])         # ONLY st_dev differs


def _require_trigger_free(conn, alias):
    if conn.execute('SELECT 1 FROM ' + qi(alias) + ".sqlite_master WHERE type='trigger' LIMIT 1").fetchone():
        raise MirrorError('local_trigger_unsupported')


def _auto_reanchor_renumbered_shard(config, registry, path, anchor, identity, header_hash, *, budget=None,_qualified_check=None,_qualified_publish=None):
    """Atomically rebind the registry and existing mirror for one proved renumber."""
    import json
    from . import native_scope_contract as sc
    from .live_readonly import readonly_database_uri
    from .native_source_recovery import atomic_preflight, private

    shard = path.name
    anchor_key = 'shard_anchor:' + shard
    prior_identity = anchor['source_identity']
    prior_header = anchor['header']
    local_path = Path(config['mirror_root']) / shard
    try:
        local_path.lstat()
    except FileNotFoundError:
        local_identity = None
    else:
        local_identity = private(local_path)
        if local_identity == identity:
            raise MirrorError('local_source_overlap')

    def qualified_charge(size):
        if _qualified_check is not None:
            from .native_account_copy_init import charge
            charge(budget,size)
    def verify_source():
        check_deadline()
        if _qualified_check is not None:
            _qualified_check();qualified_charge(16)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as header:
                stamp = os.fstat(header.fileno())
                header_digest = hashlib.sha256(header.read(16)).hexdigest()
            current = path.lstat()
        except OSError as error:
            raise MirrorError('scope_source_conflict') from error
        if ([stamp.st_dev, stamp.st_ino] != identity
                or [current.st_dev, current.st_ino] != identity
                or header_digest != header_hash
                or not _st_dev_renumber_proof(anchor, identity, header_hash)):
            raise MirrorError('scope_source_conflict')

    verify_source()
    scope_token = sc.query_scope_guard(config)
    # Close the caller's earlier bookkeeping transaction. No reanchor state
    # has been written. The dedicated transaction below owns both databases.
    if registry.in_transaction:
        _account_registry_commit(registry,config=config,budget=budget)
    attached = False
    try:
        if local_identity is not None:
            uri = readonly_database_uri(local_path).replace('mode=ro', 'mode=rw')
            registry.execute('ATTACH DATABASE ? AS d1', (uri,))
            attached = True
        registry.execute('BEGIN IMMEDIATE')
        atomic_preflight(registry, ['main', 'd1'] if attached else ['main'])
        _require_trigger_free(registry, 'main')
        if sc.state(registry, anchor_key, None) != anchor:
            raise MirrorError('scope_source_conflict')
        if attached:
            _require_trigger_free(registry, 'd1')
            if private(local_path) != local_identity:
                raise MirrorError('local_replaced')
            binding = (config['account_id'], config['source_generation'], shard)
            if registry.execute('SELECT * FROM d1.__walden_binding').fetchall() != [binding]:
                raise MirrorError('source_identity_mismatch')
        elif local_path.exists() or local_path.is_symlink():
            raise MirrorError('local_replaced')

        proofs = []
        tables = []
        from collections import OrderedDict
        observation_cache=OrderedDict()
        for (table,) in registry.execute('SELECT table_name FROM members WHERE shard=?', (shard,)):
            check_deadline()
            proof = sc.member(config, registry, shard, table,_observations=observation_cache,_budget=budget if _qualified_check is not None else None)
            proofs.append((table, proof))
            tables.append([table, proof['schema_sha256']])

        observation = dict(contract=sc.fixed(config), shard=shard, source_identity=identity,
                           header=header_hash, query_only=True, schema_cookie=None,
                           at_ns=time.time_ns(), tables=tables)
        from . import native_registry_reuse as reuse
        # Plan and pay all qualified parameter outputs before any publication.
        # The original AUTO caller retains its previous resource behavior.
        planned_members=[];planned_progress=[]
        if _qualified_check is not None:
            expected_observation=sc.digest(observation)
            for table,proof in proofs:
                updated=dict(proof,source_identity=identity,header=header_hash,observation=expected_observation)
                raw=json.dumps(updated,sort_keys=True)
                qualified_charge(len(raw.encode())+len(shard.encode())+len(table.encode()));planned_members.append((raw,shard,table))
            if attached:
                for table,size in registry.execute('SELECT table_name,length(CAST(value AS BLOB)) FROM d1.__walden_progress'):
                    check_deadline();qualified_charge(len(table.encode())+8+size)
                    raw=registry.execute('SELECT value FROM d1.__walden_progress WHERE table_name=?',(table,)).fetchone()[0]
                    if len(raw.encode())!=size:raise MirrorError('scope_copy_proof')
                    progress=json.loads(raw)
                    if table=='Name2Id':
                        if progress!={}:raise MirrorError('scope_copy_proof')
                        continue
                    if (not isinstance(progress,dict)or progress.get('source_identity')!=prior_identity or progress.get('source_header_sha256')!=prior_header):raise MirrorError('scope_copy_proof')
                    progress['source_identity']=identity;encoded=json.dumps(progress,sort_keys=True)
                    qualified_charge(len(encoded.encode())+len(table.encode()));planned_progress.append((encoded,table))
            if reuse.descriptor(config,registry)is None:qualified_charge(len(json.dumps(observation,sort_keys=True).encode()))
        obs_id = reuse.store(config,registry,observation,budget=budget)
        if _qualified_check is not None:
            if obs_id!=expected_observation:raise MirrorError('scope_member_proof')
            for values in planned_members:registry.execute('UPDATE members SET proof=? WHERE shard=? AND table_name=?',values)
        else:
            for table, proof in proofs:
                check_deadline()
                proof.update(source_identity=identity, header=header_hash, observation=obs_id)
                registry.execute('UPDATE members SET proof=? WHERE shard=? AND table_name=?',
                                 (json.dumps(proof, sort_keys=True), shard, table))
        reuse.prune(config,registry)
        if attached:
            if _qualified_check is not None:
                for values in planned_progress:registry.execute('UPDATE d1.__walden_progress SET value=? WHERE table_name=?',values)
            else:
                for table, raw in registry.execute('SELECT table_name,value FROM d1.__walden_progress'):
                    check_deadline()
                    progress = json.loads(raw)
                    if table == 'Name2Id':
                        if progress != {}:raise MirrorError('scope_copy_proof')
                        continue
                    if (not isinstance(progress, dict)or progress.get('source_identity') != prior_identity or progress.get('source_header_sha256') != prior_header):raise MirrorError('scope_copy_proof')
                    progress['source_identity'] = identity
                    registry.execute('UPDATE d1.__walden_progress SET value=? WHERE table_name=?',
                                     (json.dumps(progress, sort_keys=True), table))
            if private(local_path) != local_identity:raise MirrorError('local_replaced')
        if _qualified_check is not None:
            retry_size=registry.execute("SELECT length(CAST(value AS BLOB))FROM state WHERE key=?",('source_retry:'+shard,)).fetchone();qualified_charge(16+(retry_size[0]if retry_size else 0))
        retry=sc.state(registry,'source_retry:'+shard)
        if retry is not None:
            from .native_deadline import _current
            grant=getattr(_current.get(),'grant',None)
            if type(grant) is not dict:raise MirrorError('source_retry_binding')
            retry=_account_retry_state(config,registry,shard,grant)
            retry['binding']=dict(source_sha256=grant['source_sha256'],
                                  anchor=dict(source_identity=identity,header=header_hash))
            qualified_charge(len(json.dumps(retry,sort_keys=True).encode())+len(('source_retry:'+shard).encode()))
            sc.save(registry,'source_retry:'+shard,retry)
        qualified_charge(len(json.dumps(dict(source_identity=identity,header=header_hash),sort_keys=True).encode())+len(anchor_key.encode()))
        sc.save(registry, anchor_key, dict(source_identity=identity, header=header_hash))
        receipt = dict(kind='auto_st_dev_renumber', auto=True, shard=shard,
                       at_wall_ns=time.time_ns(), old_st_dev=prior_identity[0],
                       new_st_dev=identity[0], st_ino=identity[1], header=header_hash,
                       old_source_identity=list(prior_identity), new_source_identity=list(identity))
        qualified_charge(len(json.dumps(receipt,sort_keys=True).encode())+len(('source_st_dev_renumber_receipt:'+shard).encode()))
        sc.save(registry, 'source_st_dev_renumber_receipt:' + shard, receipt)
        if _qualified_publish is not None:_qualified_publish(registry)
        verify_source()
        sc.query_scope_guard(config, scope_token)
        _account_registry_commit(registry,config=config,budget=budget)
        if _qualified_check is not None:_qualified_check()
    finally:
        if registry.in_transaction:
            registry.rollback()
        if attached:
            registry.execute('DETACH DATABASE d1')
    return receipt


def _account_shard_anchor_check(config, registry, path, identity, header_hash, *, result=None, budget=None):
    """Per-shard source-anchor comparison (native_mirror_sync.py ~:525, the
    account-mode loop). Kept INSIDE the per-shard loop; never bypassed.

    Exact equality of shard_anchor:<shard> against the live observation is still
    enforced for every shard. The ONLY tolerated difference is a verified
    same-source st_dev renumber (see _st_dev_renumber_proof): same inode, same
    first-16-byte header, only st_dev differs. In that one case
    _auto_reanchor_renumbered_shard advances ALL pinned identity layers for THIS
    shard and writes a distinct AUTO audit receipt, then the equality guard is
    re-checked (validation is never skipped). Everything else (different inode,
    different header, missing/malformed/None anchor, missing source) still raises
    MirrorError('scope_source_conflict') exactly as before. No blanket override,
    no unconditional overwrite, no swallowed exception.
    """
    from . import native_scope_contract as sc
    live = dict(source_identity=identity, header=header_hash)
    anchor = sc.state(registry, 'shard_anchor:' + path.name, None)
    if anchor is not None and anchor != live:
        if _st_dev_renumber_proof(anchor, identity, header_hash):
            receipt = _auto_reanchor_renumbered_shard(config, registry, path, anchor, identity, header_hash, budget=budget)
            if result is not None:
                result.setdefault('auto_st_dev_renumber', []).append(receipt)
            anchor = sc.state(registry, 'shard_anchor:' + path.name, None)
        if anchor != live:
            raise MirrorError('scope_source_conflict')
    return anchor


def _account_history_candidate(local, registry, shard, cursor, anchor, budget,*,resume_pending=False):
    """One charged page; a verified unfinished head need not wait for wrap."""
    import json
    from . import native_scope_contract as sc
    budget['history_candidate_complete']=False
    probe=budget.get('tail_probe')
    until=min(budget['until'],probe['until']) if probe is not None and probe['until'] is not None else budget['until']
    if time.monotonic()>=until:return None,cursor
    local.set_progress_handler(lambda:int(time.monotonic()>=until),1000)
    try:
        visited=0
        rows=local.execute(
            'SELECT table_name,value FROM __walden_progress WHERE table_name'+('>=?' if resume_pending else '>?')+' ORDER BY table_name LIMIT ?',
            (cursor,budget['inventory']))
        for table,raw in rows:
            if time.monotonic()>=until:return None,cursor
            probe=budget.get('tail_probe')
            if probe is not None:
                size=len(raw.encode())
                if probe['tables']>=1024 or probe['bytes']+size>probe.get('ceiling',1024*1024):return None,cursor
                probe['tables']+=1;probe['bytes']+=size
            visited+=1;cursor=table;progress=json.loads(raw)
            history,ceiling=progress.get('history'),progress.get('H')
            if (type(history) is int and type(ceiling) is int and 0<=history<ceiling
                    and progress.get('source_identity')==anchor['source_identity']
                    and progress.get('source_header_sha256')==anchor['header']
                    and sc.TABLE.fullmatch(table)
                    and registry.execute('SELECT 1 FROM members WHERE shard=? AND table_name=?',(shard,table)).fetchone()):
                return table,cursor
        budget['history_candidate_complete']=visited<budget['inventory']
        return None,('' if not visited or resume_pending and budget['history_candidate_complete'] else cursor)
    except sqlite3.OperationalError as error:
        if time.monotonic()>=until and str(error)=='interrupted':return None,cursor
        raise
    finally:local.set_progress_handler(None,0)


def _account_tail_hints(config, grant):
    """Only same-instance relative names. This provides no Source authority."""
    from .native_follow_policy import Store
    from .native_follow_grant import _enabled_intent, _instance_runtime
    from .native_scope_contract import SHARD
    if not all(key in grant for key in ('store_root','instance_nonce','policy_generation','nonce','os_context')):
        return {}, False
    store=Store(grant['store_root'])
    _enabled_intent(store,grant)
    parent=_instance_runtime(store,grant)
    hint=parent.get('shard_hints') or {}
    names=hint.get('shards',{})
    node=os.stat(config['message_root'],follow_symlinks=False)
    if (parent.get('context')!=grant['os_context'] or hint.get('root_identity')!=[node.st_dev,node.st_ino]
            or type(names) is not dict or len(names)>64
            or any(type(name) is not str or not SHARD.fullmatch(name)
                   or type(value) is not int or value<1 for name,value in names.items())):
        return {}, True
    return names, bool(hint.get('fallback'))


def _account_tail_probe(config,conn,registry,path,local,anchor,budget,token,*,stable=False,copied=(),defer_discovery=False,_observations=None):
    """Bounded metadata only. Confirmed tail debt survives copy deferral."""
    from collections import OrderedDict
    import json
    from . import native_scope_contract as sc
    from . import native_account_round as round_work
    budget['_probe_stop']=None
    key='tail_probe:'+path.name
    state=sc.state(registry,key,dict(after='',pending=[],complete=False))
    if defer_discovery:
        # A view for this call only: leave persisted discovery cursor/token,
        # freshness and every queued tail untouched. No coverage is asserted.
        return dict(state,complete=False)
    if state.get('token')!=token:
        # A page preceding a newer event cannot close that event's scan.
        state.update(after='',complete=False,limited=False)
    pending=state['pending']
    # Persisted debt gets an actual guarded copy attempt before a renewed scan.
    # After each table's batch, discovery may use the remaining metadata budget
    # and yield again as soon as it finds another table needing that budget.
    if any(row[0] not in copied for row in pending):
        sc.save(registry,key,state)
        return state
    if ((pending or stable) and state['complete'] and state.get('token')==token
            and time.time()-state.get('probed_at',0)<300):
        return state
    if len(pending)>=1024:
        round_work.probe_stop(budget,'tail_probe','queue',kind='tail_queue',limit=1024,used=len(pending))
        state['complete']=False
        return state
    known={row[0] for row in pending}
    recovery = []
    attempted = budget.setdefault('_cursor_attempted', set())
    limited=state.get('limited',False)
    observations=OrderedDict()if _observations is None else _observations
    probe=budget['tail_probe']
    if probe['until'] is None:
        probe['started']=time.monotonic();probe['until']=min(budget['until'],probe['started']+2.)
    def expired():
        return time.monotonic()>=probe['until'] or time.monotonic()>=budget['until']
    def progress():
        return int(expired())
    def budget_stop(required=0):
        if expired():round_work.probe_time(budget,'tail_probe')
        elif probe['tables']>=1024:round_work.probe_stop(budget,'tail_probe','page',kind='metadata_tables',limit=1024,used=probe['tables'])
        else:round_work.probe_stop(budget,'tail_probe','metadata',kind='metadata_bytes',limit=probe.get('ceiling',1048576),used=probe['bytes'],required=required)
    if expired() or probe['tables']>=1024 or probe['bytes']>=probe.get('ceiling',1024*1024):
        budget_stop()
        state['complete']=False
        return state
    conn.set_progress_handler(progress,1000)
    try:
        rows=local.execute('SELECT table_name,value FROM __walden_progress WHERE table_name>? ORDER BY table_name LIMIT ?',
                           (state['after'], min(1025-probe['tables'],1025)))
        completed=True
        for table,raw in rows:
            if expired() or probe['tables']>=1024 or probe['bytes']+len(raw.encode())>probe.get('ceiling',1024*1024):
                budget_stop(len(raw.encode()))
                completed=False
                break
            if probe['tables']%64==0:
                check_deadline()
            probe['tables']+=1
            probe['bytes']+=len(raw.encode())
            if not sc.TABLE.fullmatch(table):
                state['after']=table
                continue
            prior=json.loads(raw)
            if (type(prior.get('tail')) is not int or prior.get('source_identity')!=anchor['source_identity']
                    or prior.get('source_header_sha256')!=anchor['header']):
                state['after']=table
                continue
            encoded_member=registry.execute('SELECT proof FROM members WHERE shard=? AND table_name=?',
                                            (path.name,table)).fetchone()
            if encoded_member is None:
                raise MirrorError('scope_table_unregistered')
            member_bytes=len(encoded_member[0].encode())
            if probe['bytes']+member_bytes>probe.get('ceiling',1024*1024):
                budget_stop(member_bytes)
                completed=False
                break
            preview=json.loads(encoded_member[0])
            observation=preview.get('observation')
            if observation not in observations:
                from .native_registry_reuse import observation_size
                size=observation_size(config,registry,observation)
                length=None if size is None else (size,)
                if length is None:
                    raise MirrorError('scope_member_proof')
                member_bytes+=length[0]
            if probe['bytes']+member_bytes>probe.get('ceiling',1024*1024):
                budget_stop(member_bytes)
                # An individually oversized proof cannot block the next table.
                # Ordinary copying keeps its existing full-proof contract.
                probe['limited']=True
                state['after']=table
                continue
            probe['bytes']+=member_bytes
            member=sc.member(config,registry,path.name,table,_observations=observations)
            if member.get('supported') is not True or member.get('available') is not True:
                round_work.probe_stop(budget,'tail_probe','probe_member_unverified')
                if len(token)==3:probe['limited']=True
                state['after']=table
                continue
            verified_cursor=False
            try:
                ddl=conn.execute("SELECT sql FROM sqlite_master WHERE name=? AND type='table'",(table,)).fetchone()
                if ddl is None or sc.sha(ddl[0].encode())!=member['schema_sha256']:
                    round_work.probe_stop(budget,'tail_probe','probe_schema_unverified')
                    probe['limited']=True
                    state['after']=table
                    continue
                ddl_bytes=len(ddl[0].encode())
                if probe['bytes']+ddl_bytes>probe.get('ceiling',1024*1024):
                    budget_stop(ddl_bytes)
                    completed=False
                    break
                probe['bytes']+=ddl_bytes
                _validate_message_cursor(conn,table)
                verified_cursor=True
                maximum=conn.execute('SELECT coalesce(max(local_id),0) FROM '+qi(table)).fetchone()[0]
            except Exception as error:
                if verified_cursor and conn.in_transaction and _account_busy(error):
                    raise _AccountShardBusy(error,'source_probe') from error
                errors,operational=_account_sqlite_types()
                code=_account_error_info(error,'source_probe')['sqlite_primary_code']
                if (not isinstance(error,errors) or not (code==9 or
                        code is None and isinstance(error,operational) and str(error)=='interrupted' and expired())):
                    raise
                if expired():round_work.probe_time(budget,'tail_probe')
                else:round_work.probe_stop(budget,'tail_probe','probe_interrupted_unknown')
                # Yield this expensive entry to ordinary guarded copying, and
                # retain the hint so it cannot claim a complete observation.
                probe['limited']=True
                state['after']=table
                completed=False
                if not conn.in_transaction:
                    raise MirrorError('source_transaction_changed')
                break
            state['after']=table
            held = cursor_recovery.pending(registry, path.name, table)
            if held is not None and held['epoch'] != prior.get('cursor_epoch',0):
                if held['epoch'] >= prior.get('cursor_epoch',0):
                    raise MirrorError('scope_copy_proof')
                cursor_recovery.set_pending(registry,path.name,table,None)
                held=None
            if held is not None or not cursor_recovery.valid_max(maximum) or maximum < cursor_recovery.floor(prior):
                if not conn.in_transaction:
                    raise MirrorError('source_transaction_changed')
                if cursor_recovery.mark(registry, path.name, table, maximum, prior) and (path.name, table) not in attempted:
                    recovery.append((table, max(maximum, prior['target'])))
                continue
            if maximum>prior['tail']:
                if table in known:
                    wanted=next(item for item in pending if item[0]==table)
                    wanted[1]=max(maximum,wanted[1])
                else:
                    pending.append([table,maximum]);known.add(table)
                if table not in copied or len(pending)>=1024:
                    completed=False
                    break
        recovery = [row for row in recovery if row[0] not in known]
        if recovery and len(pending)<1024 and not any(cursor_recovery.pending(registry,path.name,row[0]) is not None for row in pending):
            # Take one retry after confirmed healthy tail work. Rotate held
            # tables too, so a continuously busy sibling cannot freeze one.
            after = state.get('last_cursor_retry','')
            selected = min(recovery,key=lambda row:(row[0]<=after,row[0]))
            pending.append(list(selected));state['last_cursor_retry']=selected[0]
        if limited and budget.get('_probe_stop') is None:round_work.probe_stop(budget,'tail_probe','prior_probe_limit_unknown')
        state['complete']=completed and not (limited or probe['limited'])
        state['limited']=(limited or probe['limited']) and not completed
        if completed:
            state['after']=''
        state.update(token=token,probed_at=time.time())
        state=round_work.finish_discovery(state,anchor,budget)
        sc.save(registry,key,state)
        return state
    finally:
        conn.set_progress_handler(None,0)


def _account_hint_proof(config,grant):
    """Same live listener's event coverage, never a Source grant."""
    from .native_follow_policy import Store
    from .native_follow_grant import _enabled_intent,_instance_runtime
    from .native_scope_contract import SHARD,REGISTRY
    if not all(k in grant for k in ('store_root','instance_nonce','policy_generation','nonce','os_context')):
        return None
    _enabled_intent(Store(grant['store_root']),grant)
    parent=_instance_runtime(Store(grant['store_root']),grant)
    hint=parent.get('shard_hints') or {}
    node=os.stat(config['message_root'],follow_symlinks=False)
    if (parent.get('context')!=grant['os_context'] or hint.get('coverage_version')!=1
            or type(hint.get('uncertain_generation')) is not int or hint['uncertain_generation']<1
            or type(hint.get('shards')) is not dict or len(hint['shards'])>64
            or any(type(name) is not str or not SHARD.fullmatch(name) or type(generation) is not int or generation<1 for name,generation in hint['shards'].items())
            or hint.get('root_identity')!=[node.st_dev,node.st_ino]):
        return None
    lock=os.stat(Path(config['mirror_root'])/'.writer.lock',follow_symlinks=False)
    registry=os.stat(Path(config['mirror_root'])/REGISTRY,follow_symlinks=False)
    return dict(source=grant['source_sha256'],policy=grant['policy_generation'],
                instance=grant['instance_nonce'],root=hint['root_identity'],
                writer=[lock.st_dev,lock.st_ino],registry=[registry.st_dev,registry.st_ino],
                app_epoch=grant.get('app_epoch'),uncertain=hint['uncertain_generation'])


def _account_work_pins(config,registry,paths,budget,*,verify_counts=False):
    """Rollback-mode local commit headers + physical files, under writer_lock.

    All official progress writers hold that lock. The SQLite change counter,
    schema/root/page fields and version-valid-for are covered by the header
    hash; ordinary timestamps alone are never the commit witness. A WAL or
    journal, missing/unbound file, or insufficient metadata budget refuses it.
    """
    from . import native_scope_contract as sc
    from .live_readonly import readonly_database_uri
    pins={}
    for path in paths:
        local=Path(config['mirror_root'])/path.name
        anchor=sc.state(registry,'shard_anchor:'+path.name)
        if anchor is None or not local.is_file() or any(Path(str(local)+suffix).exists() for suffix in ('-wal','-journal')):
            return None
        sc._safe(local)
        if verify_counts:
            probe=budget['tail_probe']
            prefix='copy_init:'+path.name+':'
            pending=registry.execute('SELECT key FROM state WHERE key>=? AND key<? LIMIT 1',(prefix,prefix+'~')).fetchone()
            cost=16+(len(pending[0].encode()) if pending else 0)
            if probe['bytes']+cost>probe.get('ceiling',1048576):return None
            probe['bytes']+=cost
            if pending:return None
            if probe['until'] is None:probe['started']=time.monotonic();probe['until']=min(budget['until'],probe['started']+2.)
            if time.monotonic()>=probe['until']:return None
            with sqlite3.connect(readonly_database_uri(local),uri=True,timeout=.1) as db:
                db.execute('PRAGMA query_only=ON')
                db.set_progress_handler(lambda:int(time.monotonic()>=probe['until']),1000)
                try:
                    if db.execute('SELECT * FROM __walden_binding').fetchall()!=[(config['account_id'],config['source_generation'],path.name)]:return None
                    count=db.execute("SELECT count(*) FROM __walden_progress WHERE table_name GLOB 'Msg_*'").fetchone()[0]
                    if db.execute("SELECT 1 FROM __walden_progress WHERE json_extract(value,'$.initial_suffix_pending')=1 LIMIT 1").fetchone():return None
                    registry.set_progress_handler(lambda:int(time.monotonic()>=probe['until']),1000)
                    try:members=registry.execute('SELECT count(*) FROM members WHERE shard=?',(path.name,)).fetchone()[0]
                    finally:registry.set_progress_handler(None,0)
                    if count!=members:return None
                except sqlite3.OperationalError:return None
        fd=os.open(local,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            before=os.fstat(fd);header=os.read(fd,100);after=os.fstat(fd)
            fields=lambda s:[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
            if fields(before)!=fields(after) or fields(after)!=fields(local.stat()) or len(header)!=100 or header[:16]!=b'SQLite format 3\x00' or header[18:20]!=b'\x01\x01':
                return None
            value=dict(file=fields(after),commit=hashlib.sha256(header).hexdigest(),counter=int.from_bytes(header[24:28],'big'),anchor=anchor)
            size=100+len(__import__('json').dumps(value).encode())
            if budget['tail_probe']['bytes']+size>1024*1024 or time.monotonic()>=budget['until']:
                return None
            budget['tail_probe']['bytes']+=size
            pins[path.name]=value
        finally:os.close(fd)
    return pins


def _account_work_start(config,registry,paths,budget,grant,registry_witness=None):
    import json
    from . import native_scope_contract as sc
    if len(paths)>64 or registry_witness is None:return None
    proof=_account_hint_proof(config,grant)
    if proof is None:return None
    pin_start=budget['tail_probe']['bytes']
    pins=_account_work_pins(config,registry,paths,budget,verify_counts=True)
    if pins is None:return None
    witness=budget['tail_probe']['bytes']-pin_start+64*len(pins)
    length=registry.execute("SELECT length(CAST(value AS BLOB)) FROM state WHERE key='account_work'").fetchone()
    size=length[0] if length else 0
    if size>65536 or budget['tail_probe']['bytes']+size>1024*1024:return None
    budget['tail_probe']['bytes']+=size
    previous=sc.state(registry,'account_work',{}) or {}
    if type(previous) is not dict:previous={}
    valid=(previous.get('version')==2 and type(previous.get('registry_counter')) is int and not previous.get('reconcile') and previous.get('registry_counter')==registry_witness.before['counter'] and previous.get('proof')==proof and previous.get('pins')==pins
           and type(previous.get('round')) is int and previous['round']==sc.state(registry,'round_number')-1
           and type(previous.get('history')) is list and all(name in pins for name in previous['history'])
           and all(type(previous.get(key)) is dict for key in ('heads','scan_heads','verified')))
    if not valid:
        # Never turn a legacy middle page, interrupted publication or changed
        # local database into a complete import. Actual row progress is intact.
        # Drop completeness, not the bounded discovery position. An unfinished
        # import must wrap and start again before claiming a complete proof.
        sc.save(registry,'history_backlog_scan',{})
    work=dict(version=2,proof=proof,pins=pins,ready=valid and previous.get('ready') is True,
                imported=valid and previous.get('imported') is True,
                scan_heads=previous.get('scan_heads',{}) if valid else {},
                heads=previous.get('heads',{}) if valid else {},
                verified=previous.get('verified',{}) if valid else {},
                history=previous.get('history',[]) if valid else [])
    # Commit witnesses and bounded certificate processing share the original
    # metadata cap. Nothing is reserved from Source opens or message rows.
    publication=len(json.dumps(work).encode())+512*len(pins)+128
    budget['tail_probe']['finish_reserve']=witness+publication+172+registry_witness.owner.admit_cost+budget['tail_probe'].get('guard_finish_reserve',0)
    budget['tail_probe']['ceiling']=1024*1024-budget['tail_probe']['finish_reserve']
    return work


def _account_work_current(config,registry,grant,work,debts,consumed):
    from . import native_scope_contract as sc
    if work is None or work.get('unverified') or debts or _account_hint_proof(config,grant)!=work['proof']:
        return False
    if any(sc.state(registry,'gaps:'+name,[]) for name in work['pins']):return False
    hints,fallback=_account_tail_hints(config,grant)
    return all(value<=consumed['shards'].get(name,0) for name,value in hints.items())


def _account_work_finish(config,registry,paths,budget,grant,work,*,clean,complete,witness=None,registry_witness=None):
    import json
    from . import native_scope_contract as sc
    if work is None:return
    if (not clean or work.get('unverified') or _account_hint_proof(config,grant)!=work['proof']
            or any(sc.state(registry,'gaps:'+p.name,[]) for p in paths)):
        sc.save(registry,'account_work',None);return
    if witness is None or witness.changed:
        sc.save(registry,'account_work',None);return
    witness.compare_all()
    pins={name:dict(work['pins'][name],**witness.expected[str(Path(config['mirror_root'])/name)]) for name in work['pins']}
    if complete:
        work['imported']=True
        work['history']=sorted(work['scan_heads'])
        work['heads']=dict(work['scan_heads'])
    hints,_=_account_tail_hints(config,grant)
    observed=all(work['verified'].get(p.name)==[grant['instance_nonce'],hints.get(p.name,0),work['proof']['uncertain']] for p in paths)
    work['ready']=work['ready'] or work['imported'] and observed
    work.update(pins=pins,round=sc.state(registry,'round_number'),registry_counter=(registry_witness.before['counter']+1)%(1<<32))
    size=len(json.dumps(work).encode())
    if size>65536 or budget['tail_probe']['bytes']+size>1024*1024:
        sc.save(registry,'account_work',None);return
    budget['tail_probe']['bytes']+=size
    registry_witness.publication=work['registry_counter']
    sc.save(registry,'account_work',work)


def _account_known_tail_debts(config,registry,paths,budget,*,work=None):
    """Import pinned tail debt and history candidates in the same bounded page."""
    import json
    from . import native_scope_contract as sc
    from .live_readonly import readonly_database_uri
    from . import native_account_round as round_work
    budget['_probe_stop']=None
    position=sc.state(registry,'tail_debt_cursor',dict(shard='',table=''))
    if work is not None and not position['shard']:work['scan_heads']={}
    # Optional history hints must start at the beginning and follow this
    # import cursor/round chain; an older writer cannot complete their scan.
    history_scan=sc.state(registry,'history_backlog_scan',{})
    round_number=sc.state(registry,'round_number',0)
    started=(type(history_scan) is dict and history_scan.get('started_from_beginning') is True
             and history_scan.get('cursor')==position and type(history_scan.get('round_number')) is int
             and history_scan['round_number']==round_number-1)
    if not position['shard']:
        started=True
    history_scan=dict(started_from_beginning=started,complete=False,cursor=dict(position),round_number=round_number)
    sc.save(registry,'history_backlog_scan',history_scan)
    probe=budget['tail_probe']
    if probe['until'] is None:
        probe['started']=time.monotonic();probe['until']=min(budget['until'],probe['started']+2.)
    seen=0
    for path in paths:
        if path.name<position['shard']:
            continue
        from .native_account_copy_init import check_shell_target
        check_shell_target(config,registry,path.name,budget)
        anchor=sc.state(registry,'shard_anchor:'+path.name)
        local_path=Path(config['mirror_root'])/path.name
        if anchor is None or not local_path.is_file():
            sc.save(registry,'history_backlog:'+path.name,False)
            continue
        sc._safe(local_path)
        local=sqlite3.connect(readonly_database_uri(local_path),uri=True,timeout=.1)
        try:
            local.execute('PRAGMA query_only=ON')
            if local.execute('SELECT * FROM __walden_binding').fetchall()!=[
                    (config['account_id'],config['source_generation'],path.name)]:
                raise MirrorError('source_identity_mismatch')
            after=position['table'] if path.name==position['shard'] else ''
            history_key='history_backlog:'+path.name
            if not after:
                sc.save(registry,history_key,False)
            # Only True is a confirmed candidate; False/missing never proves
            # that unknown Source tables or history are complete.
            history_pending=sc.state(registry,history_key,False) is True
            position=dict(shard=path.name,table=after)
            rows=local.execute('SELECT table_name,value FROM __walden_progress WHERE table_name>? ORDER BY table_name LIMIT 257',(after,))
            for table,raw in rows:
                if (seen>=256 or probe['bytes']+len(raw.encode())>probe.get('ceiling',1024*1024)
                        or time.monotonic()>=probe['until']):
                    if seen>=256:round_work.probe_stop(budget,'history_import','page',kind='metadata_tables',limit=256,used=seen,required=1)
                    elif probe['bytes']+len(raw.encode())>probe.get('ceiling',1048576):round_work.probe_stop(budget,'history_import','metadata',kind='metadata_bytes',limit=probe.get('ceiling',1048576),used=probe['bytes'],required=len(raw.encode()))
                    else:round_work.probe_time(budget,'history_import')
                    sc.save(registry,'tail_debt_cursor',position)
                    history_scan['cursor']=dict(position)
                    sc.save(registry,'history_backlog_scan',history_scan)
                    return False
                seen+=1;probe['tables']+=1;probe['bytes']+=len(raw.encode())
                position=dict(shard=path.name,table=table)
                if not sc.TABLE.fullmatch(table):
                    continue
                value=json.loads(raw)
                if type(value) is not dict:
                    raise MirrorError('scope_copy_proof')
                pinned=(value.get('source_identity')==anchor['source_identity']
                        and value.get('source_header_sha256')==anchor['header'])
                history,ceiling=value.get('history'),value.get('H')
                if work is not None and pinned and type(history) is int and type(ceiling) is int and 0<=history<ceiling:
                    work['scan_heads'].setdefault(path.name,table)
                if (not history_pending and pinned and type(history) is int and type(ceiling) is int
                        and 0<=history<ceiling):
                    history_pending=True
                    sc.save(registry,history_key,True)
                if pinned and type(history) is int and type(ceiling) is int and 0<=history<ceiling:
                    from .native_account_round import remember
                    remember(registry,path.name,table,value,anchor,budget)
                tail,target=value.get('tail'),value.get('target')
                if work is not None and (not pinned or any(type(n) is not int for n in (history,ceiling,tail,target))
                        or not 0<=history<=ceiling<=tail<=target
                        or registry.execute('SELECT 1 FROM members WHERE shard=? AND table_name=?',(path.name,table)).fetchone() is None):
                    work['unverified']=True
                if (pinned and type(tail) is int and type(target) is int and target>tail>=0
                        and cursor_recovery.pending(registry,path.name,table) is None):
                    key='tail_probe:'+path.name
                    state=sc.state(registry,key,dict(after='',pending=[],complete=False))
                    if len(state['pending'])<1024 and table not in {item[0] for item in state['pending']}:
                        state['pending'].append([table,target])
                        sc.save(registry,key,state)
            position=dict(shard=path.name,table='')
        finally:
            local.close()
    sc.save(registry,'tail_debt_cursor',dict(shard='',table=''))
    history_scan.update(complete=started,cursor=dict(shard='',table=''))
    sc.save(registry,'history_backlog_scan',history_scan)
    return True


def _account_registry_admit(config,registry,identity,before,deadline):
    """Recheck the original authority gates inside this exact reservation."""
    import json
    from . import native_scope_contract as sc
    from . import native_registry_reuse as reuse
    registry.owner.admit_cost=reuse._cost(config,registry.owner.registry_storage,len(reuse._connections().get(reuse._connection_id(registry),{})))
    registry.owner.guard_charge(registry.owner.admit_cost,registry)
    if sc._safe(Path(config['mirror_root'])/sc.REGISTRY)!=identity:
        raise MirrorError('scope_registry_replaced')
    expected=registry.owner.registry_binding
    lengths=registry.execute('SELECT length(CAST(value AS BLOB)) FROM binding LIMIT 2').fetchall()
    if lengths!=[(len(expected.encode()),)] or registry.execute('SELECT value FROM binding LIMIT 2').fetchall()!=[(expected,)]:
        raise MirrorError('scope_registry_binding')
    length=registry.execute("SELECT length(CAST(value AS BLOB)) FROM state WHERE key='shard_anchor_schema'").fetchone()
    if length is None or length[0]>64:
        raise MirrorError('scope_registry_schema')
    sc.registry_schema(registry)
    _require_trigger_free(registry,'main')
    if registry.owner.registry_storage is not None:reuse.archive_guard(config,registry)
    sc.query_scope_guard(config,before);deadline.check()
    registry.owner.admitted=True


def _account_sync(config,*,connection_factory=None):
    from . import native_scope_contract as sc
    from .native_deadline import _current
    from .native_follow_grant import FollowDeadline
    import json
    deadline=_current.get()
    if (not isinstance(deadline,FollowDeadline) or deadline.grant.get('kind') not in ('active','drain')
            or deadline.grant.get('source_sha256')!=__import__(__package__+'.native_follow_policy',fromlist=['digest']).digest(config)):
        raise MirrorError('account_source_role_required')
    deadline.check();before=sc.query_scope_guard(config);budget=_account_budget(config)
    hints,hint_fallback=_account_tail_hints(config,deadline.grant)
    budget['tail_probe']=dict(until=None,tables=0,bytes=0,limited=False)
    budget['_cursor_attempted']=set()
    root=mirror_root(config);result=dict(sources=[],gaps=[],source_opens=0,source_attempts=0,rows_read=0,rows_written=0,committed_message_rows=0)
    from . import native_account_round as round_work
    evidence=round_work.Evidence()
    verified_media_sources={}
    preview_hint=None
    from .native_account_witness import AccountWitness,WorkChanged,WorkBudgetStop,_COMMIT_CHECK_BYTES
    registry_identity=[]
    with writer_lock(root,float(config.get('mirror_lock_timeout',10))),sc.registry(config,write=True,validated=registry_identity.append) as registry:
        registry_owner=AccountWitness(root,budget,clock=time.monotonic)
        from . import native_registry_reuse as reuse
        registry_owner.registry_storage=reuse.descriptor(config,registry)
        registry_owner.registry_binding=json.dumps(registry_owner.registry_storage or sc.fixed(config),sort_keys=True)
        registry_owner.admit_cost=reuse._cost(config,registry_owner.registry_storage,reuse.BUCKETS)
        registry_owner.registry_precommit=(lambda reserved:reuse.archive_guard(config,reserved)) if registry_owner.registry_storage is not None else None
        # The current shard can still commit inventory, copy and finally,
        # followed by terminal publication. Optional post-commit failure can
        # also require suspension admission and one guarded fallback commit.
        # Keep their actual weighted costs inside the same metadata cap; no
        # later shard or auxiliary body starts after this ceiling is spent.
        budget['tail_probe']['guard_finish_reserve']=4*(registry_owner.admit_cost+_COMMIT_CHECK_BYTES)+2*registry_owner.admit_cost
        budget['tail_probe']['ceiling']=1048576-budget['tail_probe']['guard_finish_reserve']
        registry_owner.registry_admit=lambda reserved:_account_registry_admit(config,reserved,registry_identity[0],before,deadline)
        cache_eligible=_account_hint_proof(config,deadline.grant) is not None
        if cache_eligible:
            try:registry_owner.seed(root/sc.REGISTRY,registry_owner.pin(root/sc.REGISTRY))
            except WorkChanged:cache_eligible=False
        # Authority reservation is mandatory even without optional event/cache
        # coverage or a supported local witness mode. Each commit renews it.
        registry_owner.registry_witness_enabled=cache_eligible
        registry=registry_owner.registry(root/sc.REGISTRY,registry)
        registry_witness=registry if registry.enabled and not registry_owner.changed else None
        sc.query_scope_guard(config,before)
        paths=discover_numeric_shards(Path(config['message_root']))
        roster=[p.name for p in paths];prior=sc.state(registry,'roster',[])
        if set(prior)-set(roster):result['gaps'].append('source_shard_missing')
        if not paths:result['gaps'].append('source_unavailable')
        if connection_factory is None:
            deadline.check();secret=read_private_passphrase(Path(config['passphrase_file']))
            connection_factory=lambda path:open_encrypted_readonly(path,secret)[0]
        round_number=sc.state(registry,'round_number',0);sc.save(registry,'round_number',round_number+1)
        if round_number%4==0:
            sc.save(registry,'aux_due',True)
        offset=sc.state(registry,'shard_cursor',0)
        # A bounded local retry record is not a new Source attempt. Leave the
        # actual stat/open allowance available for other authorized shards.
        ready={path.name:_account_retry_ready(config,registry,path.name,deadline.grant) for path in paths}
        ordinary=([paths[(offset+i)%len(paths)] for i in range(len(paths))
                   if ready[paths[(offset+i)%len(paths)].name]][:budget['shards']]) if paths else []
        if any(not value for value in ready.values()):result['gaps'].append('source_shard_retry_pending')
        consumed=sc.state(registry,'tail_hints',{})
        previous_consumed=consumed
        if 'shards' not in consumed or consumed.get('instance')!=deadline.grant.get('instance_nonce'):
            consumed=dict(instance=deadline.grant.get('instance_nonce'),shards={})
        consumed['shards']={name:value for name,value in consumed['shards'].items() if name in hints}
        from . import native_account_copy_init as copy_init
        from . import native_account_reconcile as copy_reconcile
        try:reconcile_request=copy_reconcile.pending(config,registry,budget)
        except WorkBudgetStop as error:
            reconcile_request=None;round_work.deferred(evidence,budget,'metadata',error,location='pending_request')
        current_management=(reconcile_request is not None and '_current'in reconcile_request and deadline.grant.get('kind')=='active')
        # This finite turn performs no message batch. Preserve optional import
        # cursors/freshness rather than paying the global scan before admission.
        work=None if current_management else _account_work_start(config,registry,paths,budget,deadline.grant,registry_witness)
        if current_management:evidence.add('selection','current_qualification_reserved',target=reconcile_request['target_ref'])
        witness=AccountWitness(root,budget,clock=time.monotonic) if work is not None else None
        if witness is not None:
            for name,pin in work['pins'].items():witness.seed(root/name,pin)
        work_invalidated=False
        reconcile_required=False
        try:
            recovered_fairness=round_work.start(registry,paths,budget,round_number,deadline.grant.get('instance_nonce'))
            evidence.add('selection','recovered_debt' if recovered_fairness else 'round_start')
        except WorkBudgetStop as error:
            budget['_fair_turn']=None;budget['_fair_heads']={}
            round_work.deferred(evidence,budget,'metadata',error)
        try:known_debt_complete=False if current_management else _account_known_tail_debts(config,registry,paths,budget,work=work)
        except WorkBudgetStop as error:
            known_debt_complete=False;round_work.deferred(evidence,budget,'metadata',error)
        round_work.emit_probe(evidence,budget)
        tail_states={p.name:sc.state(registry,'tail_probe:'+p.name,{})for p in paths}
        debts={name for name,state in tail_states.items()if state.get('pending')}
        discovery_limited=False
        try:discovery=round_work.restore_discovery(registry,paths,budget,previous_consumed,deadline.grant.get('instance_nonce'),states=tail_states)
        except WorkBudgetStop as error:
            discovery=set();discovery_limited=True;work_invalidated=True
            round_work.deferred(evidence,budget,'metadata',error,location='hint_recovery')
        if discovery or discovery_limited:
            if work is not None:work['unverified']=True
            work_invalidated=True
        for name in sorted(discovery):evidence.add('selection','discovery_origin_pending',target=__import__('hashlib').sha256(name.encode()).hexdigest())
        quiet=sc.state(registry,'tail_hint_quiet',{})
        quiet={name:value for name,value in quiet.items() if name in hints or name in discovery}
        fresh=[p for p in paths if ready[p.name] and (p.name in debts or
               ((p.name in discovery or hints.get(p.name,0)>consumed['shards'].get(p.name,0)) and quiet.get(p.name,-1)<round_number)
               or p.name in discovery and round_work.discovery_has_new_hint(p.name,hints,deadline.grant.get('instance_nonce'),budget))]
        after=sc.state(registry,'tail_shard_after','')
        fresh.sort(key=lambda p:(p.name not in debts,p.name<=after,p.name))
        priority=fresh[:budget['shards']]
        chosen=priority+[p for p in ordinary if p not in priority]
        chosen=chosen[:budget['shards']]
        if discovery_limited:reconcile_request=None
        try:init_paths=set()if discovery_limited else {p.name for p in paths if copy_init.has_pending(registry,p.name,budget)}
        except WorkBudgetStop as error:
            init_paths=set();round_work.deferred(evidence,budget,'metadata',error,location='pending_init')
        history_path=None
        work_ready=work is not None and work['ready']
        if ((work_ready or known_debt_complete and sc.state(registry,'history_backlog_scan',{}).get('complete') is True)
                and (work_ready or not debts) and len(priority)<budget['shards']):
            # Full import windows can align with the ordinary roster stride.
            # Rotate only the remaining ordinary history slot independently.
            eligible=[p for p in paths if ready[p.name] and p not in priority
                      and (p.name in init_paths or (p.name in work['history'] if work_ready else sc.state(registry,'history_backlog:'+p.name,False) is True))]
            # A positively owned first copy closes an otherwise permanent
            # import/count gap. It uses this same spare slot, after all known
            # tail debt, rather than waiting behind every old history shard.
            initializing=[p for p in eligible if p.name in init_paths]
            if initializing:eligible=initializing
            if eligible:
                history_shard_after=sc.state(registry,'history_shard_after','')
                history_path=min(eligible,key=lambda p:(p.name<=history_shard_after,p.name))
                slots=budget['shards']-len(priority)-1
                rest=[p for p in ordinary if p not in priority and p!=history_path][:slots]
                chosen=priority+[history_path]+rest if work_ready else priority+rest+[history_path]
        fair_path=round_work.choose(paths,ready,budget,priority)
        if fair_path is not None:
            chosen=[fair_path]+[p for p in chosen if p!=fair_path]
            chosen=chosen[:budget['shards']]
        history_wait=bool(budget['_fair_heads']) and not any(ready.get(name) for name in budget['_fair_heads'])
        evidence.add('selection','fair_history_due' if fair_path is not None else 'history_source_retry_wait' if history_wait else 'tail_priority' if priority else 'no_verified_history',tail_streak=(budget.get('_fair_turn') or {}).get('streak',0),history_heads=len(budget['_fair_heads']))
        result['new_tail']=dict(hinted_shards=len(hints),known_debt_shards=len(debts),
                               hint_fallback=hint_fallback,probe_complete=known_debt_complete,
                               known_debt_import_complete=known_debt_complete)
        result['new_tail']['incremental_work_ready']=work_ready
        management=False
        if reconcile_request is not None:
            result['account_copy_reconcile']=dict(status='waiting_for_spare_budget',target_ref=reconcile_request['target_ref'],prior_coverage_unknown=True)
            spare=known_debt_complete and not debts and not priority and not hint_fallback and not budget.get('_copy_init_stopped')
            # A current request grants only this target's guarded empty DDL/PG
            # initialization. It does not spend a message batch or require the
            # optional global discovery to finish before management can close.
            if deadline.grant.get('kind')=='active' and (spare or '_current'in reconcile_request):
                management=True;chosen=[]
                try:
                    changed=copy_reconcile.consume(config,registry,reconcile_request,budget,deadline,connection_factory,result)
                    result['account_copy_reconcile']['status']='initialized' if changed else 'deferred'
                    if changed:result['account_copy_reconcile'].update(changed)
                    work_invalidated=True
                except WorkBudgetStop as error:
                    result['new_tail']['work_budget_limited']=True
                    round_work.deferred(evidence,budget,'metadata',error,location='management')
                except WorkChanged:
                    reconcile_required=True;work_invalidated=True
                    if registry_witness is not None and registry_witness.owner.changed:
                        registry_witness.suspend();registry_witness=None
                except Exception as error:
                    if getattr(registry,'guard',False) and not registry.guard_valid:raise
                    deadline.check();result['gaps'].append(str(error) if isinstance(error,MirrorError) else 'source_unavailable_or_unsupported')
                    result['account_copy_reconcile'].update(status='failed',local_completion='not_confirmed')
                    result.setdefault('shard_diagnostics',[]).append(_account_error_info(error,'account_reconcile'))
        if discovery_limited:chosen=[]
        fair_handoff=False
        for path in chosen:
            if reconcile_required or fair_handoff:break
            if budget.get('_copy_init_stopped') or budget['tail_probe']['bytes']>=budget['tail_probe']['ceiling']:
                result['new_tail']['work_budget_limited']=True
                round_work.deferred(evidence,budget,'metadata')
                break
            shard_gap_start=len(result['gaps'])
            if sc.state(registry,'names_oversize:'+path.name,[]):result['gaps'].append('name2id_row_oversize')
            deadline.check()
            if time.monotonic()>=budget['until']:
                round_work.deferred(evidence,budget,'time',location='source_open');break
            conn=None
            operation_stage='stat';_diagnostic_stage='unknown'
            try:
                from .native_reconcile_current import ordinary_check
                ordinary_check(config,registry,budget.get('_current_reconcile_request'),path,budget)
                result['source_attempts']+=1
                if path==history_path:
                    sc.save(registry,'history_shard_after',path.name)
                stamp=path.stat();identity=[stamp.st_dev,stamp.st_ino]
                with path.open('rb') as header:header_hash=hashlib.sha256(header.read(16)).hexdigest()
                # Exact per-shard shard_anchor:<shard> comparison, kept inside the
                # loop (never hoisted/blanket). It reads the anchor itself, enforces
                # equality for every shard, and ONLY for a verified same-source
                # st_dev renumber auto-advances all pinned identity layers for THIS
                # shard + writes a distinct AUTO audit receipt, then re-checks the
                # equality guard. Every other mismatch still raises
                # MirrorError('scope_source_conflict') exactly as before.
                prior_anchor=sc.state(registry,'shard_anchor:'+path.name)
                reanchor=(prior_anchor is not None and prior_anchor!=dict(source_identity=identity,header=header_hash)
                          and _st_dev_renumber_proof(prior_anchor,identity,header_hash))
                if reanchor:
                    # Preserve the existing dedicated ATTACH/atomic transaction,
                    # then restore admission before any later Source operation.
                    registry.commit();registry.suspend(atomic=True);raw_registry=registry.raw
                    registry_owner.registry_witness_enabled=False
                    try:anchor=_account_shard_anchor_check(config,raw_registry,path,identity,header_hash,result=result,budget=budget)
                    finally:registry=registry_owner.registry(root/sc.REGISTRY,raw_registry)
                    registry_witness=None;work_invalidated=True;witness=None
                else:anchor=_account_shard_anchor_check(config,registry,path,identity,header_hash,result=result,budget=budget)
                if result.get('auto_st_dev_renumber'):work_invalidated=True
                if not _account_retry_ready(config,registry,path.name,deadline.grant):
                    if 'source_shard_retry_pending' not in result['gaps']:result['gaps'].append('source_shard_retry_pending')
                    continue
                operation_stage='source_open'
                conn=connection_factory(path);result['source_opens']+=1
                if conn.execute('PRAGMA query_only').fetchone()!=(1,):raise MirrorError('source_not_readonly')
                version_before=cursor_recovery.source_stamp(path)
                conn.execute('BEGIN');cookie=conn.execute('PRAGMA schema_version').fetchone()[0]
                version_after=cursor_recovery.source_stamp(path)
                budget['_cursor_snapshot']=version_before if version_before==version_after else None
                budget['_cursor_overlap']=set()
                if work is not None and sc.state(registry,'inventory:'+path.name,{}).get('cookie',cookie)!=cookie:
                    work_invalidated=True
                operation_stage='registry'
                sc.register(config,registry,dict(contract=sc.fixed(config),shard=path.name,source_identity=identity,header=header_hash,query_only=True,tables=[]),[])
                name_map={}
                history_key = 'history_copy:' + path.name
                history_cursor = sc.state(registry, history_key, {'after': '', 'regular_next': False})
                history_after = history_cursor['after']
                priority_table = None
                tail_state=None;tail_probe_progress=False
                local_path=root/path.name
                fair_table=(budget['_fair_heads'].get(path.name) or {}).get('table') if path==fair_path else None
                prior_inventory=sc.state(registry,'inventory:'+path.name,None)
                cursor=prior_inventory if prior_inventory is not None else dict(after='',cookie=cookie,pass_cookie=cookie,complete=False)
                # The fair head still passes member/DDL/MAX/local PG and every
                # original transaction guard below. A changed schema cookie
                # keeps the ordinary discovery/refresh path. Old inventory and
                # new-tail discovery are maintenance, not prerequisites for
                # rechecking this already registered, pinned history table.
                fair_metadata_turn=(fair_table is not None and prior_inventory is not None and cursor.get('cookie')==cookie)
                if fair_metadata_turn:evidence.add('selection','history_metadata_reserved',target=round_work.target(path.name,fair_table))
                init_metadata_turn=False;init_metadata_table=None;transaction_observations=None
                if local_path.is_file():
                    operation_stage='mirror'
                    from .live_readonly import readonly_database_uri
                    history_allowed=(_account_work_current(config,registry,deadline.grant,work,debts,consumed)
                                     if work_ready else known_debt_complete and path==chosen[-1])
                    probe_history = (history_allowed and not work_invalidated and path not in priority and anchor is not None and (work_ready or not history_cursor['regular_next'])
                                     and budget['used_tables'] < budget['tables']
                                     and budget['used_rows'] < budget['rows']
                                     and budget['used_bytes'] < budget['bytes'])
                    if probe_history:
                        sc._safe(local_path)
                    local=sqlite3.connect(readonly_database_uri(local_path),uri=True)
                    try:
                        local.execute('PRAGMA query_only=ON')
                        if anchor is not None:
                            sc._safe(local_path)
                            if local.execute('SELECT * FROM __walden_binding').fetchall()!=[
                                    (config['account_id'],config['source_generation'],path.name)]:
                                raise MirrorError('source_identity_mismatch')
                            current_request=budget.get('_current_reconcile_request')
                            if (current_request is not None and current_request['shard']==path.name and prior_inventory is not None and cursor.get('cookie')==cookie):
                                owned=copy_init.read(registry,path.name,current_request['table'],budget)
                                if owned is not None and owned['status']=='prepared':
                                    if owned.get('generation')!=current_request['generation']or owned.get('reconcile_request_sha256')!=current_request['request_sha256']:raise MirrorError('account_reconcile_request_conflict')
                                    length=local.execute('SELECT length(CAST(value AS BLOB))FROM __walden_progress WHERE table_name=?',(current_request['table'],)).fetchone()
                                    copy_init.charge(budget,16+(length[0]if length else 0))
                                    pg=local.execute('SELECT value FROM __walden_progress WHERE table_name=?',(current_request['table'],)).fetchone()
                                    if pg is None:raise MirrorError('account_copy_init_progress_lost')
                                    owned_progress=json.loads(pg[0])
                                    if owned_progress.get('copy_init_generation')!=owned['generation']or owned_progress.get('reconcile_request_sha256')!=current_request['request_sha256']:raise MirrorError('account_reconcile_request_conflict')
                                    if owned_progress.get('initial_suffix_pending')is True:
                                        from collections import OrderedDict
                                        init_metadata_turn=True;init_metadata_table=current_request['table'];transaction_observations=OrderedDict()
                            operation_stage='source_probe'
                            probe_token=[deadline.grant.get('instance_nonce'),hints.get(path.name,0)]+([work['proof']['uncertain']] if work is not None else [])
                            stable=(work_ready and not work_invalidated and work['verified'].get(path.name)==probe_token)
                            probe_tables_before=budget['tail_probe']['tables']
                            tail_state=_account_tail_probe(config,conn,registry,path,local,anchor,budget,probe_token,stable=stable,defer_discovery=fair_metadata_turn,_observations=transaction_observations)
                            round_work.emit_probe(evidence,budget)
                            tail_probe_progress=tail_state['complete'] or budget['tail_probe']['tables']>probe_tables_before
                            if tail_state['pending']:debts.add(path.name)
                            if fair_table is not None:
                                priority_table=fair_table
                            elif probe_history and not tail_state['pending']:
                                if work_ready and path==history_path and path.name in work['heads']:
                                    # This positive head came from the complete
                                    # import or this writer's committed copy.
                                    # The ordinary copy still revalidates its
                                    # proof/MAX/progress; no extra metadata page.
                                    priority_table=history_after=work['heads'][path.name]
                                else:
                                    priority_table, history_after = _account_history_candidate(
                                        local,registry,path.name,history_after,anchor,budget,resume_pending=work_ready)
                                if work_ready and path==history_path and priority_table is None:
                                    sc.save(registry,history_key,dict(after=history_after,regular_next=False))
                                    if not history_after and budget.get('history_candidate_complete') is True and path.name in work['history']:work['history'].remove(path.name)
                        if local.execute("SELECT name FROM sqlite_master WHERE name='Name2Id'").fetchone():
                            for (name,) in local.execute('SELECT user_name FROM Name2Id LIMIT 65536'):
                                if type(name) is str:
                                    table='Msg_'+hashlib.md5(name.encode()).hexdigest()
                                    name_map[table]=name if table not in name_map else None
                    finally:local.close()
                def refresh_inventory(*,publish=True):
                    nonlocal work_invalidated,operation_stage
                    operation_stage='inventory'
                    cursor.setdefault('pass_id',os.urandom(16).hex())
                    after=cursor['after'];remaining=budget['inventory']
                    scan=(path not in priority or tail_state is None or tail_state['complete'] and not tail_state['pending']) and (not cursor.get('complete') or cursor.get('refresh_requested') is True or cursor.get('cookie')!=cookie or time.time_ns()-cursor.get('checked_at_ns',0)>=300000000000)
                    tables=conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name>? ORDER BY name LIMIT ?",(after,remaining+1)).fetchall() if scan else []
                    page=tables[:remaining];members=[];proof_tables=[];prepared=[]
                    for name,ddl in page:
                        deadline.check()
                        if time.monotonic()>=budget['until']:
                            round_work.deferred(evidence,budget,'time',location='inventory');break
                        previous_after=cursor['after'];cursor['after']=name
                        if name.startswith('__walden_'):raise MirrorError('source_reserved_namespace')
                        if not sc.TABLE.fullmatch(name):continue
                        new_member=registry.execute('SELECT 1 FROM members WHERE shard=? AND table_name=?',(path.name,name)).fetchone() is None
                        if new_member:
                            work_invalidated=True
                        schema_sha=sc.sha(ddl.encode());item=dict(table=name,schema_sha256=schema_sha,username=None,supported=True,available=True,inventory_pass=cursor['pass_id'])
                        try:
                            _validate_message_cursor(conn,name)
                            item['username']=name_map.get(name)
                        except Exception as error:
                            # Missing conversation identity is not unsupported raw schema.
                            try:_validate_message_cursor(conn,name)
                            except Exception:item['supported']=False;item['reason']='unsupported_message_schema'
                        if new_member and item['supported'] and item['available']:
                            proof=dict(item,ref=sc.target_ref(config,path.name,name),source_identity=identity,header=header_hash)
                            try:receipt=copy_init.prepare_new(config,registry,path.name,name,proof,budget,_persist=False)
                            except WorkBudgetStop as error:
                                round_work.deferred(evidence,budget,'metadata',error,location='inventory')
                                cursor['after']=previous_after
                                break
                            prepared.append(receipt)
                        proof_tables.append([name,schema_sha]);members.append(item)
                    current=path.stat()
                    if [current.st_dev,current.st_ino]!=identity:raise MirrorError('source_replaced')
                    observation=dict(contract=sc.fixed(config),shard=path.name,source_identity=identity,header=header_hash,query_only=True,
                        schema_cookie=cookie,tables=proof_tables,at_ns=time.time_ns())
                    registry.execute('SAVEPOINT copy_inventory')
                    try:
                        if members:sc.register(config,registry,observation,members)
                        # These receipts were checked and fully charged before the
                        # current observation existed. Publish only the completed
                        # bounded prefix, atomically with its inventory members.
                        for receipt in prepared:
                            sc.save(registry,copy_init.key(path.name,receipt['table']),receipt)
                    except BaseException:
                        registry.execute('ROLLBACK TO copy_inventory');registry.execute('RELEASE copy_inventory')
                        raise
                    registry.execute('RELEASE copy_inventory')
                    reached_end=len(tables)<=remaining and (not page or cursor['after']==page[-1][0])
                    stable=cursor.get('pass_cookie')==cookie
                    if not scan:pass
                    elif reached_end:
                        if stable:
                            for known_table,raw in registry.execute('SELECT table_name,proof FROM members WHERE shard=?',(path.name,)).fetchall():
                                known=json.loads(raw)
                                if known.get('inventory_pass')!=cursor['pass_id']:
                                    known['available']=False;known['reason']='source_table_missing'
                                    registry.execute('UPDATE members SET proof=? WHERE shard=? AND table_name=?',(json.dumps(known,sort_keys=True),path.name,known_table))
                        cursor.update(after='',cookie=cookie,pass_cookie=cookie,complete=stable,refresh_requested=False,checked_at_ns=time.time_ns(),pass_id=os.urandom(16).hex())
                    else:cursor.update(cookie=cookie,complete=False)
                    sc.save(registry,'inventory:'+path.name,cursor)
                    if publish:_account_registry_commit(registry)
                if fair_metadata_turn:
                    _account_registry_commit(registry);transaction_observations=None
                elif init_metadata_turn:
                    # Keep both reader transactions intact for this exact owned
                    # suffix. No refresh cursor/freshness or hint is consumed.
                    evidence.add('selection','initial_suffix_metadata_reserved',target=round_work.target(path.name,init_metadata_table))
                else:
                    refresh_inventory();transaction_observations=None
                # Copy fairness is independent of the inventory pass cursor.
                copy_key = 'copy:' + path.name
                copy_after = sc.state(registry, copy_key, '')
                count=budget['tables']-budget['used_tables']
                candidates=registry.execute('SELECT table_name FROM members WHERE shard=? AND table_name>? ORDER BY table_name LIMIT ?',(path.name,copy_after,count)).fetchall()
                if not candidates and count:candidates=registry.execute('SELECT table_name FROM members WHERE shard=? ORDER BY table_name LIMIT ?',(path.name,count)).fetchall()
                if priority_table is not None and count:
                    candidates = ([(priority_table,)] + [row for row in candidates if row[0] != priority_table])[:count]
                new_tables=[row[0] for row in (tail_state or {}).get('pending',[])]
                if new_tables:
                    candidates=([(table,) for table in new_tables]
                                +[row for row in candidates if row[0] not in new_tables])[:count]
                if path in priority and tail_state is not None and not (tail_state['complete'] and not new_tables):
                    candidates=[(table,) for table in new_tables[:count]]
                # Confirmed debt on another Source cannot yield budget to history.
                other_debt=debts-{path.name}
                init_allowed=(known_debt_complete and not other_debt and not debts and not priority
                              and (tail_state is not None and tail_state.get('complete') and not tail_state.get('pending')
                                   or tail_state is None and not local_path.exists()))
                init_tables=copy_init.pending(registry,path.name,budget,after=copy_after,limit=max(1,count)) if init_allowed else []
                history_allowed=(_account_work_current(config,registry,deadline.grant,work,debts,consumed)
                                 and not work_invalidated and path==history_path
                                 if work_ready else known_debt_complete and path==chosen[-1])
                if not history_allowed or other_debt:
                    candidates=[row for row in candidates if row[0] in new_tables or row[0]==fair_table]
                if fair_table is not None:
                    candidates=([(fair_table,)]+[row for row in candidates if row[0]!=fair_table])[:count]
                if init_allowed:
                    candidates=([(table,) for table in init_tables]+[row for row in candidates if row[0] not in init_tables])[:count]
                if reconcile_request is not None:
                    candidates=[row for row in candidates if (path.name,row[0])!=(reconcile_request['shard'],reconcile_request['table'])]
                names_done=False
                copied_messages = False
                tail_attempted=set();tail_blocked=set()
                def discover_after_tail(table,index,entry):
                    nonlocal tail_state
                    if table in new_tables and tail_state is not None:
                        tail_attempted.add(table)
                        if entry is None or entry['rows']==0:tail_blocked.add(table)
                        copy_room=(time.monotonic()<budget['until'] and budget['used_tables']<budget['tables']
                                   and budget['used_rows']<budget['rows'] and budget['used_bytes']<budget['bytes'])
                        waiting=[(name,) for name,_ in tail_state['pending'] if name not in tail_blocked]
                        later_priority=any(p in priority for p in chosen[chosen.index(path)+1:])
                        defer_tail=bool(other_debt or later_priority)
                        if copy_room and (defer_tail or waiting):
                            # One batch is not proof that known tail is clear.
                            # Give later Sources their existing copy slot first;
                            # otherwise keep copying pending tables round-robin.
                            candidates[index+1:]=(waiting if not defer_tail else [])[:budget['tables']-budget['used_tables']]
                            return
                        if not defer_tail or not copy_room:
                            with closing(sqlite3.connect(readonly_database_uri(local_path),uri=True)) as local:
                                local.execute('PRAGMA query_only=ON')
                                tail_state=_account_tail_probe(config,conn,registry,path,local,anchor,budget,
                                    probe_token,copied=tail_attempted)
                            round_work.emit_probe(evidence,budget)
                            for pending_table,_ in tail_state['pending']:
                                if pending_table not in new_tables:new_tables.append(pending_table)
                            waiting=[(name,) for name,_ in tail_state['pending'] if name not in tail_attempted]
                            ordinary_left=[row for row in candidates[index+1:] if row[0] not in new_tables]
                            candidates[index+1:]=(waiting+ordinary_left)[:max(0,budget['tables']-budget['used_tables'])]
                        tail_state['pending'].sort(key=lambda row:row[0] in tail_attempted)
                        sc.save(registry,'tail_probe:'+path.name,tail_state)
                for index, (table,) in enumerate(candidates):
                    deadline.check()
                    force_history=table==fair_table
                    if not force_history and table not in new_tables and table not in init_tables and work is not None and not _account_work_current(config,registry,deadline.grant,work,debts,consumed):
                        work_invalidated=True
                        evidence.add('selection','work_proof_not_current')
                        break
                    if (time.monotonic() >= budget['until'] or budget['used_tables'] >= budget['tables'] or budget['used_rows'] >= budget['rows']
                            or budget['used_bytes'] >= budget['bytes']):
                        round_work.deferred(evidence,budget,'rows' if budget['used_rows']>=budget['rows'] else 'bytes' if budget['used_bytes']>=budget['bytes'] else 'time' if time.monotonic()>=budget['until'] else 'tables')
                        break
                    if tail_state and tail_state['pending'] and table not in new_tables and not force_history:
                        continue
                    if tail_state is not None and table in new_tables:
                        pending=tail_state['pending']
                        wanted=next(row for row in pending if row[0]==table)
                        pending.remove(wanted)
                        pending.append(wanted)
                        sc.save(registry,'tail_probe:'+path.name,tail_state)
                    from . import native_registry_reuse as reuse
                    shared_observation=(transaction_observations if init_metadata_turn and index==0 and table==init_metadata_table and conn.in_transaction and registry.in_transaction else None)
                    if reuse.descriptor(config,registry) is not None:
                        preview=registry.execute('SELECT proof FROM members WHERE shard=? AND table_name=?',(path.name,table)).fetchone()
                        if preview is not None:
                            copy_init.charge(budget,len(preview[0].encode())+(0 if shared_observation is not None and json.loads(preview[0])['observation']in shared_observation else reuse.observation_size(config,registry,json.loads(preview[0])['observation'])))
                    _diagnostic_stage='copy_guard'
                    proof=sc.member(config,registry,path.name,table,_observations=shared_observation)
                    transaction_observations=None  # Never reuse after this candidate's COMMIT.
                    if index == 0 and table not in new_tables:
                        # With only one slot, alternate a history attempt with the ordinary cursor.
                        next_history = {'after': history_after, 'regular_next': table == priority_table}
                        if next_history != history_cursor:
                            sc.save(registry, history_key, next_history)
                    previous_copy = copy_after
                    if table != priority_table and table not in new_tables:
                        copy_after = table
                        sc.save(registry, copy_key, copy_after)
                    budget['used_tables']+=1
                    if not proof.get('supported'):result['gaps'].append('unsupported_message_schema');continue
                    ddl_row=conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
                    if ddl_row is None:
                        proof['available']=False;proof['reason']='source_table_missing'
                        registry.execute('UPDATE members SET proof=? WHERE shard=? AND table_name=?',(json.dumps(proof,sort_keys=True),path.name,table))
                        result['gaps'].append('source_table_missing');continue
                    if sc.sha(ddl_row[0].encode())!=proof['schema_sha256']:raise MirrorError('source_schema_changed')
                    from . import native_reconcile_current as current_reconcile
                    if current_reconcile.withheld(config,registry,budget.get('_current_reconcile_request'),path,table,proof,conn,identity,ddl_row[0],budget):
                        result.setdefault('account_copy_withheld',[]).append(dict(target_ref=proof['ref'],reason='authorization_required',coverage='unknown',complete=False,current_verified=True))
                        evidence.add('selection','unowned_copy_withheld',target=proof['ref'])
                        work_invalidated=True
                        continue
                    key=SourceKey(config['account_id'],config['source_generation'],path.name,table)
                    _diagnostic_stage='local_open'
                    store=copy_init.open_store(config,registry,proof,key,budget,witness=witness)
                    if store is None:continue
                    _diagnostic_stage='source_max'
                    maximum=_account_source_read(conn,'SELECT coalesce(max(local_id),0) FROM '+qi(table),stage='source_copy',phase=_diagnostic_stage).fetchone()[0]
                    _diagnostic_stage='local_prepare'
                    initial = store.progress(table)
                    held = cursor_recovery.pending(registry, path.name, table)
                    newly_paused = False
                    required_target = next((wanted for name,wanted in (tail_state or {}).get('pending',[]) if name==table),0)
                    attributed = (proof.get('available') is True and initial is not None
                                  and initial.get('source_identity') == identity
                                  and initial.get('source_header_sha256') == header_hash)
                    if attributed and held is not None and held['epoch'] != initial.get('cursor_epoch',0):
                        if held['epoch'] >= initial.get('cursor_epoch',0):
                            raise MirrorError('scope_copy_proof')
                        cursor_recovery.set_pending(registry,path.name,table,None)
                        held=None;required_target=0
                    if not cursor_recovery.valid_max(maximum) or (attributed and maximum < max(cursor_recovery.floor(initial),required_target)):
                        if not attributed:
                            raise MirrorError('source_cursor_regression')
                        _validate_message_cursor(conn,table)
                        newly_paused = held is None
                        cursor_recovery.mark(registry,path.name,table,maximum,initial,wanted=required_target)
                        held=cursor_recovery.pending(registry,path.name,table)
                    if held is not None and not attributed:
                        raise MirrorError('scope_copy_proof')
                    initial=copy_init.prepare_local(config,registry,proof,store,key,ddl_row[0],maximum,budget)
                    if initial is None:continue
                    if initial.get('cursor_epoch') and force_history and held is None:
                        with closing(store.connect()) as local:
                            rotation_history=cursor_recovery.archives(local,table,initial)
                        force_history=round_work.recover_generation_head(registry,path.name,table,initial,rotation_history,budget)
                    if held is not None and (newly_paused or not cursor_recovery.valid_max(maximum) or (path.name,table) in budget['_cursor_attempted']):
                        budget['_cursor_attempted'].add((path.name,table))
                        if tail_state is not None and table in new_tables:
                            tail_state['pending'][:]=[row for row in tail_state['pending'] if row[0]!=table]
                            sc.save(registry,'tail_probe:'+path.name,tail_state)
                            discover_after_tail(table,index,None)
                        continue
                    if force_history and budget['_fair_turn']['streak']<round_work.MAX_TAIL and tail_state and tail_state['pending']:
                        fair_table=None;fair_path=None
                        evidence.add('selection','tail_priority')
                        continue
                    would_history=held is None and initial['history']<initial['H'] and initial['tail']>=maximum
                    if would_history and not (force_history and budget['_fair_turn']['streak']>=round_work.MAX_TAIL):
                        latest,_=_account_tail_hints(config,deadline.grant)
                        if any(value>hints.get(name,0) for name,value in latest.items()):
                            evidence.add('selection','hint_changed');work_invalidated=True
                            break
                    _diagnostic_stage='local_schema'
                    store.ensure_table(key,ddl_row[0])
                    _diagnostic_stage='source_indexes'
                    _copy_indexes(conn,store,table)
                    # Refresh sender mapping once per shard through bounded rowid pages.
                    if not names_done:
                        _diagnostic_stage='sender_schema'
                        ddl=conn.execute("SELECT sql FROM sqlite_master WHERE name='Name2Id' AND type='table'").fetchone()
                        if ddl is None:raise MirrorError('sender_mapping_missing')
                        nk=SourceKey(key.account_id,key.source_generation,key.shard_name,'Name2Id');store.ensure_table(nk,ddl[0])
                        ncur=sc.state(registry,'names:'+path.name,None)
                        columns=[(r[1],r[2].upper()) for r in conn.execute('PRAGMA table_info(Name2Id)')]
                        if not columns or len(columns)>128:raise MirrorError('unsupported_sender_schema')
                        expression='+'.join('coalesce(length(CAST('+qi(c)+' AS BLOB)),0)' for c,_ in columns)
                        count=min(256,max(1,(budget['rows']-budget['used_rows'])//4))
                        where='' if ncur is None else ' WHERE rowid>?'
                        sizes=conn.execute('SELECT rowid,('+expression+') FROM Name2Id'+where+' ORDER BY rowid LIMIT ?',((count,) if ncur is None else (ncur,count))).fetchall()
                        selected=[];size=0;last=ncur;bad=set(sc.state(registry,'names_oversize:'+path.name,[]))
                        for rowid,payload_size in sizes:
                            deadline.check();payload_size+=64*len(columns)
                            if payload_size>budget['bytes']:
                                bad.add(rowid);last=rowid;result['gaps'].append('name2id_row_oversize');continue
                            if budget['used_bytes']+size+payload_size>budget['bytes']:break
                            selected.append(rowid);size+=payload_size;last=rowid;bad.discard(rowid)
                        if len(bad)>4096:raise MirrorError('sender_oversize_inventory_limit')
                        sc.save(registry,'names_oversize:'+path.name,sorted(bad))
                        names=[]
                        _diagnostic_stage='sender_rows'
                        if selected:
                            with lossless_text_rows(conn):
                                names=conn.execute('SELECT rowid,* FROM Name2Id WHERE rowid IN ('+','.join('?' for _ in selected)+') ORDER BY rowid',tuple(selected)).fetchall()
                        with store.connect() as local,lossless_text_rows(local):
                            for row in names:
                                old=local.execute('SELECT rowid,* FROM Name2Id WHERE rowid=?',(row[0],)).fetchone()
                                if old is not None and not _sender_mapping_matches(old,row,columns):raise MirrorError('sender_identity_conflict')
                        result['rows_written']+=store.apply_batch(nk,'Name2Id',names,{})
                        budget['used_rows']+=len(sizes);budget['used_bytes']+=size
                        sc.save(registry,'names:'+path.name,last if sizes else None);names_done=True
                        if not sizes and ncur is not None:
                            inventory=sc.state(registry,'inventory:'+path.name,{})
                            inventory['refresh_requested']=True;sc.save(registry,'inventory:'+path.name,inventory)
                    operation_stage='source_copy'
                    acknowledged=round_work.prepare(registry,path.name,table,initial,budget,history=force_history and held is None,proof=proof)
                    if acknowledged=='history_already_committed':
                        _account_registry_commit(registry)
                        evidence.add('selection','recovered_history_commit',target=round_work.target(path.name,table))
                        fair_table=None;fair_path=None
                        continue
                    selected_kind='fair_history' if force_history else 'suffix' if initial.get('initial_suffix_pending') and initial['tail']>=maximum else 'tail' if initial['tail']<maximum else 'history' if would_history else 'recent'
                    evidence.add('source_read',selected_kind,target=round_work.target(path.name,table))
                    try:
                        from .native_reconcile_current import copy_guard
                        with copy_guard(config,registry,path,table,budget)as current_check:
                            entry=_account_copy_table(config,conn,path,table,store,identity,header_hash,budget,
                                                      registry=registry, media_username=proof.get('username') or proof['ref'],force_history=force_history and held is None,commit_check=current_check,_verified=attributed,preview_allowed=bool(proof.get('username')))
                    except cursor_recovery.Paused:
                        cursor_recovery.mark(registry,path.name,table,maximum,initial,wanted=required_target)
                        budget['_cursor_attempted'].add((path.name,table))
                        entry=None
                    finally:round_work.release(budget)
                    if cursor_recovery.pending(registry,path.name,table) is not None and tail_state is not None and table in new_tables:
                        tail_state['pending'][:]=[row for row in tail_state['pending'] if row[0]!=table]
                        sc.save(registry,'tail_probe:'+path.name,tail_state)
                    if entry is None:
                        deferral=budget.pop('_copy_deferral',None)
                        if deferral is not None:round_work.deferred(evidence,budget,deferral['reason'],location='copy_rows',fact=deferral)
                        discover_after_tail(table,index,entry)
                        if copied_messages and table != priority_table and table not in new_tables:
                            # Retry a table displaced by prior messages as the next ordinary head.
                            sc.save(registry, copy_key, previous_copy)
                            sc.save(registry, history_key, {'after': history_after, 'regular_next': True})
                            break
                        continue
                    if entry['batch_kind']=='cursor_generation':
                        work_invalidated=True
                    copied_messages = copied_messages or entry['rows'] > 0
                    result['sources'].append(dict(shard=path.name,table=table,**entry['progress']))
                    result['rows_read']+=entry['rows'];result['rows_written']+=entry['written'];result['committed_message_rows']+=entry['written']
                    if entry.get('preview_key'):
                        preview_hint=(path.name,entry['preview_key'])
                    evidence.add('local_commit',entry['batch_kind'],target=round_work.target(path.name,table),rows=entry['rows'],written=entry['written'],H=entry['progress']['H'],history=entry['progress']['history'],tail=entry['progress']['tail'])
                    round_work.committed(registry,path.name,table,entry,budget)
                    _account_registry_commit(registry)
                    registry.execute('SAVEPOINT copy_finish')
                    try:copy_init.finish(registry,path.name,table,entry['progress'],budget)
                    except BaseException:
                        registry.execute('ROLLBACK TO copy_finish');registry.execute('RELEASE copy_finish')
                        raise
                    registry.execute('RELEASE copy_finish')
                    handoff=bool(budget['_fair_heads']) and entry['batch_kind']=='tail' and entry['tail_advanced'] and budget['_fair_turn']['streak']>=round_work.MAX_TAIL
                    if force_history:
                        fair_table=None;fair_path=None
                        if fair_metadata_turn:
                            fair_handoff=True
                            with closing(sqlite3.connect(readonly_database_uri(local_path),uri=True)) as local:
                                local.execute('PRAGMA query_only=ON')
                                tail_state=_account_tail_probe(config,conn,registry,path,local,anchor,budget,probe_token)
                            round_work.emit_probe(evidence,budget)
                            if (tail_state.get('complete') and not tail_state.get('pending')
                                    and time.monotonic()<budget['until'] and budget['tail_probe']['bytes']<budget['tail_probe']['ceiling']):
                                # Same original inventory page, moved after the
                                # committed H. Finally publishes it: no added
                                # registry COMMIT or extra Source connection.
                                refresh_inventory(publish=False)
                    if path in priority and (entry['batch_kind']=='tail' and entry['rows']>0 or entry['progress']['tail']>=entry['progress']['target']):
                        sc.save(registry,'tail_shard_after',path.name)
                    if tail_state is not None and table in new_tables:
                        pending=tail_state['pending']
                        wanted=next((row for row in pending if row[0]==table),None)
                        if wanted is not None:
                            pending.remove(wanted)
                            target=entry['progress']['target'] if entry['batch_kind']=='cursor_generation' else max(wanted[1],entry['progress']['target'])
                            if entry['progress']['tail']<target:
                                pending.append([table,target])
                        sc.save(registry,'tail_probe:'+path.name,tail_state)
                    elif entry['progress']['target']>entry['progress']['tail'] and cursor_recovery.pending(registry,path.name,table) is None:
                        tail_state=tail_state or dict(after='',pending=[],complete=False)
                        tail_state['pending'].append([table,entry['progress']['target']])
                        new_tables.append(table)
                        sc.save(registry,'tail_probe:'+path.name,tail_state)
                    if work_ready and table not in new_tables:
                        if entry['progress']['history']<entry['progress']['H']:
                            work['heads'][path.name]=table
                        elif work['heads'].get(path.name)==table:
                            work['heads'].pop(path.name)
                    discover_after_tail(table,index,entry)
                    if fair_handoff:break
                    if handoff:
                        fair_handoff=True;evidence.add('selection','fair_history_next')
                        break
                _account_registry_commit(registry)
                if tail_state is not None:
                    if tail_state['pending']:
                        debts.add(path.name)
                    else:
                        debts.discard(path.name)
                    if path in priority and not tail_state['pending'] and tail_probe_progress:
                        sc.save(registry,'tail_shard_after',path.name)
                    if tail_state['complete'] and not tail_state['pending'] and (work is None or cursor.get('complete') is True):
                        consumed['shards'][path.name]=hints.get(path.name,0)
                        sc.save(registry,'tail_hints',consumed)
                        if path in priority and not new_tables:
                            # False hints yield a discovery turn, including a new
                            # event after this observation. Real queued debt bypasses it.
                            quiet[path.name]=round_number+1
                            sc.save(registry,'tail_hint_quiet',quiet)
                    if path.name in discovery and not tail_state['pending']and not tail_state['complete']:
                        # A recovery hint is not a confirmed message backlog.
                        # Reuse the existing one-round quiet turn so incomplete
                        # discovery cannot permanently displace verified H.
                        quiet[path.name]=round_number+1;sc.save(registry,'tail_hint_quiet',quiet)
                        evidence.add('selection','discovery_page_deferred',target=__import__('hashlib').sha256(path.name.encode()).hexdigest())
                    result['new_tail']['probe_complete'] &= tail_state['complete']
                elif path in priority:
                    # New/uncopied members require ordinary inventory and initial
                    # history. Do not pin an unverified hint at the priority head.
                    consumed['shards'][path.name]=hints.get(path.name,0)
                    sc.save(registry,'tail_hints',consumed)
                    quiet[path.name]=round_number+1
                    sc.save(registry,'tail_hint_quiet',quiet)
                    result['new_tail']['inventory_fallback']=True
                if len(result['gaps'])==shard_gap_start:
                    verified_media_sources[path.name]=dict(source_identity=identity,header=header_hash)
                    if work is not None and tail_state is not None and tail_state['complete'] and cursor.get('complete') is True:
                        work['verified'][path.name]=tail_state.get('token')
                    if sc.state(registry,'source_retry:'+path.name) is not None:
                        sc.save(registry,'source_retry:'+path.name,None)
            except WorkBudgetStop as error:
                round_work.deferred(evidence,budget,'metadata_or_witness',error)
                if tail_state is not None and tail_state['pending']:debts.add(path.name)
                elif tail_state is not None:debts.discard(path.name)
                result['new_tail']['work_budget_limited']=True
                break
            except WorkChanged:
                if time.monotonic()>=budget['until']:round_work.deferred(evidence,budget,'time')
                else:evidence.add('selection','work_proof_not_current')
                reconcile_required=True;work_invalidated=True
                if registry_witness is not None and registry_witness.owner.changed:
                    registry_witness.suspend();registry_witness=None
                break
            except _AccountShardBusy as error:
                deadline.check()
                _account_record_retry(config,registry,path.name,deadline.grant,error.diagnostic)
                if 'source_shard_retry_pending' not in result['gaps']:result['gaps'].append('source_shard_retry_pending')
                result.setdefault('shard_diagnostics',[]).append(error.diagnostic)
            except Exception as error:
                if getattr(registry,'guard',False) and not registry.guard_valid:raise
                deadline.check();result['gaps'].append(str(error) if isinstance(error,MirrorError) else 'source_unavailable_or_unsupported')
                result.setdefault('shard_diagnostics',[]).append(_account_error_info(error,operation_stage))
            finally:
                if conn is not None:conn.close()
                if not getattr(registry,'guard',False) or registry.guard_valid:
                    sc.save(registry,'gaps:'+path.name,result['gaps'][shard_gap_start:])
                    try:_account_registry_commit(registry)
                    except WorkChanged:
                        reconcile_required=True;work_invalidated=True
                        if registry_witness is not None:registry_witness.suspend();registry_witness=None
        sc.save(registry,'shard_cursor',(offset+1)%max(1,len(paths)));sc.save(registry,'roster',sorted(set(prior)|set(roster)))
        retrying_shards=sum(_account_retry_state(config,registry,path.name,deadline.grant) is not None for path in paths)
        if retrying_shards:
            if 'source_shard_retry_pending' not in result['gaps']:result['gaps'].append('source_shard_retry_pending')
            result['partial_source']=dict(successful_shards=len(verified_media_sources),retrying_shards=retrying_shards)
        paused_tables=cursor_recovery.count_pending(registry)
        if paused_tables:
            result['gaps'].append(cursor_recovery.PENDING)
            result['partial_source']=dict(successful_shards=len(verified_media_sources),
                                          retrying_shards=retrying_shards, paused_tables=paused_tables)
        result['new_tail'].update(metadata_tables=budget['tail_probe']['tables'],
            metadata_bytes=budget['tail_probe']['bytes'],probe_limited=budget['tail_probe']['limited'],
            remaining_known_debt_shards=len(debts))
        if (not management and not reconcile_required and known_debt_complete and not debts and not retrying_shards and sc.state(registry,'aux_due',False)
                and not budget.get('_copy_init_stopped') and time.monotonic()<budget['until'] and budget['tail_probe']['bytes']<budget['tail_probe']['ceiling']):
            try:
                aux=_account_aux(config,registry,budget,connection_factory)
                result['source_opens']+=aux['opens'];result['rows_read']+=aux['rows'];result['rows_written']+=aux['written']
                result['directory_snapshot']=aux['status']
                sc.save(registry,'aux_due',False)
            except Exception:
                deadline.check();result['directory_snapshot']='unavailable_or_unsupported'
        sc.save(registry,'last_shard_diagnostics',result.get('shard_diagnostics',[]))
        if not reconcile_required:
            try:
                if registry_witness is not None:registry_witness.prepare_commit()
                _account_work_finish(config,registry,paths,budget,deadline.grant,work,
                    clean=not result['gaps'] and not work_invalidated,
                    complete=known_debt_complete and sc.state(registry,'history_backlog_scan',{}).get('complete') is True,
                    witness=witness,registry_witness=registry_witness)
            except WorkChanged:reconcile_required=True
        if reconcile_required:
            if registry_witness is not None and registry_witness.owner.changed:
                registry_witness.suspend();registry_witness=None
            invalid=dict(work or {},ready=False,imported=False,reconcile=True)
            if witness is not None:invalid['pins']={name:dict(work['pins'][name],**witness.expected[str(root/name)]) for name in work['pins']}
            sc.save(registry,'account_work',invalid)
            sc.save(registry,'tail_debt_cursor',dict(shard='',table=''));sc.save(registry,'history_backlog_scan',{})
            result['new_tail'].update(incremental_work_ready=False,work_reconcile_required=True,probe_complete=False,known_debt_import_complete=False)
        result['new_tail'].update(metadata_tables=budget['tail_probe']['tables'],metadata_bytes=budget['tail_probe']['bytes'])
        sc.save(registry,'last_tail_probe',result['new_tail'])
        sc.save(registry,'last_attempt',dict(at_ns=time.time_ns(),gaps=sorted(set(result['gaps']))))
        if not reconcile_required:round_work.finish(registry,budget)
        try:_account_registry_commit(registry)
        except WorkChanged:
            reconcile_required=True
            if registry_witness is not None:registry_witness.suspend();registry_witness=None
            sc.save(registry,'account_work',dict(work or {},ready=False,imported=False,reconcile=True))
            sc.save(registry,'tail_debt_cursor',dict(shard='',table=''));sc.save(registry,'history_backlog_scan',{})
            result['new_tail'].update(incremental_work_ready=False,work_reconcile_required=True,probe_complete=False,known_debt_import_complete=False,metadata_bytes=budget['tail_probe']['bytes'])
            sc.save(registry,'last_tail_probe',result['new_tail']);_account_registry_commit(registry)
        terminal_started=time.monotonic()
        terminal_ok=False
        try:
            sc.query_scope_guard(config,before);deadline.check();terminal_ok=True
            if result.get('partial_source') and not reconcile_required and deadline.grant['kind']=='active':
                result['media_sources']=verified_media_sources
            if (preview_hint is not None and not reconcile_required and not management
                    and deadline.grant['kind']=='active' and preview_hint[0] in verified_media_sources):
                shard,key = preview_hint
                result['image_preview_hint']=dict(shard=shard,key=key,anchor=verified_media_sources[shard])

        finally:
            evidence.add('terminal','authorization_checked' if terminal_ok else 'authorization_failed',duration_ms=max(0,int((time.monotonic()-terminal_started)*1000)))
        # A committed batch is not a whole-account coverage certificate. The
        # independent account-status entry retains its original bounded check.
        known_backlog=bool(debts or paused_tables or budget.get('_fair_heads') or reconcile_required or result['new_tail'].get('work_budget_limited'))
        status=dict(check='not_run',completeness='unknown',current_snapshot_complete=False,raw_messages_complete=False,known_backlog=known_backlog,backlog_state='known' if known_backlog else 'unknown',atomic_global_snapshot=False)
        evidence.add('terminal','independent_status_not_run',committed_rows=result['rows_written'],committed_message_rows=result['committed_message_rows'])
    result['account_scope']=status
    result['round_diagnostics']=evidence.result()
    result['follow_observation']=dict(observation_id=os.urandom(16).hex(),complete=False,completeness='unknown',status_check='not_run',prior_coverage_unknown=None,known_backlog=status['known_backlog'],backlog_state=status['backlog_state'],committed_rows=result['rows_written'],committed_message_rows=result['committed_message_rows'],watermarks=[],atomic_global_snapshot=False,final_completeness='not_promised',new_tail=result['new_tail'])
    result['elapsed_seconds']=20.-max(0,budget['until']-time.monotonic());return result


def _account_copy_table(config,conn,path,table,store,identity,header_hash,budget,*,registry,media_username,commit_check=None,force_history=False,_verified=False,preview_allowed=False):
    """Copy a batch, or defer when the remaining budget prevents row progress."""
    budget.pop('_copy_deferral',None)
    key=SourceKey(config['account_id'],config['source_generation'],path.name,table)
    _diagnostic_stage='local_progress'
    progress=store.progress(table)
    _diagnostic_stage='source_max'
    maximum=_account_source_read(conn,'SELECT coalesce(max(local_id),0) FROM '+qi(table),stage='source_copy',phase=_diagnostic_stage).fetchone()[0]
    if progress is None:raise MirrorError('account_copy_init_unknown')
    before_history,before_tail=progress['history'],progress['tail']
    prior_media_max=progress.get('target');prior_media_check=progress.get('checked_at')
    if progress.get('source_identity')!=identity or progress.get('source_header_sha256')!=header_hash:raise MirrorError('source_replaced')
    if not _verified:
        if progress.get('cursor_epoch'):
            raise MirrorError('scope_copy_proof')
        if not cursor_recovery.valid_max(maximum) or maximum<max(progress['H'],progress['tail']):
            raise MirrorError('source_cursor_regression')
    prior = dict(progress)
    def promote_registry():
        from . import native_scope_contract as sc
        if sc.registry_schema(registry) == 1:
            # The old writer refuses this registry on its normal sealed
            # admission path. Commit under the original lock before touching
            # an old or new message generation.
            sc.save(registry,'shard_anchor_schema',2)
            _account_registry_commit(registry)
    def read_source(sql,params):
        return _account_source_read(conn,sql,params,stage='source_copy',phase='source_rows')
    if _verified:
        if not conn.in_transaction:
            raise MirrorError('source_transaction_changed')
        if not cursor_recovery.valid_max(maximum):
            raise cursor_recovery.Paused(cursor_recovery.PENDING)
        state=cursor_recovery.pending(registry,path.name,table)
        if state is not None or maximum<cursor_recovery.floor(progress):
            _validate_message_cursor(conn,table)
            budget.setdefault('_cursor_attempted',set()).add((path.name,table))
            columns=[r[1] for r in _account_source_read(conn,'PRAGMA table_info('+qi(table)+')',stage='source_copy',phase='source_columns')]
            if not columns or len(columns)>128:raise MirrorError('unsupported_message_schema')
            entry,remaining=cursor_recovery.recover(conn,path,store,key,table,columns,prior,maximum,
                state or dict(after=0,through=None,blocked=False,target=cursor_recovery.floor(prior),epoch=prior.get('cursor_epoch',0)),budget,int(config.get('mirror_batch_size',500)),commit_check,read_source,
                budget.get('_cursor_snapshot'),promote_registry)
            cursor_recovery.set_pending(registry,path.name,table,remaining)
            return entry
    initial=progress.get('initial_suffix_pending') is True
    history_backlog=progress['history']<progress['H'];tail_backlog=progress['tail']<maximum
    if force_history and (not history_backlog or initial):raise MirrorError('scope_copy_proof')
    turn=progress.get('account_turn',0);history=history_backlog and (force_history or not tail_backlog)
    suffix=initial and not tail_backlog
    recent=not initial and not history_backlog and not tail_backlog
    progress['account_turn']=turn+1
    if recent:
        window=dict(progress.get('account_recent') or dict(after=0,through=maximum,since=int(time.time())-86400))
        after=window['after'];through=window['through']
    else:after=progress['history'] if history else progress['tail'];through=progress['H'] if history else maximum
    count=min(500,int(config.get('mirror_batch_size',500)),budget['rows']-budget['used_rows'])
    if count <= 0:
        budget['_copy_deferral']=dict(reason='rows',kind='rows',limit=budget['rows'],used=budget['used_rows'],required=1)
        return None
    _diagnostic_stage='source_columns'
    table_columns=[r[1] for r in _account_source_read(conn,'PRAGMA table_info('+qi(table)+')',stage='source_copy',phase=_diagnostic_stage)]
    if len(table_columns)>128:raise MirrorError('unsupported_message_schema')
    row_size='+'.join('coalesce(length(CAST('+qi(c)+' AS BLOB)),0)' for c in table_columns)
    predicate=' AND create_time>='+str(window['since']) if recent else ''
    if suffix:after=0;through=progress['H']
    _diagnostic_stage='source_candidates'
    candidates=_account_source_read(conn,'SELECT local_id,('+row_size+'),0 FROM '+qi(table)+' WHERE local_id>? AND local_id<=?'+predicate+' ORDER BY local_id'+(' DESC' if suffix else '')+' LIMIT ?',(after,through,count),stage='source_copy',phase=_diagnostic_stage).fetchall()
    ids=[];estimate=0
    for local_id,body,source in candidates:
        check_deadline()
        size=body+source+4096
        if size>budget['bytes']:raise MirrorError('account_row_oversize')
        if budget['used_bytes']+estimate+size>budget['bytes']:break
        ids.append(local_id);estimate+=size
    if candidates and not ids:
        budget['_copy_deferral']=dict(reason='bytes',kind='row_bytes',limit=budget['bytes'],used=budget['used_bytes'],required=candidates[0][1]+candidates[0][2]+4096)
        return None
    rows=[]
    _diagnostic_stage='source_rows'
    if ids:
        with lossless_text_rows(conn):
            rows=_account_source_read(conn,'SELECT rowid,* FROM '+qi(table)+' WHERE local_id IN ('+','.join('?' for _ in ids)+') ORDER BY local_id',tuple(ids),stage='source_copy',phase=_diagnostic_stage).fetchall()
    _diagnostic_stage='source_columns'
    columns=[r[1] for r in conn.execute('PRAGMA table_info('+qi(table)+')')];local_index=columns.index('local_id')+1;time_index=columns.index('create_time')+1
    now=int(time.time())
    if any(type(row[time_index]) is not int or not 0<=row[time_index]<=now for row in rows):raise MirrorError('invalid_message_time')
    if suffix:
        progress['initial_suffix_pending']=False
        progress['account_recent_pending']=True
    elif recent:
        if rows:window['after']=rows[-1][local_index]
        if not candidates:
            progress.update(account_recent=None,account_recent_pending=False,rechecked_since=window['since'],account_recent_checked_at=now)
        else:progress.update(account_recent=window,account_recent_pending=True)
    else:
        if rows:progress['history' if history else 'tail']=rows[-1][local_index]
        elif not candidates:progress['history' if history else 'tail']=through
        progress['account_recent_pending']=True
    progress.update(history_complete=not progress.get('initial_suffix_pending') and progress['history']>=progress['H'],checked_at=now,target=maximum)
    progress.pop('recent_observation',None)
    _diagnostic_stage='copy_guard'
    current=path.stat()
    if [current.st_dev,current.st_ino]!=identity:raise MirrorError('source_replaced')
    _diagnostic_stage='local_prepare'
    written,rotation=cursor_recovery.write(conn,path,store,key,table,columns,rows,prior,progress,maximum,commit_check,
        verified=_verified,budget=budget,read_source=read_source,promote=promote_registry,reserved=estimate)
    if rotation is not None:
        budget['used_rows']+=len(rows);budget['used_bytes']+=estimate
        return rotation
    # This call owns its transaction (no external _connection): returning
    # means rows+PG physically committed, even if the next guard rejects.
    _diagnostic_stage='copy_guard';_diagnostic_committed=True
    preview_key=None
    if rows and not progress.get('cursor_epoch'):
        check_deadline()
        try:
            from .native_media_work import enqueue_rows
            from .native_scope_contract import _registry_page_size
            # Reuse the member already verified under this writer lock.
            _registry_page_size(registry)
            arrival=None
            if (_verified and written and not initial and not history and not recent and type(prior_media_max)is int
                    and before_tail==prior_media_max and type(prior_media_check)is int
                    and 0<=prior_media_check<now):
                arrival=dict(kind='tail_increment',before_tail=before_tail,prior_max=prior_media_max,
                             through_tail=progress['tail'],prior_checked_at=prior_media_check,observed_at=now)
            if arrival and preview_allowed and config.get('image_database') and config.get('image_attachments_root'):
                preview_key=enqueue_rows(config,path.name,table,media_username,columns,rows,arrival=arrival,preview=True)
            else:
                enqueue_rows(config,path.name,table,media_username,columns,rows,**({'arrival':arrival}if arrival else{}))
        except Exception:
            check_deadline()
    budget['used_rows']+=len(rows);budget['used_bytes']+=estimate
    return dict(progress=progress,rows=len(rows),written=written,batch_kind='suffix' if suffix else 'history' if history else 'recent' if recent else 'tail',history_advanced=progress['history']>before_history,tail_advanced=progress['tail']>before_tail,preview_key=preview_key)


def _account_aux(config,registry,budget,connection_factory):
    """Bounded contact/session snapshot staging; never publish partial tables."""
    from . import native_scope_contract as sc
    from .live_readonly import readonly_database_uri
    result=dict(opens=0,rows=0,written=0,status='unconfigured')
    options=[(field,name) for field,name in [('encrypted_contact_database','contact.db'),('session_database','session.db')] if config.get(field)]
    if not options:return result
    turn=sc.state(registry,'aux_turn',0);field,name=options[turn%len(options)];path=Path(config[field]).resolve()
    source_root=Path(config['live_db_root']).resolve()
    if source_root not in path.parents:raise MirrorError('auxiliary_source_outside_root')
    stamp=path.stat();identity=[stamp.st_dev,stamp.st_ino];conn=None
    try:
        check_deadline();conn=connection_factory(path);result['opens']=1
        if conn.execute('PRAGMA query_only').fetchone()!=(1,):raise MirrorError('source_not_readonly')
        conn.execute('BEGIN');cookie=conn.execute('PRAGMA schema_version').fetchone()[0]
        state=sc.state(registry,'aux:'+name,None)
        if state is None:
            state=dict(source_identity=identity,cookie=cookie,table_after='',table=None,rowid=None,stage='.account-aux-'+os.urandom(12).hex()+'.db')
        if state['source_identity']!=identity or state['cookie']!=cookie:raise MirrorError('auxiliary_source_replaced')
        if state['table'] is None:
            row=conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name>? ORDER BY name LIMIT 1",(state['table_after'],)).fetchone()
            if row is None:
                # Completed all staged tables. Backup copies the complete local
                # staged SQLite snapshot; no Source-wide fetchall is performed.
                stage=Path(config['mirror_root'])/state['stage'];destination=Path(config['mirror_root'])/name
                if stage.exists():
                    from .native_scope_contract import _safe
                    _safe(stage)
                    if not destination.exists():
                        fd=os.open(destination,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
                    _safe(destination)
                    source=sqlite3.connect(readonly_database_uri(stage),uri=True);target=sqlite3.connect(destination)
                    try:source.execute('PRAGMA query_only=ON');source.backup(target);target.commit()
                    finally:source.close();target.close()
                sc.save(registry,'aux:'+name,None);sc.save(registry,'aux_turn',turn+1);sc.save(registry,'aux_complete:'+name,dict(checked_at=int(time.time()),source_identity=identity,non_atomic_snapshot=True));_account_registry_commit(registry)
                if stage.exists():
                    import re
                    canonical=Path(config['mirror_root']).absolute()
                    if stage.absolute().parent!=canonical or re.fullmatch(r'\.account-aux-[0-9a-f]{24}\.db',stage.name) is None:raise MirrorError('auxiliary_stage_path')
                    sc._safe(stage)
                    from .native_scope_add import directory
                    with directory(canonical) as parent:os.unlink(stage.name,dir_fd=parent);os.fsync(parent)
                result['status']='complete';return result
            table,ddl=row
            if table.startswith('__walden_'):raise MirrorError('source_reserved_namespace')
            if 'WITHOUT ROWID' in ddl.upper():raise MirrorError('unsupported_auxiliary_cursor')
            state.update(table=table,rowid=None,ddl=ddl)
        table=state['table'];key=SourceKey(config['account_id'],config['source_generation'],name,table)
        store=MirrorStore(Path(config['mirror_root'])/state['stage'],key);store.ensure_table(key,state['ddl'])
        count=min(128,budget['rows']-budget['used_rows']);rows=[];size=0
        if count<=0:return result
        # SQLite cursor iteration bounds simultaneous rows; stop on the global
        # byte budget as well as row/time budget, leaving exact durable rowid.
        columns=[r[1] for r in conn.execute('PRAGMA table_info('+qi(table)+')')]
        if not columns or len(columns)>128:raise MirrorError('unsupported_auxiliary_schema')
        size_expr='+'.join('coalesce(length(CAST('+qi(c)+' AS BLOB)),0)' for c in columns)
        selection=[];estimate=0
        where='' if state['rowid'] is None else ' WHERE rowid>?'
        row_args=() if state['rowid'] is None else (state['rowid'],)
        for rowid,n in conn.execute('SELECT rowid,('+size_expr+') FROM '+qi(table)+where+' ORDER BY rowid LIMIT ?',row_args+(count,)):
            check_deadline();n+=64*len(columns)
            if n>budget['bytes']:raise MirrorError('auxiliary_row_oversize')
            if budget['used_bytes']+estimate+n>budget['bytes'] or time.monotonic()>=budget['until']:break
            selection.append(rowid);estimate+=n
        selected_sql='SELECT rowid,* FROM '+qi(table)+' WHERE rowid IN ('+','.join('?' for _ in selection)+') ORDER BY rowid'
        with lossless_text_rows(conn):
            for row in conn.execute(selected_sql if selection else 'SELECT rowid,* FROM '+qi(table)+' WHERE 0',tuple(selection)):
                check_deadline()
                n=len(repr(row).encode())
                if n>budget['bytes']:raise MirrorError('auxiliary_row_oversize')
                if budget['used_bytes']+size+n>budget['bytes'] or time.monotonic()>=budget['until']:break
                rows.append(row);size+=n
        current=path.stat()
        if [current.st_dev,current.st_ino]!=identity:raise MirrorError('auxiliary_source_replaced')
        result['written']=store.apply_batch(key,table,rows,dict(checked_at=int(time.time()),source_identity=identity))
        budget['used_rows']+=len(rows);budget['used_bytes']+=size;result['rows']=len(rows)
        if rows:state['rowid']=rows[-1][0]
        else:
            where='' if state['rowid'] is None else ' WHERE rowid>?'
            row_args=() if state['rowid'] is None else (state['rowid'],)
            remaining=conn.execute('SELECT 1 FROM '+qi(table)+where+' LIMIT 1',row_args).fetchone()
            if remaining is None:state.update(table_after=table,table=None,rowid=None)
        sc.save(registry,'aux:'+name,state);_account_registry_commit(registry);result['status']='pending';return result
    finally:
        if conn is not None:conn.close()

_register(_account_registry_commit,_account_budget,_account_history_candidate,_account_sync,_account_copy_table,_account_aux,
          _account_sqlite_types,_account_error_info,_account_busy,_AccountShardBusy.__init__,_account_source_read,
          _account_retry_clock,_account_retry_state,_account_retry_ready,_account_record_retry,
          _account_tail_hints,_account_tail_probe,_account_known_tail_debts,_account_hint_proof,
          _account_work_pins,_account_work_start,_account_work_current,_account_work_finish,_account_registry_admit)
