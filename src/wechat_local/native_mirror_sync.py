"""Bounded native history/tail synchronizer shared by foreground and scheduler."""
from __future__ import annotations

import fcntl
import hashlib
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .common import quote_identifier as qi
from .source_records import SourceKey
from .source_catalog import discover_numeric_shards
from .live_identity import _username_for_table
from .live_readonly import open_encrypted_readonly, read_private_passphrase
from .source_schema import _table_columns
from .native_mirror_store import MirrorError, MirrorStore, lossless_text_rows
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
                            enqueue_rows(config,path.name,table,username,columns,rows)
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
    limits.update(until=time.monotonic()+20.,used_rows=0,used_bytes=0,used_tables=0)
    return limits


def _account_registry_commit(conn):
    """Classify only this exact local registry operation; never Source errors."""
    try:conn.commit()
    except sqlite3.Error as error:
        if isinstance(error,sqlite3.OperationalError) and str(error) in ('database is locked','database table is locked'):raise MirrorError('local_registry_commit_busy') from None
        raise MirrorError('local_registry_commit_failed') from None


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


def _auto_reanchor_renumbered_shard(config, registry, path, anchor, identity, header_hash):
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

    def verify_source():
        check_deadline()
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
        _account_registry_commit(registry)
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
        for (table,) in registry.execute('SELECT table_name FROM members WHERE shard=?', (shard,)):
            check_deadline()
            proof = sc.member(config, registry, shard, table)
            proofs.append((table, proof))
            tables.append([table, proof['schema_sha256']])

        observation = dict(contract=sc.fixed(config), shard=shard, source_identity=identity,
                           header=header_hash, query_only=True, schema_cookie=None,
                           at_ns=time.time_ns(), tables=tables)
        obs_id = sc.digest(observation)
        registry.execute('INSERT OR IGNORE INTO observations VALUES(?,?)',
                         (obs_id, json.dumps(observation, sort_keys=True)))
        for table, proof in proofs:
            check_deadline()
            proof.update(source_identity=identity, header=header_hash, observation=obs_id)
            registry.execute('UPDATE members SET proof=? WHERE shard=? AND table_name=?',
                             (json.dumps(proof, sort_keys=True), shard, table))
        if attached:
            for table, raw in registry.execute('SELECT table_name,value FROM d1.__walden_progress'):
                check_deadline()
                progress = json.loads(raw)
                # Name2Id batches carry empty progress, without a source anchor.
                if table == 'Name2Id':
                    if progress != {}:
                        raise MirrorError('scope_copy_proof')
                    continue
                if (not isinstance(progress, dict)
                        or progress.get('source_identity') != prior_identity
                        or progress.get('source_header_sha256') != prior_header):
                    raise MirrorError('scope_copy_proof')
                progress['source_identity'] = identity
                registry.execute('UPDATE d1.__walden_progress SET value=? WHERE table_name=?',
                                 (json.dumps(progress, sort_keys=True), table))
            if private(local_path) != local_identity:
                raise MirrorError('local_replaced')
        sc.save(registry, anchor_key, dict(source_identity=identity, header=header_hash))
        receipt = dict(kind='auto_st_dev_renumber', auto=True, shard=shard,
                       at_wall_ns=time.time_ns(), old_st_dev=prior_identity[0],
                       new_st_dev=identity[0], st_ino=identity[1], header=header_hash,
                       old_source_identity=list(prior_identity), new_source_identity=list(identity))
        sc.save(registry, 'source_st_dev_renumber_receipt:' + shard, receipt)
        verify_source()
        sc.query_scope_guard(config, scope_token)
        _account_registry_commit(registry)
    finally:
        if registry.in_transaction:
            registry.rollback()
        if attached:
            registry.execute('DETACH DATABASE d1')
    return receipt


def _account_shard_anchor_check(config, registry, path, identity, header_hash, *, result=None):
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
            receipt = _auto_reanchor_renumbered_shard(config, registry, path, anchor, identity, header_hash)
            if result is not None:
                result.setdefault('auto_st_dev_renumber', []).append(receipt)
            anchor = sc.state(registry, 'shard_anchor:' + path.name, None)
        if anchor != live:
            raise MirrorError('scope_source_conflict')
    return anchor


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
    root=mirror_root(config);result=dict(sources=[],gaps=[],source_opens=0,rows_read=0,rows_written=0)
    with writer_lock(root,float(config.get('mirror_lock_timeout',10))),sc.registry(config,write=True) as registry:
        _require_trigger_free(registry, 'main')
        sc.query_scope_guard(config,before)
        paths=discover_numeric_shards(Path(config['message_root']))
        roster=[p.name for p in paths];prior=sc.state(registry,'roster',[])
        if set(prior)-set(roster):result['gaps'].append('source_shard_missing')
        if not paths:result['gaps'].append('source_unavailable')
        if connection_factory is None:
            deadline.check();secret=read_private_passphrase(Path(config['passphrase_file']))
            connection_factory=lambda path:open_encrypted_readonly(path,secret)[0]
        round_number=sc.state(registry,'round_number',0);sc.save(registry,'round_number',round_number+1)
        if round_number%4==0 and time.monotonic()<budget['until']:
            try:
                aux=_account_aux(config,registry,budget,connection_factory);result['source_opens']+=aux['opens'];result['rows_read']+=aux['rows'];result['rows_written']+=aux['written'];result['directory_snapshot']=aux['status']
            except Exception:
                deadline.check();result['directory_snapshot']='unavailable_or_unsupported'
        offset=sc.state(registry,'shard_cursor',0)
        chosen=[paths[(offset+i)%len(paths)] for i in range(min(len(paths),budget['shards']))] if paths else []
        for path in chosen:
            shard_gap_start=len(result['gaps'])
            if sc.state(registry,'names_oversize:'+path.name,[]):result['gaps'].append('name2id_row_oversize')
            deadline.check()
            if time.monotonic()>=budget['until']:break
            conn=None
            try:
                stamp=path.stat();identity=[stamp.st_dev,stamp.st_ino]
                with path.open('rb') as header:header_hash=hashlib.sha256(header.read(16)).hexdigest()
                # Exact per-shard shard_anchor:<shard> comparison, kept inside the
                # loop (never hoisted/blanket). It reads the anchor itself, enforces
                # equality for every shard, and ONLY for a verified same-source
                # st_dev renumber auto-advances all pinned identity layers for THIS
                # shard + writes a distinct AUTO audit receipt, then re-checks the
                # equality guard. Every other mismatch still raises
                # MirrorError('scope_source_conflict') exactly as before.
                _account_shard_anchor_check(config,registry,path,identity,header_hash,result=result)
                conn=connection_factory(path);result['source_opens']+=1
                if conn.execute('PRAGMA query_only').fetchone()!=(1,):raise MirrorError('source_not_readonly')
                conn.execute('BEGIN');cookie=conn.execute('PRAGMA schema_version').fetchone()[0]
                sc.register(config,registry,dict(contract=sc.fixed(config),shard=path.name,source_identity=identity,header=header_hash,query_only=True,tables=[]),[])
                name_map={}
                local_path=root/path.name
                if local_path.is_file():
                    from .live_readonly import readonly_database_uri
                    local=sqlite3.connect(readonly_database_uri(local_path),uri=True)
                    try:
                        local.execute('PRAGMA query_only=ON')
                        if local.execute("SELECT name FROM sqlite_master WHERE name='Name2Id'").fetchone():
                            for (name,) in local.execute('SELECT user_name FROM Name2Id LIMIT 65536'):
                                if type(name) is str:
                                    table='Msg_'+hashlib.md5(name.encode()).hexdigest()
                                    name_map[table]=name if table not in name_map else None
                    finally:local.close()
                cursor=sc.state(registry,'inventory:'+path.name,dict(after='',cookie=cookie,pass_cookie=cookie,complete=False))
                cursor.setdefault('pass_id',os.urandom(16).hex())
                after=cursor['after'];remaining=budget['inventory']
                scan=not cursor.get('complete') or cursor.get('refresh_requested') is True or cursor.get('cookie')!=cookie or time.time_ns()-cursor.get('checked_at_ns',0)>=300000000000
                tables=conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name>? ORDER BY name LIMIT ?",(after,remaining+1)).fetchall() if scan else []
                page=tables[:remaining];members=[];proof_tables=[]
                for name,ddl in page:
                    deadline.check()
                    if time.monotonic()>=budget['until']:break
                    cursor['after']=name
                    if name.startswith('__walden_'):raise MirrorError('source_reserved_namespace')
                    if not sc.TABLE.fullmatch(name):continue
                    schema_sha=sc.sha(ddl.encode());item=dict(table=name,schema_sha256=schema_sha,username=None,supported=True,available=True,inventory_pass=cursor['pass_id'])
                    try:
                        _validate_message_cursor(conn,name)
                        item['username']=name_map.get(name)
                    except Exception as error:
                        # Missing conversation identity is not unsupported raw schema.
                        try:_validate_message_cursor(conn,name)
                        except Exception:item['supported']=False;item['reason']='unsupported_message_schema'
                    proof_tables.append([name,schema_sha]);members.append(item)
                current=path.stat()
                if [current.st_dev,current.st_ino]!=identity:raise MirrorError('source_replaced')
                observation=dict(contract=sc.fixed(config),shard=path.name,source_identity=identity,header=header_hash,query_only=True,
                    schema_cookie=cookie,tables=proof_tables,at_ns=time.time_ns())
                if members:sc.register(config,registry,observation,members)
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
                sc.save(registry,'inventory:'+path.name,cursor);_account_registry_commit(registry)
                # Copy fairness is independent of the inventory pass cursor.
                copy_after=sc.state(registry,'copy:'+path.name,'')
                count=budget['tables']-budget['used_tables']
                candidates=registry.execute('SELECT table_name FROM members WHERE shard=? AND table_name>? ORDER BY table_name LIMIT ?',(path.name,copy_after,count)).fetchall()
                if not candidates and count:candidates=registry.execute('SELECT table_name FROM members WHERE shard=? ORDER BY table_name LIMIT ?',(path.name,count)).fetchall()
                names_done=False
                for (table,) in candidates:
                    deadline.check()
                    if time.monotonic()>=budget['until'] or budget['used_rows']>=budget['rows'] or budget['used_bytes']>=budget['bytes']:break
                    proof=sc.member(config,registry,path.name,table)
                    sc.save(registry,'copy:'+path.name,table);budget['used_tables']+=1
                    if not proof.get('supported'):result['gaps'].append('unsupported_message_schema');continue
                    ddl_row=conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
                    if ddl_row is None:
                        proof['available']=False;proof['reason']='source_table_missing'
                        registry.execute('UPDATE members SET proof=? WHERE shard=? AND table_name=?',(json.dumps(proof,sort_keys=True),path.name,table))
                        result['gaps'].append('source_table_missing');continue
                    if sc.sha(ddl_row[0].encode())!=proof['schema_sha256']:raise MirrorError('source_schema_changed')
                    key=SourceKey(config['account_id'],config['source_generation'],path.name,table);store=MirrorStore(root/path.name,key)
                    store.ensure_table(key,ddl_row[0]);_copy_indexes(conn,store,table)
                    # Refresh sender mapping once per shard through bounded rowid pages.
                    if not names_done:
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
                    entry=_account_copy_table(config,conn,path,table,store,identity,header_hash,budget)
                    result['sources'].append(dict(shard=path.name,table=table,**entry['progress']))
                    result['rows_read']+=entry['rows'];result['rows_written']+=entry['written']
                _account_registry_commit(registry)
            except Exception as error:
                deadline.check();result['gaps'].append(str(error) if isinstance(error,MirrorError) else 'source_unavailable_or_unsupported')
            finally:
                if conn is not None:conn.close()
                sc.save(registry,'gaps:'+path.name,result['gaps'][shard_gap_start:]);_account_registry_commit(registry)
        sc.save(registry,'shard_cursor',(offset+1)%max(1,len(paths)));sc.save(registry,'roster',sorted(set(prior)|set(roster)))
        sc.save(registry,'last_attempt',dict(at_ns=time.time_ns(),gaps=sorted(set(result['gaps']))));_account_registry_commit(registry)
        sc.query_scope_guard(config,before)
    from .native_scope_contract import account_status
    status=account_status(config);result['account_scope']=status
    result['follow_observation']=dict(observation_id=os.urandom(16).hex(),complete=status['raw_messages_complete'],known_backlog=status['known_backlog'],watermarks=[],atomic_global_snapshot=False,final_completeness='not_promised')
    result['elapsed_seconds']=20.-max(0,budget['until']-time.monotonic());return result


def _account_copy_table(config,conn,path,table,store,identity,header_hash,budget):
    key=SourceKey(config['account_id'],config['source_generation'],path.name,table)
    maximum=conn.execute('SELECT coalesce(max(local_id),0) FROM '+qi(table)).fetchone()[0]
    progress=store.progress(table)
    if progress is None:progress=dict(H=maximum,history=0,tail=maximum,source_identity=identity,source_header_sha256=header_hash)
    if progress.get('source_identity')!=identity or progress.get('source_header_sha256')!=header_hash:raise MirrorError('source_replaced')
    if type(maximum) is not int or maximum<max(progress['H'],progress['tail']):raise MirrorError('source_cursor_regression')
    history_backlog=progress['history']<progress['H'];tail_backlog=progress['tail']<maximum
    turn=progress.get('account_turn',0);history=history_backlog and (not tail_backlog or turn%2==0)
    recent=not history_backlog and not tail_backlog
    progress['account_turn']=turn+1
    if recent:
        window=progress.get('account_recent') or dict(after=0,through=maximum,since=int(time.time())-86400)
        after=window['after'];through=window['through']
    else:after=progress['history'] if history else progress['tail'];through=progress['H'] if history else maximum
    count=min(int(config.get('mirror_batch_size',500)),budget['rows']-budget['used_rows'])
    table_columns=[r[1] for r in conn.execute('PRAGMA table_info('+qi(table)+')')]
    if len(table_columns)>128:raise MirrorError('unsupported_message_schema')
    row_size='+'.join('coalesce(length(CAST('+qi(c)+' AS BLOB)),0)' for c in table_columns)
    predicate=' AND create_time>='+str(window['since']) if recent else ''
    candidates=conn.execute('SELECT local_id,('+row_size+'),0 FROM '+qi(table)+' WHERE local_id>? AND local_id<=?'+predicate+' ORDER BY local_id LIMIT ?',(after,through,count)).fetchall()
    ids=[];estimate=0
    for local_id,body,source in candidates:
        check_deadline()
        size=body+source+4096
        if size>budget['bytes']:raise MirrorError('account_row_oversize')
        if budget['used_bytes']+estimate+size>budget['bytes']:break
        ids.append(local_id);estimate+=size
    rows=[]
    if ids:
        with lossless_text_rows(conn):
            rows=conn.execute('SELECT rowid,* FROM '+qi(table)+' WHERE local_id IN ('+','.join('?' for _ in ids)+') ORDER BY local_id',tuple(ids)).fetchall()
    columns=[r[1] for r in conn.execute('PRAGMA table_info('+qi(table)+')')];local_index=columns.index('local_id')+1;time_index=columns.index('create_time')+1
    now=int(time.time())
    if any(type(row[time_index]) is not int or not 0<=row[time_index]<=now for row in rows):raise MirrorError('invalid_message_time')
    if recent:
        if rows:window['after']=rows[-1][local_index]
        if not candidates:
            progress.update(account_recent=None,account_recent_pending=False,rechecked_since=window['since'],account_recent_checked_at=now)
        else:progress.update(account_recent=window,account_recent_pending=True)
    else:
        if rows:progress['history' if history else 'tail']=rows[-1][local_index]
        elif not candidates:progress['history' if history else 'tail']=through
        progress['account_recent_pending']=True
    progress.update(history_complete=progress['history']>=progress['H'],checked_at=now,target=maximum)
    progress.pop('recent_observation',None)
    current=path.stat()
    if [current.st_dev,current.st_ino]!=identity:raise MirrorError('source_replaced')
    written=store.apply_batch(key,table,rows,progress)
    try:
        from .native_media_work import enqueue_rows
        from .native_scope_contract import member,registry
        with registry(config) as db:proof=member(config,db,path.name,table)
        enqueue_rows(config,path.name,table,proof.get('username') or proof['ref'],columns,rows)
    except Exception:check_deadline()
    budget['used_rows']+=len(rows);budget['used_bytes']+=estimate
    return dict(progress=progress,rows=len(rows),written=written)


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

_register(_account_registry_commit,_account_budget,_account_sync,_account_copy_table,_account_aux)
