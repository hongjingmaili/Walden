"""Account table recovery. The registered conversation and shard anchor stay fixed."""
import hashlib
import json
import re
import stat
import time
from pathlib import Path

from .common import quote_identifier as qi
from .native_deadline import check_deadline
from .native_mirror_store import MirrorError, lossless_text_rows
from .source_records import RawMessage, _content_fingerprint


PENDING = 'source_table_cursor_pending'
_PREFIX = 'table_cursor:'
_EPOCHS = '__walden_cursor_epochs'


class Paused(MirrorError):
    """A registered, anchored table cannot advance without better evidence."""


def pending_key(shard, table):
    return _PREFIX + shard + ':' + table


def pending(registry, shard, table):
    from .native_scope_contract import state
    value = state(registry, pending_key(shard, table))
    if value is not None:
        if (type(value) is not dict or type(value.get('after')) is not int or value['after'] < 0
                or type(value.get('blocked')) is not bool or type(value.get('epoch')) is not int
                or not 0 <= value['epoch'] <= 127 or type(value.get('target')) is not int or value['target'] < 0
                or value.get('phase') not in (None, 'verify', 'restore')
                or (value.get('through') is not None
                    and (type(value['through']) is not int or value['through'] < value['after']))
                or (value.get('stamp') is not None
                    and (type(value['stamp']) is not str or not re.fullmatch(r'[0-9a-f]{64}', value['stamp'])))):
            raise MirrorError('scope_copy_proof')
    return value


def set_pending(registry, shard, table, value):
    from .native_scope_contract import save
    key = pending_key(shard, table)
    if value is None:
        registry.execute('DELETE FROM state WHERE key=?', (key,))
    else:
        save(registry, key, value)


def count_pending(registry):
    return registry.execute('SELECT count(*) FROM state WHERE key>=? AND key<?',
                            (_PREFIX, _PREFIX + '~')).fetchone()[0]


def floor(progress):
    fields = tuple(progress.get(name) for name in ('history', 'H', 'tail', 'target'))
    if any(type(value) is not int or value < 0 for value in fields) or tuple(sorted(fields)) != fields:
        raise MirrorError('scope_copy_proof')
    return fields[-1]


def valid_max(maximum):
    return type(maximum) is int and maximum >= 0


def mark(registry, shard, table, maximum, progress, *, wanted=0):
    minimum = max(floor(progress), wanted)
    state = pending(registry, shard, table)
    epoch = progress.get('cursor_epoch', 0)
    physical(table, epoch)
    if state is None or state['epoch'] != epoch or minimum > state['target']:
        set_pending(registry, shard, table, dict(after=0, through=None, blocked=False, target=minimum, epoch=epoch))
    # Invalid values never enter a recovery comparison or diagnostics.
    return valid_max(maximum) and (maximum >= minimum or maximum > 0)


def physical(table, epoch):
    if not re.fullmatch(r'Msg_[0-9a-f]{32}', table) or type(epoch) is not int or epoch < 0:
        raise MirrorError('scope_copy_proof')
    return table if epoch == 0 else f'__walden_rows_{table[4:]}_{epoch}'


def archives(conn, table, progress):
    active = progress.get('cursor_epoch', 0)
    if type(active) is not int or not 0 <= active <= 127:
        raise MirrorError('scope_copy_proof')
    if not active:
        return []
    archived = conn.execute(f'SELECT epoch, progress FROM {_EPOCHS} WHERE table_name=? ORDER BY epoch LIMIT 128', (table,))
    values = []
    for epoch, raw in archived:
        check_deadline()
        prior = json.loads(raw)
        if epoch != len(values) or prior.get('cursor_epoch', 0) != epoch:
            raise MirrorError('scope_copy_proof')
        floor(prior)
        values.append(prior)
    if active != len(values):
        raise MirrorError('scope_copy_proof')
    return values


def generations(conn, table, progress):
    return [physical(table, epoch) for epoch in range(len(archives(conn, table, progress)) + 1)]


def _typed_equal(left, right):
    return all(type(a) is type(b) and a == b for a, b in zip(left, right)) and len(left) == len(right)


def _is_reused(local, table, epoch, columns, old, row):
    if old is None or row is None or 'server_id' not in columns:
        return False
    index = 1 + columns.index('server_id')
    old_server, new_server = old[index], row[index]
    if (type(old_server) is not int or type(new_server) is not int
            or min(old_server, new_server) <= 0 or old_server == new_server):
        return False
    fields = dict(zip(columns, old[1:]))
    record = RawMessage(fields['local_id'], old_server, fields['local_type'], fields['create_time'],
                        fields['real_sender_id'], fields['message_content'], fields['WCDB_CT_message_content'])
    observations = '__walden_epoch_observed' if epoch else '__walden_observed'
    parameters = (table, old[0], _content_fingerprint(record), str(old_server))
    return local.execute(
        'SELECT 1 FROM ' + observations + ' WHERE table_name=? AND local_id=? AND fingerprint=? AND server_id=?'
        + (' AND epoch=?' if epoch else ''), (*parameters, epoch) if epoch else parameters,
    ).fetchone() is not None


def source_stamp(path):
    """Commit-file metadata, for continuity between bounded Source transactions."""
    values = []
    for suffix in ('', '-wal', '-journal'):
        try:
            node = Path(str(path) + suffix).lstat()
        except FileNotFoundError:
            if not suffix:
                return None
            values.append(None)
            continue
        except OSError:
            return None
        if not stat.S_ISREG(node.st_mode):
            return None
        values.append((node.st_dev, node.st_ino, node.st_size, node.st_mtime_ns, node.st_ctime_ns))
    return hashlib.sha256(json.dumps(values).encode()).hexdigest()


def _validated_commit(source, path, prior, commit_check, *, snapshot=None):
    check_deadline()
    if not source.in_transaction or source.execute('PRAGMA query_only').fetchone() != (1,):
        raise MirrorError('source_transaction_changed')
    stat = path.stat()
    with path.open('rb') as file:
        header = hashlib.sha256(file.read(16)).hexdigest()
    if [stat.st_dev, stat.st_ino] != prior['source_identity'] or header != prior['source_header_sha256']:
        raise MirrorError('source_replaced')
    if snapshot is not None and source_stamp(path) != snapshot:
        raise Paused(PENDING)
    if commit_check is not None:
        commit_check()


def _begin(local, store, table, prior):
    if not local.in_transaction:
        local.execute('BEGIN IMMEDIATE')
    if local.execute('SELECT * FROM __walden_binding').fetchall() != [store.binding]:
        raise MirrorError('source_identity_mismatch')
    raw = local.execute('SELECT value FROM __walden_progress WHERE table_name=?', (table,)).fetchone()
    if raw is None or json.dumps(json.loads(raw[0]), sort_keys=True) != json.dumps(prior, sort_keys=True):
        raise MirrorError('scope_copy_proof')
    if local.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' LIMIT 1").fetchone():
        raise MirrorError('local_trigger_unsupported')
    return raw[0]


def _rotate(local, store, key, table, old_raw, prior, row, maximum, commit, promote):
    from contextlib import closing
    import sqlite3

    epoch = prior.get('cursor_epoch', 0)
    if epoch >= 127:
        raise Paused(PENDING)
    name = physical(table, epoch + 1)
    # Let SQLite perform the rename in a disposable database. The original
    # local DDL is the verified canonical schema and its table remains intact.
    schema = local.execute("SELECT sql FROM sqlite_master WHERE name=? AND type='table'", (table,)).fetchone()
    if schema is None:
        raise MirrorError('scope_copy_proof')
    with closing(sqlite3.connect(':memory:')) as probe:
        probe.execute(schema[0])
        probe.execute('ALTER TABLE ' + qi(table) + ' RENAME TO ' + qi(name))
        new_ddl = probe.execute("SELECT sql FROM sqlite_master WHERE name=? AND type='table'", (name,)).fetchone()[0]
    commit()
    promote()
    local.execute(new_ddl)
    local.execute('CREATE INDEX ' + qi(name + '_ordered') + ' ON ' + qi(name) + '(create_time DESC,local_id DESC)')
    local.execute(f'CREATE TABLE IF NOT EXISTS {_EPOCHS}(table_name TEXT, epoch INTEGER, progress TEXT NOT NULL, PRIMARY KEY(table_name,epoch))')
    local.execute(f'INSERT INTO {_EPOCHS} VALUES(?,?,?)', (table, epoch, old_raw))
    local.execute('CREATE TABLE IF NOT EXISTS __walden_epoch_observed(table_name TEXT, epoch INTEGER, local_id INTEGER, server_id TEXT, kind INTEGER, timestamp INTEGER, sender INTEGER, fingerprint TEXT, UNIQUE(table_name,epoch,local_id,fingerprint))')
    local.execute('CREATE INDEX IF NOT EXISTS __walden_epoch_observed_ids ON __walden_epoch_observed(local_id)')
    progress = dict(prior, cursor_epoch=epoch + 1, cursor_guarded=True, H=maximum, history=0,
                    tail=maximum, target=maximum, history_complete=False,
                    account_recent_pending=True, account_recent=None, checked_at=int(time.time()),
                    prior_coverage_unknown=True)
    progress.pop('recent_observation', None)
    progress.pop('rechecked_since', None)
    progress.pop('account_recent_checked_at', None)
    written = store.apply_batch(key, table, [row], progress, _connection=local, _physical=name, _commit_check=commit)
    return _entry(progress, 1, written, 'cursor_generation')


def _entry(progress, count, written, kind):
    return dict(progress=progress, rows=count, written=written, batch_kind=kind,
                history_advanced=False, tail_advanced=False)


def _unknown_overlap_matches(local, source, name, table, columns, ids, budget, read_source, reserved):
    slots = ' WHERE local_id IN (' + ','.join('?' for _ in ids) + ') ORDER BY local_id'
    size = '+'.join('coalesce(length(CAST(' + qi(c) + ' AS BLOB)),0)' for c in columns)
    measure = lambda current: 'SELECT sum(' + size + ') FROM ' + qi(current) + slots
    cost = (local.execute(measure(name), ids).fetchone()[0] or 0)
    cost += (read_source(measure(table), ids).fetchone()[0] or 0)
    if budget['used_bytes'] + reserved + cost > budget['bytes']:
        return False
    budget['used_bytes'] += cost
    rows = lambda current: 'SELECT rowid,* FROM ' + qi(current) + slots
    with lossless_text_rows(local), lossless_text_rows(source):
        old = local.execute(rows(name), ids).fetchall()
        new = read_source(rows(table), ids).fetchall()
    return len(old) == len(new) == len(ids) and all(_typed_equal(left, right) for left, right in zip(old, new))


def _tail_reuse(local, source, name, table, columns, read_source, until, budget, reserved):
    """Classify existing overlap before assigning any new tail to this generation."""
    fields = 'local_id,server_id' if 'server_id' in columns else 'local_id,NULL'
    select = 'SELECT ' + fields + ' FROM '
    old = local.execute(select + qi(name) + ' ORDER BY local_id')
    ambiguous = False
    try:
        while True:
            check_deadline()
            if time.monotonic() >= until:
                raise Paused(PENDING)
            page = old.fetchmany(256)
            if not page:
                if ambiguous:
                    raise Paused(PENDING)
                return None
            ids = tuple(ident for ident, _ in page)
            slots = ','.join('?' for _ in ids)
            observed = dict(read_source(select + qi(table) + ' WHERE local_id IN (' + slots + ')', ids))
            uncertain = []
            for ident, prior_server in page:
                if ident not in observed:
                    ambiguous = True
                    continue
                server = observed[ident]
                known = type(prior_server) is int and prior_server > 0 and type(server) is int and server > 0
                if known and server != prior_server:
                    with lossless_text_rows(local):
                        original = local.execute('SELECT rowid,* FROM ' + qi(name) + ' WHERE local_id=?', (ident,)).fetchone()
                    return ident, original
                if not known:
                    if type(server) is not type(prior_server) or server != prior_server:
                        ambiguous = True
                    else:
                        uncertain.append(ident)
            if not ambiguous and uncertain and not _unknown_overlap_matches(
                    local, source, name, table, columns, tuple(uncertain), budget, read_source, reserved):
                ambiguous = True
    finally:
        old.close()


def write(source, path, store, key, table, columns, rows, prior, progress, maximum, guard, *, verified,
          budget, read_source, promote, reserved):
    """Check every row that could overwrite an ID in the committed batch."""
    if not verified:
        return store.apply_batch(key, table, rows, progress, **({'_commit_check': guard} if guard else {})), None
    name = physical(table, prior.get('cursor_epoch', 0))
    commit = lambda: _validated_commit(source, path, prior, guard)
    def before_rows(local):
        raw = _begin(local, store, table, prior)
        epoch = prior.get('cursor_epoch', 0)
        checked = budget.setdefault('_cursor_overlap', set())
        if progress['tail'] > prior['tail'] and (table,epoch) not in checked:
            overlap = _tail_reuse(local, source, name, table, columns, read_source,
                                  min(budget['until'], time.monotonic() + 1.0), budget, reserved)
            if overlap is not None:
                ident, old = overlap
                with lossless_text_rows(source):
                    renewed = read_source('SELECT rowid,* FROM ' + qi(table) + ' WHERE local_id=?', (ident,)).fetchone()
                timestamp = 1 + columns.index('create_time')
                if not (renewed is not None and type(renewed[timestamp]) is int and 0 <= renewed[timestamp] <= int(time.time())
                        and _is_reused(local, table, epoch, columns, old, renewed)):
                    raise Paused(PENDING)
                return _rotate(local, store, key, table, raw, prior, renewed, maximum, commit, promote)
            checked.add((table,epoch))
        for row in rows:
            with lossless_text_rows(local):
                old = local.execute('SELECT rowid,* FROM ' + qi(name) + ' WHERE rowid=?', (row[0],)).fetchone()
            if old is not None and not _typed_equal(old, row):
                if _is_reused(local, table, prior.get('cursor_epoch', 0), columns, old, row):
                    return _rotate(local, store, key, table, raw, prior, row, maximum, commit, promote)
                # An ordinary revision with the same meaningful server ID
                # keeps its existing behavior, except during/after recovery.
                i = 1 + columns.index('server_id') if 'server_id' in columns else 0
                if prior.get('cursor_guarded') or not i or type(old[i]) is not int or old[i] <= 0 or type(row[i]) is not int or row[i] != old[i]:
                    raise Paused(PENDING)
    outcome=store.apply_batch(key, table, rows, progress, _physical=name, _before_rows=before_rows, _commit_check=commit)
    return (0, outcome) if isinstance(outcome, dict) else (outcome, None)


def recover(source, path, store, key, table, columns, prior, maximum, state, budget,
            batch_size, guard, read_source, snapshot, promote):
    """Verify the keyset span against the exact Source and local write snapshots."""
    epoch = prior.get('cursor_epoch', 0)
    if state['epoch'] != epoch:
        raise MirrorError('scope_copy_proof')
    ceiling = max(floor(prior), state['target'])
    if snapshot is None or source_stamp(path) != snapshot:
        return None, state
    after, through = state['after'], state['through']
    blocked = state['blocked']
    can_restore = maximum >= ceiling
    phase = state.get('phase', 'verify')
    if state.get('stamp') != snapshot or through is None or maximum != through:
        after, through, blocked, phase = 0, maximum, False, 'verify'
    name = physical(table, prior.get('cursor_epoch', 0))
    count = min(500, batch_size, budget['rows'] - budget['used_rows'])
    if count <= 0:
        return None, state
    length = '+'.join('coalesce(length(CAST(' + qi(c) + ' AS BLOB)),0)' for c in columns)
    sql = lambda current: ('SELECT local_id,(' + length + ') FROM ' + qi(current)
                           + ' WHERE local_id>? AND local_id<=? ORDER BY local_id LIMIT ?')
    commit = lambda: _validated_commit(source, path, prior, guard, snapshot=snapshot)
    with store.connect() as local:
        raw = _begin(local, store, table, prior)
        old_sizes = dict(local.execute(sql(name), (after, through, count)))
        new_sizes = dict(read_source(sql(table), (after, through, count)))
        ids = sorted(old_sizes.keys() | new_sizes.keys())
        size = 0
        selected = []
        for ident in ids[:count]:
            check_deadline()
            cost = old_sizes.get(ident, 0) + new_sizes.get(ident, 0) + 4096
            if time.monotonic() >= budget['until'] or budget['used_bytes'] + size + cost > budget['bytes']:
                break
            selected.append(ident)
            size += cost
        if ids and not selected:
            return None, state
        end = selected[-1] if selected else through
        data = lambda current: 'SELECT rowid,* FROM ' + qi(current) + ' WHERE local_id>? AND local_id<=? ORDER BY local_id'
        with lossless_text_rows(local), lossless_text_rows(source):
            old_rows = dict((row[0], row) for row in local.execute(data(name), (after, end)))
            rows = list(read_source(data(table), (after, end)))
        new_rows = {row[0]: row for row in rows}
        time_index = 1 + columns.index('create_time')
        now = int(time.time())
        if any(type(row[time_index]) is not int or not 0 <= row[time_index] <= now for row in rows):
            raise MirrorError('invalid_message_time')
        budget['used_rows'] += len(selected)
        budget['used_bytes'] += size
        for ident, old in old_rows.items():
            check_deadline()
            row = new_rows.get(ident)
            if row is None or not _typed_equal(old, row):
                if _is_reused(local, table, prior.get('cursor_epoch', 0), columns, old, row):
                    return _rotate(local, store, key, table, raw, prior, row, maximum, commit, promote), None
                blocked = True
        finished = not ids or (len(selected) == len(ids) and max(len(old_sizes), len(new_sizes)) < count) or end == through
        # A full proof must precede inserts. A small table can prove and
        # restore its complete span in this exact transaction. For a larger
        # table, retain only the verified keyset position while the Source
        # commit files have the same stamp. Changes restart that evidence.
        if can_restore and not blocked and (phase == 'restore' or finished and not after):
            if finished:
                progress = dict(prior, cursor_guarded=True, tail=max(prior['tail'], through),
                                target=maximum, checked_at=now, account_recent=None, account_recent_pending=True)
                progress.pop('recent_observation', None)
            else:
                progress = prior
            # An existing, exact old row is never rewritten; only missing
            # local IDs in this source snapshot enter the batch.
            new_only = [row for row in rows if row[0] not in old_rows]
            written = store.apply_batch(key, table, new_only, progress, _connection=local,
                                        _physical=name, _commit_check=commit, _keep_progress=not finished)
            remaining = None if finished else dict(after=end, through=through, blocked=False, phase='restore', stamp=snapshot, target=ceiling, epoch=epoch)
            return _entry(progress, len(rows), written, 'cursor_recovery'), remaining
        # No writes for an unproven identity. Once all overlap is verified
        # under one Source commit stamp, replay missing IDs from the start.
        commit()
        if finished:
            if can_restore and not blocked:
                return None, dict(after=0, through=through, blocked=False, phase='restore', stamp=snapshot, target=ceiling, epoch=epoch)
            return None, dict(after=0, through=None, blocked=False, target=ceiling, epoch=epoch)
        return None, dict(after=end, through=through, blocked=blocked, phase='verify', stamp=snapshot, target=ceiling, epoch=epoch)


def observed_rows(conn, local_id):
    legacy = conn.execute('SELECT * FROM __walden_observed WHERE local_id=?', (local_id,)).fetchall()
    if conn.execute("SELECT 1 FROM sqlite_master WHERE name='__walden_epoch_observed' AND type='table'").fetchone():
        legacy += conn.execute(
            'SELECT table_name,local_id,server_id,kind,timestamp,sender,fingerprint '
            'FROM __walden_epoch_observed WHERE local_id=?', (local_id,)
        ).fetchall()
    return legacy


def query_rows(conn, table, state, columns, start, end, limit, membership=None):
    names = generations(conn, table, state)
    if len(names) == 1:
        params = [start, end]
        if membership is None:
            predicate = ''
        elif membership:
            predicate = ' AND local_id IN (' + ','.join('?' for _ in membership) + ')'
            params.extend(membership)
        else:
            predicate = ' AND 0'
        sql = ('SELECT * FROM ' + qi(table) + ' WHERE create_time>=? AND create_time<=?' + predicate
               + ' ORDER BY create_time DESC,local_id DESC LIMIT ?')
        return [(None, row) for row in conn.execute(sql, (*params, limit))]
    if membership is not None:
        raise MirrorError('request_cache_incomplete')
    import heapq
    from .source_records import _typed_bytes

    server = columns.index('server_id')
    local_id, stamp = columns.index('local_id'), columns.index('create_time')
    facts = [columns.index(field) for field in
             ('server_id', 'local_type', 'create_time', 'real_sender_id',
              'message_content', 'WCDB_CT_message_content', 'source', 'WCDB_CT_source') if field in columns]

    def ordered(epoch, name):
        sql = 'SELECT * FROM ' + qi(name) + ' WHERE create_time>=? AND create_time<=? ORDER BY create_time DESC,local_id DESC'
        for row in conn.execute(sql, (start, end)):
            yield epoch, row

    streams = [ordered(epoch, name) for epoch, name in enumerate(names)]
    order = lambda value: (value[1][stamp], value[1][local_id], value[0])
    seen = set()
    result = []
    for epoch, row in heapq.merge(*streams, key=order, reverse=True):
        check_deadline()
        if type(row[server]) is int and row[server] > 0:
            identity = hashlib.sha256()
            for index in facts:
                identity.update(type(row[index]).__name__.encode() + b':')
                identity.update(_typed_bytes(row[index]))
            fingerprint = identity.digest()
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
        result.append((epoch, row))
        if len(result) >= limit:
            break
    return result
