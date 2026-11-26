"""Private, source-bound native SQLite storage; body rows and cursors commit together."""
from __future__ import annotations

import json
import os
import sqlite3
import re
from contextlib import contextmanager, nullcontext, closing
from dataclasses import dataclass
from pathlib import Path

from .common import quote_identifier
from .source_records import SourceKey, RawMessage, _content_fingerprint


class MirrorError(RuntimeError):
    """A mirror cannot safely accept or serve the requested operation."""


@dataclass(frozen=True, repr=False)
class RawText:
    """Internal undecodable UTF-8 TEXT, deliberately distinct from BLOB bytes."""
    data: bytes


@contextmanager
def lossless_text_rows(connection):
    """Decode only a bounded row read; never alter metadata/identity readers."""
    previous = connection.text_factory
    def decode(raw):
        try:
            return raw.decode('utf-8')
        except UnicodeDecodeError:
            return RawText(raw)
    connection.text_factory = decode
    try:
        yield
    finally:
        connection.text_factory = previous


class MirrorStore:
    def __init__(self, path: Path, source: SourceKey, *, witness=None):
        self.path = Path(path)
        self._witness = witness
        if witness is not None:witness.before_open(self.path)
        self.binding = (source.account_id, source.source_generation, source.shard_name)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise MirrorError('mirror_symlink')
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if witness is None or (self.path.stat().st_mode & 0o777)!=0o600:os.chmod(self.path, 0o600)
        with self.connect() as conn:
            self._initialize(conn)

    def _initialize(self, conn):
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables and '__walden_binding' not in tables:
            raise MirrorError('unbound_existing_database')
        conn.execute('CREATE TABLE IF NOT EXISTS __walden_binding(account TEXT, generation TEXT, shard TEXT)')
        found = conn.execute('SELECT * FROM __walden_binding').fetchall()
        if found and found != [self.binding]:
            raise MirrorError('source_identity_mismatch')
        if not found:
            conn.execute('INSERT INTO __walden_binding VALUES(?,?,?)', self.binding)
        conn.execute('CREATE TABLE IF NOT EXISTS __walden_progress(table_name TEXT PRIMARY KEY, value TEXT NOT NULL)')
        conn.execute('CREATE TABLE IF NOT EXISTS __walden_observed(table_name TEXT, local_id INTEGER, server_id TEXT, kind INTEGER, timestamp INTEGER, sender INTEGER, fingerprint TEXT, UNIQUE(table_name,local_id,fingerprint))')

    @classmethod
    def metadata_shell_bytes(cls, source):
        """Exact default SQLite allocation for this binding, without any file."""
        value=object.__new__(cls);value.binding=(source.account_id,source.source_generation,source.shard_name)
        with closing(sqlite3.connect(':memory:')) as conn:
            value._initialize(conn);conn.commit()
            return conn.execute('PRAGMA page_count').fetchone()[0]*conn.execute('PRAGMA page_size').fetchone()[0]

    @classmethod
    def bound_transaction(cls,path,source,connection,database='main'):
        """Existing attached database only: no constructor DDL or independent commit."""
        if not re.fullmatch(r'main|d[0-9]+',database):raise MirrorError('invalid_database_alias')
        binding=(source.account_id,source.source_generation,source.shard_name)
        if connection.execute('SELECT * FROM '+quote_identifier(database)+'.__walden_binding').fetchall()!=[binding]:raise MirrorError('source_identity_mismatch')
        value=object.__new__(cls);value.path=Path(path);value.binding=binding;return value

    def connect(self):
        witness=getattr(self,'_witness',None)
        return witness.connect(self.path) if witness is not None else sqlite3.connect(self.path)

    def _check(self, source):
        if (source.account_id, source.source_generation, source.shard_name) != self.binding:
            raise MirrorError('source_identity_mismatch')

    def ensure_table(self, source, ddl, *, _connection=None):
        self._check(source)
        # Let SQLite parse DDL in a disposable database, never execute unvalidated
        # source SQL against the mirror metadata namespace.
        with sqlite3.connect(':memory:') as probe:
            probe.execute(ddl)
            tables = probe.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
            if len(tables) != 1:
                raise MirrorError('unsupported_schema')
            name, sql = tables[0]
            if name != source.table_name or name.startswith('__walden_'):
                raise MirrorError('reserved_or_mismatched_table')
            columns = probe.execute('PRAGMA table_xinfo(' + quote_identifier(name) + ')').fetchall()
            if any(row[6] for row in columns) or any(row[1].lower() in ('rowid','_rowid_','oid') and not (row[2].upper() == 'INTEGER' and row[5] == 1 and sum(bool(c[5]) for c in columns) == 1) for row in columns) or 'WITHOUT ROWID' in sql.upper():
                raise MirrorError('unsupported_schema')
        with (self.connect() if _connection is None else nullcontext(_connection)) as conn:
            if _connection is not None:
                databases=conn.execute('PRAGMA database_list').fetchall()
                if (not conn.in_transaction or not any(row[1]=='main' and Path(row[2]).resolve()==self.path.resolve() for row in databases)
                        or conn.execute('SELECT * FROM __walden_binding').fetchall()!=[self.binding]):
                    raise MirrorError('source_identity_mismatch')
            prior = conn.execute('SELECT sql FROM sqlite_master WHERE name=?', (name,)).fetchone()
            if prior is not None and prior[0] != sql:
                raise MirrorError('schema_changed')
            if prior is None:
                conn.execute(sql)

    def progress(self, table):
        with self.connect() as conn:
            row = conn.execute('SELECT value FROM __walden_progress WHERE table_name=?', (table,)).fetchone()
            return json.loads(row[0]) if row else None

    def apply_batch(self, source, table, rows, progress, *, replace_snapshot=False, _connection=None, _database='main', _complete_snapshot=False, _commit_check=None, _physical=None, _before_rows=None, _keep_progress=False):
        _diagnostic_stage='local_prepare'
        self._check(source)
        if not re.fullmatch(r'main|d[0-9]+',_database) or (_database!='main' and _connection is None):raise MirrorError('invalid_database_alias')
        database='' if _database=='main' else quote_identifier(_database)+'.'
        if type(_complete_snapshot) is not bool or (_complete_snapshot and (not replace_snapshot or _connection is None or (_connection.isolation_level is None and not _connection.in_transaction) or table.startswith('Msg_'))):raise MirrorError('invalid_complete_snapshot')
        if table != source.table_name or table.startswith('__walden_'):
            raise MirrorError('reserved_or_mismatched_table')
        if _keep_progress and (_connection is None or _physical is None or _commit_check is None):
            raise MirrorError('scope_copy_proof')
        physical = table if _physical is None else _physical
        if _physical is not None:
            from .native_table_cursor import physical as epoch_table
            if (_database != 'main' or replace_snapshot
                    or (_connection is None and _before_rows is None)
                    or (_connection is not None and not _connection.in_transaction)
                    or physical != epoch_table(table, progress.get('cursor_epoch', 0))):
                raise MirrorError('scope_copy_proof')
        with (self.connect() if _connection is None else nullcontext(_connection)) as conn:
            if _physical is None and table.startswith('Msg_') and conn.execute(
                    'SELECT 1 FROM '+(database or 'main.')+"sqlite_master WHERE type='table' AND name='__walden_cursor_epochs'").fetchone():
                if conn.execute('SELECT 1 FROM '+database+'__walden_cursor_epochs WHERE table_name=?',(table,)).fetchone():
                    raise MirrorError('scope_copy_proof')
            if _before_rows is not None:
                replaced = _before_rows(conn)
                if replaced is not None:
                    return replaced
            columns = conn.execute('PRAGMA '+database+'table_info(' + quote_identifier(physical) + ')').fetchall()
            if not columns:
                raise MirrorError('unknown_table')
            if replace_snapshot:
                conn.execute('DELETE FROM ' + database + quote_identifier(physical))
            names = ['rowid'] + [item[1] for item in columns]
            insert = 'INSERT OR REPLACE INTO ' if _physical is None else 'INSERT INTO '
            prefix = insert + database + quote_identifier(physical) + '(' + ','.join(map(quote_identifier, names)) + ') VALUES('
            # Only an actual matching rowid can be updated. A secondary
            # UNIQUE conflict cannot replace a different retained message.
            on_conflict = '' if _physical is None else ' ON CONFLICT(rowid) DO UPDATE SET ' + ','.join(
                quote_identifier(name) + '=excluded.' + quote_identifier(name) for name in names[1:])
            sql = prefix + ','.join('?' for _ in names) + ')' + on_conflict
            if _complete_snapshot:
                # Recovery has frozen the complete schema and rejects triggers.
                # Verify the empty target, then bulk-bind bounded same-storage
                # runs in original rowid order; no per-row empty SELECT.
                if conn.execute('SELECT 1 FROM '+database+quote_identifier(physical)+' LIMIT 1').fetchone() is not None:raise MirrorError('snapshot_not_empty')
                if conn.execute('SELECT 1 FROM '+(database or 'main.')+"sqlite_master WHERE type='trigger' LIMIT 1").fetchone():raise MirrorError('snapshot_trigger_unsupported')
                written=self._insert_complete_snapshot(conn,prefix,rows,len(names))
                conn.execute('INSERT OR REPLACE INTO '+database+'__walden_progress VALUES(?,?)',(table,json.dumps(progress,sort_keys=True)))
                if _commit_check is not None:_commit_check()
                return written
            written = 0
            _diagnostic_stage='local_write'
            for row in rows:
                with lossless_text_rows(conn):
                    previous = conn.execute('SELECT rowid,* FROM ' + database + quote_identifier(physical) + ' WHERE rowid=?', (row[0],)).fetchone()
                if previous != tuple(row):
                    if any(isinstance(value, RawText) for value in row):
                        expressions = ['CAST(? AS TEXT)' if isinstance(value, RawText) else '?' for value in row]
                        values = [value.data if isinstance(value, RawText) else value for value in row]
                        conn.execute(prefix + ','.join(expressions) + ')' + on_conflict, values)
                    else:
                        conn.execute(sql, row)
                    written += 1
                if table.startswith('Msg_'):
                    record = dict(zip(names, row))
                    message = RawMessage(record['local_id'], record.get('server_id'), record['local_type'], record['create_time'], record['real_sender_id'], record['message_content'], record['WCDB_CT_message_content'])
                    observation = (message.local_id, str(message.server_id) if message.server_id is not None else None, message.local_type, message.create_time, message.real_sender_id, _content_fingerprint(message))
                    if _physical is not None and physical != table:
                        conn.execute('INSERT OR IGNORE INTO __walden_epoch_observed VALUES(?,?,?,?,?,?,?,?)', (table, progress['cursor_epoch'], *observation))
                    else:
                        conn.execute('INSERT OR IGNORE INTO '+database+'__walden_observed VALUES(?,?,?,?,?,?,?)', (table, *observation))
            if table.startswith('Msg_') and (written or replace_snapshot) and progress.get('recent_observation'):
                prior = conn.execute('SELECT value FROM '+database+'__walden_progress WHERE table_name=?', (table,)).fetchone()
                prior_token = json.loads(prior[0]).get('recent_observation', {}).get('observation_id') if prior else None
                if prior_token == progress['recent_observation'].get('observation_id'):
                    # A legal later body write cannot retain an old source proof.
                    # Historical __walden_observed fingerprints are not current truth.
                    progress = dict(progress)
                    progress.pop('recent_observation', None)
            if not _keep_progress:
                conn.execute('INSERT OR REPLACE INTO '+database+'__walden_progress VALUES(?,?)', (table, json.dumps(progress, sort_keys=True)))
            if _commit_check is not None:_commit_check()
            _diagnostic_stage='local_commit'
        return written

    @staticmethod
    def _insert_complete_snapshot(conn,prefix,rows,width):
        pending=[];previous=None;mask=None;written=0
        def flush():
            if pending:
                sql=prefix+','.join('CAST(? AS TEXT)' if raw else '?' for raw in mask)+')'
                conn.executemany(sql,pending);pending.clear()
        for row in rows:
            if len(row)!=width or type(row[0]) is not int or previous is not None and row[0]<=previous:raise MirrorError('snapshot_row_order_invalid')
            previous=row[0];current=tuple(isinstance(value,RawText) for value in row)
            if mask is not None and current!=mask:flush()
            mask=current;pending.append(tuple(value.data if isinstance(value,RawText) else value for value in row));written+=1
            if len(pending)==128:flush()
        flush();return written
