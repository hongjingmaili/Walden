"""Required message schema validation shared by native reads and synchronization."""
from __future__ import annotations
from typing import Any
from .common import quote_identifier

class SourceSchemaError(RuntimeError):
    """A source table cannot be read without weakening the existing schema contract."""

REQUIRED_COLUMNS = {
    "local_id",
    "local_type",
    "create_time",
    "real_sender_id",
    "message_content",
    "WCDB_CT_message_content",
}


def _table_columns(conn: Any, table_name: str) -> dict[str, tuple[Any, ...]]:
    rows = conn.execute(
        f"PRAGMA table_info({quote_identifier(table_name)})"
    ).fetchall()
    if not rows:
        raise SourceSchemaError("Message table does not exist")
    columns = {str(row[1]): tuple(row) for row in rows}
    missing = REQUIRED_COLUMNS - set(columns)
    if missing:
        raise SourceSchemaError(
            f"Message table is missing required columns: {sorted(missing)}"
        )
    if int(columns["local_id"][5] or 0) < 1:
        raise SourceSchemaError("local_id must be the message table primary key")
    return columns

