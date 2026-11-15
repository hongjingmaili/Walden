"""Shared raw source records and byte-exact identity primitives; no stores."""
from __future__ import annotations
import hashlib
from dataclasses import dataclass
from typing import Any


def observed_association_conflict(candidates: list[tuple], observed_rows: list[tuple]) -> bool:
    """Pure comparison shared by event-backed and native read-only queries.

    Rows are (table, local_id, server_id, kind, timestamp, sender, fingerprint).
    Only nonempty server IDs establish the existing observed-conflict predicate.
    """
    expected_rows: dict[tuple, set[str]] = {}
    for own, local_id, expected in candidates:
        if expected[0] is not None and str(expected[0]):
            expected_rows.setdefault((local_id, *expected), set()).add(own)
    for row in observed_rows:
        origins = expected_rows.get(tuple(row)[1:])
        if origins and (len(origins) > 1 or row[0] not in origins):
            return True
    return False


@dataclass(frozen=True)
class SourceKey:
    """Identity of one physical message table within one database generation."""

    account_id: str
    source_generation: str
    shard_name: str
    table_name: str

    def __post_init__(self) -> None:
        for field_name in (
            "account_id",
            "source_generation",
            "shard_name",
            "table_name",
        ):
            value = getattr(self, field_name)
            if not value or value.strip() != value:
                raise ValueError(f"{field_name} must be a non-empty trimmed string")
            if any(ord(character) < 32 for character in value):
                raise ValueError(f"{field_name} must not contain control characters")


@dataclass(frozen=True)
class RawMessage:
    """Raw fields needed to persist and later reprocess one physical message."""

    local_id: int
    server_id: int | None
    local_type: int
    create_time: int
    real_sender_id: int | None
    raw_content: str | bytes | None
    compression_type: int | None
    # Bounded, query-window-only source XML for display facts such as mentions.
    # These fields are intentionally not persisted into EventStore revisions.
    raw_source: str | bytes | None = None
    source_compression_type: int | None = None

    def __post_init__(self) -> None:
        if self.local_id < 0:
            raise ValueError("local_id must not be negative")


def _typed_bytes(value: Any) -> bytes:
    if value is None:
        payload = b""
        kind = b"N"
    elif isinstance(value, bytes):
        payload = value
        kind = b"B"
    elif isinstance(value, str):
        payload = value.encode("utf-8", errors="surrogatepass")
        kind = b"S"
    else:
        payload = str(value).encode("ascii", errors="strict")
        kind = b"I"
    return kind + len(payload).to_bytes(8, "big") + payload


def _content_fingerprint(message: RawMessage) -> str:
    digest = hashlib.sha256()
    for value in (
        message.server_id,
        message.local_type,
        message.create_time,
        message.real_sender_id,
        message.raw_content,
        message.compression_type,
    ):
        digest.update(_typed_bytes(value))
    return digest.hexdigest()

