"""Optional pre-existing reply evidence verification; never creates or normalizes a store.

Only explicit reply operations import this compatibility module. Native init,
refresh and local queries neither read nor probe pre-existing event evidence.
"""
from __future__ import annotations
from dataclasses import dataclass
from .source_records import SourceKey,observed_association_conflict

# Frozen c6b evidence profile. These are not a normalization engine.
STANDARD_EVENT_SPEC_VERSION = "wechat-local.standard-event/1"
WECHAT_NORMALIZER_NAME = "wechat-macos-v4"
NORMALIZER_VERSION = "2"

class ReplyEvidenceError(RuntimeError):
    """Existing evidence cannot prove the original association contract."""

@dataclass(frozen=True)
class ProjectionProfile:
    contract_version: str = STANDARD_EVENT_SPEC_VERSION
    normalizer_name: str = WECHAT_NORMALIZER_NAME
    normalizer_version: str = NORMALIZER_VERSION
    redaction_profile: str = "p5-safe-v1"

    def __post_init__(self) -> None:
        for field_name in (
            "contract_version",
            "normalizer_name",
            "normalizer_version",
            "redaction_profile",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value or value.strip() != value:
                raise ValueError(f"{field_name} must be nonempty trimmed text")
            if any(ord(character) < 32 for character in value):
                raise ValueError(f"{field_name} contains control characters")
            if "|" in value:
                raise ValueError(f"{field_name} contains the profile delimiter")

    @property
    def profile_id(self) -> str:
        # Values are validated and the delimiter is part of this v1 profile format.
        return "|".join(
            (
                self.contract_version,
                self.normalizer_name,
                self.normalizer_version,
                self.redaction_profile,
            )
        )


def _source_values(source: SourceKey) -> tuple[str, str, str, str]:
    return (
        source.account_id,
        source.source_generation,
        source.shard_name,
        source.table_name,
    )


def _association_conflict(connection, candidates: list[tuple]) -> bool:
    """Check only observed candidate IDs against other tables in their shard.

    Historical revisions indicate an observed conflict, not current source
    state. No source bodies are read and no existing facts are changed.
    """
    by_source: dict[SourceKey, list[tuple]] = {}
    grouped: dict[tuple, list[tuple]] = {}
    for source, local_id, server, kind, timestamp, sender, fingerprint in candidates:
        expected = (None if server is None else str(server), kind, timestamp, sender, fingerprint)
        by_source.setdefault(source, []).append((local_id, expected))
        if server is not None and str(server):
            key = (source.account_id, source.source_generation, source.shard_name)
            grouped.setdefault(key, []).append((source.table_name, local_id, expected))
    for source, items in by_source.items():
        for offset in range(0, len(items), 400):
            chunk = items[offset:offset+400]
            expected = dict(chunk)
            if len(expected) != len(chunk):
                raise ReplyEvidenceError('association_duplicate_candidate')
            placeholders = ','.join('?' for _ in chunk)
            rows = connection.execute(
                'SELECT e.local_id,r.server_id,r.local_type,r.create_time,r.real_sender_id,r.content_fingerprint '
                'FROM events e JOIN event_revisions r ON r.id=e.current_revision_id '
                'WHERE e.account_id=? AND e.source_generation=? AND e.shard_name=? AND e.table_name=? '
                f'AND e.local_id IN ({placeholders})', (*_source_values(source), *expected),
            ).fetchall()
            if len(rows) != len(chunk) or any(tuple(row)[1:] != expected.get(row[0]) for row in rows):
                raise ReplyEvidenceError('association_current_revision_unavailable')
    for key, items in grouped.items():
        for offset in range(0, len(items), 400):
            chunk = items[offset:offset+400]
            identifiers = sorted({item[1] for item in chunk})
            placeholders = ','.join('?' for _ in identifiers)
            rows = connection.execute(
                'SELECT e.table_name,e.local_id,r.server_id,r.local_type,r.create_time,r.real_sender_id,r.content_fingerprint '
                'FROM events e JOIN event_revisions r ON r.event_id=e.id '
                'WHERE e.account_id=? AND e.source_generation=? AND e.shard_name=? '
                'AND e.table_name IN (SELECT DISTINCT table_name FROM events WHERE account_id=? AND source_generation=? AND shard_name=?) '
                f'AND e.local_id IN ({placeholders})', (*key, *key, *identifiers),
            ).fetchall()
            if observed_association_conflict(chunk, rows):
                return True
    return False

