"""Pinned readonly native table routes and protected numeric source discovery."""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any,Iterable
from .source_records import SourceKey
from .source_schema import SourceSchemaError as LiveTailerError,_table_columns

SHARD_NAME_PATTERN = re.compile(r"(?:biz_)?message_[0-9]+\.db")
TABLE_NAME_PATTERN = re.compile(r"Msg_[0-9a-f]{32}")


class LiveCatalogError(RuntimeError):
    """Raised when an authorized shard cannot be catalogued safely."""


def _require_query_only(conn: Any) -> None:
    row = conn.execute("PRAGMA query_only").fetchone()
    if not row or int(row[0]) != 1:
        raise LiveCatalogError("Message source connection must have query_only enabled")


@dataclass(frozen=True)
class LiveShard:
    path: Path
    connection: Any

    @property
    def shard_name(self) -> str:
        return self.path.name



def _is_within(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def discover_numeric_shards(live_root: Path) -> tuple[Path, ...]:
    """Enumerate direct numeric message shard files in one explicit live root."""

    root = live_root.resolve()
    if not root.is_dir():
        raise LiveCatalogError("Live shard root must be an existing directory")
    found: list[Path] = []
    for candidate in live_root.iterdir():
        if SHARD_NAME_PATTERN.fullmatch(candidate.name) is None:
            continue
        if candidate.is_symlink():
            resolved = candidate.resolve()
            if not _is_within(resolved, root):
                raise LiveCatalogError("Message shard symbolic link escapes live root")
            raise LiveCatalogError("Message shard candidates must not be symbolic links")
        if not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if not _is_within(resolved, root):
            raise LiveCatalogError("Message shard resolves outside live root")
        found.append(resolved)
    if len(set(found)) != len(found):
        raise LiveCatalogError("Discovered message shard paths must be unique")
    return tuple(sorted(found, key=lambda path: path.name))


class LiveCatalog:
    """Borrow only explicitly supplied query-only connections; never open a source."""
    def __init__(self, shards: Iterable[LiveShard]):
        items = tuple(shards)
        if not items:
            raise LiveCatalogError("At least one message shard is required")
        self._set_shards(items)

    def _set_shards(self, items: tuple[LiveShard, ...]) -> None:
        resolved_paths = tuple(item.path.resolve() for item in items)
        if len(set(resolved_paths)) != len(resolved_paths):
            raise LiveCatalogError("Message shard paths must be unique")
        shard_names = tuple(path.name for path in resolved_paths)
        if len(set(shard_names)) != len(shard_names):
            raise LiveCatalogError("Message shard basenames must be unique")
        if any(
            SHARD_NAME_PATTERN.fullmatch(name) is None
            for name in shard_names
        ):
            raise LiveCatalogError(
                "Only numeric message_<n>.db or biz_message_<n>.db shards are accepted"
            )

        routes: dict[str, list[LiveShard]] = {}
        normalized: list[LiveShard] = []
        for item, path in zip(items, resolved_paths):
            _require_query_only(item.connection)
            shard = LiveShard(path=path, connection=item.connection)
            normalized.append(shard)
            rows = item.connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='table' AND name GLOB 'Msg_*'
                ORDER BY name
                """
            ).fetchall()
            for (table_name,) in rows:
                name = str(table_name)
                if TABLE_NAME_PATTERN.fullmatch(name) is None:
                    continue
                try:
                    _table_columns(item.connection, name)
                except LiveTailerError:
                    continue
                routes.setdefault(name, []).append(shard)

        self._shards = tuple(normalized)
        self._routes = {name: tuple(found) for name, found in routes.items()}

    @property
    def shards(self) -> tuple[LiveShard, ...]:
        return self._shards


    def discovered_routes_for(self, table_name: str) -> tuple[LiveShard, ...]:
        return self._routes.get(table_name, ())

    def shard_for_source(self, source: SourceKey) -> LiveShard | None:
        for shard in self.discovered_routes_for(source.table_name):
            if shard.shard_name == source.shard_name:
                return shard
        return None

    def table_count(self) -> int:
        return len(self._routes)

