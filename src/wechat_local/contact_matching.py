"""Pure matching of already scoped contact facts; no inventory or source queries."""
from __future__ import annotations
import unicodedata
from typing import Any

CONTACT_FIELDS = ("username", "alias", "remark", "nick_name", "display_name")

def normalize(value: str | None) -> str:
    return unicodedata.normalize("NFKC", value or "").strip().casefold()


def _display_name(contact: dict[str, Any]) -> str:
    return (
        str(contact.get("remark") or "").strip()
        or str(contact.get("nick_name") or "").strip()
        or str(contact.get("alias") or "").strip()
        or str(contact["username"])
    )


def _kind(username: str) -> str:
    if username.endswith("@chatroom"):
        return "群聊"
    if username.startswith("gh_"):
        return "公众号"
    return "私聊/其他"


def _matched_fields(contact: dict[str, Any], query: str, exact: bool) -> list[str]:
    fields = []
    for field in CONTACT_FIELDS:
        value = normalize(str(contact.get(field) or ""))
        if not value:
            continue
        if (value == query) if exact else (query in value):
            fields.append(field)
    return fields

