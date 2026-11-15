"""Byte-exact stable source identity encoding; no stores or projections."""
from __future__ import annotations
import hashlib
from typing import Any

def _typed_bytes(value: Any) -> bytes:
    if value is None:
        kind = b"N"
        payload = b""
    elif isinstance(value, bytes):
        kind = b"B"
        payload = value
    elif isinstance(value, str):
        kind = b"S"
        payload = value.encode("utf-8", errors="surrogatepass")
    elif isinstance(value, int) and not isinstance(value, bool):
        kind = b"I"
        payload = str(value).encode("ascii")
    else:
        raise TypeError("Standard ID inputs must be null, bytes, text, or integers")
    return kind + len(payload).to_bytes(8, "big") + payload


def _standard_id(prefix: str, domain: str, *values: Any) -> str:
    digest = hashlib.sha256()
    for value in (domain, *values):
        digest.update(_typed_bytes(value))
    return prefix + digest.hexdigest()

