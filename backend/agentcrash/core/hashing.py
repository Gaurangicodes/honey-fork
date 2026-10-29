"""Canonical JSON hashing used for state fingerprints and evidence integrity.

A single implementation keeps fingerprints stable across components: the same
logical state must always hash to the same value regardless of key order or
whitespace.

FR-DB-04 asks for an *integrity check* over canonicalized receipts, not a
signature. The hash is computed over the record with its own ``integrity_hash``
field removed, so a reader can recompute it from the stored body and detect a
later modification. It proves nothing about whether the evidence is true, and
the report says so explicitly.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# The field carrying the digest. Excluded from the digest itself, otherwise the
# hash could never be recomputed from the stored record.
INTEGRITY_FIELD = "integrity_hash"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def canonical_hash(value: Any) -> str:
    return "0x" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


def canonical_body(value: Any) -> Any:
    """The hashable body of a record: its canonical form minus its own digest."""
    body = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
    body = json.loads(json.dumps(body, default=str))
    if isinstance(body, dict):
        body.pop(INTEGRITY_FIELD, None)
    return body


def integrity_hash(value: Any) -> str:
    """FR-DB-04: digest of a record's canonical body."""
    return canonical_hash(canonical_body(value))


def verify_integrity(value: Any, expected: str | None = None) -> bool:
    """True when the stored digest still matches the record's current content.

    ``expected`` defaults to the record's own ``integrity_hash`` field, which is
    the common case: a tampered record keeps its old digest and therefore fails.
    """
    if expected is None:
        expected = getattr(value, INTEGRITY_FIELD, None)
        if expected is None and isinstance(value, dict):
            expected = value.get(INTEGRITY_FIELD)
    if not expected:
        return False
    return integrity_hash(value) == expected
