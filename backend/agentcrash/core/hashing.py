"""Canonical JSON hashing used for state fingerprints and evidence integrity.

A single implementation keeps fingerprints stable across components: the same
logical state must always hash to the same value regardless of key order or
whitespace.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def canonical_hash(value: Any) -> str:
    return "0x" + hashlib.sha256(canonical_json(value).encode()).hexdigest()
