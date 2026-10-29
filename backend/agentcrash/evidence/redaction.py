"""Secret redaction for evidence, transcripts and reports (NFR-07, SR-05).

Applied at the serialization boundary so credentials can never reach a report,
a transcript, a log line or a browser-visible error.

A bare ``0x`` + 64 hex value is ambiguous: it is exactly the shape of both a
private key *and* a transaction hash. Redacting every match would destroy the
transaction evidence the SRS requires the dashboard to show (section 24), so the
decision is made with the field name as context. A value under a field that
names a hash is evidence and is preserved; a value under any other field keeps
the private-key rule. Free text (no field name available) keeps the strict rule,
because a key pasted into prose must never survive.
"""

from __future__ import annotations

import re
from typing import Any

_REDACTED = "[REDACTED]"

# 0x-prefixed 64-hex. Matches a private key *or* a transaction/digest hash.
_HEX64 = re.compile(r"0x[a-fA-F0-9]{64}")

# Patterns that are never legitimate evidence and are always applied.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # OpenAI-style keys.
    (re.compile(r"sk-[A-Za-z0-9]{16,}"), _REDACTED),
    # GitHub tokens.
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"), _REDACTED),
    # Generic bearer tokens / api keys in "key=value" form.
    (
        re.compile(
            r"(?i)(api[_-]?key|secret|token|password|private[_-]?key|mnemonic|seed[_-]?phrase)"
            r"\s*[:=]\s*['\"]?([^\s'\"]{6,})"
        ),
        r"\1=" + _REDACTED,
    ),
    # Seed phrases: 12+ lowercase words in a row.
    (re.compile(r"\b(?:[a-z]{3,}\s+){11,}[a-z]{3,}\b"), _REDACTED),
]

# Field names that carry a credential. Matched as substrings so
# ``user_password`` and ``signing_key`` are covered too.
SENSITIVE_MARKERS = (
    "private_key",
    "privatekey",
    "mnemonic",
    "seed_phrase",
    "seedphrase",
    "passphrase",
    "api_key",
    "apikey",
    "secret",
    "password",
    "authorization",
    "credential",
    "keystore",
)

# Field names that carry chain evidence. A 64-hex value here is a transaction
# hash, a block hash or an integrity digest, and must survive redaction.
EVIDENCE_MARKERS = (
    "hash",
    "digest",
    "tx",
    "transaction",
    "evidence_id",
    "snapshot_id",
)

# Retained for callers that check membership directly.
SENSITIVE_KEYS = set(SENSITIVE_MARKERS)


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in SENSITIVE_MARKERS)


def _is_evidence(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in EVIDENCE_MARKERS)


def redact_text(text: str) -> str:
    """Redact secrets from free text, including 64-hex values.

    No field name is available here, so a 64-hex value is treated as a
    credential. Callers that know the field name should use :func:`redact`.
    """
    text = _HEX64.sub(_REDACTED, text)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_text_keeping_hashes(text: str) -> str:
    """Apply the unambiguous rules but leave 64-hex values alone."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact(value: Any, *, keep_hex_hashes: bool = False) -> Any:
    """Recursively redact secrets from JSON-like structures.

    Field names decide how a 64-hex value is treated, which is what keeps a
    transaction hash readable while a private key still cannot leak. When a
    field is known to hold evidence, ``keep_hex_hashes`` carries that decision
    down into lists such as ``transaction_hashes``.
    """
    if isinstance(value, str):
        return _redact_text_keeping_hashes(value) if keep_hex_hashes else redact_text(value)
    if isinstance(value, dict):
        cleaned: dict[Any, Any] = {}
        for key, item in value.items():
            name = str(key)
            if _is_sensitive(name):
                cleaned[key] = _REDACTED
            elif _is_evidence(name):
                cleaned[key] = redact(item, keep_hex_hashes=True)
            else:
                cleaned[key] = redact(item, keep_hex_hashes=keep_hex_hashes)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [redact(item, keep_hex_hashes=keep_hex_hashes) for item in value]
    return value
