"""Secret redaction for evidence, transcripts and reports (NFR-07, SR-05).

Applied at the serialization boundary so credentials can never reach a report,
a transcript, a log line or a browser-visible error.
"""

from __future__ import annotations

import re
from typing import Any

_REDACTED = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # 0x-prefixed 64-hex private keys (but not 40-hex addresses or tx hashes).
    (re.compile(r"0x[a-fA-F0-9]{64}"), _REDACTED),
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

SENSITIVE_KEYS = {
    "private_key",
    "privatekey",
    "mnemonic",
    "seed_phrase",
    "seedphrase",
    "api_key",
    "apikey",
    "secret",
    "password",
    "authorization",
}


def redact_text(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact(value: Any) -> Any:
    """Recursively redact secrets from JSON-like structures."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            key: (_REDACTED if str(key).lower() in SENSITIVE_KEYS else redact(item))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value
