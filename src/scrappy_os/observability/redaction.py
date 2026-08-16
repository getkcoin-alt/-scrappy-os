"""Secret redaction.

Every payload that reaches a log line, an audit row or an LLM prompt passes
through here first. Redaction is applied at the *sink*, not at the call site,
because relying on each caller to remember is how credentials end up in logs.

Two complementary strategies:

* **Key matching** - a mapping key that looks like a secret has its value
  replaced regardless of content (``api_key``, ``password``, ``token``, ...).
* **Value matching** - strings that look like known credential formats are
  masked even when the key is innocent (``{"note": "sk-live-..."}``).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

REDACTED: Final = "[REDACTED]"
MAX_STRING_LENGTH: Final = 8192

#: Substrings that make a mapping key secret-bearing.
SENSITIVE_KEY_PARTS: Final[frozenset[str]] = frozenset(
    {
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "cookie",
        "credential",
        "passwd",
        "password",
        "private_key",
        "secret",
        "session",
        "signature",
        "token",
    }
)

#: Value shapes that are credentials no matter where they appear.
SENSITIVE_VALUE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),  # OpenAI-style keys
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),  # GitHub tokens
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),  # Slack tokens
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key ids
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._\-+/=]{12,}"),
)


def is_sensitive_key(key: str) -> bool:
    """Whether a mapping key should have its value hidden outright."""
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def redact_text(value: str) -> str:
    """Mask credential-shaped substrings inside free text."""
    for pattern in SENSITIVE_VALUE_PATTERNS:
        value = pattern.sub(REDACTED, value)
    return value


def redact(value: Any, *, max_depth: int = 12) -> Any:
    """Return a redacted copy of an arbitrary structure.

    Never mutates the input: audit records and live objects must not share
    state. Depth is bounded so a self-referential structure cannot hang a log
    write.
    """
    return _redact(value, depth=0, max_depth=max_depth)


def _redact(value: Any, *, depth: int, max_depth: int) -> Any:
    if depth > max_depth:
        return "[TRUNCATED: max depth]"

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            if is_sensitive_key(key):
                result[key] = REDACTED if item is not None else None
            else:
                result[key] = _redact(item, depth=depth + 1, max_depth=max_depth)
        return result

    if isinstance(value, str):
        masked = redact_text(value)
        if len(masked) > MAX_STRING_LENGTH:
            return masked[:MAX_STRING_LENGTH] + f"... [truncated {len(masked)} chars]"
        return masked

    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"

    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return [_redact(item, depth=depth + 1, max_depth=max_depth) for item in value]

    if isinstance(value, set | frozenset):
        return sorted(_redact(item, depth=depth + 1, max_depth=max_depth) for item in value)

    return value


def sha256_of(value: str | bytes) -> str:
    """Stable digest, used when audit stores a fingerprint instead of content."""
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


__all__ = [
    "REDACTED",
    "SENSITIVE_KEY_PARTS",
    "SENSITIVE_VALUE_PATTERNS",
    "is_sensitive_key",
    "redact",
    "redact_text",
    "sha256_of",
]
