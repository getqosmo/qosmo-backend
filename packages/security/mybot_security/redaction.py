"""Redaction for logs, audit details and error messages.

Logs are the classic accidental secret store: nobody classifies them, they get
shipped to third parties, they outlive the data they describe, and they are
readable by more people than the database is.  So MyBot redacts on the way
*in*, not at the log sink.

The strategy is allowlist-flavoured where it matters.  Keys whose *name*
suggests a secret are redacted regardless of their value, because that check
cannot be fooled by an unusual format.  Value-shaped detection (JWTs, bearer
tokens, card numbers, keys) is a second pass for secrets that arrive under an
innocuous key.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

#: Any key containing one of these substrings is redacted outright.
SENSITIVE_KEY_PARTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth_header",
    "credential",
    "private_key",
    "privatekey",
    "refresh",
    "access_key",
    "session_key",
    "cookie",
    "ssn",
    "social_security",
    "passport_number",
    "account_number",
    "routing_number",
    "card_number",
    "cvv",
    "pin",
    "master_key",
    "seed_phrase",
    "mnemonic",
    "otp",
    "totp",
    "signature",
    "ciphertext",
    "nonce",
)

#: Keys that are sensitive but where a masked tail is more useful than nothing
#: (matching an account in the UI, for instance).
PARTIAL_KEY_PARTS: tuple[str, ...] = ("iban", "account_ref", "last4")

_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{16,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}\b")),
    ("google_oauth", re.compile(r"\bya29\.[A-Za-z0-9_\-]{10,}\b")),
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("pem", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
)

_MAX_STRING = 2000


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def _is_partial_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in PARTIAL_KEY_PARTS)


def mask_tail(value: str, keep: int = 4) -> str:
    """Show only the last few characters, e.g. ``•••• 3812``."""
    if len(value) <= keep:
        return "•" * len(value)
    return "•••• " + value[-keep:]


def redact_text(value: str) -> str:
    """Strip secret-shaped substrings from free text."""
    if len(value) > _MAX_STRING:
        value = value[:_MAX_STRING] + f"…[truncated {len(value) - _MAX_STRING} chars]"
    for _label, pattern in _VALUE_PATTERNS:
        value = pattern.sub(REDACTED, value)
    return value


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Recursively redact a structure destined for a log or audit record.

    Depth-limited so a cyclic or pathologically nested payload cannot turn a
    log call into a denial of service.
    """
    if _depth > 12:
        return "[TRUNCATED: max depth]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        return f"[BYTES len={len(value)}]"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        out: dict = {}
        for key, item in value.items():
            key_str = str(key)
            if _is_sensitive_key(key_str):
                out[key_str] = REDACTED
            elif _is_partial_key(key_str) and isinstance(item, str):
                out[key_str] = mask_tail(item)
            else:
                out[key_str] = redact(item, _depth=_depth + 1)
        return out
    if isinstance(value, (list, tuple, set)):
        return [redact(v, _depth=_depth + 1) for v in list(value)[:200]]
    return redact_text(str(value))


def contains_secret(value: Any) -> bool:
    """True when redaction would change something.

    Used by tests that assert log output is clean, and by the model-egress
    guard as a last line of defence before a payload leaves the machine.
    """
    return redact(value) != value


__all__ = [
    "PARTIAL_KEY_PARTS",
    "REDACTED",
    "SENSITIVE_KEY_PARTS",
    "contains_secret",
    "mask_tail",
    "redact",
    "redact_text",
]
