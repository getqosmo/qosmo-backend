"""Authentication: passwords, session tokens and auth-level elevation.

Design notes worth stating explicitly:

* **Argon2id** for passwords, with parameters that are deliberately not the
  library minimum.
* **Server-side sessions.**  The bearer token is random; the database stores
  only its hash.  A stateless JWT would be smaller but could not be revoked,
  and revocation is load-bearing for lockdown and stolen devices.
* **Elevation, not roles.**  ``AuthLevel`` is time-boxed proof of presence,
  not a permanent attribute.  A STRONG elevation lapses back to BASIC after a
  few minutes, so an unattended logged-in laptop cannot authorise a payment an
  hour later.
* **No SMS.**  The second factor here is a TOTP-shaped shared secret in
  development, and the interface is built so passkeys and hardware keys drop
  in without changing call sites.
"""

from __future__ import annotations

import datetime as dt
import hmac
import struct
import time
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from mybot_schemas.enums import AuthLevel

from .crypto import b64d, random_token, sha256_hex, token_fingerprint

#: Tuned for an interactive login on a laptop or Core: ~64 MiB, 3 passes.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)

MIN_PASSWORD_LENGTH = 12


class AuthError(RuntimeError):
    """Authentication failure. Message is deliberately non-specific."""


class WeakPasswordError(ValueError):
    pass


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        )
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify a password.

    Returns a boolean rather than raising so call sites cannot accidentally
    distinguish "no such user" from "wrong password" in their error handling --
    that difference is a user-enumeration oracle.
    """
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except (InvalidHashError, ValueError):  # pragma: no cover
        return True


@dataclass(frozen=True)
class IssuedToken:
    token: str
    token_hash: str
    expires_at: dt.datetime


def issue_session_token(ttl_seconds: int) -> IssuedToken:
    """Mint an opaque bearer token; only its hash is ever stored."""
    token = random_token(32)
    return IssuedToken(
        token=token,
        token_hash=token_fingerprint(token),
        expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(seconds=ttl_seconds),
    )


def hash_ip(ip: str | None) -> str | None:
    """Store a hash of the client IP, not the IP.

    Enough to spot "this session moved to a new network"; not a location
    history sitting in the database.
    """
    if not ip:
        return None
    return sha256_hex(f"mybot-ip|{ip}")[:32]


# ---------------------------------------------------------------------------
# Second factor
# ---------------------------------------------------------------------------


def generate_totp_secret() -> str:
    """Base32-ish shared secret for the development second factor."""
    return random_token(20)


def totp_code(secret: str, *, at: int | None = None, period: int = 30, digits: int = 6) -> str:
    """RFC-6238-shaped TOTP over the raw secret.

    Development stand-in for a passkey.  Kept small and standard rather than
    invented; the point is that the *interface* -- prove a second factor to
    elevate -- is exercised end to end.
    """
    counter = int((at if at is not None else time.time()) // period)
    key = b64d(secret) if _looks_b64(secret) else secret.encode()
    digest = hmac.new(key, struct.pack(">Q", counter), "sha1").digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)


def verify_totp(secret: str, code: str, *, window: int = 1) -> bool:
    """Verify with a small clock-skew window, in constant time."""
    if not code or not code.isdigit():
        return False
    now = int(time.time())
    for drift in range(-window, window + 1):
        candidate = totp_code(secret, at=now + drift * 30)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def _looks_b64(value: str) -> bool:
    try:
        b64d(value)
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Auth levels
# ---------------------------------------------------------------------------


def effective_auth_level(
    stored_level: str, elevated_until: dt.datetime | None, *, now: dt.datetime | None = None
) -> AuthLevel:
    """Collapse a session's recorded level to what it is *right now*.

    Elevation expires.  This is called on every request rather than trusted
    from the row, so a long-lived session cannot retain STRONG indefinitely.
    """
    now = now or dt.datetime.now(dt.UTC)
    level = AuthLevel(stored_level)
    if level.rank <= AuthLevel.BASIC.rank:
        return level
    if elevated_until is None or elevated_until <= now:
        return AuthLevel.BASIC
    return level


__all__ = [
    "AuthError",
    "IssuedToken",
    "MIN_PASSWORD_LENGTH",
    "WeakPasswordError",
    "effective_auth_level",
    "generate_totp_secret",
    "hash_ip",
    "hash_password",
    "issue_session_token",
    "needs_rehash",
    "totp_code",
    "verify_password",
    "verify_totp",
]
