"""Cryptographic primitives.

MyBot invents nothing here.  Everything is a thin, well-labelled wrapper over
``cryptography``'s audited implementations:

* AES-256-GCM for secrets at rest (AEAD, so tampering is detected, not just
  hidden).
* HKDF-SHA256 to derive purpose-specific subkeys from one master key, so the
  master key itself is never used directly for anything.
* Argon2id for passwords.
* SHA-256 for the audit hash chain and content addressing.
* HMAC-SHA256 for lookup hashes where a plain digest would be brute-forceable
  (short values like an email address or a name).

The one design decision worth stating: every AEAD operation takes explicit
*additional authenticated data* binding the ciphertext to its owner and its
purpose.  A vault blob copied from one user's row into another's therefore
fails to decrypt rather than silently succeeding.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12


class CryptoError(RuntimeError):
    """Any failure in encrypt/decrypt. Never carries key or plaintext detail."""


@dataclass(frozen=True)
class SealedBox:
    nonce: bytes
    ciphertext: bytes
    aad: str
    key_version: int


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def derive_subkey(master_key: bytes, purpose: str, *, length: int = AES_KEY_BYTES) -> bytes:
    """Derive a purpose-bound subkey from the master key.

    Separate keys for separate jobs means compromising, say, the PII lookup
    HMAC key does not hand over the key that decrypts OAuth refresh tokens.
    """
    if len(master_key) < 32:
        raise CryptoError("master key too short")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=f"mybot/v1/{purpose}".encode(),
    )
    return hkdf.derive(master_key)


def seal(key: bytes, plaintext: bytes, aad: str, *, key_version: int = 1) -> SealedBox:
    """AES-256-GCM encrypt with authenticated context."""
    if len(key) != AES_KEY_BYTES:
        raise CryptoError("invalid key length")
    nonce = os.urandom(GCM_NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad.encode("utf-8"))
    return SealedBox(nonce=nonce, ciphertext=ct, aad=aad, key_version=key_version)


def unseal(key: bytes, box: SealedBox) -> bytes:
    """Decrypt, verifying the bound context.

    A mismatch in ``aad`` -- wrong owner, wrong ref -- fails here rather than
    returning somebody else's secret.
    """
    if len(key) != AES_KEY_BYTES:
        raise CryptoError("invalid key length")
    try:
        return AESGCM(key).decrypt(box.nonce, box.ciphertext, box.aad.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - never surface crypto internals
        raise CryptoError("decryption failed: wrong key, wrong context, or tampering") from exc


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hmac_hex(key: bytes, data: bytes | str) -> str:
    """Keyed hash for lookup columns.

    Used where the value space is small enough that a bare SHA-256 index would
    be trivially reversible (email addresses, street addresses, names).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def canonical_json(payload) -> str:
    """Stable JSON for hashing.

    Sorted keys, no incidental whitespace, no NaN.  The audit chain depends on
    two processes producing byte-identical input for the same event.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        default=str,
    )


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_fingerprint(token: str) -> str:
    """Hash used to store session tokens.

    Tokens are high-entropy random strings, so a plain SHA-256 is sufficient
    here -- there is no dictionary to attack.  Passwords use Argon2 instead.
    """
    return sha256_hex(token)


__all__ = [
    "AES_KEY_BYTES",
    "CryptoError",
    "SealedBox",
    "b64d",
    "b64e",
    "canonical_json",
    "constant_time_equals",
    "derive_subkey",
    "generate_key",
    "hmac_hex",
    "random_token",
    "seal",
    "sha256_hex",
    "token_fingerprint",
    "unseal",
]
