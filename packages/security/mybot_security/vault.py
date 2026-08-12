"""The MyBot Vault.

The Vault holds credentials, key material and the most sensitive identity
data.  Its API is shaped by one deliberate bias: **prefer performing the
operation over handing back the secret.**

    # Avoid
    password = vault.get_secret("cred:bank")
    bank.login(password)

    # Prefer
    vault.authorize_request("cred:bank", operation="balance_read")

``authorize_request`` returns a short-lived, narrowly-scoped grant rather than
key material.  Reading a raw secret is still possible -- an OAuth refresh has
to happen somewhere -- but it goes through :meth:`reveal_secret`, which
demands an explicit purpose, records an audit event, and is the only method
in the codebase that returns plaintext.  That makes "who can see secrets"
answerable with one grep.

The LLM layer has no reference to this module at all.  It cannot import it,
call it, or name a ref that would reach it: Rule 1, enforced by dependency
direction rather than by instruction.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import sqlalchemy as sa
from mybot_schemas.enums import Classification
from mybot_schemas.models import CredentialReference, VaultSecret
from sqlalchemy.orm import Session

from .crypto import CryptoError, SealedBox, hmac_hex, seal, unseal
from .hardware.keystore import SecureKeyStore

#: Key derivation purposes. Distinct labels keep the subkeys independent.
PURPOSE_SECRETS = "vault-secrets"
PURPOSE_PII_LOOKUP = "pii-lookup"
PURPOSE_DOCUMENTS = "document-storage"


class VaultError(RuntimeError):
    pass


class VaultAccessDenied(PermissionError):
    """Raised when a caller is not permitted to reach a secret."""


@dataclass(frozen=True)
class AuthorizedRequest:
    """A capability, not a credential.

    Handed to an integration adapter so it can perform exactly one kind of
    operation.  Carries no key material; the adapter exchanges it back at the
    Vault boundary when it genuinely needs to sign or authenticate.
    """

    ref: str
    operation: str
    owner_id: str
    granted_at: dt.datetime
    expires_at: dt.datetime
    scopes: tuple[str, ...] = ()
    grant_id: str = ""

    def valid_at(self, when: dt.datetime | None = None) -> bool:
        when = when or dt.datetime.now(dt.UTC)
        return self.granted_at <= when < self.expires_at


@dataclass
class VaultAuditHook:
    """Callback the Vault uses to record access.

    Injected rather than imported so the security package does not depend on
    the audit service (which depends on the schemas package, which the audit
    service also uses).  Keeps the dependency graph acyclic and the Vault
    unit-testable without a database full of audit rows.
    """

    on_access: Callable[[str, str, str, bool, str | None], None] | None = None

    def record(
        self, owner_id: str, ref: str, operation: str, granted: bool, reason: str | None = None
    ) -> None:
        if self.on_access is not None:
            self.on_access(owner_id, ref, operation, granted, reason)


@dataclass
class Vault:
    """Encrypted secret storage bound to a keystore.

    Ciphertext lives in the database; the key never does.
    """

    keystore: SecureKeyStore
    data_dir: Path
    audit: VaultAuditHook = field(default_factory=VaultAuditHook)
    #: How long an ``AuthorizedRequest`` stays usable.
    grant_ttl_seconds: int = 300

    # -- key material ----------------------------------------------------

    def _secret_key(self) -> bytes:
        return self.keystore.derive(PURPOSE_SECRETS)

    def pii_lookup_key(self) -> bytes:
        """Keyed-hash key for the PII token index.

        Separate from the encryption key so the tokenizer's lookup table
        cannot be used to decrypt anything.
        """
        return self.keystore.derive(PURPOSE_PII_LOOKUP)

    def document_key(self) -> bytes:
        return self.keystore.derive(PURPOSE_DOCUMENTS)

    @staticmethod
    def _aad(owner_id: str, ref: str, key_version: int) -> str:
        """Bind ciphertext to owner, ref and key version.

        Without this, a row swapped between users would decrypt cleanly.
        """
        return f"mybot|v1|owner={owner_id}|ref={ref}|kv={key_version}"

    # -- writing ---------------------------------------------------------

    def put_secret(
        self,
        session: Session,
        owner_id: str,
        ref: str,
        plaintext: str | bytes,
        *,
        classification: Classification = Classification.SECRET,
    ) -> VaultSecret:
        """Store or replace a secret."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        kv = self.keystore.key_version
        box = seal(self._secret_key(), plaintext, self._aad(owner_id, ref, kv), key_version=kv)

        existing = session.execute(
            sa.select(VaultSecret).where(
                VaultSecret.owner_id == owner_id, VaultSecret.ref == ref
            )
        ).scalar_one_or_none()

        if existing is not None:
            existing.nonce = box.nonce
            existing.ciphertext = box.ciphertext
            existing.aad = box.aad
            existing.key_version = kv
            existing.classification = classification.value
            existing.rotated_at = dt.datetime.now(dt.UTC)
            record = existing
        else:
            record = VaultSecret(
                owner_id=owner_id,
                ref=ref,
                nonce=box.nonce,
                ciphertext=box.ciphertext,
                aad=box.aad,
                key_version=kv,
                classification=classification.value,
            )
            session.add(record)
        session.flush()
        self.audit.record(owner_id, ref, "put", True)
        return record

    # -- reading ---------------------------------------------------------

    def has_secret(self, session: Session, owner_id: str, ref: str) -> bool:
        return (
            session.execute(
                sa.select(sa.func.count())
                .select_from(VaultSecret)
                .where(VaultSecret.owner_id == owner_id, VaultSecret.ref == ref)
            ).scalar_one()
            > 0
        )

    def authorize_request(
        self,
        session: Session,
        owner_id: str,
        ref: str,
        operation: str,
        *,
        required_scopes: tuple[str, ...] = (),
    ) -> AuthorizedRequest:
        """Grant permission to use a credential without revealing it.

        This is the method integrations should call.  It verifies the
        credential exists, is not revoked or expired, and covers the scopes
        the operation needs -- least privilege checked at use time, not just
        at grant time.
        """
        cred = session.execute(
            sa.select(CredentialReference).where(
                CredentialReference.owner_id == owner_id, CredentialReference.ref == ref
            )
        ).scalar_one_or_none()

        now = dt.datetime.now(dt.UTC)
        if cred is None:
            self.audit.record(owner_id, ref, operation, False, "unknown credential reference")
            raise VaultAccessDenied(f"unknown credential reference: {ref}")
        if cred.revoked_at is not None:
            self.audit.record(owner_id, ref, operation, False, "credential revoked")
            raise VaultAccessDenied("credential has been revoked")
        if cred.expires_at is not None and cred.expires_at <= now:
            self.audit.record(owner_id, ref, operation, False, "credential expired")
            raise VaultAccessDenied("credential has expired")

        missing = [s for s in required_scopes if s not in (cred.scopes or [])]
        if missing:
            self.audit.record(
                owner_id, ref, operation, False, f"missing scopes: {','.join(missing)}"
            )
            raise VaultAccessDenied(
                f"credential {ref} lacks required scopes: {', '.join(missing)}"
            )

        cred.last_used_at = now
        grant = AuthorizedRequest(
            ref=ref,
            operation=operation,
            owner_id=owner_id,
            granted_at=now,
            expires_at=now + dt.timedelta(seconds=self.grant_ttl_seconds),
            scopes=tuple(cred.scopes or ()),
            grant_id=hmac_hex(self.pii_lookup_key(), f"{owner_id}|{ref}|{operation}|{now}")[:32],
        )
        self.audit.record(owner_id, ref, operation, True)
        return grant

    def reveal_secret(
        self,
        session: Session,
        owner_id: str,
        ref: str,
        *,
        purpose: str,
        grant: AuthorizedRequest | None = None,
    ) -> bytes:
        """Return plaintext. The only method here that does.

        Requires a stated ``purpose`` and, when a grant is supplied, checks it
        matches and is unexpired.  Every call is audited whether it succeeds or
        not.  Call sites are meant to be few and reviewable.
        """
        if not purpose:
            raise VaultAccessDenied("reveal_secret requires an explicit purpose")
        if grant is not None:
            if grant.owner_id != owner_id or grant.ref != ref:
                self.audit.record(owner_id, ref, purpose, False, "grant/ref mismatch")
                raise VaultAccessDenied("grant does not match the requested secret")
            if not grant.valid_at():
                self.audit.record(owner_id, ref, purpose, False, "grant expired")
                raise VaultAccessDenied("authorization grant has expired")

        row = session.execute(
            sa.select(VaultSecret).where(
                VaultSecret.owner_id == owner_id, VaultSecret.ref == ref
            )
        ).scalar_one_or_none()
        if row is None:
            self.audit.record(owner_id, ref, purpose, False, "not found")
            raise VaultAccessDenied(f"no secret stored at {ref}")

        try:
            plaintext = unseal(
                self._secret_key(),
                SealedBox(
                    nonce=row.nonce,
                    ciphertext=row.ciphertext,
                    aad=row.aad,
                    key_version=row.key_version,
                ),
            )
        except CryptoError:
            self.audit.record(owner_id, ref, purpose, False, "decryption failed")
            raise
        self.audit.record(owner_id, ref, purpose, True)
        return plaintext

    # -- lifecycle -------------------------------------------------------

    def delete_secret(self, session: Session, owner_id: str, ref: str) -> bool:
        row = session.execute(
            sa.select(VaultSecret).where(
                VaultSecret.owner_id == owner_id, VaultSecret.ref == ref
            )
        ).scalar_one_or_none()
        if row is None:
            return False
        session.delete(row)
        session.flush()
        self.audit.record(owner_id, ref, "delete", True)
        return True

    def rotate_owner_secrets(self, session: Session, owner_id: str) -> int:
        """Re-encrypt an owner's secrets under the current key version.

        Rotation is incremental by design: blobs record the version that
        sealed them, so a partially-rotated vault is still fully readable.
        """
        rows = (
            session.execute(sa.select(VaultSecret).where(VaultSecret.owner_id == owner_id))
            .scalars()
            .all()
        )
        rotated = 0
        target_version = self.keystore.key_version
        for row in rows:
            if row.key_version == target_version:
                continue
            plaintext = unseal(
                self._secret_key(),
                SealedBox(row.nonce, row.ciphertext, row.aad, row.key_version),
            )
            box = seal(
                self._secret_key(),
                plaintext,
                self._aad(owner_id, row.ref, target_version),
                key_version=target_version,
            )
            row.nonce, row.ciphertext, row.aad = box.nonce, box.ciphertext, box.aad
            row.key_version = target_version
            row.rotated_at = dt.datetime.now(dt.UTC)
            rotated += 1
        session.flush()
        return rotated

    # -- narrow adapter for the PII tokenizer ----------------------------
    #
    # The LLM package must not import this module (Rule 1, asserted by
    # ``tests/security/test_five_rules.py``). It declares a two-method
    # ``TokenSecretStore`` protocol instead, and these methods satisfy it --
    # so the Vault can serve the tokenizer without the tokenizer being able to
    # reach anything else on this object.

    def store_pii_value(self, session: Session, owner_id: str, ref: str, value: str) -> None:
        """Store one real identifier behind a placeholder token."""
        self.put_secret(session, owner_id, ref, value, classification=Classification.SENSITIVE)

    def describe(self) -> dict:
        """Security Center summary. Contains no secret material."""
        return {
            "keystore": self.keystore.describe(),
            "grant_ttl_seconds": self.grant_ttl_seconds,
            "algorithm": "AES-256-GCM",
            "key_derivation": "HKDF-SHA256",
        }


__all__ = [
    "AuthorizedRequest",
    "Vault",
    "VaultAccessDenied",
    "VaultAuditHook",
    "VaultError",
]
