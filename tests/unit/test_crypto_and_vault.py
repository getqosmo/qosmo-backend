"""Cryptography, the Vault, and log redaction."""

from __future__ import annotations

import datetime as dt

import pytest
from mybot_schemas.models import CredentialReference
from mybot_security.auth import (
    MIN_PASSWORD_LENGTH,
    WeakPasswordError,
    effective_auth_level,
    generate_totp_secret,
    hash_ip,
    hash_password,
    totp_code,
    verify_password,
    verify_totp,
)
from mybot_security.crypto import (
    CryptoError,
    SealedBox,
    canonical_json,
    derive_subkey,
    generate_key,
    seal,
    sha256_hex,
    unseal,
)
from mybot_security.redaction import contains_secret, mask_tail, redact, redact_text
from mybot_security.vault import VaultAccessDenied

# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------


def test_seal_and_unseal_round_trip():
    key = generate_key()
    box = seal(key, b"top secret", "aad|owner=1|ref=x")
    assert b"top secret" not in box.ciphertext
    assert unseal(key, box) == b"top secret"


def test_wrong_key_fails():
    box = seal(generate_key(), b"data", "aad")
    with pytest.raises(CryptoError):
        unseal(generate_key(), box)


def test_tampered_ciphertext_is_detected():
    """AEAD, not just encryption -- a flipped bit must fail, not decrypt to junk."""
    key = generate_key()
    box = seal(key, b"transfer $100", "aad")
    corrupted = SealedBox(
        nonce=box.nonce,
        ciphertext=box.ciphertext[:-1] + bytes([box.ciphertext[-1] ^ 0x01]),
        aad=box.aad,
        key_version=box.key_version,
    )
    with pytest.raises(CryptoError):
        unseal(key, corrupted)


def test_aad_binding_prevents_moving_a_blob_between_owners():
    key = generate_key()
    box = seal(key, b"alice's token", "mybot|v1|owner=alice|ref=cred|kv=1")
    stolen = SealedBox(box.nonce, box.ciphertext, "mybot|v1|owner=bob|ref=cred|kv=1", 1)
    with pytest.raises(CryptoError):
        unseal(key, stolen)


def test_subkeys_are_independent():
    master = generate_key()
    a = derive_subkey(master, "vault-secrets")
    b = derive_subkey(master, "pii-lookup")
    c = derive_subkey(master, "document-storage")
    assert len({a, b, c}) == 3
    # Deterministic across calls, so restarts do not lose data.
    assert derive_subkey(master, "vault-secrets") == a


def test_nonces_differ_per_encryption():
    key = generate_key()
    boxes = [seal(key, b"same plaintext", "aad") for _ in range(20)]
    assert len({b.nonce for b in boxes}) == 20
    assert len({b.ciphertext for b in boxes}) == 20


def test_canonical_json_is_stable():
    a = canonical_json({"b": 1, "a": [3, 2], "c": {"z": 1, "y": 2}})
    b = canonical_json({"c": {"y": 2, "z": 1}, "a": [3, 2], "b": 1})
    assert a == b
    assert sha256_hex(a) == sha256_hex(b)


# ---------------------------------------------------------------------------
# Passwords and second factor
# ---------------------------------------------------------------------------


def test_password_hashing_is_salted_and_verifiable():
    a = hash_password("correct horse battery staple")
    b = hash_password("correct horse battery staple")
    assert a != b  # unique salts
    assert verify_password(a, "correct horse battery staple")
    assert not verify_password(a, "wrong password entirely")
    assert a.startswith("$argon2")


def test_short_passwords_are_refused():
    with pytest.raises(WeakPasswordError):
        hash_password("a" * (MIN_PASSWORD_LENGTH - 1))


def test_verify_password_returns_false_rather_than_raising():
    """Call sites must not be able to distinguish failure modes."""
    assert verify_password("not-a-hash", "anything") is False
    assert verify_password("", "anything") is False


def test_totp_round_trip_and_rejection():
    secret = generate_totp_secret()
    assert verify_totp(secret, totp_code(secret))
    assert not verify_totp(secret, "000000")
    assert not verify_totp(secret, "notacode")
    assert not verify_totp(secret, "")


def test_ip_addresses_are_hashed_not_stored():
    hashed = hash_ip("203.0.113.42")
    assert hashed is not None
    assert "203.0.113" not in hashed
    assert hash_ip("203.0.113.42") == hashed
    assert hash_ip(None) is None


def test_elevation_expires():
    now = dt.datetime.now(dt.UTC)
    assert effective_auth_level("STRONG", now + dt.timedelta(minutes=5), now=now).value == "STRONG"
    assert effective_auth_level("STRONG", now - dt.timedelta(seconds=1), now=now).value == "BASIC"
    assert effective_auth_level("STRONG", None, now=now).value == "BASIC"


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------


def test_vault_round_trip(vault, db, as_alice):
    vault.put_secret(db, as_alice, "cred:test", "hunter2-the-real-one")
    revealed = vault.reveal_secret(db, as_alice, "cred:test", purpose="unit test")
    assert revealed == b"hunter2-the-real-one"


def test_vault_ciphertext_does_not_contain_plaintext(vault, db, as_alice):
    import sqlalchemy as sa
    from mybot_schemas.models import VaultSecret

    vault.put_secret(db, as_alice, "cred:test", "SUPER-SECRET-VALUE")
    row = db.execute(sa.select(VaultSecret).where(VaultSecret.ref == "cred:test")).scalar_one()
    assert b"SUPER-SECRET-VALUE" not in row.ciphertext
    assert b"SUPER-SECRET-VALUE" not in row.nonce


def test_vault_requires_an_explicit_purpose_to_reveal(vault, db, as_alice):
    vault.put_secret(db, as_alice, "cred:test", "value")
    with pytest.raises(VaultAccessDenied):
        vault.reveal_secret(db, as_alice, "cred:test", purpose="")


def test_vault_refuses_another_owners_secret(vault, db, alice, bob):
    from mybot_schemas.db.scope import session_owner_scope

    with session_owner_scope(db, alice.id):
        vault.put_secret(db, alice.id, "cred:shared-name", "alice's value")
    with session_owner_scope(db, bob.id):
        with pytest.raises(VaultAccessDenied):
            vault.reveal_secret(db, bob.id, "cred:shared-name", purpose="test")


def test_authorize_request_returns_a_grant_not_a_secret(vault, db, as_alice):
    db.add(
        CredentialReference(
            owner_id=as_alice,
            ref="cred:google:calendar",
            provider="google",
            purpose="calendar read",
            scopes=["calendar.readonly"],
        )
    )
    db.flush()

    grant = vault.authorize_request(
        db, as_alice, "cred:google:calendar", "list_events",
        required_scopes=("calendar.readonly",),
    )
    assert grant.ref == "cred:google:calendar"
    assert grant.valid_at()
    # The grant carries no key material at all.
    assert not any(
        isinstance(value, bytes) for value in grant.__dict__.values()
    )


def test_authorize_request_enforces_least_privilege(vault, db, as_alice):
    db.add(
        CredentialReference(
            owner_id=as_alice,
            ref="cred:google:calendar",
            provider="google",
            purpose="calendar read",
            scopes=["calendar.readonly"],
        )
    )
    db.flush()
    with pytest.raises(VaultAccessDenied) as exc:
        vault.authorize_request(
            db, as_alice, "cred:google:calendar", "delete_event",
            required_scopes=("calendar.events",),
        )
    assert "scopes" in str(exc.value)


def test_revoked_and_expired_credentials_are_refused(vault, db, as_alice):
    from mybot_schemas.db.types import utcnow

    db.add(
        CredentialReference(
            owner_id=as_alice, ref="cred:revoked", provider="x", purpose="y",
            revoked_at=utcnow(),
        )
    )
    db.add(
        CredentialReference(
            owner_id=as_alice, ref="cred:expired", provider="x", purpose="y",
            expires_at=utcnow() - dt.timedelta(minutes=1),
        )
    )
    db.flush()
    for ref in ("cred:revoked", "cred:expired"):
        with pytest.raises(VaultAccessDenied):
            vault.authorize_request(db, as_alice, ref, "use")


def test_expired_grant_cannot_reveal(vault, db, as_alice):
    from mybot_schemas.db.types import utcnow
    from mybot_security.vault import AuthorizedRequest

    vault.put_secret(db, as_alice, "cred:test", "value")
    stale = AuthorizedRequest(
        ref="cred:test",
        operation="read",
        owner_id=as_alice,
        granted_at=utcnow() - dt.timedelta(hours=2),
        expires_at=utcnow() - dt.timedelta(hours=1),
    )
    with pytest.raises(VaultAccessDenied):
        vault.reveal_secret(db, as_alice, "cred:test", purpose="test", grant=stale)


def test_key_rotation_re_encrypts_without_losing_data(vault, db, as_alice):
    import sqlalchemy as sa
    from mybot_schemas.models import VaultSecret

    vault.put_secret(db, as_alice, "cred:rotate", "value-to-keep")
    row = db.execute(sa.select(VaultSecret).where(VaultSecret.ref == "cred:rotate")).scalar_one()
    original_ciphertext = bytes(row.ciphertext)

    vault.keystore.key_version = 2
    assert vault.rotate_owner_secrets(db, as_alice) == 1

    db.refresh(row)
    assert row.key_version == 2
    assert bytes(row.ciphertext) != original_ciphertext
    assert vault.reveal_secret(db, as_alice, "cred:rotate", purpose="test") == b"value-to-keep"


def test_vault_access_is_audited(vault, db, as_alice, services):
    """The hook records every access, granted or denied."""
    seen = []
    vault.audit.on_access = lambda owner, ref, op, granted, reason: seen.append(
        (ref, op, granted)
    )
    vault.put_secret(db, as_alice, "cred:audited", "value")
    vault.reveal_secret(db, as_alice, "cred:audited", purpose="test")
    with pytest.raises(VaultAccessDenied):
        vault.reveal_secret(db, as_alice, "cred:missing", purpose="test")

    assert ("cred:audited", "put", True) in seen
    assert ("cred:audited", "test", True) in seen
    assert ("cred:missing", "test", False) in seen


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["password", "api_key", "access_token", "refresh_token", "private_key", "ssn",
     "card_number", "cvv", "authorization", "session_key", "totp_secret"],
)
def test_sensitive_keys_are_redacted_regardless_of_value(key):
    assert redact({key: "anything at all"})[key] == "[REDACTED]"


@pytest.mark.parametrize(
    "value",
    [
        "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
        "sk-abcdefghijklmnopqrstuvwx",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghijklmno",
        "Bearer abcdefghijklmnopqrstuvwxyz123456",
        "ya29.a0AfH6SMBabcdefghijklmnop",
        "ghp_abcdefghijklmnopqrstuvwxyz1234",
        "4111 1111 1111 1111",
        "123-45-6789",
    ],
)
def test_secret_shaped_values_are_redacted_under_innocuous_keys(value):
    """A secret that arrives under the key ``note`` is still a secret."""
    result = redact({"note": value})["note"]
    assert value not in result
    assert "[REDACTED]" in result


def test_private_key_blocks_are_removed():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA1234567890\n"
        "-----END RSA PRIVATE KEY-----"
    )
    assert "MIIEow" not in redact_text(pem)


def test_redaction_recurses_and_bounds_depth():
    payload = {"a": {"b": {"c": {"password": "x", "safe": "keep"}}}}
    result = redact(payload)
    assert result["a"]["b"]["c"]["password"] == "[REDACTED]"
    assert result["a"]["b"]["c"]["safe"] == "keep"

    # A pathologically nested payload must not hang or recurse forever.
    deep: dict = {}
    node = deep
    for _ in range(50):
        node["next"] = {}
        node = node["next"]
    assert "TRUNCATED" in str(redact(deep))


def test_bytes_are_never_logged_verbatim():
    assert redact({"blob": b"secret bytes"}) == {"blob": "[BYTES len=12]"}


def test_account_identifiers_are_masked_not_removed():
    """Enough to recognise the account, not enough to use it."""
    assert mask_tail("1234567890123812") == "•••• 3812"
    assert redact({"account_ref": "1234567890123812"})["account_ref"] == "•••• 3812"


def test_contains_secret_detects_leaks():
    assert contains_secret({"token": "abc"})
    assert not contains_secret({"title": "Dentist appointment", "count": 3})


def test_ordinary_content_survives_redaction():
    payload = {
        "title": "Car registration expires in 4 days",
        "amount": 148.20,
        "due_at": "2026-08-16",
        "count": 3,
    }
    assert redact(payload) == payload


def test_audit_details_are_redacted_on_write(services, as_alice):
    event = services.audit.record(
        as_alice,
        "test.event",
        details={"password": "hunter2", "api_key": "sk-ant-abcdefghijklmnop", "safe": "ok"},
    )
    assert event.details["password"] == "[REDACTED]"
    assert event.details["api_key"] == "[REDACTED]"
    assert event.details["safe"] == "ok"


def test_structured_logger_redacts_before_emitting(caplog):
    import logging

    from mybot_security.logging import JsonFormatter, get_logger

    logger = get_logger("test.redaction")
    with caplog.at_level(logging.INFO):
        logger.info("secret.test", token="sk-ant-abcdefghijklmnopqrs", safe="visible")

    record = next(r for r in caplog.records if r.getMessage() == "secret.test")
    rendered = JsonFormatter().format(record)
    assert "sk-ant-abcdefghijklmnopqrs" not in rendered
    assert "[REDACTED]" in rendered
    assert "visible" in rendered
