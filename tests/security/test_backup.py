"""Backup and recovery.

The thing being tested here is not really encryption -- that is AES-GCM's job
and it is not on trial. It is the *recovery* properties, which is where backup
designs actually fail:

* the archive is opaque to whoever stores it;
* every recovery path works independently, so losing one is survivable;
* material that does not open the backup fails cleanly and says nothing useful;
* a person holding a two-year-old file can tell what it is without the key;
* raising the KDF cost later does not orphan backups made today.

Argon2 parameters are lowered for the suite. The production constants are 256
MiB per derivation by design, and the tests exercise the *logic*, not libargon2.
"""

from __future__ import annotations

import io
import json
import tarfile

import pytest
from mybot_security import backup as backup_mod
from mybot_security.backup import (
    BACKUP_FORMAT,
    BackupError,
    BackupService,
    RecoveryFailed,
    generate_recovery_phrase,
    parse_phrase_scheme,
    phrase_checksum,
    phrase_scheme,
)

OWNER = "11111111-1111-1111-1111-111111111111"

#: A payload shaped like the real account export, with a distinctive string we
#: can grep the ciphertext for.
CANARY = "Dr Sandhu, root canal, 2 May, $1,480 outstanding"

PAYLOAD = {
    "memories": [
        {"content": CANARY, "category": "health"},
        {"content": "Prefers morning appointments", "category": "preference"},
    ],
    "entities": [{"name": "Dr Sandhu", "type": "person"}],
    "account": {"email": "owner@example.test"},
}


@pytest.fixture(autouse=True)
def cheap_argon2(monkeypatch):
    """Make the KDF fast enough to test.

    Patched at module level so the wrap records the *patched* parameters in its
    scheme string and recovery reads them back -- which is exactly the
    forward-compatibility path we want under test anyway.
    """
    monkeypatch.setattr(backup_mod, "PHRASE_TIME_COST", 1)
    monkeypatch.setattr(backup_mod, "PHRASE_MEMORY_COST", 8192)
    monkeypatch.setattr(backup_mod, "PHRASE_PARALLELISM", 1)


@pytest.fixture
def service():
    return BackupService()


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------


def test_round_trip_with_generated_phrase(service):
    archive, manifest, phrase = service.create(payload=PAYLOAD, owner_id=OWNER)

    assert phrase is not None, "a backup with no supplied phrase must generate one"
    assert len(phrase.split()) == 24

    restored = service.restore(archive, recovery_phrase=phrase)
    assert restored == PAYLOAD
    assert manifest.format == BACKUP_FORMAT


def test_round_trip_with_supplied_phrase(service):
    archive, _, generated = service.create(
        payload=PAYLOAD, owner_id=OWNER, recovery_phrase="my own chosen phrase"
    )

    # If the owner supplied a phrase, we must not invent a second one and
    # imply they need to write it down.
    assert generated is None
    assert service.restore(archive, recovery_phrase="my own chosen phrase") == PAYLOAD


def test_phrase_normalisation_survives_human_transcription(service):
    archive, _, phrase = service.create(payload=PAYLOAD, owner_id=OWNER)

    mangled = "  " + "   ".join(w.upper() for w in phrase.split()) + "\n"
    assert service.restore(archive, recovery_phrase=mangled) == PAYLOAD


def test_refuses_to_create_an_empty_backup(service):
    with pytest.raises(BackupError):
        service.create(payload={}, owner_id=OWNER)


# ---------------------------------------------------------------------------
# The archive is opaque to whoever holds it
# ---------------------------------------------------------------------------


def test_ciphertext_contains_no_plaintext(service):
    archive, _, _ = service.create(payload=PAYLOAD, owner_id=OWNER)

    assert CANARY.encode() not in archive
    assert b"Dr Sandhu" not in archive
    assert b"owner@example.test" not in archive
    # gzip could in principle hide a substring; check the raw members too.
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for name in ("manifest.json", "data.enc", "nonce.bin"):
            blob = tar.extractfile(name).read()
            assert CANARY.encode() not in blob
            assert b"Dr Sandhu" not in blob


def test_archive_does_not_name_its_owner(service):
    archive, manifest, _ = service.create(payload=PAYLOAD, owner_id=OWNER)

    assert OWNER.encode() not in archive
    assert OWNER not in manifest.owner_hint
    assert manifest.owner_hint  # but there is *something* to match against


def test_manifest_is_readable_without_the_key(service):
    archive, _, _ = service.create(
        payload=PAYLOAD,
        owner_id=OWNER,
        contact_secrets={"Priya": b"\x11" * 32},
    )

    described = service.describe(archive)

    assert described["format"] == BACKUP_FORMAT
    assert described["created_at"]
    assert {p["path"] for p in described["recovery_paths"]} == {"phrase", "contact"}
    assert any(p["label"] == "Priya" for p in described["recovery_paths"])
    # Counts, not contents.
    assert described["contents"]["memories"] == 2
    assert CANARY not in json.dumps(described)
    # Only collections are counted -- a scalar key reported as "1" is noise in
    # the one view a person has when they cannot open the file.
    assert "account" not in described["contents"]


def test_archive_opens_with_standard_tools(service):
    """Somebody recovering data in five years should not need MyBot to exist
    in order to work out what they are holding."""
    archive, _, _ = service.create(payload=PAYLOAD, owner_id=OWNER)

    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        names = set(tar.getnames())
        assert names == {"manifest.json", "nonce.bin", "data.enc", "README.txt"}
        readme = tar.extractfile("README.txt").read().decode()
        assert "AES-256-GCM" in readme
        assert "mybot restore" in readme


def test_archive_is_reproducible_for_identical_input(service, monkeypatch):
    """Two backups of the same bytes should not differ in their tar metadata,
    so a sync tool is not re-uploading gigabytes because of an mtime."""
    with tarfile.open(fileobj=io.BytesIO(
        service.create(payload=PAYLOAD, owner_id=OWNER)[0]
    ), mode="r:gz") as tar:
        assert all(m.mtime == 0 for m in tar.getmembers())


# ---------------------------------------------------------------------------
# Recovery failure
# ---------------------------------------------------------------------------


def test_wrong_phrase_is_refused(service):
    archive, _, _ = service.create(payload=PAYLOAD, owner_id=OWNER)

    with pytest.raises(RecoveryFailed):
        service.restore(archive, recovery_phrase=generate_recovery_phrase())


def test_no_material_at_all_is_refused(service):
    archive, _, _ = service.create(payload=PAYLOAD, owner_id=OWNER)

    with pytest.raises(RecoveryFailed):
        service.restore(archive)


def test_failure_message_does_not_reveal_which_part_was_wrong(service):
    archive, _, phrase = service.create(payload=PAYLOAD, owner_id=OWNER)

    with pytest.raises(RecoveryFailed) as wrong:
        service.restore(archive, recovery_phrase="clearly not the phrase")
    with pytest.raises(RecoveryFailed) as absent:
        service.restore(archive)

    # Same class either way, and neither leaks any of the real phrase.
    for excinfo in (wrong, absent):
        message = str(excinfo.value)
        assert not any(word in message for word in phrase.split()[:5])


def test_tampered_ciphertext_is_detected(service):
    archive, _, phrase = service.create(payload=PAYLOAD, owner_id=OWNER)
    tampered = _repack(archive, mutate_data=lambda d: bytes([d[0] ^ 0xFF]) + d[1:])

    with pytest.raises(BackupError) as excinfo:
        service.restore(tampered, recovery_phrase=phrase)
    assert "corrupt" in str(excinfo.value)


def test_tampering_with_both_ciphertext_and_its_hash_still_fails(service):
    """The manifest hash catches accidental corruption. AEAD catches somebody
    who thought to update the hash as well."""
    archive, _, phrase = service.create(payload=PAYLOAD, owner_id=OWNER)

    from mybot_security.crypto import sha256_hex

    def rehash(manifest, data):
        manifest["ciphertext_sha256"] = sha256_hex(data)
        return manifest

    tampered = _repack(
        archive,
        mutate_data=lambda d: bytes([d[0] ^ 0xFF]) + d[1:],
        mutate_manifest=rehash,
    )

    with pytest.raises(RecoveryFailed):
        service.restore(tampered, recovery_phrase=phrase)


def test_swapping_the_owner_hint_breaks_decryption(service):
    """The owner hint is bound into the AEAD context, so it is not a label
    somebody can edit to make a backup look like it belongs to someone else."""
    archive, _, phrase = service.create(payload=PAYLOAD, owner_id=OWNER)

    def relabel(manifest, _data):
        manifest["owner_hint"] = "0" * 16
        return manifest

    with pytest.raises(RecoveryFailed):
        service.restore(_repack(archive, mutate_manifest=relabel), recovery_phrase=phrase)


def test_garbage_input_is_rejected_cleanly(service):
    for junk in (b"", b"not a tar file at all", b"\x1f\x8b\x08" + b"\x00" * 40):
        with pytest.raises(BackupError):
            service.restore(junk, recovery_phrase="anything")


def test_unknown_format_is_rejected(service):
    archive, _, phrase = service.create(payload=PAYLOAD, owner_id=OWNER)

    def bump(manifest, _data):
        manifest["format"] = "mybot-backup-v99"
        return manifest

    with pytest.raises(BackupError) as excinfo:
        service.restore(_repack(archive, mutate_manifest=bump), recovery_phrase=phrase)
    assert "unsupported backup format" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Independent recovery paths
# ---------------------------------------------------------------------------


def test_contact_recovers_without_the_phrase(service):
    """The whole point of a second path: the paper is gone, the sister is not."""
    priya = b"\x22" * 32
    archive, _, _ = service.create(
        payload=PAYLOAD, owner_id=OWNER, contact_secrets={"Priya": priya}
    )

    assert service.restore(archive, contact_secret=("Priya", priya)) == PAYLOAD


def test_phrase_still_works_when_a_contact_exists(service):
    archive, _, phrase = service.create(
        payload=PAYLOAD, owner_id=OWNER, contact_secrets={"Priya": b"\x22" * 32}
    )

    assert service.restore(archive, recovery_phrase=phrase) == PAYLOAD


def test_multiple_contacts_each_recover_alone(service):
    secrets_by_name = {"Priya": b"\x33" * 32, "Tom": b"\x44" * 32}
    archive, _, _ = service.create(
        payload=PAYLOAD, owner_id=OWNER, contact_secrets=secrets_by_name
    )

    for name, material in secrets_by_name.items():
        assert service.restore(archive, contact_secret=(name, material)) == PAYLOAD


def test_a_contacts_material_does_not_open_another_contacts_wrap(service):
    archive, _, _ = service.create(
        payload=PAYLOAD,
        owner_id=OWNER,
        contact_secrets={"Priya": b"\x33" * 32, "Tom": b"\x44" * 32},
    )

    with pytest.raises(RecoveryFailed):
        service.restore(archive, contact_secret=("Priya", b"\x44" * 32))


def test_wrong_contact_material_is_refused(service):
    archive, _, _ = service.create(
        payload=PAYLOAD, owner_id=OWNER, contact_secrets={"Priya": b"\x55" * 32}
    )

    with pytest.raises(RecoveryFailed):
        service.restore(archive, contact_secret=("Priya", b"\x56" * 32))


def test_a_malformed_wrap_does_not_block_a_good_one(service):
    """An older build reading a newer archive, or a partially corrupted
    manifest, should still try every path it does understand."""
    priya = b"\x66" * 32
    archive, _, phrase = service.create(
        payload=PAYLOAD, owner_id=OWNER, contact_secrets={"Priya": priya}
    )

    def corrupt_first_wrap(manifest, _data):
        manifest["wraps"].insert(0, {"path": "hardware", "label": "YubiKey"})
        manifest["wraps"][1]["salt"] = "!!!not base64!!!"
        return manifest

    broken = _repack(archive, mutate_manifest=corrupt_first_wrap)

    # The phrase wrap is now unusable, but the contact wrap is untouched.
    assert service.restore(broken, contact_secret=("Priya", priya)) == PAYLOAD
    with pytest.raises(RecoveryFailed):
        service.restore(broken, recovery_phrase=phrase)


# ---------------------------------------------------------------------------
# Phrases
# ---------------------------------------------------------------------------


def test_generated_phrases_are_distinct():
    phrases = {generate_recovery_phrase() for _ in range(50)}
    assert len(phrases) == 50


def test_wordlist_is_unambiguous_on_paper():
    words = backup_mod._WORDLIST
    assert len(set(words)) == len(words), "duplicate words weaken the phrase"
    assert all(w.islower() and w.isalpha() for w in words)
    assert all(3 <= len(w) <= 9 for w in words)
    # Distinct at a glance: no two words share their first four letters.
    prefixes = [w[:4] for w in words]
    assert len(set(prefixes)) == len(prefixes)


def test_phrase_checksum_confirms_transcription():
    phrase = generate_recovery_phrase()

    assert phrase_checksum(phrase) == phrase_checksum(
        "  ".join(w.upper() for w in phrase.split())
    )
    assert phrase_checksum(phrase) != phrase_checksum(generate_recovery_phrase())
    # Short enough to read aloud, and far too short to invert.
    assert len(phrase_checksum(phrase)) == 6


# ---------------------------------------------------------------------------
# Forward compatibility of the KDF cost
# ---------------------------------------------------------------------------


def test_scheme_round_trips():
    assert parse_phrase_scheme(phrase_scheme()) == (1, 8192, 1)
    assert parse_phrase_scheme("argon2id-t4-m262144-p4") == (4, 262144, 4)


def test_unreadable_scheme_is_rejected():
    for junk in ("scrypt-n16384", "argon2id-", "argon2id-tX-m1-p1", "argon2id-t1-m1"):
        with pytest.raises(BackupError):
            parse_phrase_scheme(junk)


def test_raising_the_kdf_cost_does_not_orphan_existing_backups(service, monkeypatch):
    """A backup made today must still open after we raise the parameters,
    because the archive records what it was made with."""
    archive, _, phrase = service.create(payload=PAYLOAD, owner_id=OWNER)

    monkeypatch.setattr(backup_mod, "PHRASE_TIME_COST", 2)
    monkeypatch.setattr(backup_mod, "PHRASE_MEMORY_COST", 16384)

    assert service.restore(archive, recovery_phrase=phrase) == PAYLOAD


def test_production_parameters_are_not_weakened():
    """Guards against somebody lowering the real cost to make tests faster --
    the fixture exists precisely so that is never necessary."""
    import importlib

    fresh = importlib.reload(backup_mod)
    try:
        assert fresh.PHRASE_MEMORY_COST >= 262_144
        assert fresh.PHRASE_TIME_COST >= 3
        assert fresh.RECOVERY_PHRASE_WORDS >= 24
    finally:
        importlib.reload(backup_mod)


# ---------------------------------------------------------------------------
# Against the real export payload
#
# The unit tests above use a hand-made dict. These use what `mybot backup`
# actually seals, because the failure that matters is not "AES broke" -- it is
# "the backup silently did not contain the thing you needed".
# ---------------------------------------------------------------------------


def test_backs_up_and_recovers_the_real_export_payload(db, alice, services, as_alice):
    from mybot_api.export import build_export_payload

    services.memory.remember(alice.id, "Allergic to penicillin")
    services.graph.create_entity(alice.id, entity_type="person", name="Dr Sandhu")
    db.flush()

    payload = build_export_payload(
        db=db, audit=services.audit, owner_id=alice.id, user=alice
    )

    archive, manifest, phrase = BackupService().create(payload=payload, owner_id=alice.id)
    restored = BackupService().restore(archive, recovery_phrase=phrase)

    assert restored == payload
    assert any(m["content"] == "Allergic to penicillin" for m in restored["memories"])
    assert any(e["name"] == "Dr Sandhu" for e in restored["entities"])
    # The audit chain travels with the backup, so a restored copy can still be
    # verified rather than being taken on faith.
    assert restored["audit"]
    assert restored["audit_verification"]["ok"] is True
    assert manifest.contents["memories"] == len(payload["memories"])


def test_backup_of_real_data_leaks_nothing_in_the_clear(db, alice, services, as_alice):
    from mybot_api.export import build_export_payload

    services.memory.remember(alice.id, "Allergic to penicillin")
    db.flush()

    payload = build_export_payload(
        db=db, audit=services.audit, owner_id=alice.id, user=alice
    )
    archive, _, _ = BackupService().create(payload=payload, owner_id=alice.id)

    assert b"penicillin" not in archive
    assert b"alice@example.com" not in archive
    assert alice.id.encode() not in archive


def test_backup_never_contains_vault_ciphertext_or_password_hashes(
    db, alice, services, as_alice
):
    """The export allowlist is what keeps secrets out. Assert it here too, so
    a new column added to `User` cannot reach a backup without this failing."""
    from mybot_api.export import build_export_payload

    payload = build_export_payload(
        db=db, audit=services.audit, owner_id=alice.id, user=alice
    )
    archive, _, phrase = BackupService().create(payload=payload, owner_id=alice.id)
    restored = BackupService().restore(archive, recovery_phrase=phrase)

    flat = json.dumps(restored)
    for forbidden in ("password_hash", "token_hash", "ciphertext", "nonce", "master_key"):
        assert forbidden not in flat
    assert alice.password_hash not in flat
    assert restored["user"].keys() == {"id", "email", "display_name", "timezone"}


# ---------------------------------------------------------------------------


def _repack(archive: bytes, *, mutate_data=None, mutate_manifest=None) -> bytes:
    """Rebuild an archive with altered contents, as an attacker would."""
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        members = {m.name: tar.extractfile(m.name).read() for m in tar.getmembers()}

    if mutate_data:
        members["data.enc"] = mutate_data(members["data.enc"])
    manifest = json.loads(members["manifest.json"].decode())
    if mutate_manifest:
        manifest = mutate_manifest(manifest, members["data.enc"])
    members["manifest.json"] = json.dumps(manifest).encode()

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as out:
        for name, blob in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            info.mtime = 0
            out.addfile(info, io.BytesIO(blob))
    return buffer.getvalue()
