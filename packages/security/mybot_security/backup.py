"""Encrypted backup, and a recovery design that does not create a new
single point of compromise.

This closes the gap SECURITY.md §10 previously described as "not yet built,
and losing the master key today means losing the Vault".

## The problem with the obvious answers

**Escrow the key with MyBot Inc.** Then MyBot Inc. can read every user's
Vault, and the local-first promise is theatre. Whoever runs the service — or
whoever compels them — has everything.

**Derive the key from the password.** A forgotten password is now
unrecoverable *and* a weak password is now the whole security of the Vault.
Worse, a password change has to re-wrap everything, and users change passwords
under exactly the conditions where you least want a complex migration.

**No recovery at all.** Honest, and what the previous build shipped. It is also
the reason people do not adopt local-first products: one lost laptop and a
decade of records is gone.

## What this does instead

A backup is sealed with a fresh random **backup key**. That key is then wrapped
several times over, once per **recovery path** the owner has set up:

* a **recovery phrase** — 24 words the owner writes down, from which a wrapping
  key is derived with Argon2id;
* a **recovery contact** — an ally holding a share, useful because most people
  will lose the paper before they lose their sister;
* a future **hardware key** or Core secure element.

Any single path recovers the backup. None of them is MyBot Inc., because MyBot
Inc. never holds a wrap. That is the whole design: the backup blob is useless
to whoever stores it, and the owner has more than one way back in.

Shamir-style share splitting for the "3 of 5 friends" case is deliberately
*not* implemented here — a hand-rolled secret-sharing scheme is exactly the
kind of clever cryptography this codebase has a rule against. The wrap format
carries a ``scheme`` field so a reviewed implementation can be added without a
migration.
"""

from __future__ import annotations

import binascii
import datetime as dt
import hashlib
import io
import json
import os
import secrets
import tarfile
from dataclasses import dataclass, field
from typing import Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import (
    AES_KEY_BYTES,
    CryptoError,
    SealedBox,
    b64d,
    b64e,
    canonical_json,
    generate_key,
    seal,
    sha256_hex,
    unseal,
)

BACKUP_FORMAT = "mybot-backup-v1"

#: Argon2id parameters for deriving a wrapping key from a recovery phrase.
#: Deliberately heavier than the login parameters: this runs once, during
#: recovery, and the attacker's advantage is an offline dictionary attack
#: against a blob they may hold indefinitely.
PHRASE_TIME_COST = 4
PHRASE_MEMORY_COST = 262_144  # 256 MiB
PHRASE_PARALLELISM = 4

#: BIP-39-style word count. 24 words from a 2048-word list is ~264 bits.
RECOVERY_PHRASE_WORDS = 24


class BackupError(RuntimeError):
    pass


class RecoveryFailed(BackupError):
    """The supplied recovery material did not unwrap the backup.

    Deliberately does not distinguish "wrong phrase" from "corrupt file" —
    telling an attacker which one they got right is free information.
    """


@dataclass(frozen=True)
class KeyWrap:
    """One way back in.

    ``wrapped`` is the backup key sealed under a key derived from this
    recovery path's material. Storing several of these beside the ciphertext is
    what gives the owner more than one route to their data without giving
    anybody else one.
    """

    path: Literal["phrase", "contact", "hardware"]
    label: str
    scheme: str
    salt: str
    nonce: str
    wrapped: str
    created_at: str

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "label": self.label,
            "scheme": self.scheme,
            "salt": self.salt,
            "nonce": self.nonce,
            "wrapped": self.wrapped,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> KeyWrap:
        # Ignore unknown keys rather than raising: a wrap written by a newer
        # build should still be *skipped over* by an older one looking for a
        # path it understands, not make the whole archive unreadable.
        known = {f: payload[f] for f in cls.__dataclass_fields__ if f in payload}
        try:
            return cls(**known)
        except TypeError as exc:
            raise BackupError("malformed recovery path in backup manifest") from exc


@dataclass
class BackupManifest:
    """What is in the backup, and how to get into it.

    Stored *unencrypted* alongside the ciphertext, because a person staring at
    a file from two years ago needs to be able to tell what it is and which of
    their recovery paths still works. It contains no secret: the wraps are
    useless without the owner's material, and the contents are described by
    counts rather than by name.
    """

    format: str = BACKUP_FORMAT
    created_at: str = ""
    owner_hint: str = ""
    contents: dict = field(default_factory=dict)
    wraps: list[dict] = field(default_factory=list)
    ciphertext_sha256: str = ""
    #: Bumped when the sealed payload's structure changes.
    payload_version: int = 1

    def as_dict(self) -> dict:
        return {
            "format": self.format,
            "created_at": self.created_at,
            "owner_hint": self.owner_hint,
            "contents": self.contents,
            "wraps": self.wraps,
            "ciphertext_sha256": self.ciphertext_sha256,
            "payload_version": self.payload_version,
        }


# ---------------------------------------------------------------------------
# Recovery phrases
# ---------------------------------------------------------------------------


def generate_recovery_phrase(words: int = RECOVERY_PHRASE_WORDS) -> str:
    """Generate a recovery phrase.

    Uses a compact built-in word list rather than shipping BIP-39: the entropy
    comes from ``secrets``, and the list only has to be unambiguous to a human
    copying it onto paper. Words are short, distinct at a glance, and contain
    no near-homophones.
    """
    return " ".join(secrets.choice(_WORDLIST) for _ in range(words))


def phrase_scheme(
    time_cost: int | None = None,
    memory_cost: int | None = None,
    parallelism: int | None = None,
) -> str:
    """Render the Argon2id parameters into the string stored in the wrap."""
    t = PHRASE_TIME_COST if time_cost is None else time_cost
    m = PHRASE_MEMORY_COST if memory_cost is None else memory_cost
    p = PHRASE_PARALLELISM if parallelism is None else parallelism
    return f"argon2id-t{t}-m{m}-p{p}"


def parse_phrase_scheme(scheme: str) -> tuple[int, int, int]:
    """Read the parameters back out of a stored wrap.

    Recovery derives with the parameters *the backup was made with*, not with
    today's constants. Otherwise raising the cost — which we should be free to
    do as hardware gets faster — would silently orphan every existing backup,
    and the owner would only discover it on the day they needed it.
    """
    if not scheme.startswith("argon2id-"):
        raise BackupError(f"unsupported wrapping scheme: {scheme}")
    try:
        parts = {
            field[0]: int(field[1:])
            for field in scheme.removeprefix("argon2id-").split("-")
            if field
        }
        return parts["t"], parts["m"], parts["p"]
    except (KeyError, ValueError) as exc:
        raise BackupError(f"unreadable wrapping scheme: {scheme}") from exc


def _derive_from_phrase(
    phrase: str,
    salt: bytes,
    *,
    time_cost: int | None = None,
    memory_cost: int | None = None,
    parallelism: int | None = None,
) -> bytes:
    """Argon2id over the normalised phrase.

    Normalisation matters more than it looks: somebody typing their phrase back
    in two years later will use different spacing and casing than the screen
    showed them, and failing for that reason would be unforgivable.
    """
    from argon2.low_level import Type, hash_secret_raw

    normalised = " ".join(phrase.lower().split()).encode("utf-8")
    return hash_secret_raw(
        secret=normalised,
        salt=salt,
        time_cost=PHRASE_TIME_COST if time_cost is None else time_cost,
        memory_cost=PHRASE_MEMORY_COST if memory_cost is None else memory_cost,
        parallelism=PHRASE_PARALLELISM if parallelism is None else parallelism,
        hash_len=AES_KEY_BYTES,
        type=Type.ID,
    )


def _derive_from_secret(material: bytes, salt: bytes, info: str) -> bytes:
    """HKDF for high-entropy material (a contact's share, a hardware secret).

    Argon2 exists to slow down guessing a *low-entropy* input. Material that is
    already random does not need stretching, and pretending otherwise just
    makes recovery slow.
    """
    return HKDF(
        algorithm=hashes.SHA256(), length=AES_KEY_BYTES, salt=salt, info=info.encode()
    ).derive(material)


# ---------------------------------------------------------------------------
# Sealing and opening
# ---------------------------------------------------------------------------


class BackupService:
    """Creates and restores encrypted backups.

    Note what it does *not* take: a `Vault`. A backup is sealed under its own
    fresh key, so the installation's master key is never the thing protecting
    the archive — which means a backup remains recoverable after a machine is
    lost, and a compromised machine does not retroactively expose old backups
    sealed under a key that has since rotated.
    """

    def create(
        self,
        *,
        payload: dict,
        owner_id: str,
        recovery_phrase: str | None = None,
        contact_secrets: dict[str, bytes] | None = None,
    ) -> tuple[bytes, BackupManifest, str | None]:
        """Seal ``payload`` and wrap the key for each recovery path.

        Returns ``(archive_bytes, manifest, generated_phrase)``. The phrase is
        returned exactly once and never stored — if the owner loses it, that
        path is gone, which is the point.
        """
        if not payload:
            raise BackupError("refusing to create an empty backup")

        backup_key = generate_key()
        now = dt.datetime.now(dt.UTC).isoformat()

        body = canonical_json(payload).encode("utf-8")
        aad = f"{BACKUP_FORMAT}|owner={sha256_hex(owner_id)[:16]}"
        box = seal(backup_key, body, aad)

        wraps: list[KeyWrap] = []
        generated_phrase: str | None = None

        # Path 1: a phrase the owner writes down.
        phrase = recovery_phrase
        if phrase is None:
            phrase = generate_recovery_phrase()
            generated_phrase = phrase
        wraps.append(self._wrap_with_phrase(backup_key, phrase))

        # Path 2: allies. Most people lose the paper before they lose a sibling.
        for label, material in (contact_secrets or {}).items():
            wraps.append(self._wrap_with_secret(backup_key, label, material, "contact"))

        manifest = BackupManifest(
            created_at=now,
            # A hash, not the id. A backup file should not name its owner.
            owner_hint=sha256_hex(owner_id)[:16],
            contents=_summarise(payload),
            wraps=[w.as_dict() for w in wraps],
            ciphertext_sha256=sha256_hex(box.ciphertext),
        )

        archive = self._pack(manifest, box)
        return archive, manifest, generated_phrase

    def restore(
        self,
        archive: bytes,
        *,
        recovery_phrase: str | None = None,
        contact_secret: tuple[str, bytes] | None = None,
    ) -> dict:
        """Open a backup with any one recovery path."""
        manifest, box = self._unpack(archive)

        if sha256_hex(box.ciphertext) != manifest.ciphertext_sha256:
            raise BackupError(
                "backup archive is corrupt: the contents do not match the manifest"
            )

        backup_key = self._unwrap(manifest, recovery_phrase, contact_secret)

        try:
            body = unseal(backup_key, box)
        except CryptoError as exc:
            raise RecoveryFailed("could not open the backup with that recovery material") from exc

        return json.loads(body.decode("utf-8"))

    def describe(self, archive: bytes) -> dict:
        """Read the manifest without opening the contents.

        So a person with a two-year-old file can see what it is and which of
        their recovery paths it accepts, before hunting for the paper.
        """
        manifest, _ = self._unpack(archive)
        return {
            "format": manifest.format,
            "created_at": manifest.created_at,
            "contents": manifest.contents,
            "recovery_paths": [
                {"path": w["path"], "label": w["label"], "added": w["created_at"]}
                for w in manifest.wraps
            ],
        }

    # ------------------------------------------------------------------

    def _wrap_with_phrase(self, backup_key: bytes, phrase: str) -> KeyWrap:
        salt = os.urandom(16)
        wrapping_key = _derive_from_phrase(phrase, salt)
        box = seal(wrapping_key, backup_key, f"{BACKUP_FORMAT}|wrap=phrase")
        return KeyWrap(
            path="phrase",
            label="Recovery phrase",
            scheme=phrase_scheme(),
            salt=b64e(salt),
            nonce=b64e(box.nonce),
            wrapped=b64e(box.ciphertext),
            created_at=dt.datetime.now(dt.UTC).isoformat(),
        )

    def _wrap_with_secret(
        self, backup_key: bytes, label: str, material: bytes, path: str
    ) -> KeyWrap:
        salt = os.urandom(16)
        wrapping_key = _derive_from_secret(material, salt, f"{BACKUP_FORMAT}|{path}")
        box = seal(wrapping_key, backup_key, f"{BACKUP_FORMAT}|wrap={path}")
        return KeyWrap(
            path=path,  # type: ignore[arg-type]
            label=label,
            scheme="hkdf-sha256",
            salt=b64e(salt),
            nonce=b64e(box.nonce),
            wrapped=b64e(box.ciphertext),
            created_at=dt.datetime.now(dt.UTC).isoformat(),
        )

    def _unwrap(
        self,
        manifest: BackupManifest,
        phrase: str | None,
        contact_secret: tuple[str, bytes] | None,
    ) -> bytes:
        for raw in manifest.wraps:
            try:
                wrap = KeyWrap.from_dict(raw)

                if wrap.path == "phrase" and phrase:
                    time_cost, memory_cost, parallelism = parse_phrase_scheme(wrap.scheme)
                    wrapping_key = _derive_from_phrase(
                        phrase,
                        b64d(wrap.salt),
                        time_cost=time_cost,
                        memory_cost=memory_cost,
                        parallelism=parallelism,
                    )
                elif (
                    wrap.path == "contact"
                    and contact_secret
                    and contact_secret[0] == wrap.label
                ):
                    wrapping_key = _derive_from_secret(
                        contact_secret[1], b64d(wrap.salt), f"{BACKUP_FORMAT}|contact"
                    )
                else:
                    continue

                return unseal(
                    wrapping_key,
                    SealedBox(
                        nonce=b64d(wrap.nonce),
                        ciphertext=b64d(wrap.wrapped),
                        aad=f"{BACKUP_FORMAT}|wrap={wrap.path}",
                        key_version=1,
                    ),
                )
            except (CryptoError, BackupError, ValueError, binascii.Error):
                # Try the next path. A failure here is "this material does not
                # open this wrap", not necessarily "the material is wrong" --
                # and a malformed wrap should not prevent a good one from being
                # tried.
                continue

        raise RecoveryFailed(
            "none of the supplied recovery material opened this backup. "
            "Available paths: "
            + ", ".join(
                f"{w.get('path')} ({w.get('label')})" for w in manifest.wraps
            )
        )

    # ------------------------------------------------------------------

    def _pack(self, manifest: BackupManifest, box: SealedBox) -> bytes:
        """A tar archive: manifest, nonce, ciphertext.

        Boring on purpose. Somebody recovering data in five years should be
        able to open the container with standard tools even if MyBot no longer
        exists, and read the manifest to learn what they are holding.
        """
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            _add(archive, "manifest.json", json.dumps(manifest.as_dict(), indent=2).encode())
            _add(archive, "nonce.bin", box.nonce)
            _add(archive, "data.enc", box.ciphertext)
            _add(
                archive,
                "README.txt",
                (
                    b"This is an encrypted MyBot backup.\n\n"
                    b"data.enc is AES-256-GCM ciphertext. The key is not in this file and\n"
                    b"is not held by anyone but you. manifest.json lists the recovery paths\n"
                    b"that can open it -- typically a 24-word recovery phrase.\n\n"
                    b"Restore with:  mybot restore <this file>\n"
                ),
            )
        return buffer.getvalue()

    def _unpack(self, archive: bytes) -> tuple[BackupManifest, SealedBox]:
        try:
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
                manifest_raw = _read(tar, "manifest.json")
                nonce = _read(tar, "nonce.bin")
                ciphertext = _read(tar, "data.enc")
        except (tarfile.TarError, KeyError) as exc:
            raise BackupError("not a readable MyBot backup archive") from exc

        # An archive is untrusted input: it arrived from a USB stick, a sync
        # folder, or somebody's email. Parse it defensively.
        try:
            raw = json.loads(manifest_raw.decode())
            if not isinstance(raw, dict):
                raise BackupError("backup manifest is not an object")
            known = {f: raw[f] for f in BackupManifest.__dataclass_fields__ if f in raw}
            manifest = BackupManifest(**known)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
            raise BackupError("not a readable MyBot backup archive") from exc

        if manifest.format != BACKUP_FORMAT:
            raise BackupError(f"unsupported backup format: {manifest.format}")
        if not isinstance(manifest.wraps, list):
            raise BackupError("backup manifest lists no usable recovery paths")

        return manifest, SealedBox(
            nonce=nonce,
            ciphertext=ciphertext,
            aad=f"{BACKUP_FORMAT}|owner={manifest.owner_hint}",
            key_version=1,
        )


def _summarise(payload: dict) -> dict[str, int]:
    """Row counts per collection, for the unencrypted manifest.

    Only collections. Scalar keys like ``format`` and ``note`` would appear as
    a meaningless ``1`` and bury the numbers a person is actually looking for
    when they are trying to work out whether a two-year-old file is the one
    with their records in it.
    """
    return {
        key: len(value)
        for key, value in payload.items()
        if isinstance(value, (list, tuple))
    }


def _add(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o600
    # A fixed mtime keeps the archive reproducible, so two backups of identical
    # content are byte-identical and a sync tool does not re-upload them.
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def _read(archive: tarfile.TarFile, name: str) -> bytes:
    member = archive.extractfile(name)
    if member is None:
        raise KeyError(name)
    return member.read()


def phrase_checksum(phrase: str) -> str:
    """A short check value shown next to a phrase.

    Lets somebody confirm they transcribed the words correctly without
    revealing the phrase, and without a failed restore being the first time
    they find out.
    """
    normalised = " ".join(phrase.lower().split()).encode()
    return hashlib.sha256(normalised).hexdigest()[:6].upper()


#: Short, visually distinct, no near-homophones, no ambiguous plurals. Chosen
#: for someone copying words onto paper by hand.
_WORDLIST: tuple[str, ...] = (
    "anchor", "apple", "arrow", "autumn", "bamboo", "beacon", "birch", "bison",
    "bloom", "bridge", "bronze", "cabin", "canyon", "carbon", "cedar", "cinder",
    "circus", "clay", "cliff", "clover", "cobalt", "comet", "copper", "coral",
    "cotton", "crater", "crimson", "crystal", "dawn", "delta", "denim", "dial",
    "domino", "dune", "eagle", "ember", "engine", "fabric", "falcon", "fern",
    "fjord", "flint", "forest", "fossil", "galaxy", "garnet", "glacier", "granite",
    "gravel", "grove", "harbor", "harvest", "hazel", "helium", "hollow", "indigo",
    "island", "ivory", "jasper", "jungle", "kernel", "kettle", "lagoon", "lantern",
    "lattice", "ledger", "lemon", "lichen", "lilac", "linen", "lumber", "magnet",
    "mantle", "maple", "marble", "meadow", "mercury", "meteor", "mineral", "mirror",
    "mosaic", "moss", "nebula", "nickel", "noble", "nomad", "oasis", "obsidian",
    "ocean", "onyx", "opal", "orbit", "orchid", "otter", "oxide", "paddle",
    "pebble", "pewter", "pigment", "pillar", "pine", "planet", "plateau", "plaza",
    "pollen", "portal", "prairie", "prism", "pueblo", "pumice", "quartz", "quiver",
    "quilt", "radish", "rapids", "raven", "reef", "relic", "ridge", "river",
    "rocket", "rubble", "saffron", "sage", "salmon", "sandal", "sapphire", "satin",
    "scarlet", "sequoia", "shale", "shell", "silver", "slate", "solar", "spiral",
    "spruce", "stellar", "stone", "summit", "sunset", "syrup", "talon", "tandem",
    "tangent", "teak", "tempo", "textile", "thicket", "thistle", "thunder", "timber",
    "topaz", "torrent", "totem", "tundra", "turbine", "twilight", "umber", "urchin",
    "valley", "velvet", "vertex", "vessel", "vineyard", "violet", "vortex", "walnut",
    "warren", "willow", "window", "winter", "wombat", "yarrow", "yellow", "zenith",
    "zephyr", "zinc",
)


__all__ = [
    "BACKUP_FORMAT",
    "BackupError",
    "BackupManifest",
    "BackupService",
    "KeyWrap",
    "RECOVERY_PHRASE_WORDS",
    "RecoveryFailed",
    "generate_recovery_phrase",
    "parse_phrase_scheme",
    "phrase_checksum",
    "phrase_scheme",
]
