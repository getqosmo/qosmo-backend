"""Where the master key lives.

This is the seam between software MyBot and the MyBot Core.  Today every
implementation is software; on the Core the master key will be generated
inside a secure element and never leave it, and only
:class:`SecureKeyStore` needs a new subclass for that to be true.

Note the shape of the interface: it exposes ``derive`` (give me a subkey for
this purpose) rather than ``get_master_key``.  A hardware implementation
physically cannot satisfy the latter, so designing around it now avoids
building an API the real device can never provide.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path

from ..crypto import AES_KEY_BYTES, CryptoError, b64d, b64e, derive_subkey, generate_key


class KeyStoreError(RuntimeError):
    pass


class SecureKeyStore(ABC):
    """Provides purpose-bound key material without exposing the root key."""

    #: Bumped when a rotation happens; sealed blobs record which version made
    #: them so rotation can be incremental rather than a stop-the-world event.
    key_version: int = 1

    @abstractmethod
    def derive(self, purpose: str, *, length: int = AES_KEY_BYTES) -> bytes:
        """Return a subkey for ``purpose``."""

    @abstractmethod
    def describe(self) -> dict:
        """Non-sensitive description for the Security Center."""

    @property
    def hardware_backed(self) -> bool:
        return False

    def rotate(self) -> int:  # pragma: no cover - overridden where supported
        raise KeyStoreError("this keystore does not support rotation")


class SoftwareKeyStore(SecureKeyStore):
    """Development default: a key file under the data directory.

    Honest about what it is.  The file is created 0600 and the directory is
    tightened too, but a software keystore on a general-purpose OS offers no
    protection against an attacker who already has the user's account -- which
    is precisely the gap the Core hardware closes.
    """

    def __init__(self, data_dir: Path):
        self._path = Path(data_dir) / "vault_master.key"
        self._version_path = Path(data_dir) / "vault_master.version"
        self._key = self._load_or_create()
        self.key_version = self._load_version()

    def _load_or_create(self) -> bytes:
        if self._path.exists():
            raw = b64d(self._path.read_text().strip())
            if len(raw) != AES_KEY_BYTES:
                raise KeyStoreError("master key file is corrupt")
            return raw
        key = generate_key()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Create with restrictive permissions from the start rather than
        # chmod-ing after: no window where the key is world-readable.
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(b64e(key))
        try:
            os.chmod(self._path.parent, 0o700)
        except OSError:  # pragma: no cover - platform dependent
            pass
        return key

    def _load_version(self) -> int:
        if self._version_path.exists():
            try:
                return int(self._version_path.read_text().strip())
            except ValueError:  # pragma: no cover
                return 1
        return 1

    def derive(self, purpose: str, *, length: int = AES_KEY_BYTES) -> bytes:
        return derive_subkey(self._key, purpose, length=length)

    def describe(self) -> dict:
        return {
            "backend": "software",
            "hardware_backed": False,
            "key_version": self.key_version,
            "location": str(self._path),
            "note": "Development keystore. Offers no protection against local account compromise.",
        }


class EnvKeyStore(SecureKeyStore):
    """Master key supplied by the environment.

    For containers and CI, where writing a key file is the wrong shape.  Also
    the path a deployment would use with a real KMS or secrets manager
    injecting the value.
    """

    def __init__(self, encoded_key: str, key_version: int = 1):
        if not encoded_key:
            raise KeyStoreError("MYBOT_VAULT_MASTER_KEY is empty")
        raw = b64d(encoded_key)
        if len(raw) != AES_KEY_BYTES:
            raise KeyStoreError("MYBOT_VAULT_MASTER_KEY must decode to 32 bytes")
        self._key = raw
        self.key_version = key_version

    def derive(self, purpose: str, *, length: int = AES_KEY_BYTES) -> bytes:
        return derive_subkey(self._key, purpose, length=length)

    def describe(self) -> dict:
        return {"backend": "env", "hardware_backed": False, "key_version": self.key_version}


class KeyringKeyStore(SecureKeyStore):
    """OS keychain (macOS Keychain, Windows DPAPI, Secret Service).

    Better than a key file on a laptop: the OS gates access per-application
    and can require the login password.  Optional dependency; falls back with
    a clear error rather than silently downgrading to something weaker.
    """

    SERVICE = "MyBot"
    ACCOUNT = "vault_master_key"

    def __init__(self, key_version: int = 1):
        try:
            import keyring
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise KeyStoreError(
                "keyring backend requested but the `keyring` package is not installed "
                "(pip install 'mybot[keyring]')"
            ) from exc
        self._keyring = keyring
        stored = keyring.get_password(self.SERVICE, self.ACCOUNT)
        if stored is None:
            key = generate_key()
            keyring.set_password(self.SERVICE, self.ACCOUNT, b64e(key))
        else:
            key = b64d(stored)
            if len(key) != AES_KEY_BYTES:
                raise KeyStoreError("keyring master key is corrupt")
        self._key = key
        self.key_version = key_version

    def derive(self, purpose: str, *, length: int = AES_KEY_BYTES) -> bytes:
        return derive_subkey(self._key, purpose, length=length)

    def describe(self) -> dict:
        return {"backend": "keyring", "hardware_backed": False, "key_version": self.key_version}


class HardwareKeyStore(SecureKeyStore):  # pragma: no cover - no hardware in dev
    """Placeholder for the MyBot Core secure element.

    Intentionally unimplemented rather than faked.  Constructing it raises, so
    nothing can accidentally believe it has hardware protection it does not
    have -- a mock that pretends to be a TPM is worse than no TPM.
    """

    def __init__(self, *_args, **_kwargs):
        raise KeyStoreError(
            "hardware keystore is not available on this platform; MyBot Core hardware "
            "is on the roadmap and this class is the interface it will implement"
        )

    def derive(self, purpose: str, *, length: int = AES_KEY_BYTES) -> bytes:
        raise KeyStoreError("not available")

    def describe(self) -> dict:
        return {"backend": "hardware", "hardware_backed": True}

    @property
    def hardware_backed(self) -> bool:
        return True


def build_keystore(backend: str, *, data_dir: Path, env_key: str = "") -> SecureKeyStore:
    backend = (backend or "software").lower()
    if backend == "software":
        return SoftwareKeyStore(data_dir)
    if backend == "env":
        return EnvKeyStore(env_key)
    if backend == "keyring":
        return KeyringKeyStore()
    if backend == "hardware":
        return HardwareKeyStore()
    raise KeyStoreError(f"unknown keystore backend: {backend!r}")


__all__ = [
    "CryptoError",
    "EnvKeyStore",
    "HardwareKeyStore",
    "KeyStoreError",
    "KeyringKeyStore",
    "SecureKeyStore",
    "SoftwareKeyStore",
    "build_keystore",
]
