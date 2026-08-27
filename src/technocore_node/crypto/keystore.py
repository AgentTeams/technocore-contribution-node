"""On-disk custody of the node's one production key.

The private key lives in an encrypted PKCS#8 PEM file, mode 0600, owned by the service
user, outside the repository and outside any directory the service can write to. The
passphrase lives in a second 0600 file, read at the moment of decryption and dropped
immediately afterwards — it is never held on a config object, never logged, and never
placed in the process environment where `/proc/<pid>/environ` would expose it.

The node generates **one** production identity and keeps it. There is no rotation
schedule, because a did:key's whole value here is continuity: the identifier *is* the key,
nothing can vouch for a replacement, and a node that rotates has thrown away every
receipt that pointed at it.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import didkey


class KeystoreError(RuntimeError):
    """The key could not be loaded, created, or is stored unsafely."""


@dataclass(frozen=True, slots=True)
class Identity:
    """A loaded signing identity. The private key never leaves this object."""

    private_key: Ed25519PrivateKey
    did: str

    @property
    def fingerprint(self) -> str:
        return didkey.fingerprint(self.did)

    @property
    def public_key_hash(self) -> str:
        return hashlib.sha256(self.private_key.public_key().public_bytes_raw()).hexdigest()

    def sign(self, message: str) -> str:
        return didkey.sign(self.private_key, message)


def _assert_private_mode(path: Path) -> None:
    """Refuse to use a key file that anyone but its owner can read.

    Failing closed here is the whole point: a key readable by the group or by the world
    has to be treated as disclosed, and continuing to sign with it would publish
    attributable messages under a key someone else may hold.
    """
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise KeystoreError(
            f"{path} is group- or world-accessible (mode {stat.S_IMODE(mode):04o}); "
            "refusing to load a key that must be treated as disclosed. chmod 600 it, "
            "and rotate it if it was ever exposed."
        )


def generate(path: Path, passphrase: bytes | None, *, overwrite: bool = False) -> Identity:
    """Create the node's production key at `path` and return its identity.

    Refuses to overwrite an existing key unless explicitly told to: replacing the key
    discards the identity every published receipt refers to.
    """
    path = Path(path)
    if path.exists() and not overwrite:
        raise KeystoreError(
            f"{path} already exists. This node keeps one production identity; "
            "overwriting it would orphan every receipt already published under it."
        )
    if not passphrase:
        raise KeystoreError("a passphrase is required: this node does not store a bare key")

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Create at 0600 rather than writing then chmod-ing: the window between the two is
    # exactly long enough for another process to open the file.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return Identity(private_key=key, did=didkey.encode_did(key.public_key()))


def load(path: Path, passphrase: bytes | None) -> Identity:
    """Load the identity at `path`, or raise :class:`KeystoreError`."""
    path = Path(path)
    if not path.exists():
        raise KeystoreError(f"no key at {path}; run `technocore-node keygen` first")
    _assert_private_mode(path)
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=passphrase)
    except (ValueError, TypeError) as exc:
        # The message deliberately does not echo the exception: cryptography's text
        # distinguishes "bad passphrase" from "not encrypted", and both are facts about
        # the key an error surface has no reason to broadcast.
        raise KeystoreError(f"could not decrypt the key at {path}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise KeystoreError(f"{path} holds a {type(key).__name__}, not an Ed25519 key")
    return Identity(private_key=key, did=didkey.encode_did(key.public_key()))


def load_or_create(path: Path, passphrase: bytes | None) -> tuple[Identity, bool]:
    """Load the key, creating it on first run. Returns `(identity, created)`."""
    if Path(path).exists():
        return load(path, passphrase), False
    return generate(path, passphrase), True


def verify_restores_same_did(
    backup_pem: bytes, passphrase: bytes | None, expected_did: str
) -> bool:
    """Prove a backup still yields the production DID, without writing it anywhere.

    The whole restore drill: decrypt the backup bytes in memory, derive the DID, compare.
    Nothing is written to disk and no key material is returned to the caller.
    """
    try:
        key = serialization.load_pem_private_key(backup_pem, password=passphrase)
    except (ValueError, TypeError):
        return False
    if not isinstance(key, Ed25519PrivateKey):
        return False
    return didkey.encode_did(key.public_key()) == expected_did
