"""`did:key` (Ed25519) encoding, decoding, signing and verification.

Deliberately a mirror of the upstream server's `src/didkey.py` acceptance boundary
(technocore-chat @ 9c7df0e, Apache-2.0): a DID this module accepts is a DID the server
accepts, and a signature this module produces is one the server verifies. Every check
fails closed — there is no "malformed but tolerated" path, because the only thing a
signature establishes is possession of a key, and a lenient parser gives that away.

What a signature does NOT establish is anything about the signer's honesty or identity.
See `docs/SECURITY.md`.
"""

from __future__ import annotations

import base64
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PREFIX = "did:key:"
#: multicodec `ed25519-pub`, varint-encoded. Every Ed25519 did:key therefore starts z6Mk.
MULTICODEC_ED25519 = b"\xed\x01"
#: 2 codec bytes + 32 key bytes = 34 bytes = 47 base58btc characters, plus the `z` tag.
MULTIBASE_CHARS = 48
#: 64 raw signature bytes, base64url, unpadded.
SIG_CHARS = 86

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}

DID_PATTERN = rf"{PREFIX}z6Mk[1-9A-HJ-NP-Za-km-z]{{{MULTIBASE_CHARS - 4}}}"
SIG_PATTERN = rf"[A-Za-z0-9_-]{{{SIG_CHARS}}}"
#: 19 digits is the int64 ceiling, which is what the server accepts.
NONCE_PATTERN = r"[0-9]{1,19}"

DID_RE = re.compile(DID_PATTERN)
SIG_RE = re.compile(SIG_PATTERN)
NONCE_RE = re.compile(NONCE_PATTERN)


class DidError(ValueError):
    """Not a usable `did:key`, or a structurally invalid signature/nonce encoding."""


class SignatureError(ValueError):
    """A well-formed DID whose signature does not cover the message it was offered for."""


def _b58decode(raw: str) -> bytes:
    n = 0
    for ch in raw:
        digit = _B58_INDEX.get(ch)
        if digit is None:
            raise DidError(f"bad did:key: {ch!r} is not base58btc")
        n = n * 58 + digit
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    # Leading zero bytes are not carried by the integer, so re-add them as '1's.
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + out


def public_key_bytes(did: str) -> bytes:
    """The 32 raw Ed25519 public-key bytes of `did`, or raise :class:`DidError`."""
    if not isinstance(did, str) or not did.startswith(PREFIX):
        raise DidError(f"bad did:key: expected {PREFIX}z6Mk...")
    mb = did[len(PREFIX) :]
    if len(mb) != MULTIBASE_CHARS or not mb.startswith("z"):
        raise DidError(
            f"bad did:key: expected {MULTIBASE_CHARS} multibase characters starting 'z', "
            f"got {len(mb)}"
        )
    decoded = _b58decode(mb[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise DidError("bad did:key: only ed25519-pub (z6Mk...) keys are accepted")
    return decoded[2:]


def encode_did(public_key: Ed25519PublicKey | bytes) -> str:
    """Render an Ed25519 public key as a `did:key:z6Mk…` identifier."""
    raw = public_key.public_bytes_raw() if isinstance(public_key, Ed25519PublicKey) else public_key
    if len(raw) != 32:
        raise DidError(f"bad public key: expected 32 bytes, got {len(raw)}")
    return PREFIX + "z" + _b58encode(MULTICODEC_ED25519 + raw)


def is_did(value: object) -> bool:
    """True only for a DID this node — and the server — would verify against."""
    if not isinstance(value, str):
        return False
    try:
        public_key_bytes(value)
    except DidError:
        return False
    return True


def abbreviate(did: str) -> str:
    """`z6Mk…2doK` — how the server's text view renders a verified writer."""
    mb = did[len(PREFIX) :]
    return f"{mb[:4]}…{mb[-4:]}"


def fingerprint(did: str) -> str:
    """The first 16 lowercase hex characters of SHA-256 over the did:key *string*.

    This is the server's published convention for locating a DID's profile note, and is
    the source of this node's room names. It is a convention, not a server feature.
    """
    if not is_did(did):
        raise DidError("fingerprint requires a valid did:key")
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


def note_path(did: str) -> tuple[str, str]:
    """The sharded profile-note location for `did`: `(namespace, key)`.

    `/kv/did-<first 2>/<remaining 14>`, per the published convention.
    """
    fp = fingerprint(did)
    return f"did-{fp[:2]}", fp[2:]


def legacy_note_path(did: str) -> tuple[str, str]:
    """The pre-shard location readers still fall back to: `/kv/did/<all 16>`."""
    return "did", fingerprint(did)


def encode_signature(raw: bytes) -> str:
    """64 raw signature bytes as the 86 unpadded base64url characters the server wants."""
    if len(raw) != 64:
        raise DidError(f"bad signature: expected 64 bytes, got {len(raw)}")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_signature(signature: str) -> bytes:
    """The 64 raw bytes behind an 86-character unpadded base64url signature."""
    if not SIG_RE.fullmatch(signature or ""):
        raise DidError(f"bad signature encoding: expected {SIG_CHARS} base64url characters")
    return base64.urlsafe_b64decode(signature[:SIG_CHARS] + "==")


def sign(private_key: Ed25519PrivateKey, message: str) -> str:
    """Sign `message` (UTF-8) and return the server's signature encoding."""
    return encode_signature(private_key.sign(message.encode("utf-8")))


def verify(did: str, signature: str, message: str) -> None:
    """Raise unless `signature` is `did`'s Ed25519 signature over `message` (UTF-8)."""
    key = Ed25519PublicKey.from_public_bytes(public_key_bytes(did))
    raw = decode_signature(signature)
    try:
        key.verify(raw, message.encode("utf-8"))
    except InvalidSignature:
        raise SignatureError("signature does not cover this message") from None


def verify_ok(did: str, signature: str, message: str) -> bool:
    """:func:`verify` as a boolean, for callers reporting a verdict rather than gating."""
    try:
        verify(did, signature, message)
    except (DidError, SignatureError):
        return False
    return True
