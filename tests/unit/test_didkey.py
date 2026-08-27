"""did:key encoding, decoding and verification — the acceptance boundary."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_node.crypto import didkey


def test_encode_decode_roundtrip(key: Ed25519PrivateKey) -> None:
    did = didkey.encode_did(key.public_key())
    assert did.startswith("did:key:z6Mk")
    assert len(did) == 56, "the server accepts exactly 56 characters"
    assert didkey.public_key_bytes(did) == key.public_key().public_bytes_raw()


def test_did_matches_the_servers_own_pattern(did: str) -> None:
    assert didkey.DID_RE.fullmatch(did)


def test_signature_is_86_unpadded_base64url(key: Ed25519PrivateKey) -> None:
    sig = didkey.sign(key, "room|1|hello")
    assert len(sig) == 86
    assert "=" not in sig
    assert didkey.SIG_RE.fullmatch(sig)


def test_verify_accepts_its_own_signature(key: Ed25519PrivateKey, did: str) -> None:
    didkey.verify(did, didkey.sign(key, "lobby|7|hi"), "lobby|7|hi")


def test_verify_rejects_a_different_message(key: Ed25519PrivateKey, did: str) -> None:
    sig = didkey.sign(key, "lobby|7|hi")
    with pytest.raises(didkey.SignatureError):
        didkey.verify(did, sig, "lobby|7|hi ")


def test_verify_rejects_another_keys_signature(did: str) -> None:
    other = Ed25519PrivateKey.generate()
    with pytest.raises(didkey.SignatureError):
        didkey.verify(did, didkey.sign(other, "lobby|1|x"), "lobby|1|x")


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "did:key:",
        "did:key:z6Mk",
        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",  # secp256k1
        "did:key:z6Mk" + "0" * 44,  # '0' is not base58btc
        "did:key:z6Mk" + "1" * 43,  # too short
        "not-a-did",
    ],
)
def test_malformed_dids_are_refused(bad: str) -> None:
    assert not didkey.is_did(bad)
    with pytest.raises(didkey.DidError):
        didkey.public_key_bytes(bad)


@pytest.mark.parametrize("bad", ["", "short", "a" * 85, "a" * 87, "!" * 86, "a" * 86 + "="])
def test_malformed_signatures_are_refused(did: str, bad: str) -> None:
    with pytest.raises(didkey.DidError):
        didkey.decode_signature(bad)
    assert not didkey.verify_ok(did, bad, "x")


def test_fingerprint_is_16_lowercase_hex(did: str) -> None:
    fp = didkey.fingerprint(did)
    assert len(fp) == 16
    assert fp == fp.lower()
    int(fp, 16)


def test_note_path_follows_the_published_shard_convention(did: str) -> None:
    namespace, key_part = didkey.note_path(did)
    fp = didkey.fingerprint(did)
    assert namespace == f"did-{fp[:2]}"
    assert key_part == fp[2:]
    assert len(key_part) == 14


def test_known_vector_from_the_did_key_spec() -> None:
    """The canonical `did:key` Ed25519 example, decoded and re-encoded.

    Pins the multibase/multicodec path against a string nobody here chose. The upstream
    server's own docstring abbreviates the same example as `did:key:z6Mk...2doK`.
    """
    known = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    expected = bytes.fromhex("2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6")
    assert didkey.public_key_bytes(known) == expected
    assert didkey.encode_did(expected) == known
    assert didkey.abbreviate(known) == "z6Mk\u20262doK"
