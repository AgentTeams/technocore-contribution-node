"""The published examples are checked, not just published.

`examples/verify_receipt.py` reimplements canonicalisation, `did:key` decoding and
signature checking from the specification, deliberately sharing no code with the node.
That independence is the reason it is worth running — and the reason it can silently
drift until it disagrees with the receipts it is supposed to check.

So it is exercised here against receipts this node actually builds, including the ways a
tampered one must fail. If the two implementations ever disagree, one of them is wrong
about the protocol and this is where that surfaces.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_node.crypto import didkey
from technocore_node.receipts.receipt import build_receipt

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, EXAMPLES / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def verifier() -> Any:
    return _load("verify_receipt")


@pytest.fixture
def receipt() -> tuple[dict[str, Any], str]:
    key = Ed25519PrivateKey.generate()
    did = didkey.encode_did(key.public_key())
    return (
        build_receipt(
            key,
            receipt_id="rcpt-000000000000000000000001",
            job_id="example-job-0001",
            requester_did=didkey.encode_did(Ed25519PrivateKey.generate().public_key()),
            provider_did=did,
            request_room="mb-tc-jobs-example",
            reply_room="mb-p-example",
            request_hash_value="sha256:" + "11" * 32,
            result_hash_value="sha256:" + "22" * 32,
            provider_signature="A" * 86,
            request_seq=4,
            internal_test=False,
        ),
        did,
    )


def test_the_independent_verifier_accepts_a_real_receipt(
    verifier: Any, receipt: tuple[dict[str, Any], str]
) -> None:
    """The two implementations agree on a receipt the node signed."""
    body, did = receipt
    assert verifier.verify(body, did) == []


def test_its_canonical_form_matches_the_nodes(
    verifier: Any, receipt: tuple[dict[str, Any], str]
) -> None:
    """Byte-for-byte, not merely both-parse-the-same.

    The hash is taken over these bytes, so agreeing on the object while disagreeing on
    its serialisation is exactly the failure this catches.
    """
    from technocore_node.protocol.canonical import canonicalize

    body, _ = receipt
    assert verifier.canonical(body) == canonicalize(body)


def test_a_did_decoded_independently_is_the_same_key(verifier: Any) -> None:
    for _ in range(20):
        key = Ed25519PrivateKey.generate()
        did = didkey.encode_did(key.public_key())
        theirs = verifier.did_to_public_key(did).public_bytes_raw()
        assert theirs == key.public_key().public_bytes_raw()


@pytest.mark.parametrize(
    "field, value",
    [
        ("job_id", "tampered-job-01"),
        ("requester_did", "did:key:z6MkfyqMqvC4QGbyMAzpL4haXspn1f1ZGUwhdPearjqPpnnc"),
        ("result_hash", "sha256:" + "33" * 32),
        ("internal_test", True),
        ("request_seq", 5),
    ],
)
def test_editing_any_field_is_caught(
    verifier: Any, receipt: tuple[dict[str, Any], str], field: str, value: Any
) -> None:
    """Every field is covered by the hash and the signature, so every edit fails both."""
    body, did = receipt
    body[field] = value

    problems = verifier.verify(body, did)
    assert any("receipt_hash does not match" in p for p in problems)
    assert any("not a valid signature" in p for p in problems)


def test_a_signature_from_another_key_is_caught(
    verifier: Any, receipt: tuple[dict[str, Any], str]
) -> None:
    """Re-signing a tampered receipt with a different key does not rescue it.

    This is the attack the DID check exists for: the content and its signature can be
    made perfectly consistent by anyone, because anyone can generate a key. What they
    cannot do is make it consistent *and* signed by the node's key.
    """
    body, did = receipt
    impostor = Ed25519PrivateKey.generate()
    body["result_hash"] = "sha256:" + "44" * 32
    forged = build_receipt(
        impostor,
        receipt_id=body["receipt_id"],
        job_id=body["job_id"],
        requester_did=body["requester_did"],
        provider_did=didkey.encode_did(impostor.public_key()),
        request_room=body["request_room"],
        reply_room=body["reply_room"],
        request_hash_value=body["request_hash"],
        result_hash_value=body["result_hash"],
        provider_signature=body["provider_signature"],
        request_seq=body["request_seq"],
        internal_test=False,
    )

    # Internally consistent — and that is precisely why consistency is not enough.
    assert verifier.verify(forged, didkey.encode_did(impostor.public_key())) == []
    assert any("expected " + did in p for p in verifier.verify(forged, did))


def test_not_pinning_a_did_is_reported_as_a_gap_rather_than_a_pass(
    verifier: Any, receipt: tuple[dict[str, Any], str]
) -> None:
    """Silence about an unchecked identity would read as an endorsement of it."""
    body, _ = receipt
    problems = verifier.verify(body, None)
    assert problems == [
        "provider_did was not checked against a known identity — a valid signature "
        "by an unknown key proves possession of that key and nothing more"
    ]


def test_a_receipt_missing_its_signature_is_refused_before_anything_else(
    verifier: Any, receipt: tuple[dict[str, Any], str]
) -> None:
    body, did = receipt
    del body["sig"]
    assert verifier.verify(body, did) == ["missing required field 'sig'"]


def test_the_sender_example_is_syntactically_whole() -> None:
    """It is documentation people paste, so it must at least import and expose its parts."""
    sender = _load("send_job")
    assert callable(sender.sign_job)
    assert callable(sender.main)
    assert json.loads(json.dumps(sender.EXAMPLE_JOB))["task"] == "canonical_json_sha256"
