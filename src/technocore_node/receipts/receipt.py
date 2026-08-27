"""Hashing, signing and verifying the JOB → RESULT → RECEIPT chain.

Everything here is defined in terms of one operation: take the RFC 8785 canonical form of
a JSON object with its own signature fields removed, hash it with SHA-256, and sign or
compare that. Stating the rule once — and naming the canonicalisation, rather than
inventing one — is what makes a receipt checkable by somebody who did not write this code.

One property is stated in the receipt itself rather than left implicit: `request_seq`
comes from the server, so it is provenance and never proof. A verifier that treats a seq
as signed would be trusting the transport for something the transport never claimed.

There is deliberately no `result_seq`. The receipt is built and signed before the result
is published, so the result's seq does not exist yet — and adding it afterwards would
invalidate the signature that makes the receipt worth anything. A field that can only ever
be null is worse than an absent one: it invites a reader to wait for a value that is not
coming.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..crypto import didkey
from ..ledger.db import utcnow
from ..protocol.canonical import canonical_bytes

#: Fields stripped before hashing, because they carry the hash or the signature itself.
RESULT_EXCLUDED = ("sig",)
RECEIPT_EXCLUDED = ("sig", "receipt_hash")


class ReceiptError(ValueError):
    """A chain does not hold together."""


def canonical_hash(value: Any) -> str:
    """`sha256:<hex>` over the RFC 8785 canonical form of `value`."""
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _without(obj: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {k: v for k, v in obj.items() if k not in keys}


def request_hash(job: dict[str, Any]) -> str:
    """The hash a claim, a result and a receipt all point back to."""
    return canonical_hash(job)


def result_signing_payload(result: dict[str, Any]) -> bytes:
    """The exact bytes a result's detached signature covers."""
    return canonical_bytes(_without(result, RESULT_EXCLUDED))


def sign_result(private_key: Ed25519PrivateKey, result: dict[str, Any]) -> str:
    """Sign a result object, returning the value for its `sig` field."""
    return didkey.encode_signature(private_key.sign(result_signing_payload(result)))


def verify_result(result: dict[str, Any]) -> None:
    """Raise unless the result's detached signature is the provider DID's own."""
    sig = result.get("sig")
    provider = result.get("provider_did")
    if not isinstance(sig, str) or not isinstance(provider, str):
        raise ReceiptError("result is missing sig or provider_did")
    payload = result_signing_payload(result)
    try:
        didkey.verify(provider, sig, payload.decode("utf-8"))
    except (didkey.DidError, didkey.SignatureError) as exc:
        raise ReceiptError(f"result signature does not verify: {exc}") from None


def build_receipt(
    private_key: Ed25519PrivateKey,
    *,
    receipt_id: str,
    job_id: str,
    requester_did: str,
    provider_did: str,
    request_room: str,
    reply_room: str,
    request_hash_value: str,
    result_hash_value: str,
    provider_signature: str,
    request_seq: int | None,
    internal_test: bool,
) -> dict[str, Any]:
    """Assemble a receipt, hash it, sign it, and return it ready to publish."""
    receipt: dict[str, Any] = {
        "v": "1",
        "type": "receipt",
        "receipt_id": receipt_id,
        "job_id": job_id,
        "requester_did": requester_did,
        "provider_did": provider_did,
        "request_room": request_room,
        "reply_room": reply_room,
        "request_seq": request_seq,
        "request_hash": request_hash_value,
        "result_hash": result_hash_value,
        "provider_signature": provider_signature,
        "internal_test": internal_test,
        "created_at": utcnow(),
    }
    receipt["receipt_hash"] = canonical_hash(_without(receipt, RECEIPT_EXCLUDED))
    receipt["sig"] = didkey.encode_signature(
        private_key.sign(canonical_bytes(_without(receipt, ("sig",))))
    )
    return receipt


def verify_receipt(receipt: dict[str, Any]) -> list[str]:
    """Check one receipt in isolation. Returns the list of problems — empty means good.

    Returning findings rather than raising is deliberate: this runs as a *service* for
    other agents, and "which of the seven checks failed" is the answer they came for.
    """
    problems: list[str] = []

    for field in (
        "receipt_hash",
        "sig",
        "provider_did",
        "requester_did",
        "request_hash",
        "result_hash",
        "job_id",
    ):
        if field not in receipt:
            problems.append(f"missing field: {field}")
    if problems:
        return problems

    recomputed = canonical_hash(_without(receipt, RECEIPT_EXCLUDED))
    if recomputed != receipt["receipt_hash"]:
        problems.append("receipt_hash does not match the canonical form of the receipt")

    provider = receipt["provider_did"]
    if not didkey.is_did(provider):
        problems.append("provider_did is not a valid did:key")
    elif not didkey.is_did(receipt["requester_did"]):
        problems.append("requester_did is not a valid did:key")
    else:
        payload = canonical_bytes(_without(receipt, ("sig",)))
        if not didkey.verify_ok(provider, str(receipt["sig"]), payload.decode("utf-8")):
            problems.append("receipt signature does not verify against provider_did")

    return problems


def verify_chain(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    """Verify a set of receipts together: each one, plus the cross-receipt properties.

    The cross-receipt checks are the ones a single-receipt verifier cannot make — a
    duplicate `job_id` (the same work claimed twice) and a `created_at` that runs
    backwards against a monotonically issued `receipt_id`.
    """
    per_receipt: list[dict[str, Any]] = []
    seen_jobs: dict[str, int] = {}
    duplicates: list[str] = []

    for index, receipt in enumerate(receipts):
        problems = verify_receipt(receipt)
        job_id = str(receipt.get("job_id", ""))
        if job_id:
            if job_id in seen_jobs:
                duplicates.append(job_id)
                problems.append(f"duplicate job_id, first seen at index {seen_jobs[job_id]}")
            else:
                seen_jobs[job_id] = index
        per_receipt.append(
            {
                "index": index,
                "job_id": job_id or None,
                "valid": not problems,
                "problems": problems,
            }
        )

    timestamps = [str(r.get("created_at", "")) for r in receipts if r.get("created_at")]
    ordered = timestamps == sorted(timestamps)

    return {
        "count": len(receipts),
        "all_valid": all(item["valid"] for item in per_receipt),
        "duplicate_job_ids": sorted(set(duplicates)),
        "chronological": ordered,
        "receipts": per_receipt,
    }
