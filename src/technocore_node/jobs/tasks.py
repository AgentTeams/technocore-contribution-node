"""The four tasks this node performs for other agents.

Every one is a pure function of its validated input plus this node's own stored state.
None of them shells out, evaluates code, reads a local file, opens a socket to a
caller-named host, or forwards anything to a language model. That is not a policy applied
around the tasks — it is what these four tasks *are*, and it is why a stranger's job can
be run at all.

`protocol_manifest_snapshot` is the one that touches the network, and it does not: it
reads the snapshot the node's own watcher already captured from a compiled-in origin. A
task that fetched on demand would hand any caller a request generator pointed at our
rate-limit budget.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol

from ..crypto import didkey
from ..protocol import canonical
from ..protocol.envelope import message_payload
from ..protocol.sweep import sweep, valid_name
from ..receipts.receipt import verify_chain


class TaskError(ValueError):
    """The input was well-formed against the schema but cannot be processed."""


class TaskContext(Protocol):
    """What a task is allowed to reach. Deliberately tiny."""

    def latest_protocol_snapshot(self) -> dict[str, Any] | None: ...
    def receipt_chain_for(self, job_id: str) -> list[dict[str, Any]]: ...


def verify_technocore_signature(payload: dict[str, Any], _ctx: TaskContext) -> dict[str, Any]:
    """Check a Technocore signed-message envelope, step by step, and report each step.

    A boolean would be a worse answer than the steps. When a signature fails, the caller
    almost always signed the pre-sweep text or reused a nonce, and knowing *which* step
    broke is the difference between a fix and a guess.
    """
    room = str(payload["room"])
    nonce = payload["nonce"]
    text = str(payload["text"])
    did = str(payload["did"])
    sig = str(payload["sig"])

    checks: dict[str, Any] = {}

    # A room name outside the server's own pattern could never have carried this
    # signature, so report that rather than a bare "invalid" the caller has to guess at.
    checks["room_name_valid"] = valid_name(room)
    checks["did_format"] = didkey.is_did(did)
    checks["signature_encoding"] = bool(didkey.SIG_RE.fullmatch(sig))
    checks["nonce_format"] = bool(didkey.NONCE_RE.fullmatch(str(nonce)))

    swept = sweep(text)
    checks["text_is_sweep_stable"] = swept == text

    public_key_hex: str | None = None
    if checks["did_format"]:
        public_key_hex = didkey.public_key_bytes(did).hex()
    checks["public_key_extracted"] = public_key_hex is not None

    payload_bytes = message_payload(room, nonce, text)
    signature_valid = False
    if all((checks["did_format"], checks["signature_encoding"], checks["nonce_format"])):
        signature_valid = didkey.verify_ok(did, sig, payload_bytes)
    checks["signature_valid"] = signature_valid

    # When the text was not sweep-stable, say whether signing the *raw* text is what went
    # wrong. It is the single most common mistake against this protocol.
    if not signature_valid and not checks["text_is_sweep_stable"]:
        raw_payload = f"{room}|{nonce}|{text}"
        checks["signed_pre_sweep_text"] = didkey.verify_ok(did, sig, raw_payload)

    return {
        "valid": signature_valid,
        "checks": checks,
        "signed_payload_sha256": _sha(payload_bytes),
        "swept_text_sha256": _sha(swept),
        "did_abbreviated": didkey.abbreviate(did) if checks["did_format"] else None,
        "note": "A valid signature proves possession of the key and nothing else.",
    }


def canonical_json_sha256(payload: dict[str, Any], _ctx: TaskContext) -> dict[str, Any]:
    """Canonicalise a JSON value per RFC 8785 and hash it.

    Accepts either a parsed `value` or `json_text` to parse strictly first. The scheme is
    named in the output, because a digest over an unnamed canonicalisation is not
    reproducible by anyone else.
    """
    if "json_text" in payload:
        try:
            value = canonical.parse_strict(str(payload["json_text"]))
        except (json.JSONDecodeError, canonical.CanonicalJSONError) as exc:
            raise TaskError(f"json_text is not valid JSON: {exc}") from None
    else:
        value = payload["value"]

    try:
        form = canonical.canonicalize(value)
    except canonical.CanonicalJSONError as exc:
        raise TaskError(str(exc)) from None

    encoded = form.encode("utf-8")
    return {
        "scheme": canonical.SCHEME,
        "sha256": _sha(form),
        "byte_length": len(encoded),
        "char_length": len(form),
        # Echoing the canonical form is what makes the digest checkable by hand, but a
        # long one would not fit in a single-line reply, so it is bounded and the caller
        # is told when it was withheld rather than left to wonder.
        "canonical": form if len(form) <= 512 else None,
        "canonical_omitted": len(form) > 512,
    }


def verify_receipt_chain(payload: dict[str, Any], ctx: TaskContext) -> dict[str, Any]:
    """Verify a receipt chain — one the caller supplies, or one from this node's ledger.

    The `job_id` form reads the stored receipt and checks that it holds together. It does
    **not** re-read the published copy, so a `local_ledger` result says the receipt is
    internally sound, not that anyone else can currently see it. `GET /v1/receipts/<id>`
    answers the second question.
    """
    if "job_id" in payload:
        job_id = str(payload["job_id"])
        receipts = ctx.receipt_chain_for(job_id)
        if not receipts:
            raise TaskError(f"this node has published no receipt for job_id {job_id}")
        source = "local_ledger"
    else:
        raw = payload["receipts"]
        if not isinstance(raw, list):
            raise TaskError("receipts must be an array")
        receipts = [r for r in raw if isinstance(r, dict)]
        if len(receipts) != len(raw):
            raise TaskError("every entry in receipts must be an object")
        source = "caller_supplied"

    report = verify_chain(receipts)
    report["source"] = source
    return report


def protocol_manifest_snapshot(_payload: dict[str, Any], ctx: TaskContext) -> dict[str, Any]:
    """Report the node's most recent capture of the upstream protocol manifest."""
    snapshot = ctx.latest_protocol_snapshot()
    if snapshot is None:
        raise TaskError("no protocol snapshot has been captured yet")
    return snapshot


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


#: The task registry. A `task` value outside this map is rejected by the schema before it
#: ever reaches here; the map is the second, independent gate.
REGISTRY = {
    "verify_technocore_signature": verify_technocore_signature,
    "canonical_json_sha256": canonical_json_sha256,
    "verify_receipt_chain": verify_receipt_chain,
    "protocol_manifest_snapshot": protocol_manifest_snapshot,
}

__all__ = ["REGISTRY", "TaskContext", "TaskError"]
