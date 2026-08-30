"""Signed job submission over HTTP.

A second way in for agents that can sign but would rather not learn a chat protocol. It
reuses the pieces that already exist — the same validator, the same four tasks, the same
receipt chain, the same ledger — because the transport is the only thing that differs and
duplicating a security-relevant pipeline is how the two copies drift apart.

Everything the mailbox lane refuses, this refuses too, plus what HTTP adds:

* **Domain separation.** The signature covers a version-tagged payload that cannot collide
  with a room signature, so neither lane's signatures are usable in the other.
* **Replay.** A per-DID monotonic nonce is claimed in one transaction, and the signature
  binds a hash of the body, so a captured request can be neither resent nor edited.
* **Idempotency.** The same `(requester DID, job_id)` returns the first answer rather than
  doing the work twice.
* **The safety gate.** The endpoint is refused outright unless the node is in a state where
  a receipt it issues would mean something — the same gate the mailbox lane passes.

Disabled by default. Enabling it is a decision, not a default.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse

from ..jobs.runner import RejectedJob
from ..logging import get_logger
from ..protocol.canonical import CanonicalJSONError, canonical_bytes, parse_strict
from ..protocol.http_envelope import HttpEnvelopeError, http_job_payload, verify_http_job
from ..service.node import Node

log = get_logger(__name__)

#: A submission body must fit this. Far above any legitimate job and far below anything
#: that could be used to make the node hold a large buffer per request.
MAX_BODY_BYTES = 16 * 1024


def _problem(code: str, detail: str, http_status: int) -> JSONResponse:
    """A refusal a caller can act on, saying nothing about this host.

    `code` is stable and worth branching on; `detail` is prose and may change.
    """
    return JSONResponse({"error": code, "detail": detail[:300]}, status_code=http_status)


def register(router: APIRouter, node: Node) -> None:
    """Attach the submission endpoint to `router`."""

    @router.post(
        "/v1/jobs",
        tags=["jobs"],
        summary="Submit a signed job over HTTP",
        status_code=status.HTTP_200_OK,
    )
    async def submit_job(request: Request, response: Response) -> Any:
        if not node.settings.http_job_intake_enabled:
            # 404 rather than 403: a disabled lane is not a lane with a locked door, and
            # advertising its existence invites people to keep knocking.
            return _problem("not_found", "no such endpoint", status.HTTP_404_NOT_FOUND)

        if not node.can_accept_third_party_jobs("http"):
            _, reasons = node.lane_is_open("http")
            # The same gate the mailbox lane passes. A receipt issued now could not be
            # audited, so declining is the only honest answer — and it says why, because
            # the caller can do nothing about a refusal they cannot see the shape of.
            return _problem(
                "not_accepting_jobs",
                "this node is not currently accepting third-party work: " + "; ".join(reasons),
                status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            return _problem(
                "request_too_large",
                f"body is {len(raw)} bytes, limit {MAX_BODY_BYTES}",
                status.HTTP_413_CONTENT_TOO_LARGE,
            )

        try:
            # `parse_strict`, not `json.loads`. Python keeps the last of a duplicate key,
            # so `{"task":"a","task":"b"}` would be signed and hashed as if only `b` were
            # written, while a verifier that keeps the first reads the same bytes
            # differently. The signature would verify and the two parties would disagree
            # about what was signed — the one property a receipt exists to rule out. The
            # mailbox lane refuses this at the parse; so does this one.
            envelope = parse_strict(raw.decode("utf-8"))
        except UnicodeDecodeError:
            return _problem("not_json", "body is not UTF-8", status.HTTP_400_BAD_REQUEST)
        except json.JSONDecodeError:
            return _problem("not_json", "body is not JSON", status.HTTP_400_BAD_REQUEST)
        except CanonicalJSONError as exc:
            return _problem("not_canonical_json", str(exc), status.HTTP_400_BAD_REQUEST)
        if not isinstance(envelope, dict):
            return _problem("not_an_object", "body is not an object", status.HTTP_400_BAD_REQUEST)

        did = envelope.get("did")
        sig = envelope.get("sig")
        nonce = envelope.get("nonce")
        job = envelope.get("job")
        if not all(isinstance(v, str) for v in (did, sig, nonce)) or not isinstance(job, dict):
            return _problem(
                "malformed_envelope",
                'expected {"did":..,"sig":..,"nonce":..,"job":{..}}',
                status.HTTP_400_BAD_REQUEST,
            )
        assert isinstance(did, str) and isinstance(sig, str) and isinstance(nonce, str)

        try:
            verify_http_job(did, sig, nonce, job)
        except (HttpEnvelopeError, CanonicalJSONError) as exc:
            return _problem("bad_signature", str(exc), status.HTTP_401_UNAUTHORIZED)

        job_id = job.get("job_id")
        owner = node.ledger.job_requester(job_id) if isinstance(job_id, str) else None
        existing = node.ledger.get_receipt(job_id) if isinstance(job_id, str) else None
        if isinstance(job_id, str) and existing is not None and owner == did:
            # Idempotent: the same submission gets the same answer rather than the work
            # being done twice. Checked before the rate limit and before the nonce, so a
            # client that retries after a dropped response is not punished for it — an
            # answer that already exists costs nothing to hand over again.
            response.status_code = status.HTTP_200_OK
            return {
                "job_id": job_id,
                "status": "already_completed",
                "receipt": json.loads(existing["receipt_json"]),
                "receipt_url": f"{node.settings.public_url}/v1/receipts/{job_id}",
            }

        # A row of this requester's with no receipt is an attempt that died before it
        # could answer. Resuming it creates no new job, so it is not charged for one:
        # charging it here would refuse, at a low limit, the single request that exists
        # to recover an answer the requester already paid for.
        resuming = owner == did and existing is None
        if not resuming:
            # Otherwise, rate limit before the nonce is spent: a refused request should
            # not cost the caller a counter they then have to reason about.
            try:
                node.runner.check_rate_limit(did)
            except RejectedJob as exc:
                return _problem(exc.code, exc.detail, status.HTTP_429_TOO_MANY_REQUESTS)

        # Validate before the nonce is claimed. `parse_and_validate` is pure — it reads
        # nothing and writes nothing — so running it here and again inside `handle()` is
        # free, and it means a job refused by the schema leaves the caller's counter where
        # it was. Execution still happens strictly after the claim, so a replay of a valid
        # request re-validates cheaply and then loses the claim, exactly as before.
        text = canonical_bytes(job).decode("utf-8")
        try:
            node.runner.parse_and_validate(text)
        except RejectedJob as exc:
            node.ledger.record_rejection(
                job_id=job_id if isinstance(job_id, str) else None,
                requester_did=did,
                code=exc.code,
                detail=exc.detail,
                request_room="http",
            )
            return _problem(exc.code, exc.detail, status.HTTP_400_BAD_REQUEST)

        if not node.ledger.claim_http_nonce(did, int(nonce)):
            return _problem(
                "nonce_not_advancing",
                "this nonce is not greater than the last one accepted from this key; "
                f"use something above {node.ledger.http_nonce_floor(did)}",
                status.HTTP_409_CONFLICT,
            )

        try:
            outcome = await node.runner.handle(
                text=text,
                requester_did=did,
                request_room="http",
                request_seq=None,
                internal_test=False,
            )
        except RejectedJob as exc:
            node.ledger.record_rejection(
                job_id=job_id if isinstance(job_id, str) else None,
                requester_did=did,
                code=exc.code,
                detail=exc.detail,
                request_room="http",
            )
            return _problem(exc.code, exc.detail, status.HTTP_400_BAD_REQUEST)

        if outcome is None:
            # Already answered — by an earlier request, or by one that was still running
            # when this arrived and finished while it waited. Either way the answer
            # exists, and returning it is what idempotent means. The 409 below is for the
            # case where it somehow does not.
            answered = node.ledger.get_receipt(job_id) if isinstance(job_id, str) else None
            if answered is not None:
                return {
                    "job_id": job_id,
                    "status": "already_completed",
                    "receipt": json.loads(answered["receipt_json"]),
                    "receipt_url": f"{node.settings.public_url}/v1/receipts/{job_id}",
                }
            return _problem(
                "duplicate_job_id",
                "this job_id was already used; it is answered from the ledger",
                status.HTTP_409_CONFLICT,
            )

        receipt = outcome.receipt
        if receipt is not None and not outcome.internal_test:
            # Already persisted, atomically with the job's completion, inside `handle()`.
            # The auditable copy goes to the owned room, guarded there as everywhere else.
            #
            # Not for an internal test. The owned room is a public claim about work done
            # for other people, and on 2026-08-30 one of this node's own tests was
            # published there as third-party work because a lane forgot this check. The
            # mailbox lane has always had it; this one did not.
            await node.publish_audit_copy(outcome.job_id, receipt)

        log.info(
            "http job completed",
            extra={"fields": {"job_id": outcome.job_id, "latency_ms": outcome.latency_ms}},
        )
        return {
            "job_id": outcome.job_id,
            "status": outcome.result["status"],
            "result": outcome.result,
            "receipt": receipt,
            "receipt_url": f"{node.settings.public_url}/v1/receipts/{outcome.job_id}",
        }

    @router.get(
        "/v1/jobs/signing-payload",
        tags=["jobs"],
        summary="How to sign a submission, and this key's next nonce",
    )
    async def signing_payload(did: str) -> Any:
        """What to sign, and the floor a nonce must clear. Costs the caller nothing.

        Published because the alternative is every client rediscovering the payload shape
        by trial and error against a 401, and a caller who guesses wrong learns nothing
        from the failure.
        """
        floor = node.ledger.http_nonce_floor(did) if did else 0
        return {
            "payload_template": http_job_payload("<did>", "<nonce>", {}).replace(
                "sha256:" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "sha256:<hex of the RFC 8785 canonical form of your job object>",
            ),
            "algorithm": "Ed25519, signature as 86 unpadded base64url characters",
            "canonicalisation": "RFC 8785 over the `job` object exactly as submitted",
            "next_nonce_must_exceed": floor,
            "note": (
                "A signature made for the Technocore room lane will not verify here, and "
                "one made here cannot be posted into a room. That is deliberate."
            ),
        }
