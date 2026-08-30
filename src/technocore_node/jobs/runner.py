"""The job lifecycle: JOB → VALIDATED → CLAIM → EXECUTE → RESULT → RECEIPT → CONFIRMED.

Every stage is a gate, and the order is chosen so the cheapest refusal happens first: a
malformed line costs a JSON parse, a bad DID costs a regex, and only a request that has
passed all of those reaches a task. Nothing runs before the request has been recorded, so
a crash mid-job leaves a job row in a known state rather than silent work that nobody can
account for.

The one rule this module exists to enforce: **a message is data.** The text arriving in
the mailbox is a stranger's, its signature proves possession of a key and nothing more,
and no field in it is ever treated as an instruction. `task` selects from a compiled-in
registry; it never names code.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jsonschema
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .. import __version__
from ..crypto import didkey
from ..ledger.db import Ledger, utcnow
from ..logging import get_logger
from ..protocol.canonical import CanonicalJSONError, canonicalize, parse_strict
from ..protocol.sweep import room_classes
from ..receipts.receipt import build_receipt, canonical_hash, sign_result
from . import schema as job_schema
from .tasks import REGISTRY, TaskContext, TaskError

log = get_logger(__name__)

_JOB_VALIDATOR = jsonschema.Draft202012Validator(job_schema.JOB_SCHEMA)
_INPUT_VALIDATORS = {
    name: jsonschema.Draft202012Validator(spec)
    for name, spec in job_schema.TASK_INPUT_SCHEMAS.items()
}


class RejectedJob(Exception):
    """The request will not be processed. `code` is what gets recorded and reported."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail[:200]


@dataclass(frozen=True, slots=True)
class Outcome:
    """What the runner produced for one request, ready for the poster to publish."""

    job_id: str
    claim: dict[str, Any]
    result: dict[str, Any]
    receipt: dict[str, Any] | None
    reply_room: str
    internal_test: bool
    latency_ms: int


class JobRunner:
    """Validates, executes and records jobs. Publishing is somebody else's problem.

    Keeping the transport out of here is what makes the pipeline testable without a
    network, and what keeps a task from ever reaching one.
    """

    def __init__(
        self,
        ledger: Ledger,
        identity_did: str,
        private_key: Ed25519PrivateKey,
        context: TaskContext,
        *,
        max_concurrent: int = 2,
        timeout_seconds: int = 15,
        requester_jobs_per_hour: int = 60,
        source_commit: str = "",
    ) -> None:
        self.ledger = ledger
        self.did = identity_did
        self._key = private_key
        self.context = context
        self.timeout_seconds = timeout_seconds
        self.requester_jobs_per_hour = requester_jobs_per_hour
        self.source_commit = source_commit[:40]
        self._semaphore = asyncio.Semaphore(max_concurrent)
        #: The running attempt for each `job_id`, as `(requester, task)`, so a second
        #: submission of one id joins the first rather than starting beside it — and only
        #: if it is the same requester. The DID is held here because the ownership check
        #: lives inside `_run`, which a joining caller never enters: keyed on `job_id`
        #: alone, a stranger who guessed an in-flight id was handed somebody else's
        #: result, receipt, reply room and DID.
        #:
        #: A lock was not enough. A job whose row exists but whose receipt does not is
        #: resumable (see `handle`), and the work runs in a worker thread that no
        #: cancellation can stop: a client that disconnected mid-job released the lock
        #: while its thread carried on, and the retry then started a second one. Holding
        #: the *task* and awaiting it through a shield means the disconnect abandons the
        #: waiting, never the work — and the entry is dropped by the task's own callback,
        #: when it has actually finished.
        self._in_flight: dict[str, tuple[str, asyncio.Task[Outcome | None]]] = {}

    # ------------------------------------------------------------- validation

    def parse_and_validate(self, text: str) -> dict[str, Any]:
        """Turn one mailbox line into a validated job object, or raise :class:`RejectedJob`."""
        if len(text) > job_schema.MAX_INPUT_CHARS + 600:
            raise RejectedJob("request_too_large", f"{len(text)} characters")
        try:
            job = parse_strict(text)
        except json.JSONDecodeError:
            raise RejectedJob("not_json") from None
        except CanonicalJSONError as exc:
            # Duplicate keys, NaN, Infinity: parseable by Python, but not documents with
            # one meaning. A hash over them would not be evidence of anything.
            raise RejectedJob("not_canonical_json", str(exc)) from None
        if not isinstance(job, dict):
            raise RejectedJob("not_an_object")

        errors = sorted(_JOB_VALIDATOR.iter_errors(job), key=lambda e: list(e.path))
        if errors:
            first = errors[0]
            path = "/".join(str(p) for p in first.path) or "(root)"
            raise RejectedJob("schema_invalid", f"{path}: {first.message}")

        reply_room = str(job["reply_room"])
        if not _is_repliable(reply_room):
            # `reply_room` is a stranger's string, and this node writes three messages
            # into it. Left open, a request naming `lobby` turns the node into a spam
            # reflector aimed at a shared room; left half-open, one naming somebody
            # else's mailbox aims it at a specific victim instead. Only a room whose name
            # is itself evidence the requester holds it will do.
            raise RejectedJob(
                "reply_room_not_allowed",
                "reply_room must be an unlisted room whose name you chose — p-<random> "
                "or mb-p-<random>. A plain mb- room proves only that its writers are "
                "signed, not that you hold it.",
            )

        task = str(job["task"])
        if task not in REGISTRY:
            # Unreachable via the schema's enum; kept as an independent second gate so a
            # future schema edit cannot widen the executable surface by itself.
            raise RejectedJob("unknown_task", task)

        payload = job.get("input", {})
        if not isinstance(payload, dict):
            raise RejectedJob("schema_invalid", "input must be an object")
        try:
            canonical_input = canonicalize(payload)
        except CanonicalJSONError as exc:
            # An unpaired surrogate reaches here: json.loads accepts it and the schema is
            # happy, but it is not UTF-8 and so has no canonical form. Left uncaught it
            # surfaced much later as an unhandled UnicodeEncodeError, which meant no
            # refusal record, no signed answer, and no rate-limit accounting.
            raise RejectedJob("input_not_canonical", str(exc)) from None
        if len(canonical_input) > job_schema.MAX_INPUT_CHARS:
            raise RejectedJob("input_too_large", f"limit {job_schema.MAX_INPUT_CHARS} characters")

        validator = _INPUT_VALIDATORS.get(task)
        if validator is not None:
            input_errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.path))
            if input_errors:
                first = input_errors[0]
                path = "/".join(str(p) for p in first.path) or "input"
                raise RejectedJob("input_invalid", f"{path}: {first.message}")

        return job

    def check_rate_limit(self, requester_did: str) -> None:
        since = (
            (datetime.now(UTC) - timedelta(hours=1))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
        used = self.ledger.requester_job_count_since(requester_did, since)
        if used >= self.requester_jobs_per_hour:
            raise RejectedJob("rate_limited", f"{used} jobs in the last hour")

    # ------------------------------------------------------------- execution

    async def handle(
        self,
        *,
        text: str,
        requester_did: str,
        request_room: str,
        request_seq: int | None,
        internal_test: bool = False,
    ) -> Outcome | None:
        """Run one inbound mailbox line all the way to a signed receipt.

        Returns None when the request is a duplicate that was already answered — the
        idempotency contract: the same `job_id` is never executed twice, whatever it says.
        """
        started = datetime.now(UTC)

        if not didkey.is_did(requester_did):
            raise RejectedJob("unsigned_or_unverified_sender", "sender is not a did:key")

        job = self.parse_and_validate(text)
        job_id = str(job["job_id"])
        reply_room = str(job["reply_room"])
        task = str(job["task"])

        entry = self._in_flight.get(job_id)
        if entry is not None and entry[0] != requester_did:
            # The same refusal `_run` would give, given here because the joining caller
            # never reaches it. `job_id` is globally unique and public; without this, one
            # requester's in-flight work is readable by anyone who guesses its id.
            raise RejectedJob(
                "job_id_taken",
                "another requester already used this job_id; choose one with a random component",
            )
        running = entry[1] if entry is not None else None
        if running is None:
            running = asyncio.create_task(
                self._run(
                    job=job,
                    job_id=job_id,
                    reply_room=reply_room,
                    task=task,
                    requester_did=requester_did,
                    request_room=request_room,
                    request_seq=request_seq,
                    internal_test=internal_test,
                    started=started,
                )
            )
            self._in_flight[job_id] = (requester_did, running)
            running.add_done_callback(lambda done: self._retire(job_id, done))
        # Shielded: cancelling the caller must not cancel work that is already underway,
        # because the thread running it would not stop anyway and the receipt is owed
        # either way. The task carries its own timeout.
        return await asyncio.shield(running)

    def _retire(self, job_id: str, done: asyncio.Task[Outcome | None]) -> None:
        """Drop a finished attempt, and consume its exception so the loop does not shout.

        Every caller that was awaiting it has already seen the exception through the
        shield; a task nobody is left waiting on — the disconnected client — would
        otherwise be reported as never retrieved.
        """
        self._in_flight.pop(job_id, None)
        if not done.cancelled():
            done.exception()

    async def _run(
        self,
        *,
        job: dict[str, Any],
        job_id: str,
        reply_room: str,
        task: str,
        requester_did: str,
        request_room: str,
        request_seq: int | None,
        internal_test: bool,
        started: datetime,
    ) -> Outcome | None:
        if not internal_test and self.ledger.take_expected_internal_test(requester_did, job_id):
            # Declared as this node's own before it was sent. Decided here, once, after
            # the job_id is known — not by whichever caller happens to run it, which is
            # what let a self-test be published as third-party use.
            internal_test = True

        resuming = False
        owner = self.ledger.job_requester(job_id)
        if owner == requester_did:
            # A row already exists, so the classification was settled when it was made.
            # Re-deriving it would depend on a declaration this run has already consumed,
            # and a resumed job would come back as somebody else's.
            existing_row = self.ledger.get_job(job_id)
            if existing_row is not None:
                internal_test = bool(existing_row["internal_test"])
        if owner is not None:
            if owner != requester_did:
                # `job_id` is globally unique because it is also the public receipt
                # identifier. Silently dropping this would let anyone erase another
                # agent's job by guessing its id first — no execution, no reply, no
                # record. It is refused loudly instead, and the refusal is readable.
                raise RejectedJob(
                    "job_id_taken",
                    "another requester already used this job_id; choose one with a "
                    "random component",
                )
            if self.ledger.get_receipt(job_id) is not None:
                log.info(
                    "duplicate job ignored",
                    extra={
                        "fields": {"job_id": job_id, "requester": didkey.abbreviate(requester_did)}
                    },
                )
                return None
            # The row exists and the receipt does not: a previous attempt died between
            # inserting the job and writing its answer. "Already seen" is not "already
            # answered", and treating it as such spent the caller's `job_id` on work they
            # can never be shown. The tasks are pure and the row is already theirs, so
            # this resumes rather than refusing.
            log.warning(
                "resuming a job whose previous attempt left no receipt",
                extra={"fields": {"job_id": job_id, "requester": didkey.abbreviate(requester_did)}},
            )
            resuming = True

        if not resuming:
            # The rate limit counts jobs, and this job is already counted — its row is
            # what the counter is reading. Charging again would let the limit refuse the
            # one retry that exists to recover an answer the requester already paid for,
            # and at a low limit that refusal lasts until the window rolls over.
            self.check_rate_limit(requester_did)

        request_hash = canonical_hash(job)
        inserted = self.ledger.insert_job(
            job_id=job_id,
            protocol_version=str(job["v"]),
            requester_did=requester_did,
            provider_did=self.did,
            request_room=request_room,
            reply_room=reply_room,
            request_seq=request_seq,
            request_hash=request_hash,
            task_type=task,
            status="validated",
            internal_test=internal_test,
        )
        if not inserted:
            # Either the row is ours from an attempt that died — the resume path above —
            # or we lost the insert race. Two different requesters can both pass the
            # check above before either has written, and the loser must still be told
            # rather than dropped, otherwise the whole squatting problem survives inside
            # the race window.
            winner = self.ledger.job_requester(job_id)
            if winner is not None and winner != requester_did:
                raise RejectedJob(
                    "job_id_taken",
                    "another requester already used this job_id; choose one with a "
                    "random component",
                )
            if winner == requester_did and self.ledger.get_receipt(job_id) is not None:
                return None

        claim = {
            "v": job_schema.PROTOCOL_VERSION,
            "type": "claim",
            "job_id": job_id,
            "provider_did": self.did,
            "request_hash": request_hash,
            "accepted_at": utcnow(),
            "max_processing_ms": self.timeout_seconds * 1000,
        }
        self.ledger.update_job(job_id, status="claimed", claimed_at=utcnow())

        status = "ok"
        summary: dict[str, Any] = {}
        error_message = ""
        failure_code: str | None = None

        try:
            async with self._semaphore:
                summary = await asyncio.wait_for(
                    asyncio.to_thread(REGISTRY[task], job.get("input", {}), self.context),
                    timeout=self.timeout_seconds,
                )
        except TimeoutError:
            status, failure_code, error_message = "error", "task_timeout", "task exceeded its limit"
        except TaskError as exc:
            status, failure_code, error_message = "error", "task_rejected", str(exc)[:200]
        except Exception as exc:
            # A task fault becomes a signed error result, never an unhandled crash: the
            # requester is owed an answer either way, and the poller has to survive.
            status, failure_code, error_message = "error", "task_failed", type(exc).__name__
            log.exception("task raised", extra={"fields": {"job_id": job_id, "task": task}})

        latency_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)

        result: dict[str, Any] = {
            "v": job_schema.PROTOCOL_VERSION,
            "type": "result",
            "job_id": job_id,
            "task": task,
            "requester_did": requester_did,
            "provider_did": self.did,
            "request_hash": request_hash,
            "status": status,
            "completed_at": utcnow(),
            "impl_version": __version__,
        }
        if self.source_commit:
            result["source_commit"] = self.source_commit
        if status == "ok":
            result["summary"] = summary
        else:
            result["error"] = error_message or failure_code or "error"

        try:
            result["result_hash"] = canonical_hash(
                summary if status == "ok" else {"error": error_message}
            )
        except CanonicalJSONError as exc:
            # A task returned something that cannot be canonicalised. The requester is
            # still owed a signed answer, so the result degrades to an error rather than
            # taking the pipeline down with it.
            status, failure_code = "error", "result_not_canonical"
            summary = {}
            result.pop("summary", None)
            result["status"] = "error"
            result["error"] = f"result_not_canonical: {exc}"[:200]
            result["result_hash"] = canonical_hash({"error": "result_not_canonical"})
        result["sig"] = sign_result(self._key, result)

        self.ledger.record_result(
            job_id=job_id,
            result_hash=result["result_hash"],
            status=status,
            summary_bytes=len(json.dumps(summary, ensure_ascii=True).encode("utf-8")),
            provider_signature=result["sig"],
            result_seq=None,
        )
        receipt = build_receipt(
            self._key,
            receipt_id=f"rcpt-{secrets.token_hex(12)}",
            job_id=job_id,
            requester_did=requester_did,
            provider_did=self.did,
            request_room=request_room,
            reply_room=reply_room,
            request_hash_value=request_hash,
            result_hash_value=result["result_hash"],
            provider_signature=result["sig"],
            request_seq=request_seq,
            internal_test=internal_test,
        )

        # One transaction, because marking the job finished and holding its receipt are
        # one fact. Split across two writes, a crash in between leaves a job whose
        # duplicate check refuses every retry and whose receipt does not exist: the work
        # done and unprovable, with the `job_id` spent. Done here rather than in each
        # caller so both intake lanes get it, and a third cannot forget to.
        self.ledger.record_receipt(
            receipt,
            json.dumps(receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True),
            internal_test,
            complete_job={
                "status": "completed" if status == "ok" else "failed",
                "completed_at": utcnow() if status == "ok" else None,
                "failed_at": None if status == "ok" else utcnow(),
                "latency_ms": latency_ms,
                "failure_code": failure_code,
            },
        )

        return Outcome(
            job_id=job_id,
            claim=claim,
            result=result,
            receipt=receipt,
            reply_room=reply_room,
            internal_test=internal_test,
            latency_ms=latency_ms,
        )


def _is_repliable(room: str) -> bool:
    """True only for a room whose name is itself evidence the requester holds it.

    The first version of this allowed any `mb-` room, on the reasoning that a mailbox
    takes signed writes only. That was the wrong reading: `mb-` says every writer is
    attributable, not that *this* requester owns the room. A stranger could name somebody
    else's public mailbox and have this node post three messages into it — a narrower
    reflector than aiming at `lobby`, and aimed at a specific victim.

    The `p-` class is the one that carries evidence. An unlisted room is never enumerated,
    so its name is a capability: knowing it is how the upstream models being handed access
    to it. `p-`, `mb-p-` and `e-p-` all qualify; a plain `mb-` room no longer does.
    """
    return "p-" in room_classes(room)
