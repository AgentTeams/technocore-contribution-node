"""The node: identity, ledger, client, runner, and the mailbox loop that drives them.

The mailbox loop is the only place inbound work enters. It long-polls the node's public
mailbox, hands each new line to the runner, and publishes what comes back. Two properties
matter more than anything else here:

* **Nothing read from a room is ever executed or resolved.** A line is JSON to be
  validated, and its fields select from compiled-in tables. There is no path from a
  message to a shell, an import, an eval, or an outbound request to a named host.
* **A failure in one message never stops the loop.** Every iteration is wrapped, the
  cursor only advances past a message once it has been accounted for, and a crash resumes
  from the stored cursor rather than replaying the room.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx2 as httpx
import jsonschema

from ..config import Settings
from ..crypto import didkey
from ..crypto.keystore import Identity, load
from ..jobs.runner import JobRunner, RejectedJob
from ..jobs.schema import RECEIPT_SCHEMA
from ..ledger.db import Ledger, utcnow
from ..logging import get_logger
from ..protocol.client import (
    DuplicateRefused,
    NonceAllocator,
    RateLimited,
    TechnocoreClient,
    TechnocoreError,
)
from ..protocol.sweep import MAX_TEXT_CHARS
from .rooms import mailbox_room, result_room
from .watcher import ProtocolWatcher

log = get_logger(__name__)

_RECEIPT_VALIDATOR = jsonschema.Draft202012Validator(RECEIPT_SCHEMA)


class NodeContext:
    """The narrow surface a task is allowed to reach — see `jobs.tasks.TaskContext`."""

    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger

    def latest_protocol_snapshot(self) -> dict[str, Any] | None:
        row = self._ledger.latest_snapshot()
        if row is None:
            return None
        return {
            "captured_at": row["captured_at"],
            "source": row["source"],
            "aggregate_sha256": row["sha256"],
            "source_hashes": json.loads(row["per_source_json"]),
            "upstream_commit": row["upstream_commit"],
            "service_version": row["service_version"],
            "limits": json.loads(row["limits_json"]) if row["limits_json"] else None,
            "compatibility_status": row["compatibility_status"],
            "changed_from_previous": bool(row["changed_from_prev"]),
            "diff_summary": row["diff_summary"],
        }

    def receipt_chain_for(self, job_id: str) -> list[dict[str, Any]]:
        row = self._ledger.get_receipt(job_id)
        if row is None:
            return []
        parsed: dict[str, Any] = json.loads(row["receipt_json"])
        return [parsed]


class Node:
    """Everything the service needs, assembled once at startup."""

    def __init__(
        self, settings: Settings, *, identity: Identity | None = None, ledger: Ledger | None = None
    ) -> None:
        self.settings = settings
        self.ledger = ledger or Ledger(settings.db_path)
        self.identity = identity or load(settings.identity_path, settings.passphrase())
        self.did = self.identity.did
        self.fingerprint = self.identity.fingerprint
        self.mailbox = mailbox_room(self.did)
        self.result_room = result_room(self.did)
        self.context = NodeContext(self.ledger)
        self.started_at = utcnow()
        self._tasks: list[asyncio.Task[None]] = []

        self.ledger.record_identity(
            self.did, self.fingerprint, self.identity.public_key_hash, label="production"
        )

        self.nonces = NonceAllocator(floor_lookup=self.ledger.last_nonce)
        self.client = TechnocoreClient(
            settings.origin,
            private_key=self.identity.private_key,
            did=self.did,
            nonces=self.nonces,
        )
        self.runner = JobRunner(
            self.ledger,
            self.did,
            self.identity.private_key,
            self.context,
            max_concurrent=settings.max_concurrent_jobs,
            timeout_seconds=settings.job_timeout_seconds,
            requester_jobs_per_hour=settings.requester_jobs_per_hour,
            source_commit=_source_commit(),
        )
        self.watcher = ProtocolWatcher(self.ledger, settings.origin)

    async def aclose(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                # Shutdown is not the place to surface a loop's last error, but it is
                # the place to record it: a task that died on the way out would
                # otherwise vanish silently.
                log.exception("background task ended with an error")
        self._tasks.clear()
        await self.client.aclose()

    # ------------------------------------------------------------ publication

    async def publish(self, room: str, obj: dict[str, Any]) -> int | None:
        """Post one protocol object as a single compact line, and record the outcome.

        `ensure_ascii=True` is not cosmetic: it guarantees the payload is already stable
        under the server's single-line sweep, so the bytes signed and the bytes stored are
        the same bytes with no round-trip surprise.
        """
        text = json.dumps(obj, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        if len(text) > MAX_TEXT_CHARS:
            log.error(
                "refusing to publish an oversized message",
                extra={"fields": {"room": room, "chars": len(text), "type": obj.get("type")}},
            )
            return None
        try:
            confirmation = await self.client.say_signed(room, text)
        except (RateLimited, DuplicateRefused, TechnocoreError) as exc:
            # Keep the server's own words. When the reason a receipt cannot be published
            # is upstream capacity, that sentence is the most useful thing this node can
            # hand a reader asking whether it works — and it is observed rather than
            # typed into a README.
            if room in (self.result_room, self.mailbox):
                self.ledger.set_state(f"last_publish_error:{room}", str(exc)[:300])
            self.ledger.record_message(
                local_event_id=f"out-{obj.get('type')}-{obj.get('job_id', '')}-{utcnow()}",
                direction="out",
                room=room,
                did=self.did,
                normalized_text_sha256=_sha(text),
                status="failed",
                error_code=type(exc).__name__,
            )
            log.warning(
                "publish failed",
                extra={
                    "fields": {"room": room, "type": obj.get("type"), "error": type(exc).__name__}
                },
            )
            return None

        if room in (self.result_room, self.mailbox):
            self.ledger.set_state(f"last_publish_error:{room}", None)
        self.ledger.record_message(
            local_event_id=f"out-{room}-{confirmation.nonce}",
            direction="out",
            room=room,
            did=self.did,
            nonce=confirmation.nonce,
            normalized_text_sha256=_sha(confirmation.text),
            signature=confirmation.sig,
            technocore_seq=confirmation.seq,
            technocore_ts=confirmation.ts,
            status="confirmed",
            confirmed_at=utcnow(),
        )
        return confirmation.seq

    # ------------------------------------------------------------ mailbox loop

    async def process_message(
        self, message: dict[str, Any], *, internal_test: bool = False
    ) -> None:
        """Handle one inbound mailbox line, start to finish."""
        sender = str(message.get("from", ""))
        text = str(message.get("text", ""))
        seq = int(message.get("seq", 0))

        if not didkey.is_did(sender):
            # The server refuses unsigned writes to an `mb-` room, so this is belt and
            # braces — but a gate that only holds because something else holds is not a
            # gate, and this node must never attribute work to a nickname.
            self.ledger.record_rejection(
                job_id=None,
                requester_did=None,
                code="unsigned_sender",
                detail="mailbox line was not signed",
                request_room=self.mailbox,
            )
            return

        self.ledger.record_message(
            local_event_id=f"in-{self.mailbox}-{seq}",
            direction="in",
            room=self.mailbox,
            did=sender,
            nonce=message.get("nonce"),
            normalized_text_sha256=_sha(text),
            technocore_seq=seq,
            technocore_ts=str(message.get("ts", "")),
            status="received",
        )

        try:
            outcome = await self.runner.handle(
                text=text,
                requester_did=sender,
                request_room=self.mailbox,
                request_seq=seq,
                internal_test=internal_test,
            )
        except RejectedJob as exc:
            job_id = _peek_job_id(text)
            self.ledger.record_rejection(
                job_id=job_id,
                requester_did=sender,
                code=exc.code,
                detail=exc.detail,
                request_room=self.mailbox,
            )
            log.info(
                "job rejected",
                extra={
                    "fields": {
                        "code": exc.code,
                        "requester": didkey.abbreviate(sender),
                        "job_id": job_id,
                    }
                },
            )
            return

        if outcome is None:
            return

        receipt = outcome.receipt
        receipt_json = ""
        if receipt is not None:
            # Recorded before anything is announced. A crash after this point costs an
            # unannounced copy, which the row says is owed; a crash before it, with the
            # job already marked complete, would lose the receipt entirely — the
            # duplicate check would suppress every retry.
            receipt_json = json.dumps(
                receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            )
            self.ledger.record_receipt(receipt, receipt_json, outcome.internal_test)

        await self.publish(outcome.reply_room, outcome.claim)
        result_seq = await self.publish(outcome.reply_room, outcome.result)
        if result_seq is not None:
            summary_json = json.dumps(outcome.result.get("summary", {}), ensure_ascii=True)
            self.ledger.record_result(
                job_id=outcome.job_id,
                result_hash=outcome.result["result_hash"],
                status=str(outcome.result["status"]),
                summary_bytes=len(summary_json.encode("utf-8")),
                provider_signature=outcome.result["sig"],
                result_seq=result_seq,
            )

        if receipt is not None:
            reply_seq = await self.publish(outcome.reply_room, receipt)
            if reply_seq is not None:
                self.ledger.record_receipt_reply_seq(outcome.job_id, reply_seq)

            # The auditable copy goes to the room only this node's key can write to. It
            # is owed rather than best-effort: if it does not land now, the row stays
            # `owed` and the reconciler keeps trying.
            #
            # Internal tests are excluded: the owned room is a public claim about work
            # done for other agents, and this node's own tests are not that.
            if not outcome.internal_test:
                await self.publish_audit_copy(outcome.job_id, receipt)

        log.info(
            "job completed",
            extra={
                "fields": {
                    "job_id": outcome.job_id,
                    "latency_ms": outcome.latency_ms,
                    "internal_test": outcome.internal_test,
                }
            },
        )

    #: Attempts before a receipt is taken out of the retry queue.
    MAX_AUDIT_ATTEMPTS = 5

    async def publish_audit_copy(self, job_id: str, receipt: dict[str, Any]) -> int | None:
        """Publish one receipt to the owned room and record the outcome."""
        seq = await self.publish(self.result_room, receipt)
        if seq is not None:
            self.ledger.set_audit_seq(job_id, seq)
            return seq
        quarantined = self.ledger.note_audit_attempt(
            job_id, "publish to the owned room failed", self.MAX_AUDIT_ATTEMPTS
        )
        log.warning(
            "receipt not yet publicly auditable",
            extra={"fields": {"job_id": job_id, "quarantined": quarantined}},
        )
        return None

    async def observe_reachability(self) -> None:
        """Record, read-only, what this node can currently observe about its own reach.

        One note read. It answers the question every visitor actually has — can I send
        this thing a job? — from evidence rather than from an operator's memory, and it
        corrects itself the moment the upstream situation changes.
        """
        try:
            owner = await self.client.room_owner(self.result_room)
        except (TechnocoreError, httpx.HTTPError) as exc:
            # Record that the check failed, and leave the last real observation alone.
            # Writing None here would have been indistinguishable from having read the
            # room and found no owner — turning "I could not look" into "there is nobody
            # there", which is the exact substitution this release exists to stop.
            self.ledger.set_state("owned_room_error", str(exc)[:300])
            return
        self.ledger.set_state("owned_room_owner", owner)
        self.ledger.set_state("owned_room_observed", "1")
        self.ledger.set_state("owned_room_error", None)

    async def sync_owned_room(self) -> int:
        """Read the owned room and mark every receipt already there as published.

        The room is the authority on what is in it, so it is consulted before anything is
        written to it again. This is what makes retrying safe after a crash between the
        publish and the record, and what stops a database migrated from an older build
        from re-announcing receipts it published long ago.
        """
        since = self.ledger.cursor(self.result_room)
        try:
            data = await self.client.read_room(self.result_room, since=since)
        except TechnocoreError:
            # The owned room may not exist yet, or the upstream may be refusing reads.
            # Neither is a reason to fail a job; the next pass tries again.
            return 0

        first_seq = data.get("first_seq")
        if since and first_seq is not None and int(first_seq) > since + 1:
            # The room is a ring and it dropped messages we never read. Anything lost is
            # genuinely no longer in the room, so republishing it restores the audit
            # record rather than duplicating it — but an operator should know the gap
            # happened, because it means the room is turning over faster than we read it.
            log.warning(
                "owned room dropped messages before they were read",
                extra={
                    "fields": {
                        "room": self.result_room,
                        "since": since,
                        "first_seq": int(first_seq),
                    }
                },
            )

        observed: dict[str, tuple[int, str]] = {}
        for message in data.get("messages", []):
            if message.get("from") != self.did:
                continue
            try:
                published = json.loads(str(message.get("text", "")))
            except json.JSONDecodeError:
                continue
            if not isinstance(published, dict) or published.get("type") != "receipt":
                continue
            job_id = published.get("job_id")
            receipt_hash = published.get("receipt_hash")
            # Both, and matched against the stored row: the job_id alone would let any
            # message carrying that id mark a different receipt publicly auditable.
            if isinstance(job_id, str) and isinstance(receipt_hash, str):
                observed[job_id] = (int(message.get("seq", 0)), receipt_hash)

        marked = self.ledger.mark_published(observed)
        last_seq = data.get("last_seq")
        if last_seq is not None:
            self.ledger.set_cursor(self.result_room, int(last_seq))
        return marked

    async def reconcile_audit_copies(self, limit: int = 3) -> int:
        """Publish owed owned-room copies, a few at a time. Returns how many landed.

        Bounded so that a backlog after an outage cannot become a write storm the moment
        the node recovers, and preceded by a room sync so a copy that did land during a
        crash is recognised rather than posted twice.
        """
        await self.sync_owned_room()

        landed = 0
        for row in self.ledger.receipts_awaiting_audit_copy(limit):
            job_id = str(row["job_id"])
            problem = _unpublishable(row["receipt_json"], job_id, str(row["receipt_hash"]))
            if problem is not None:
                # No number of retries fixes a stored row that is not a receipt, so it
                # leaves the queue now rather than occupying a slot in it forever — or,
                # worse, being posted into the audit room as whatever it actually is.
                self.ledger.quarantine_receipt(job_id, problem)
                log.error(
                    "quarantined an unpublishable receipt",
                    extra={"fields": {"job_id": job_id, "problem": problem}},
                )
                continue
            receipt = json.loads(row["receipt_json"])
            if await self.publish_audit_copy(job_id, receipt) is not None:
                landed += 1
        return landed

    async def poll_mailbox_once(self, *, wait: int = 10) -> int:
        """One long-poll cycle. Returns how many messages were processed."""
        since = self.ledger.cursor(self.mailbox)
        data = await self.client.read_room(self.mailbox, since=since, wait=wait)
        messages = data.get("messages", [])
        for message in messages:
            try:
                await self.process_message(message)
            except Exception:
                # One malformed or hostile message must never end the loop.
                log.exception(
                    "message handling failed", extra={"fields": {"seq": message.get("seq")}}
                )
            finally:
                self.ledger.set_cursor(self.mailbox, int(message.get("seq", since)))
        if not messages and data.get("last_seq") is not None:
            self.ledger.set_cursor(self.mailbox, int(data["last_seq"]))
        return len(messages)

    async def run_mailbox(self) -> None:
        backoff = 1.0
        while True:
            try:
                await self.poll_mailbox_once()
                await self.reconcile_audit_copies()
                await self.observe_reachability()
                backoff = 1.0
            except RateLimited as exc:
                log.warning(
                    "mailbox poll rate limited",
                    extra={"fields": {"retry_after_s": exc.retry_after}},
                )
                await asyncio.sleep(exc.retry_after)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("mailbox poll failed")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)

    def availability(self) -> dict[str, Any]:
        """What this node can honestly say about being reachable, and on what evidence.

        Every field is observed or counted, never asserted. `intake` is `available` only
        when a third party has actually completed a job here — the one piece of evidence
        that cannot be produced by wishing.
        """
        owner, owner_at = self.ledger.get_state("owned_room_owner")
        observed, _ = self.ledger.get_state("owned_room_observed")
        owner_err, owner_err_at = self.ledger.get_state("owned_room_error")
        result_err, _ = self.ledger.get_state(f"last_publish_error:{self.result_room}")
        metrics = self.ledger.metrics()
        audit = self.ledger.audit_backlog()

        completed = int(metrics["completed_jobs"])
        blockers: list[str] = []
        if owner_err:
            # Not knowing is its own state, and it is still a reason not to claim to be
            # reachable — but it is reported as not knowing.
            blockers.append(f"this node could not verify who owns its result room: {owner_err}")
        elif observed and owner is None:
            blockers.append(
                "this node's owned result room has no owner note, so receipts cannot be "
                "published where a third party could audit them"
            )
        elif observed and owner != self.did:
            # Stronger than being unowned, not weaker. An unclaimed room can still be
            # claimed; one held by another key never will be, and the whole value of that
            # room is that only this node can write to it. A receipt published there by
            # somebody else's key is not an audit record of anything.
            blockers.append(
                "this node's owned result room is held by a different key, so nothing it "
                "publishes there could serve as an audit record"
            )
        if result_err:
            blockers.append(f"last publish to the owned room was refused: {result_err}")
        if not self.settings.public_url:
            blockers.append("no public HTTPS endpoint is configured (no DNS record)")

        # Blockers are about now; a completed job is about the past. A node that once
        # served somebody and is unreachable today is unreachable today, so the current
        # facts decide and history only distinguishes "working" from "never tried".
        if blockers:
            intake = "unavailable"
        elif completed > 0:
            intake = "available"
        else:
            intake = "unverified"

        return {
            "third_party_intake": intake,
            "third_party_jobs_completed": completed,
            "blockers": blockers,
            "public_url": self.settings.public_url or None,
            "owned_result_room": {
                "room": self.result_room,
                # `null` here is ambiguous on its own, so it never stands alone:
                # `observed` says whether anyone has successfully looked.
                "observed": bool(observed),
                "owner": owner,
                "owned_by_this_node": bool(observed) and owner == self.did,
                "observed_at": owner_at,
                "read_error": owner_err,
                "read_error_at": owner_err_at if owner_err else None,
            },
            "receipts": {
                "publicly_auditable": audit["published"],
                "awaiting_public_copy": audit["owed"],
                "quarantined": audit["quarantined"],
            },
            "note": (
                "Observed, not asserted. `intake` reads `available` only once a third "
                "party has actually completed a job here."
            ),
        }

    def start_background(self) -> None:
        if self.settings.mailbox_enabled:
            self._tasks.append(asyncio.create_task(self.run_mailbox(), name="mailbox"))
        if self.settings.watcher_enabled:
            self._tasks.append(asyncio.create_task(self.watcher.run_forever(), name="watcher"))


def _unpublishable(receipt_json: Any, job_id: str, receipt_hash: str) -> str | None:
    """Why this stored row must not be published, or None if it is fine to publish.

    Checking only that the JSON parses was not enough: `{}`, `[]` and `"text"` all parse,
    and each would either be posted into the audit room as something that is not a
    receipt, or raise inside the publisher and stall the queue without ever counting as
    an attempt.
    """
    try:
        parsed = json.loads(str(receipt_json))
    except json.JSONDecodeError:
        return "stored receipt is not valid JSON"
    if not isinstance(parsed, dict):
        return f"stored receipt is a {type(parsed).__name__}, not an object"
    if parsed.get("type") != "receipt":
        return "stored value is not a receipt"
    if parsed.get("job_id") != job_id:
        return "stored receipt names a different job_id"
    if parsed.get("receipt_hash") != receipt_hash:
        return "stored receipt does not match its recorded hash"
    errors = list(_RECEIPT_VALIDATOR.iter_errors(parsed))
    if errors:
        return f"stored receipt fails its own schema: {errors[0].message}"[:200]
    return None


def _sha(text: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _peek_job_id(text: str) -> str | None:
    """Best-effort job_id from a request that failed validation, for the refusal record."""
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    candidate = parsed.get("job_id")
    return candidate if isinstance(candidate, str) and len(candidate) <= 64 else None


def _source_commit() -> str:
    """The commit this build came from, when the environment recorded one."""
    import os

    return os.environ.get("TCN_SOURCE_COMMIT", "")[:40]
