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
from datetime import UTC, datetime
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

#: Slack for ordinary clock jitter between writing an observation and reading it back.
#: Beyond this into the future, a timestamp is treated as unusable rather than recent.
_CLOCK_TOLERANCE_SECONDS = 60

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
        if room == self.result_room and not self.owns_result_room():
            # The guard lives at the sink, not only at the callers.
            #
            # It was at the callers first, and a review pointed out what that is worth:
            # `publish()` is public, and anything written later that reaches for the
            # result room bypasses every check made above it. A rule enforced at each
            # call site is a rule somebody will one day forget to apply — and here
            # forgetting it means writing into a room where anyone can forge a receipt
            # beside ours, or creating the room and foreclosing ever owning it.
            self.ledger.set_state(
                f"last_publish_error:{room}",
                "refused locally: this node has not confirmed it owns the result room",
            )
            log.warning(
                "refusing to write to the result room: ownership is not confirmed",
                extra={"fields": {"room": room, "type": obj.get("type")}},
            )
            return None

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
    ) -> bool:
        """Handle one inbound mailbox line, start to finish.

        Returns True when the message was dealt with — executed, refused, or recognised
        as a duplicate — and False when it was left untouched because the node is not in
        a safe state. The caller uses that to decide whether the cursor may move past it.
        """
        sender = str(message.get("from", ""))
        text = str(message.get("text", ""))
        seq = int(message.get("seq", 0))

        if not internal_test and not self.can_accept_third_party_jobs():
            # Checked here as well as in the poll loop. `process_message` is public and
            # is called directly by the self-test and by anything written later; a gate
            # that only exists at one call site protects only that call site.
            _, reasons = self.safety_state()
            log.warning(
                "refusing to process a third-party job: unsafe state",
                extra={"fields": {"seq": seq, "reasons": reasons}},
            )
            return False

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
            return True  # seen and refused on its own merits

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
            return True  # refused, recorded, and readable at /v1/receipts/<job_id>

        if outcome is None:
            return True  # a duplicate job_id: already answered, nothing left to do

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
        return True

    #: Attempts before a receipt is taken out of the retry queue.
    MAX_AUDIT_ATTEMPTS = 5

    async def publish_audit_copy(self, job_id: str, receipt: dict[str, Any]) -> int | None:
        """Publish one receipt to the owned room and record the outcome.

        Guarded on ownership independently of every other check. Writing an audit record
        into a room this node does not own does not merely fail to prove anything — it
        creates a room where a forgery sits beside a genuine receipt, indistinguishable
        to anyone reading it. Refusing is strictly better than publishing there.
        """
        if not self.owns_result_room():
            self.ledger.set_state(
                f"last_publish_error:{self.result_room}",
                "refused locally: this node has not confirmed it owns the result room",
            )
            log.warning(
                "refusing to publish an audit copy into a room this node does not own",
                extra={"fields": {"job_id": job_id, "room": self.result_room}},
            )
            return None

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

    async def inspect_result_room(self) -> dict[str, Any]:
        """Read the result room's state without writing anything. Read-only, always.

        Returns the two facts a recovery decision turns on — who owns it, and whether it
        holds any message — plus a verdict naming the one safe next step.
        """
        owner = await self.client.room_owner(self.result_room)
        data = await self.client.read_room(self.result_room, limit=1)
        count = int(data.get("count", 0))
        last_seq = int(data.get("last_seq", 0))
        exists = count > 0 or last_seq > 0

        if owner == self.did:
            verdict, action = "owned", "nothing to recover"
        elif owner is not None:
            verdict, action = "owned_by_other", "STOP: another key owns this name; pick another"
        elif exists:
            verdict, action = (
                "unclaimable",
                "WAIT: the room holds messages, and upstream allows a claim only from "
                "birth. Write nothing to it. A room still on its single message is "
                "reclaimed after 24 hours idle; then claim it before anything else.",
            )
        else:
            verdict, action = "claimable", "claim it now, before writing anything to it"

        return {
            "room": self.result_room,
            "owner": owner,
            "owned_by_this_node": owner == self.did,
            "message_count": count,
            "last_seq": last_seq,
            "exists": exists,
            "verdict": verdict,
            "next_action": action,
        }

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

        Gated on confirmed ownership, because reading is harmless but *believing* what is
        read is not. `mark_published()` turns a message in this room into the claim
        "publicly auditable", and that claim holds only if none but this node's key can
        write here. In an unowned room anyone can post a copy of a receipt lifted from the
        requester's reply room, and treating that as evidence would let a stranger decide
        what this node asserts about its own work.
        """
        if not self.owns_result_room():
            return 0

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
        """One long-poll cycle. Returns how many messages were processed.

        When the safety gate is closed the room is still read — knowing what is waiting is
        useful and costs a stranger nothing — but nothing is executed and **the cursor
        does not move**. Advancing it would be the quiet failure: the node would look
        healthy, the queue would look empty, and every job that arrived while it was
        unsafe would have been thrown away without the requester ever being told.
        Leaving the cursor still means the work is deferred rather than discarded — but
        deferred is not preserved. The mailbox is a ring, so a long enough closure ages
        unread messages out upstream, where no cursor can reach them. That gap is detected
        from `first_seq`, logged at `error` and recorded; it cannot be undone.
        """
        safe, reasons = self.safety_state()
        since = self.ledger.cursor(self.mailbox)
        data = await self.client.read_room(self.mailbox, since=since, wait=wait)
        messages = data.get("messages", [])

        first_seq = data.get("first_seq")
        if since and first_seq is not None and int(first_seq) > since + 1:
            # The mailbox is a ring. Holding the cursor defers work; it does not preserve
            # it, and pretending otherwise would be the same class of overclaim this
            # release exists to remove. If the room turned over faster than the node read
            # it, those messages are gone from upstream and no cursor can bring them back.
            log.error(
                "mailbox dropped messages before they were read",
                extra={
                    "fields": {
                        "room": self.mailbox,
                        "cursor": since,
                        "oldest_available": int(first_seq),
                        "lost": int(first_seq) - since - 1,
                    }
                },
            )
            self.ledger.set_state(
                "mailbox_gap",
                f"{int(first_seq) - since - 1} message(s) aged out unread before seq {first_seq}",
            )

        if not safe:
            if messages:
                log.warning(
                    "holding inbound jobs unprocessed: this node is not in a safe state",
                    extra={
                        "fields": {
                            "waiting": len(messages),
                            "cursor_held_at": since,
                            "reasons": reasons,
                        }
                    },
                )
            return 0

        for message in messages:
            handled = False
            try:
                handled = await self.process_message(message)
            except Exception:
                # One malformed or hostile message must never end the loop. It counts as
                # handled: it was seen, it failed on its own merits, and re-reading it
                # forever would wedge the queue behind one bad line.
                handled = True
                log.exception(
                    "message handling failed", extra={"fields": {"seq": message.get("seq")}}
                )
            if not handled:
                # The gate closed between the start of this cycle and this message —
                # ownership lapsed, the public URL went away, a ledger read failed.
                # Advancing now would drop a job nobody was ever told about, which is
                # the precise failure the cursor hold exists to prevent.
                log.warning(
                    "stopping this cycle with the cursor held: state became unsafe mid-poll",
                    extra={"fields": {"seq": message.get("seq"), "cursor_held_at": since}},
                )
                return 0
            self.ledger.set_cursor(self.mailbox, int(message.get("seq", since)))
        if not messages and data.get("last_seq") is not None:
            self.ledger.set_cursor(self.mailbox, int(data["last_seq"]))
        return len(messages)

    #: How often the ownership lease is renewed. The upstream deletes a note with no
    #: write for seven days, so this is set far below that: a renewal may fail on six
    #: consecutive days — an upstream outage, a rate limit, a restart — and the lease
    #: still holds. A cadence that only just fits leaves no room for the ordinary.
    OWNERSHIP_RENEWAL_SECONDS = 6 * 3600

    #: How soon to try again after a renewal fails, doubling up to the interval above.
    #: A fixed cadence waits longest exactly when waiting is worst: a node restarting on
    #: day six, whose first attempt meets a 503, would have slept past the expiry without
    #: trying again. The lease is renewed on a schedule; a failure is retried on a clock.
    OWNERSHIP_RETRY_FLOOR_SECONDS = 60

    #: What the upstream publishes as `retention_seconds`. Recorded so the cadence above
    #: can be checked against it rather than against a remembered number, and so the
    #: reported lease age means something to a reader who does not know the rule.
    UPSTREAM_NOTE_RETENTION_SECONDS = 7 * 24 * 3600

    async def maintain_result_room_ownership(self) -> str:
        """Renew, or recover, this node's claim on the result room. One cycle.

        Returns what it did, for the log and for the tests: `renewed`, `claimed`,
        `unclaimable`, `owned_by_other`, or `failed`.

        A claim is a lease. The upstream deletes any note with no write for seven days, so
        ownership that nothing renews expires — the room reverts to "an ordinary open
        room", and the first stranger to write to it makes it permanently unclaimable.
        Every guard elsewhere in this file checks whether the room *is* ours; none of them
        kept it that way.
        """
        try:
            owner = await self.client.room_owner(self.result_room)
        except TechnocoreError as exc:
            log.warning(
                "could not read result room ownership",
                extra={"fields": {"room": self.result_room, "error": str(exc)[:200]}},
            )
            return "failed"

        if owner == self.did:
            try:
                renewed = await self.client.refresh_room_ownership(self.result_room)
            except TechnocoreError as exc:
                log.warning(
                    "ownership renewal failed",
                    extra={"fields": {"room": self.result_room, "error": str(exc)[:200]}},
                )
                return "failed"
            if renewed:
                self.ledger.set_state("owned_room_renewed", utcnow())
                log.info("ownership lease renewed", extra={"fields": {"room": self.result_room}})
                return "renewed"
            return "failed"

        if owner is not None:
            # Somebody else's. Never touched, never contested — and loudly, because it
            # means every receipt this node holds is unpublishable and the operator needs
            # to know why rather than reading it off a gate that has quietly closed.
            log.error(
                "the result room is owned by another key",
                extra={"fields": {"room": self.result_room}},
            )
            return "owned_by_other"

        # Unowned. Claiming is the recovery, and it writes only to the ownership note —
        # never to the room, which is what made the room unclaimable the first time.
        # `claim_room` carries `if_absent`, so it refuses rather than overwrites if
        # somebody claimed it a moment ago.
        try:
            claimed = await self.client.claim_room(self.result_room)
        except TechnocoreError as exc:
            log.warning(
                "reclaim failed",
                extra={"fields": {"room": self.result_room, "error": str(exc)[:200]}},
            )
            return "failed"
        if claimed:
            # A claim is a successful write to the same note a renewal writes, so it
            # resets the same clock. Recording only renewals would leave the published
            # lease age reading `null` on a node that had just recovered the room.
            self.ledger.set_state("owned_room_renewed", utcnow())
            log.warning(
                "the ownership lease had lapsed and was reclaimed",
                extra={"fields": {"room": self.result_room}},
            )
            return "claimed"
        log.error(
            "the result room is unowned and can no longer be claimed",
            extra={"fields": {"room": self.result_room}},
        )
        return "unclaimable"

    async def run_ownership_lease(self) -> None:
        """Renew the lease forever, whatever else this node is or is not doing.

        Separate from the mailbox loop on purpose. Intake is switched off for months at a
        time — it is off in production as this is written — and the lease expires on the
        calendar regardless. Tying the renewal to the loop that reads jobs would mean the
        room is lost precisely while the node is being careful.
        """
        failures = 0
        while True:
            outcome = "failed"
            try:
                outcome = await self.maintain_result_room_ownership()
                await self.observe_reachability()
            except asyncio.CancelledError:
                raise
            except Exception:
                # This loop must outlive anything it touches. A renewal that raises is a
                # renewal to retry, not a reason to stop renewing.
                log.exception("ownership lease cycle failed", extra={"fields": {}})

            if outcome in ("renewed", "claimed"):
                failures = 0
                delay = self.OWNERSHIP_RENEWAL_SECONDS
            elif outcome == "failed":
                # Transient: an upstream 5xx, a rate limit, a contended nonce. Back off
                # from seconds rather than sleeping through the window.
                failures += 1
                delay = min(
                    self.OWNERSHIP_RETRY_FLOOR_SECONDS * 2 ** (failures - 1),
                    self.OWNERSHIP_RENEWAL_SECONDS,
                )
            else:
                # `owned_by_other` or `unclaimable`. Neither is fixed by asking again in a
                # minute, and hammering somebody else's server over a state only they can
                # change is its own fault.
                failures = 0
                delay = self.OWNERSHIP_RENEWAL_SECONDS
            await asyncio.sleep(delay)

    async def run_mailbox(self) -> None:
        backoff = 1.0
        while True:
            try:
                # Observe first. The gate reads persisted state, and persisted state is
                # only as good as when it was written: a node restarting with an
                # ownership record from a previous run would otherwise process a cycle's
                # worth of jobs, and publish for them, before ever checking whether it
                # still owns the room. Reordering closes the window; the freshness bound
                # in `_ownership_observation` is what closes it for good.
                await self.observe_reachability()
                await self.poll_mailbox_once()
                await self.reconcile_audit_copies()
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

    #: How old an ownership observation may be and still be acted on. The mailbox loop
    #: refreshes it every cycle, so this is many cycles of slack — it exists to catch a
    #: node that restarted, or whose loop stopped, not to second-guess a healthy one.
    OWNERSHIP_MAX_AGE_SECONDS = 900

    def _ownership_observation(self) -> tuple[str | None, str | None, str | None, float | None]:
        """`(owner, observed_flag, error, age_seconds)` for the result room.

        `age_seconds` is None when nothing has ever been observed. It is the reason this
        is a helper rather than three `get_state` calls: "confirmed by a read" has to mean
        confirmed *recently*, or a record written before the room changed hands would keep
        authorising writes indefinitely.
        """
        owner, owner_at = self.ledger.get_state("owned_room_owner")
        observed, _ = self.ledger.get_state("owned_room_observed")
        error, _ = self.ledger.get_state("owned_room_error")

        age: float | None = None
        if owner_at:
            try:
                seen = datetime.fromisoformat(owner_at.replace("Z", "+00:00"))
            except ValueError:
                age = None  # unparseable: treated as never observed, which fails closed
            else:
                delta = (datetime.now(UTC) - seen).total_seconds()
                # A record from the future is not fresh, it is wrong. Clamping it to zero
                # would make an old observation look current after a clock jumped forward
                # and was corrected — trusting the timestamp most in the one case where it
                # is least trustworthy.
                age = None if delta < -_CLOCK_TOLERANCE_SECONDS else max(0.0, delta)
        return owner, observed, error, age

    def _age_of(self, timestamp: str | None) -> int | None:
        """Seconds since `timestamp`, or None if it is absent or unreadable."""
        if not timestamp:
            return None
        try:
            when = datetime.fromisoformat(timestamp)
        except ValueError:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        age = (datetime.now(UTC) - when).total_seconds()
        return int(age) if age >= -_CLOCK_TOLERANCE_SECONDS else None

    def _ownership_is_fresh(self, age: float | None) -> bool:
        return age is not None and age <= self.OWNERSHIP_MAX_AGE_SECONDS

    def safety_state(self) -> tuple[bool, list[str]]:
        """Whether it is safe to do work for a stranger, and why not when it is not.

        This is the gate, and it is separate from :meth:`availability` on purpose.
        `availability` describes; this decides. They were the same thing once — a status
        block that read `unavailable` while the mailbox loop went on accepting jobs
        underneath it — which is a description of a system that reports its own safety
        and does not act on it.

        The condition that matters most is the owned result room. A receipt is only
        evidence because it sits somewhere none but this node's key can write; if the
        room is unowned, anyone can post a forged receipt beside ours, and publishing
        there would be manufacturing exactly the ambiguity the receipt exists to remove.
        So an unverified or foreign owner is not a warning to display. It is a stop.
        """
        reasons: list[str] = []

        owner, observed, owner_err, age = self._ownership_observation()

        if observed and not owner_err and not self._ownership_is_fresh(age):
            reasons.append(
                "the result room ownership check is stale "
                f"({int(age) if age is not None else 'unknown'}s old, limit "
                f"{self.OWNERSHIP_MAX_AGE_SECONDS}s); it will re-check before accepting work"
            )
        elif owner_err:
            reasons.append(f"result room ownership could not be verified: {owner_err}")
        elif not observed:
            reasons.append("result room ownership has never been successfully checked")
        elif owner is None:
            reasons.append(
                f"result room {self.result_room} has no owner, so anything published "
                "there could be forged by anyone"
            )
        elif owner != self.did:
            reasons.append(
                f"result room {self.result_room} is owned by another key, so this node "
                "cannot publish an auditable record there"
            )

        if not self.settings.public_url:
            reasons.append("no public URL is configured, so a requester cannot verify a receipt")

        if not self.settings.mailbox_enabled:
            # The only intake this version has. With the loop switched off nothing is
            # polling, so "accepting third-party jobs" would be false however healthy
            # everything else looked — and a status that ignores whether anyone is
            # listening is the same mismatch this release exists to remove.
            reasons.append(
                "mailbox intake is disabled (TCN_MAILBOX_ENABLED=false), so no job is being read"
            )

        return (not reasons, reasons)

    def can_accept_third_party_jobs(self) -> bool:
        """The single gate every third-party execution path must pass."""
        return self.safety_state()[0]

    def owns_result_room(self) -> bool:
        """Confirmed, from a successful read, that the result room is this node's.

        Deliberately independent of :meth:`can_accept_third_party_jobs`: a write to the
        audit room must be refused on the ownership fact alone, whatever else is or is
        not true, and whichever caller thought it had already checked.
        """
        owner, observed, owner_err, age = self._ownership_observation()
        return (
            bool(observed) and not owner_err and owner == self.did and self._ownership_is_fresh(age)
        )

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

        # One source of truth. These were two lists once — the gate's and the report's —
        # and they drifted: the report could read `available` from a stale ownership
        # record the gate had already rejected, which is exactly the status/action
        # mismatch this release exists to remove.
        # `blockers` is exactly what the gate refuses on — no more. A past publish
        # failure is worth showing and is shown, but as its own field: folding it in here
        # made `stop_reasons` non-empty while `accepting_third_party_jobs` stayed true,
        # which is the very disagreement these two fields exist to make impossible.
        safe, blockers = self.safety_state()

        # Blockers are about now; a completed job is about the past. A node that once
        # served somebody and is unreachable today is unreachable today.
        if not safe:
            intake = "unavailable"
        elif completed > 0:
            intake = "available"
        else:
            intake = "unverified"

        renewed_at, _ = self.ledger.get_state("owned_room_renewed")
        return {
            "third_party_intake": intake,
            # The lease, not just the ownership. A room that is ours today and whose
            # renewal stopped a week ago is a room we are about to lose, and reporting
            # only `owner == us` says everything is fine right up until it is not.
            "ownership_lease": {
                "renewed_at": renewed_at,
                "renewed_seconds_ago": self._age_of(renewed_at),
                "upstream_expiry_seconds": self.UPSTREAM_NOTE_RETENTION_SECONDS,
                "note": (
                    "Ownership upstream is a note, and a note with no write for "
                    f"{self.UPSTREAM_NOTE_RETENTION_SECONDS}s is deleted. This node "
                    f"renews every {self.OWNERSHIP_RENEWAL_SECONDS}s. Null means it has "
                    "not renewed since this ledger was created."
                ),
            },
            # What the node will actually *do*, next to what it reports. When these two
            # disagree the reader should be able to see it, not have to infer it.
            "accepting_third_party_jobs": safe,
            "stop_reasons": blockers,
            "last_publish_error": result_err,
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
        # Started unconditionally. The lease is a fact about the calendar, not about
        # whether this node is accepting work: with intake off — which is how production
        # runs today — nothing else would renew it, and the room would be lost while the
        # node was doing exactly what it was told.
        self._tasks.append(asyncio.create_task(self.run_ownership_lease(), name="ownership"))
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
