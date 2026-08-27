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

from ..config import Settings
from ..crypto import didkey
from ..crypto.keystore import Identity, load
from ..jobs.runner import JobRunner, RejectedJob
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

        receipt = outcome.receipt
        if receipt is not None:
            receipt_json = json.dumps(
                receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            )
            published_seq = await self.publish(outcome.reply_room, receipt)

            # The same receipt also goes to the room this node owns, where only its key
            # can write. That is the difference between "the requester has a receipt" and
            # "anyone can audit what this node did" — the reply room is the requester's,
            # and they can post anything they like into it. A third party checking this
            # node's claims needs a record the node cannot repudiate and nobody else can
            # forge, and the owned room is the only place that exists.
            #
            # Internal tests are excluded. The owned room is a public claim about work
            # done for other agents, and this node's own tests are not that.
            if not outcome.internal_test:
                await self.publish(self.result_room, receipt)

            self.ledger.record_receipt(receipt, receipt_json, published_seq, outcome.internal_test)

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

    def start_background(self) -> None:
        if self.settings.mailbox_enabled:
            self._tasks.append(asyncio.create_task(self.run_mailbox(), name="mailbox"))
        if self.settings.watcher_enabled:
            self._tasks.append(asyncio.create_task(self.watcher.run_forever(), name="watcher"))


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
