"""A room has lifetimes, and a cursor is a position in one of them.

Found in production on 2026-10-05: both of this node's rooms had been deleted upstream —
the upstream deletes a room after a week without a write — and the ledger still held the
mailbox cursor at 3. Nothing in the node knew a room could be replaced.

It got away with it. Since upstream #343 a deleted room leaves its last seq behind as a
floor and a recreated one is numbered on from it, and both rooms kept theirs (3 and 5), so
the next job would have arrived at seq 4 and been read. But a name the upstream holds no
record of starts again at 1 (`/interop.md`), and a cursor held at 3 skips seq 1 to 3 of
that room without a word: a read with `since=` echoes the cursor back as `last_seq` when
nothing is newer. These tests cover both.

`FakeUpstream` keeps rooms the way upstream 0.14.5 does (`src/store.py`).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from technocore_node.config import load_settings
from technocore_node.crypto import keystore
from technocore_node.ledger.db import utcnow
from technocore_node.protocol.client import Confirmation, TechnocoreError
from technocore_node.service.node import Node

from ..conftest import job_line

PASSPHRASE = b"test-secret-do-not-use"
REQUESTER = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
STRANGER = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"


class FakeUpstream:
    """Rooms with lifetimes, as upstream 0.14.5 keeps them (`src/store.py`).

    A room is created by its first write, and `generation` counts its lifetimes: 0 for a
    name the upstream holds no record of, bumped each time the name is written to after a
    deletion. A deleted room leaves its last seq behind as a floor, and a recreated one is
    numbered on from it — unless the record is gone (`forget=True`) or the upstream keeps
    no floors (`keep_floor=False`), and then numbering starts again at 1.

    A read returns the *newest* `limit` records after the cursor (default 50, at most
    200), oldest first. With none to return it answers `last_seq` as the lower of the
    cursor and the room's head — the floor, for an emptied room, but only when a cursor was
    given; with `echo_cursor=True`, as the cursor itself, which is how `/interop.md`
    describes it. With `bump_late=True` a recreated room's first record is readable one
    read before its generation moves, as upstream writes the two in that order.
    """

    def __init__(self, *, keep_floor: bool = True) -> None:
        self.rooms: dict[str, list[dict[str, Any]]] = {}
        self.generations: dict[str, int] = {}
        self.floors: dict[str, int] = {}
        self.keep_floor = keep_floor
        self.echo_cursor = False
        self.report_generation = True
        self.bump_late = False
        self.reads: list[tuple[str, int | None]] = []
        self._pending: dict[str, int] = {}
        self._nonce = 0

    def _head(self, room: str) -> int:
        messages = self.rooms.get(room)
        return messages[-1]["seq"] if messages else self.floors.get(room, 0)

    def post(self, room: str, sender: str, text: str) -> int:
        seq = self._head(room) + 1
        messages = self.rooms.setdefault(room, [])
        if not messages:
            bumped = self.generations.get(room, 0) + 1
            if self.bump_late:
                self._pending[room] = bumped
            else:
                self.generations[room] = bumped
        self._nonce += 1
        messages.append(
            {"seq": seq, "ts": "now", "from": sender, "nonce": self._nonce, "text": text}
        )
        return seq

    def reap(self, room: str, *, forget: bool = False) -> None:
        """Delete the room. Its generation stays behind, and its last seq as a floor."""
        self.floors[room] = self._head(room) if self.keep_floor else 0
        self.rooms[room] = []
        if forget:
            # A name the upstream holds no record of at all.
            self.generations[room] = 0
            self.floors[room] = 0

    def _generation(self, room: str) -> int:
        seen = self.generations.get(room, 0)
        if room in self._pending:
            self.generations[room] = self._pending.pop(room)
        return seen

    async def read_room(
        self, room: str, *, since: int | None = None, wait: int = 0, limit: int | None = None
    ) -> dict[str, Any]:
        self.reads.append((room, since))
        messages = self.rooms.get(room, [])
        after = [m for m in messages if since is None or m["seq"] > since]
        out = after[-max(1, min(limit or 50, 200)) :]
        if out:
            last_seq = out[-1]["seq"]
        elif self.echo_cursor:
            last_seq = since or 0
        else:
            head = messages[-1]["seq"] if messages else (self.floors.get(room, 0) if since else 0)
            last_seq = min(since or 0, head)
        body: dict[str, Any] = {
            "room": room,
            "count": len(out),
            "first_seq": out[0]["seq"] if out else None,
            "last_seq": last_seq,
            "messages": [dict(m) for m in out],
        }
        if self.report_generation:
            body["generation"] = self._generation(room)
        return body

    async def export_room(self, room: str) -> tuple[int | None, list[dict[str, Any]]]:
        return self.generations.get(room, 0), [dict(m) for m in self.rooms.get(room, [])]


@pytest.fixture
def node(env: dict[str, str]) -> Node:
    keystore.generate(Path(env["TCN_IDENTITY_PATH"]), PASSPHRASE)
    node = Node(load_settings())
    object.__setattr__(node.settings, "public_url", "https://example.invalid")
    object.__setattr__(node.settings, "mailbox_enabled", True)
    return node


@pytest.fixture
def upstream(node: Node) -> FakeUpstream:
    """Every read and every write the node makes goes to the same fake rooms."""
    fake = FakeUpstream()

    async def say_signed(room: str, text: str, *, confirm: bool = True) -> Confirmation:
        seq = fake.post(room, node.did, text)
        return Confirmation(
            room=room, did=node.did, nonce=seq, text=text, sig="a" * 85 + "A", seq=seq, ts="now"
        )

    node.client.read_room = fake.read_room  # type: ignore[method-assign]
    node.client.export_room = fake.export_room  # type: ignore[method-assign]
    node.client.say_signed = say_signed  # type: ignore[method-assign]
    return fake


def _own_the_room(node: Node) -> None:
    node.ledger.set_state("owned_room_owner", node.did)
    node.ledger.set_state("owned_room_observed", "1")
    node.ledger.set_state("owned_room_error", None)
    node.ledger.set_state("owned_room_renewed", utcnow())


def _lose_the_room(node: Node) -> None:
    node.ledger.set_state("owned_room_owner", None)
    node.ledger.set_state("owned_room_observed", "1")
    node.ledger.set_state("owned_room_error", None)
    node.ledger.set_state("owned_room_renewed", utcnow())


def _job(job_id: str) -> str:
    return job_line(job_id=job_id, reply_room="mb-p-r")


def _three_lines_already_read(node: Node, upstream: FakeUpstream) -> None:
    for n in range(3):
        upstream.post(node.mailbox, REQUESTER, f"line {n}")
    node.ledger.set_cursor(node.mailbox, 3)


# ------------------------------------------------------------------ the mailbox


async def test_production_as_found_still_hears_the_next_job(
    node: Node, upstream: FakeUpstream
) -> None:
    """The rooms as they stood on 2026-10-05: emptied, a floor kept, generation 0.

    v0.2.2 hears this job too — the floor is what saved it — so this pins the outcome, not
    a fix: whatever the node does about lifetimes must not cost it this.
    """
    _own_the_room(node)
    _three_lines_already_read(node, upstream)
    upstream.reap(node.mailbox)
    upstream.generations[node.mailbox] = 0  # these rooms predate the upstream's generations

    assert await node.poll_mailbox_once(wait=0) == 0
    upstream.post(node.mailbox, REQUESTER, _job("after-reap-0001"))
    assert await node.poll_mailbox_once(wait=0) == 1
    row = node.ledger.get_job("after-reap-0001")
    assert row is not None
    assert row["request_seq"] == 4, "numbered on from the floor"
    assert node.ledger.cursor(node.mailbox) == 4


async def test_a_name_with_no_record_is_read_again_from_seq_1(
    node: Node, upstream: FakeUpstream
) -> None:
    """The case nothing caught: the upstream has no record, so the room restarts at 1."""
    _own_the_room(node)
    node.ledger.set_cursor(node.mailbox, 3)
    upstream.reap(node.mailbox, forget=True)

    assert await node.poll_mailbox_once(wait=0) == 0
    assert node.ledger.cursor(node.mailbox) == 0, "a position in a deleted room means nothing"

    upstream.post(node.mailbox, REQUESTER, _job("after-reap-0002"))
    assert await node.poll_mailbox_once(wait=0) == 1
    assert node.ledger.get_job("after-reap-0002") is not None
    assert node.ledger.cursor(node.mailbox) == 1


async def test_a_room_replaced_between_reads_and_renumbered_is_read_from_the_start(
    node: Node, upstream: FakeUpstream
) -> None:
    """The generation catches a replacement the moment a read shows it, probe or not."""
    _own_the_room(node)
    upstream.keep_floor = False
    _three_lines_already_read(node, upstream)
    node.ledger.adopt_cursor_epoch(node.mailbox, 1)
    assert await node.poll_mailbox_once(wait=0) == 0  # checked, and nothing new

    upstream.reap(node.mailbox)
    upstream.post(node.mailbox, REQUESTER, _job("replaced-00001"))
    upstream.post(node.mailbox, REQUESTER, _job("replaced-00002"))

    # What came back was read from an old position in a new room, so none of it is handled.
    assert await node.poll_mailbox_once(wait=0) == 0
    assert (node.ledger.cursor(node.mailbox), node.ledger.cursor_epoch(node.mailbox)) == (0, 2)
    assert node.ledger.get_job("replaced-00001") is None

    assert await node.poll_mailbox_once(wait=0) == 2
    first = node.ledger.get_job("replaced-00001")
    second = node.ledger.get_job("replaced-00002")
    assert first is not None and second is not None
    assert (first["request_seq"], second["request_seq"]) == (1, 2), "and in order"


async def test_a_room_replaced_and_numbered_on_is_read_once_and_in_order(
    node: Node, upstream: FakeUpstream
) -> None:
    """Upstream 0.14.5's own behaviour: the floor carries the numbering into the new room.
    The restart is not needed then, and must cost nothing but a cycle."""
    _own_the_room(node)
    _three_lines_already_read(node, upstream)
    node.ledger.adopt_cursor_epoch(node.mailbox, 1)
    assert await node.poll_mailbox_once(wait=0) == 0

    upstream.reap(node.mailbox)
    upstream.post(node.mailbox, REQUESTER, _job("numbered-on-001"))
    upstream.post(node.mailbox, REQUESTER, _job("numbered-on-002"))

    handled = [await node.poll_mailbox_once(wait=0) for _ in range(3)]
    assert sum(handled) == 2, handled
    first = node.ledger.get_job("numbered-on-001")
    second = node.ledger.get_job("numbered-on-002")
    assert first is not None and second is not None
    assert (first["request_seq"], second["request_seq"]) == (4, 5)
    assert node.ledger.cursor_epoch(node.mailbox) == 2


async def test_a_read_that_comes_back_behind_the_cursor_restarts_at_once(
    node: Node, upstream: FakeUpstream
) -> None:
    """No generation needed, and no probe: `last_seq` below the cursor says it already."""
    _own_the_room(node)
    upstream.keep_floor = False
    upstream.report_generation = False
    _three_lines_already_read(node, upstream)
    assert await node.poll_mailbox_once(wait=0) == 0

    upstream.reap(node.mailbox)
    upstream.post(node.mailbox, REQUESTER, _job("behind-cursor-01"))
    assert await node.poll_mailbox_once(wait=0) == 0
    assert node.ledger.cursor(node.mailbox) == 0
    assert await node.poll_mailbox_once(wait=0) == 1
    assert node.ledger.get_job("behind-cursor-01") is not None


async def test_a_rewind_an_echoing_upstream_hides_is_caught_by_the_next_probe(
    node: Node, upstream: FakeUpstream
) -> None:
    """For an upstream that echoes the cursor whatever the room holds and reports no
    generation, the cursor-free read is the only check left."""
    _own_the_room(node)
    upstream.keep_floor = False
    upstream.echo_cursor = True
    upstream.report_generation = False
    _three_lines_already_read(node, upstream)
    assert await node.poll_mailbox_once(wait=0) == 0

    upstream.reap(node.mailbox)
    upstream.post(node.mailbox, REQUESTER, _job("unnumbered-0001"))
    assert await node.poll_mailbox_once(wait=0) == 0, "invisible until the probe is due"

    node._epoch_probed[node.mailbox] -= node.ROOM_EPOCH_PROBE_SECONDS
    assert await node.poll_mailbox_once(wait=0) == 1
    assert node.ledger.get_job("unnumbered-0001") is not None


async def test_a_plausible_cursor_is_kept_and_its_lifetime_recorded(
    node: Node, upstream: FakeUpstream
) -> None:
    """Upgrading must not replay a room the node has already read.

    Reading from the start whenever the lifetime is unrecorded would answer nothing twice —
    job ids are idempotent — but it would record every refusal again, and refusals are a
    published count.
    """
    _lose_the_room(node)  # gate shut: nothing is handled, only read
    for n in range(5):
        upstream.post(node.mailbox, REQUESTER, f"line {n}")
    node.ledger.set_cursor(node.mailbox, 3)

    assert await node.poll_mailbox_once(wait=0) == 0
    assert node.ledger.cursor(node.mailbox) == 3
    assert node.ledger.cursor_epoch(node.mailbox) == 1
    assert upstream.reads == [(node.mailbox, 2), (node.mailbox, 3)]


async def test_the_cursor_restarts_even_while_the_gate_is_shut(
    node: Node, upstream: FakeUpstream
) -> None:
    """Moving back to the start of a new room skips nothing, so it does not wait for the
    gate. Holding the old position while shut would skip the jobs once it opened."""
    _lose_the_room(node)
    node.ledger.set_cursor(node.mailbox, 3)
    upstream.reap(node.mailbox, forget=True)
    assert await node.poll_mailbox_once(wait=0) == 0
    assert node.ledger.cursor(node.mailbox) == 0

    upstream.post(node.mailbox, REQUESTER, _job("held-reaped-001"))
    assert await node.poll_mailbox_once(wait=0) == 0
    assert node.ledger.get_job("held-reaped-001") is None, "deferred while the gate is shut"
    assert node.ledger.cursor(node.mailbox) == 0

    _own_the_room(node)
    assert await node.poll_mailbox_once(wait=0) == 1
    assert node.ledger.get_job("held-reaped-001") is not None


async def test_a_failed_probe_reads_nothing_from_an_unchecked_position(node: Node) -> None:
    _own_the_room(node)
    node.ledger.set_cursor(node.mailbox, 3)
    positions: list[int] = []

    async def read_room(room: str, *, since: int | None = None, **kwargs: Any) -> dict[str, Any]:
        if since != 3:  # anything but a read from the cursor is the check
            raise TechnocoreError("HTTP 503: upstream unavailable")
        positions.append(since)
        return {"room": room, "count": 0, "last_seq": since, "generation": 1, "messages": []}

    node.client.read_room = read_room  # type: ignore[method-assign]
    with pytest.raises(TechnocoreError):
        await node.poll_mailbox_once(wait=0)
    assert positions == []
    assert node.ledger.cursor(node.mailbox) == 3


async def test_a_backlog_longer_than_one_read_is_handled_whole_and_in_order(
    node: Node, upstream: FakeUpstream
) -> None:
    """A read returns the newest 200 after the cursor. A backlog of 250 — a gate held
    shut, a burst — used to cost its oldest 200 without a word; they were still in the
    room, and only the export reaches them."""
    _own_the_room(node)
    for n in range(250):
        upstream.post(node.mailbox, REQUESTER, f"backlog line {n}")

    for _ in range(4):
        await node.poll_mailbox_once(wait=0)
    assert node.ledger.cursor(node.mailbox) == 250
    rows = node.ledger.conn.execute(
        "SELECT technocore_seq FROM messages WHERE direction = 'in' ORDER BY technocore_seq"
    ).fetchall()
    assert [r["technocore_seq"] for r in rows] == list(range(1, 251)), "each once, in order"
    assert node.ledger.get_state("mailbox_gap")[0] is None, "nothing aged out"


async def test_a_new_lifetime_seen_before_its_bump_is_not_answered_twice(
    node: Node, upstream: FakeUpstream
) -> None:
    """Upstream writes a recreated room's first record before it bumps the generation, so
    one read can show the record under the old number. Restarting when the bump then
    shows would handle that record a second time — two refusals for one line, both
    charged to the sender's hourly budget."""
    _own_the_room(node)
    _three_lines_already_read(node, upstream)
    node.ledger.adopt_cursor_epoch(node.mailbox, 1)
    assert await node.poll_mailbox_once(wait=0) == 0

    upstream.reap(node.mailbox)
    upstream.bump_late = True
    upstream.post(node.mailbox, REQUESTER, "not a job")
    assert await node.poll_mailbox_once(wait=0) == 1  # read under the old generation
    assert await node.poll_mailbox_once(wait=0) == 0  # the bump shows; nothing new
    assert await node.poll_mailbox_once(wait=0) == 0  # and nothing is read again
    assert node.ledger.cursor_epoch(node.mailbox) == 2
    refusals = node.ledger.conn.execute("SELECT COUNT(*) AS n FROM rejections").fetchone()
    assert refusals["n"] == 1


async def test_a_room_renumbered_under_the_same_generation_is_caught_on_restart(
    node: Node, upstream: FakeUpstream
) -> None:
    """The upstream loses its record of the mailbox; a new room starts at 1 as generation
    1, the number the old one had; and it passes the cursor while nothing is reading —
    the node down, or intake shut. Neither the numbers nor the generation show it. The
    message at the cursor does: it is not the one this node handled there."""
    _own_the_room(node)
    for n in range(3):
        upstream.post(node.mailbox, REQUESTER, f"old line {n}")
    assert await node.poll_mailbox_once(wait=0) == 3
    assert (node.ledger.cursor(node.mailbox), node.ledger.cursor_epoch(node.mailbox)) == (3, 1)

    upstream.reap(node.mailbox, forget=True)
    for n in range(5):
        upstream.post(node.mailbox, STRANGER, f"new line {n}")
    node._epoch_probed.clear()  # a fresh process

    handled = [await node.poll_mailbox_once(wait=0) for _ in range(2)]
    assert sum(handled) == 5, handled
    assert node.ledger.cursor(node.mailbox) == 5


async def test_an_emptied_room_keeps_its_gap_accounting(node: Node, upstream: FakeUpstream) -> None:
    """Gate shut, seq 4 to 10 unread, the room deleted with its numbering kept. Nothing
    below the cursor can be missed, so the cursor stays — and the next job's seq says how
    many went unread, where a restart to zero would have said nothing."""
    _lose_the_room(node)
    for n in range(10):
        upstream.post(node.mailbox, REQUESTER, f"line {n}")
    node.ledger.set_cursor(node.mailbox, 3)
    assert await node.poll_mailbox_once(wait=0) == 0

    upstream.reap(node.mailbox)
    assert await node.poll_mailbox_once(wait=0) == 0
    assert node.ledger.cursor(node.mailbox) == 3, "an emptied room is not a replaced one"

    upstream.post(node.mailbox, REQUESTER, _job("after-the-gap-1"))
    assert await node.poll_mailbox_once(wait=0) == 0
    gap, _ = node.ledger.get_state("mailbox_gap")
    assert gap is not None and gap.startswith("7 message(s)")


async def test_a_probe_that_answers_with_no_room_is_not_a_check(node: Node) -> None:
    _own_the_room(node)
    node.ledger.set_cursor(node.mailbox, 3)

    async def read_room(room: str, **kwargs: Any) -> dict[str, Any]:
        return {}

    node.client.read_room = read_room  # type: ignore[method-assign]
    with pytest.raises(TechnocoreError):
        await node.poll_mailbox_once(wait=0)
    assert node.mailbox not in node._epoch_probed, "tried again next cycle, not in ten minutes"
    assert node.ledger.cursor(node.mailbox) == 3


@pytest.mark.parametrize("seq", [True, "7", -1, None])
async def test_a_message_without_a_usable_seq_is_not_handled_and_moves_nothing(
    node: Node, seq: Any
) -> None:
    _own_the_room(node)

    async def read_room(room: str, **kwargs: Any) -> dict[str, Any]:
        message = {"seq": seq, "ts": "now", "from": REQUESTER, "nonce": 1, "text": "x"}
        return {"room": room, "last_seq": 0, "messages": [message]}

    node.client.read_room = read_room  # type: ignore[method-assign]
    assert await node.poll_mailbox_once(wait=0) == 0
    assert node.ledger.cursor(node.mailbox) == 0
    rows = node.ledger.conn.execute("SELECT COUNT(*) AS n FROM messages").fetchone()
    assert rows["n"] == 0


@pytest.mark.parametrize("generation", [True, -1, "2", 1.5, None])
async def test_a_generation_that_is_not_a_count_is_not_recorded(
    node: Node, generation: Any
) -> None:
    """The envelope is untrusted. `True` is an int to Python, and it is not lifetime 1."""

    async def read_room(room: str, **kwargs: Any) -> dict[str, Any]:
        return {"room": room, "last_seq": 0, "generation": generation, "messages": []}

    node.client.read_room = read_room  # type: ignore[method-assign]
    await node.poll_mailbox_once(wait=0)
    assert node.ledger.cursor_epoch(node.mailbox) is None


async def test_inbound_records_from_two_lifetimes_are_both_kept(node: Node) -> None:
    """seq 1 can name a different message in each lifetime. Neither record may replace the
    other — this is an evidence ledger, and it was keyed on the seq alone."""
    _own_the_room(node)

    async def say_signed(room: str, text: str, *, confirm: bool = True) -> Confirmation:
        return Confirmation(
            room=room, did=node.did, nonce=1, text=text, sig="a" * 85 + "A", seq=1, ts="now"
        )

    node.client.say_signed = say_signed  # type: ignore[method-assign]
    for generation, job_id in ((1, "lifetime-one-01"), (2, "lifetime-two-01")):
        message = {"seq": 1, "ts": "now", "from": REQUESTER, "nonce": 1, "text": _job(job_id)}
        assert await node.process_message(message, generation=generation)

    rows = node.ledger.conn.execute(
        "SELECT local_event_id FROM messages WHERE direction = 'in' ORDER BY local_event_id"
    ).fetchall()
    assert [r["local_event_id"] for r in rows] == [
        f"in-{node.mailbox}-g1-1",
        f"in-{node.mailbox}-g2-1",
    ]


# ------------------------------------------------------------- the owned room


async def test_a_copy_in_a_replaced_owned_room_is_recognised(
    node: Node, upstream: FakeUpstream
) -> None:
    """The reconciler publishes straight after this sync. A copy already in the new room
    that the sync cannot see is a copy that gets posted twice."""
    _own_the_room(node)
    job_id = "audited-000001"
    receipt = {
        "type": "receipt",
        "receipt_id": "receipt-000001",
        "job_id": job_id,
        "requester_did": REQUESTER,
        "provider_did": node.did,
        "request_hash": "sha256:" + "0" * 64,
        "result_hash": "sha256:" + "1" * 64,
        "provider_signature": "a" * 85 + "A",
        "receipt_hash": "sha256:" + "2" * 64,
        "created_at": utcnow(),
    }
    node.ledger.insert_job(
        job_id=job_id,
        protocol_version="1",
        requester_did=REQUESTER,
        provider_did=node.did,
        request_room=node.mailbox,
        reply_room="mb-p-r",
        request_seq=1,
        request_hash=receipt["request_hash"],
        task_type="canonical_json_sha256",
        status="completed",
        internal_test=False,
    )
    node.ledger.record_receipt(receipt, json.dumps(receipt), internal_test=False)
    node.ledger.set_cursor(node.result_room, 5)

    upstream.reap(node.result_room, forget=True)
    upstream.post(node.result_room, node.did, json.dumps(receipt))

    assert await node.sync_owned_room() == 1
    row = node.ledger.get_receipt(job_id)
    assert row is not None
    assert (row["audit_state"], row["audit_seq"]) == ("published", 1)
    assert node.ledger.cursor(node.result_room) == 1
