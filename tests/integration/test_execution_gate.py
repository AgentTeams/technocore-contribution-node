"""The execution gate, and the accident that made it necessary.

`v0.1.1` added `availability()`, which reported honestly that the node was not usable —
and then went on accepting work underneath that report. A status block that describes a
system without constraining it is not a safety property; it is a label.

Two things went wrong in production and both are pinned here.

**The room was born unowned.** `publish-profile` posted a profile attestation into the
result room. Upstream, writing to a room that does not exist creates it, and a `d-` room
that already holds a message can *never* be claimed — "ownable from birth or not at all".
So the write that was meant to make the room trustworthy is what permanently prevented it
from being trustworthy. That name is lost.

**Nothing stopped work continuing anyway.** With the room unowned, any stranger who
created the mailbox and posted a job would have had a receipt published into a room where
anybody can post one too — a forgery sitting beside a genuine record, indistinguishable to
a reader.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from technocore_node.api import create_app
from technocore_node.config import load_settings
from technocore_node.crypto import keystore
from technocore_node.protocol.client import Confirmation, TechnocoreError
from technocore_node.service.node import Node

from ..conftest import job_line

PASSPHRASE = b"test-secret-do-not-use"
REQUESTER = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
STRANGER = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"


@pytest.fixture
def node(env: dict[str, str]) -> Node:
    keystore.generate(Path(env["TCN_IDENTITY_PATH"]), PASSPHRASE)
    node = Node(load_settings())
    object.__setattr__(node.settings, "public_url", "https://example.invalid")
    return node


def _own_the_room(node: Node) -> None:
    node.ledger.set_state("owned_room_owner", node.did)
    node.ledger.set_state("owned_room_observed", "1")
    node.ledger.set_state("owned_room_error", None)


def _room_state(node: Node, owner: str | None, observed: bool, error: str | None = None) -> None:
    node.ledger.set_state("owned_room_owner", owner)
    node.ledger.set_state("owned_room_observed", "1" if observed else None)
    node.ledger.set_state("owned_room_error", error)


class _Recorder:
    """Stands in for the network, and remembers every room written to."""

    def __init__(self, node: Node) -> None:
        self.writes: list[tuple[str, str]] = []
        self._node = node

    async def say_signed(self, room: str, text: str, *, confirm: bool = True) -> Confirmation:
        self.writes.append((room, text))
        return Confirmation(
            room=room, did=self._node.did, nonce=1, text=text, sig="a" * 86, seq=1, ts="now"
        )

    def rooms(self) -> set[str]:
        return {room for room, _ in self.writes}


# ------------------------------------------------------------------- the gate


def test_the_gate_is_closed_while_the_room_is_unowned(node: Node) -> None:
    """The production state on the day this was written."""
    _room_state(node, owner=None, observed=True)
    safe, reasons = node.safety_state()
    assert safe is False
    assert node.can_accept_third_party_jobs() is False
    assert any("no owner" in r for r in reasons), reasons


def test_the_gate_is_closed_when_another_key_owns_the_room(node: Node) -> None:
    _room_state(node, owner=STRANGER, observed=True)
    assert node.can_accept_third_party_jobs() is False
    assert any("owned by another key" in r for r in node.safety_state()[1])


def test_the_gate_is_closed_when_ownership_was_never_checked(node: Node) -> None:
    """Never having looked is not the same as having looked and been satisfied."""
    assert node.can_accept_third_party_jobs() is False
    assert any("never been successfully checked" in r for r in node.safety_state()[1])


def test_the_gate_is_closed_when_the_check_itself_failed(node: Node) -> None:
    _room_state(node, owner=None, observed=False, error="HTTP 503: upstream unavailable")
    assert node.can_accept_third_party_jobs() is False
    assert any("could not be verified" in r for r in node.safety_state()[1])


def test_the_gate_is_closed_without_a_public_url(node: Node) -> None:
    _own_the_room(node)
    object.__setattr__(node.settings, "public_url", "")
    assert node.can_accept_third_party_jobs() is False
    assert any("public URL" in r for r in node.safety_state()[1])


def test_the_gate_opens_only_when_every_condition_holds(node: Node) -> None:
    _own_the_room(node)
    assert node.safety_state() == (True, [])
    assert node.can_accept_third_party_jobs() is True


# ------------------------------------------- the gate actually stops the work


async def test_a_third_party_job_is_not_executed_while_unsafe(node: Node) -> None:
    """`availability()` said `unavailable` and the work happened anyway. Not any more."""
    _room_state(node, owner=None, observed=True)
    recorder = _Recorder(node)
    node.client.say_signed = recorder.say_signed  # type: ignore[method-assign]

    await node.process_message(
        {
            "from": REQUESTER,
            "text": job_line(job_id="blocked-000001"),
            "seq": 1,
            "ts": "now",
            "nonce": 1,
        }
    )

    assert recorder.writes == [], "nothing may be published while the gate is closed"
    assert node.ledger.get_job("blocked-000001") is None, "no work may be recorded either"


async def test_a_job_is_executed_once_the_gate_opens(node: Node) -> None:
    """The gate must be a gate, not a wall: the same message goes through when safe."""
    _own_the_room(node)
    recorder = _Recorder(node)
    node.client.say_signed = recorder.say_signed  # type: ignore[method-assign]

    await node.process_message(
        {
            "from": REQUESTER,
            "text": job_line(job_id="allowed-000001", reply_room="mb-p-r"),
            "seq": 1,
            "ts": "now",
            "nonce": 1,
        }
    )

    assert node.ledger.get_job("allowed-000001") is not None
    assert "mb-p-r" in recorder.rooms()
    assert node.result_room in recorder.rooms(), "the audit copy goes to the owned room"


async def test_an_internal_test_is_not_blocked_by_the_gate(node: Node) -> None:
    """The gate protects strangers' receipts, not the node's own verification."""
    _room_state(node, owner=None, observed=True)
    recorder = _Recorder(node)
    node.client.say_signed = recorder.say_signed  # type: ignore[method-assign]

    await node.process_message(
        {
            "from": REQUESTER,
            "text": job_line(job_id="internal-00001", reply_room="p-x"),
            "seq": 1,
            "ts": "now",
            "nonce": 1,
        },
        internal_test=True,
    )
    assert node.ledger.get_job("internal-00001") is not None
    assert node.result_room not in recorder.rooms(), "internal tests never touch the audit room"


# ------------------------------- work is deferred, never silently thrown away


async def test_the_cursor_does_not_move_while_the_gate_is_closed(node: Node) -> None:
    """The quiet failure this avoids.

    Advancing the cursor past unprocessed jobs would leave the node looking healthy and
    the queue looking empty, while every request that arrived during the unsafe window
    was discarded and its sender never told. Holding the cursor means the work waits.
    """
    _room_state(node, owner=None, observed=True)

    async def read_room(room: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "room": room,
            "count": 2,
            "first_seq": 5,
            "last_seq": 6,
            "messages": [
                {
                    "seq": 5,
                    "ts": "now",
                    "from": REQUESTER,
                    "nonce": 1,
                    "text": job_line(job_id="waiting-000001"),
                },
                {
                    "seq": 6,
                    "ts": "now",
                    "from": REQUESTER,
                    "nonce": 2,
                    "text": job_line(job_id="waiting-000002"),
                },
            ],
        }

    node.client.read_room = read_room  # type: ignore[method-assign]
    assert await node.poll_mailbox_once(wait=0) == 0
    assert node.ledger.cursor(node.mailbox) == 0, "the cursor must not have advanced"
    assert node.ledger.get_job("waiting-000001") is None


async def test_the_held_jobs_are_processed_after_recovery(node: Node) -> None:
    """The other half of the promise: deferred means deferred, not lost."""
    _room_state(node, owner=None, observed=True)
    recorder = _Recorder(node)
    node.client.say_signed = recorder.say_signed  # type: ignore[method-assign]

    async def read_room(room: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "room": room,
            "count": 1,
            "first_seq": 5,
            "last_seq": 5,
            "messages": [
                {
                    "seq": 5,
                    "ts": "now",
                    "from": REQUESTER,
                    "nonce": 1,
                    "text": job_line(job_id="deferred-00001", reply_room="mb-p-r"),
                }
            ],
        }

    node.client.read_room = read_room  # type: ignore[method-assign]
    assert await node.poll_mailbox_once(wait=0) == 0
    assert node.ledger.get_job("deferred-00001") is None

    _own_the_room(node)
    assert await node.poll_mailbox_once(wait=0) == 1
    assert node.ledger.get_job("deferred-00001") is not None
    assert node.ledger.cursor(node.mailbox) == 5


# ------------------------------------------------ the audit room owner guard


async def test_an_audit_copy_is_refused_into_a_room_this_node_does_not_own(node: Node) -> None:
    """Guarded independently of the main gate, and of whoever thought they had checked.

    Publishing there would not merely fail to prove anything — it would put a genuine
    receipt in a room where anyone can post a forged one beside it.
    """
    _room_state(node, owner=None, observed=True)
    recorder = _Recorder(node)
    node.client.say_signed = recorder.say_signed  # type: ignore[method-assign]

    assert await node.publish_audit_copy("job-1", {"type": "receipt", "job_id": "job-1"}) is None
    assert recorder.writes == []
    error, _ = node.ledger.get_state(f"last_publish_error:{node.result_room}")
    assert error is not None and "has not confirmed it owns" in error


@pytest.mark.parametrize(
    ("owner", "observed", "error"),
    [
        (None, True, None),  # read succeeded, nobody owns it
        (STRANGER, True, None),  # somebody else owns it
        (None, False, None),  # never checked
        (None, False, "HTTP 503"),  # the check failed
    ],
)
async def test_every_unconfirmed_ownership_state_refuses_the_write(
    node: Node, owner: str | None, observed: bool, error: str | None
) -> None:
    _room_state(node, owner=owner, observed=observed, error=error)
    recorder = _Recorder(node)
    node.client.say_signed = recorder.say_signed  # type: ignore[method-assign]
    assert await node.publish_audit_copy("j", {"type": "receipt", "job_id": "j"}) is None
    assert recorder.writes == []


async def test_the_audit_copy_is_published_once_ownership_is_confirmed(node: Node) -> None:
    _own_the_room(node)
    recorder = _Recorder(node)
    node.client.say_signed = recorder.say_signed  # type: ignore[method-assign]
    assert await node.publish_audit_copy("j", {"type": "receipt", "job_id": "j"}) == 1
    assert recorder.rooms() == {node.result_room}


# --------------------------------------------- the accident, reproduced exactly


async def test_an_attestation_cannot_create_the_room_it_means_to_certify(node: Node) -> None:
    """The regression test for what actually happened.

    Sequence in production: the result room did not exist; `publish-profile` wrote the
    attestation into it, which *created* it; the ownership claim was then refused with
    `already has messages, so it can no longer be claimed`. The write intended to make
    the room trustworthy is what permanently prevented it from being so.

    The order is the safety property, so the write is refused unless ownership has
    already been confirmed by a read.
    """
    _room_state(node, owner=None, observed=True)  # exists-or-not, but not ours
    recorder = _Recorder(node)
    node.client.say_signed = recorder.say_signed  # type: ignore[method-assign]

    attestation = {"v": "1", "type": "profile_attestation", "did": node.did}
    assert await node.publish_audit_copy("profile", attestation) is None
    assert node.result_room not in recorder.rooms(), (
        "publishing here is what made the room unclaimable; it must not happen again"
    )


async def test_inspect_reports_the_unclaimable_state_without_writing(node: Node) -> None:
    """The room as production found it: one message, no owner, no way back."""
    recorder = _Recorder(node)
    node.client.say_signed = recorder.say_signed  # type: ignore[method-assign]

    async def owner(room: str) -> str | None:
        return None

    async def read_room(room: str, **kwargs: Any) -> dict[str, Any]:
        return {"room": room, "count": 1, "first_seq": 1, "last_seq": 1, "messages": []}

    node.client.room_owner = owner  # type: ignore[method-assign]
    node.client.read_room = read_room  # type: ignore[method-assign]

    state = await node.inspect_result_room()
    assert state["verdict"] == "unclaimable"
    assert "WAIT" in state["next_action"]
    assert "24 hours" in state["next_action"]
    assert recorder.writes == [], "inspection never writes"


async def test_inspect_reports_a_reaped_room_as_claimable(node: Node) -> None:
    """After the upstream reclaims it, the name is free and claim-first is possible."""

    async def owner(room: str) -> str | None:
        return None

    async def read_room(room: str, **kwargs: Any) -> dict[str, Any]:
        return {"room": room, "count": 0, "first_seq": None, "last_seq": 0, "messages": []}

    node.client.room_owner = owner  # type: ignore[method-assign]
    node.client.read_room = read_room  # type: ignore[method-assign]

    state = await node.inspect_result_room()
    assert state["verdict"] == "claimable"
    assert "claim it now, before writing" in state["next_action"]


async def test_inspect_stops_on_a_room_owned_by_someone_else(node: Node) -> None:
    async def owner(room: str) -> str | None:
        return STRANGER

    async def read_room(room: str, **kwargs: Any) -> dict[str, Any]:
        return {"room": room, "count": 3, "first_seq": 1, "last_seq": 3, "messages": []}

    node.client.room_owner = owner  # type: ignore[method-assign]
    node.client.read_room = read_room  # type: ignore[method-assign]

    state = await node.inspect_result_room()
    assert state["verdict"] == "owned_by_other"
    assert state["next_action"].startswith("STOP")


async def test_inspect_surfaces_a_read_failure_rather_than_guessing(node: Node) -> None:
    async def owner(room: str) -> str | None:
        raise TechnocoreError("HTTP 503: upstream unavailable")

    node.client.room_owner = owner  # type: ignore[method-assign]
    with pytest.raises(TechnocoreError):
        await node.inspect_result_room()


# ------------------------------------------------------- what the API reports


def test_the_api_reports_the_gate_next_to_the_description(env: dict[str, str]) -> None:
    """The two disagreed once. A reader should be able to see that, not infer it."""
    keystore.generate(Path(env["TCN_IDENTITY_PATH"]), PASSPHRASE)
    node = Node(load_settings())
    node.ledger.set_state("owned_room_owner", None)
    node.ledger.set_state("owned_room_observed", "1")

    client = TestClient(create_app(node), raise_server_exceptions=False)
    availability = client.get("/v1/info").json()["availability"]

    assert availability["accepting_third_party_jobs"] is False
    assert availability["stop_reasons"], "the reasons it will not act are stated"
    assert any("no owner" in r for r in availability["stop_reasons"])


# ------------------------- the guard belongs at the sink, not only at callers


async def test_publish_itself_refuses_the_result_room_when_ownership_is_unconfirmed(
    node: Node,
) -> None:
    """The lowest sink, checked directly.

    The guard was at the callers first. `publish()` is public, so anything written later
    that reaches for the result room would have bypassed every check above it — and here
    bypassing it means writing where a forgery can sit beside a genuine receipt, or
    creating the room and foreclosing ever owning it.
    """
    _room_state(node, owner=None, observed=True)
    recorder = _Recorder(node)
    node.client.say_signed = recorder.say_signed  # type: ignore[method-assign]

    assert await node.publish(node.result_room, {"type": "receipt", "job_id": "j"}) is None
    assert recorder.writes == []


async def test_publish_still_allows_other_rooms_while_the_result_room_is_blocked(
    node: Node,
) -> None:
    """The guard is about one room, not a general freeze: a requester's reply room is
    theirs, and a receipt they can hold is still worth sending."""
    _room_state(node, owner=None, observed=True)
    recorder = _Recorder(node)
    node.client.say_signed = recorder.say_signed  # type: ignore[method-assign]

    assert await node.publish("mb-p-theirs", {"type": "receipt", "job_id": "j"}) == 1
    assert recorder.rooms() == {"mb-p-theirs"}


async def test_publish_writes_to_the_result_room_once_ownership_is_confirmed(
    node: Node,
) -> None:
    _own_the_room(node)
    recorder = _Recorder(node)
    node.client.say_signed = recorder.say_signed  # type: ignore[method-assign]
    assert await node.publish(node.result_room, {"type": "receipt", "job_id": "j"}) == 1
    assert recorder.rooms() == {node.result_room}


# ------------------ the cursor must not advance past work that was not done


async def test_the_cursor_holds_when_the_gate_closes_partway_through_a_cycle(
    node: Node,
) -> None:
    """Safe at the start of the poll, unsafe by the second message.

    The `finally` that advanced the cursor did so whatever `process_message` decided, so
    a lapse mid-cycle dropped a job nobody was ever told about — the precise failure the
    hold exists to prevent, reintroduced one level down.
    """
    _own_the_room(node)
    recorder = _Recorder(node)
    node.client.say_signed = recorder.say_signed  # type: ignore[method-assign]

    async def read_room(room: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "room": room,
            "count": 2,
            "first_seq": 1,
            "last_seq": 2,
            "messages": [
                {
                    "seq": 1,
                    "ts": "now",
                    "from": REQUESTER,
                    "nonce": 1,
                    "text": job_line(job_id="first-00000001", reply_room="mb-p-r"),
                },
                {
                    "seq": 2,
                    "ts": "now",
                    "from": REQUESTER,
                    "nonce": 2,
                    "text": job_line(job_id="second-0000001", reply_room="mb-p-r"),
                },
            ],
        }

    node.client.read_room = read_room  # type: ignore[method-assign]

    real_process = node.process_message

    async def process_then_lapse(message: dict[str, Any], **kwargs: Any) -> bool:
        handled = await real_process(message, **kwargs)
        # Ownership lapses immediately after the first message is dealt with.
        _room_state(node, owner=None, observed=True)
        return handled

    node.process_message = process_then_lapse  # type: ignore[method-assign]

    await node.poll_mailbox_once(wait=0)

    assert node.ledger.get_job("first-00000001") is not None, "the first was processed"
    assert node.ledger.get_job("second-0000001") is None, "the second was not"
    assert node.ledger.cursor(node.mailbox) == 1, "the cursor stopped at the last one done"


async def test_a_message_that_raises_still_advances_the_cursor(node: Node) -> None:
    """A bad line is handled, not held: re-reading it forever would wedge the queue."""
    _own_the_room(node)

    async def read_room(room: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "room": room,
            "count": 1,
            "first_seq": 3,
            "last_seq": 3,
            "messages": [{"seq": 3, "ts": "now", "from": REQUESTER, "nonce": 1, "text": "{"}],
        }

    async def boom(message: dict[str, Any], **kwargs: Any) -> bool:
        raise RuntimeError("handler exploded")

    node.client.read_room = read_room  # type: ignore[method-assign]
    node.process_message = boom  # type: ignore[method-assign]

    await node.poll_mailbox_once(wait=0)
    assert node.ledger.cursor(node.mailbox) == 3


async def test_a_ring_gap_is_detected_and_recorded(node: Node) -> None:
    """Holding the cursor defers work; it does not preserve it.

    The mailbox is a ring. Saying "deferred, not lost" without noticing a gap would be
    the same class of overclaim this release exists to remove.
    """
    _own_the_room(node)
    node.ledger.set_cursor(node.mailbox, 10)

    async def read_room(room: str, **kwargs: Any) -> dict[str, Any]:
        return {"room": room, "count": 0, "first_seq": 25, "last_seq": 30, "messages": []}

    node.client.read_room = read_room  # type: ignore[method-assign]
    await node.poll_mailbox_once(wait=0)

    gap, _ = node.ledger.get_state("mailbox_gap")
    assert gap is not None and "14 message(s)" in gap, gap


# ----------------------------------- a whitespace public URL is not a public URL


@pytest.mark.parametrize("raw", ["", "   ", "\t\n"])
def test_a_blank_public_url_reads_as_blank(raw: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate asks `if not public_url`, and `"   "` is true.

    Configuration that is almost blank must read as blank, or a whitespace typo silently
    opens a gate written to stay shut.
    """
    monkeypatch.setenv("TCN_PUBLIC_URL", raw)
    assert load_settings().public_url == ""


@pytest.mark.parametrize("raw", ["http://x.example", "agent.example.com", "https://", "ftp://x"])
def test_a_public_url_that_is_not_https_is_refused(
    raw: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A requester who cannot fetch the receipt back over a trusted channel cannot
    verify it, so an unverifiable endpoint is not advertised as one."""
    from technocore_node.config import ConfigError

    monkeypatch.setenv("TCN_PUBLIC_URL", raw)
    with pytest.raises(ConfigError):
        load_settings()


def test_a_whitespace_public_url_does_not_open_the_gate(
    node: Node, monkeypatch: pytest.MonkeyPatch
) -> None:
    _own_the_room(node)
    object.__setattr__(node.settings, "public_url", "")
    assert node.can_accept_third_party_jobs() is False
