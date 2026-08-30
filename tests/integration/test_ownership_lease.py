"""The claim is a lease, and something has to renew it.

The upstream deletes any note with no write for seven days — `retention_seconds` in
`/.well-known/agent.json`, with no exemption for the signed namespaces. Ownership is a
note. So a room claimed and then left alone reverts to "an ordinary open room", and the
first stranger to write to it makes it permanently unclaimable: the accident of
2026-08-28 again, with a seven-day fuse instead of an immediate one.

Every other guard in this codebase asks whether the room *is* ours. None of them kept it
that way. These tests are about the one that does — and, at least as much, about what it
must refuse to do, because a loop that can write to an ownership note without `if_absent`
is one bug away from taking somebody else's room.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2 as httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_node.config import load_settings
from technocore_node.crypto import didkey, keystore
from technocore_node.ledger.db import utcnow
from technocore_node.protocol.client import TechnocoreError
from technocore_node.service.node import Node

PASSPHRASE = b"test-secret-do-not-use"


@pytest.fixture
def node(env: dict[str, str]) -> Node:
    keystore.generate(Path(env["TCN_IDENTITY_PATH"]), PASSPHRASE)
    return Node(load_settings())


class Upstream:
    """A tiny stand-in that records what was actually sent to the ownership note."""

    def __init__(self, owner: str | None) -> None:
        self.owner = owner
        self.writes: list[dict[str, Any]] = []
        self.claims = 0
        self.claim_succeeds = True
        # The upstream shares one replay counter across both signed namespaces and
        # advances it on every accepted write. A mock that returns a constant would let a
        # replayed nonce pass here and fail against the real server.
        self.nonce = 1

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/kv/room-owners/") and request.method == "GET":
            if self.owner is None:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, text=f"!! UNTRUSTED CONTENT\n\n{self.owner}\n")
        if path.startswith("/kv/room-nonce/"):
            return httpx.Response(200, text=f"!! UNTRUSTED CONTENT\n\n{self.nonce}\n")
        if path.startswith("/kv/room-owners/") and request.method == "POST":
            body = json.loads(request.content)
            if int(body["nonce"]) <= self.nonce:
                return httpx.Response(409, text="nonce not advancing")
            if body.get("if_absent"):
                self.claims += 1
                if not self.claim_succeeds:
                    return httpx.Response(403, text="already has messages")
                self.owner = body["value"]
                self.nonce = int(body["nonce"])
                return httpx.Response(200, text="ok")
            self.writes.append(body)
            self.owner = body["value"]
            self.nonce = int(body["nonce"])
            return httpx.Response(200, text="ok")
        return httpx.Response(200, text='{"messages":[],"count":0,"last_seq":0}')


@pytest.fixture
def upstream(node: Node) -> Upstream:
    server = Upstream(owner=node.did)
    node.client._http = httpx.AsyncClient(  # type: ignore[attr-defined]
        transport=httpx.MockTransport(server.handler), base_url="https://upstream.invalid"
    )
    return server


# ------------------------------------------------------------- renewing


async def test_a_lease_this_node_holds_is_renewed(node: Node, upstream: Upstream) -> None:
    """The whole point: a write that resets the retention clock."""
    assert await node.maintain_result_room_ownership() == "renewed"

    assert len(upstream.writes) == 1
    assert upstream.writes[0]["value"] == node.did
    assert upstream.writes[0]["did"] == node.did
    # No `if_absent`: a refresh must overwrite the note, which is exactly why the
    # ownership check before it is load-bearing rather than decorative.
    assert "if_absent" not in upstream.writes[0]


async def test_renewal_is_recorded_so_a_stalled_lease_is_visible(
    node: Node, upstream: Upstream
) -> None:
    """A lease nobody can see expiring is a lease nobody renews."""
    assert node.ledger.get_state("owned_room_renewed")[0] is None

    await node.maintain_result_room_ownership()

    when, _ = node.ledger.get_state("owned_room_renewed")
    assert when is not None


async def test_the_nonce_advances_so_a_renewal_is_not_a_replay(
    node: Node, upstream: Upstream
) -> None:
    """The upstream shares one replay counter across both signed namespaces."""
    await node.maintain_result_room_ownership()
    await node.maintain_result_room_ownership()

    first, second = (int(w["nonce"]) for w in upstream.writes)
    assert second > first


# ------------------------------------------------- what it must not do


async def test_it_never_writes_over_another_keys_ownership(node: Node, upstream: Upstream) -> None:
    """The refusal that separates a maintenance loop from a room theft.

    `refresh_room_ownership` omits `if_absent` — it has to, or it could not renew — so
    the write itself would succeed against a stranger's note. Nothing but this check
    stands between the two.
    """
    upstream.owner = didkey.encode_did(Ed25519PrivateKey.generate().public_key())

    assert await node.maintain_result_room_ownership() == "owned_by_other"

    assert upstream.writes == []
    assert upstream.claims == 0


async def test_the_client_refuses_directly_too_not_only_through_the_node(
    node: Node, upstream: Upstream
) -> None:
    """Checked where the write happens, not only at the caller that happens to check."""
    upstream.owner = didkey.encode_did(Ed25519PrivateKey.generate().public_key())

    assert await node.client.refresh_room_ownership(node.result_room) is False
    assert upstream.writes == []


async def test_it_refuses_a_room_that_cannot_be_owned(node: Node, upstream: Upstream) -> None:
    """Only `d-` rooms are ownable upstream; anything else is a caller error."""
    for room in ("mb-tc-jobs-x", "lobby", "p-private", "not a name"):
        with pytest.raises(TechnocoreError):
            await node.client.refresh_room_ownership(room)
    assert upstream.writes == []


async def test_a_read_failure_does_not_become_a_blind_write(node: Node, upstream: Upstream) -> None:
    """Not knowing who owns it is not permission to write to it."""

    def refuse(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/kv/room-owners/") and request.method == "GET":
            return httpx.Response(503, text="unavailable")
        return upstream.handler(request)

    node.client._http = httpx.AsyncClient(  # type: ignore[attr-defined]
        transport=httpx.MockTransport(refuse), base_url="https://upstream.invalid"
    )

    assert await node.maintain_result_room_ownership() == "failed"
    assert upstream.writes == []


# ---------------------------------------------------------- recovering


async def test_a_lapsed_lease_is_reclaimed(node: Node, upstream: Upstream) -> None:
    """If it did expire, take it back — through the claim path, which cannot overwrite."""
    upstream.owner = None

    assert await node.maintain_result_room_ownership() == "claimed"

    assert upstream.claims == 1
    assert upstream.owner == node.did


async def test_a_room_that_can_no_longer_be_claimed_is_reported_not_written_to(
    node: Node, upstream: Upstream
) -> None:
    """The 2026-08-28 state. Nothing to do but say so — and above all, write nothing."""
    upstream.owner = None
    upstream.claim_succeeds = False

    assert await node.maintain_result_room_ownership() == "unclaimable"

    assert upstream.writes == []
    assert node.owns_result_room() is False


async def test_reclaiming_never_writes_to_the_room_itself(node: Node, upstream: Upstream) -> None:
    """The original accident was a write that created the room before it was claimed.

    Recovery must touch the ownership note and nothing else: a write to `/r/<room>` here
    would recreate exactly the state it is supposed to be recovering from.
    """
    posts: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            posts.append(request.url.path)
        return upstream.handler(request)

    node.client._http = httpx.AsyncClient(  # type: ignore[attr-defined]
        transport=httpx.MockTransport(record), base_url="https://upstream.invalid"
    )
    upstream.owner = None

    await node.maintain_result_room_ownership()

    assert posts == [f"/kv/room-owners/{node.result_room}"]
    assert not any(p.startswith("/r/") for p in posts)


# -------------------------------------------------------- when it runs


async def test_the_lease_is_maintained_even_while_intake_is_disabled(
    node: Node, upstream: Upstream
) -> None:
    """Which is how production runs, and is when the room would otherwise be lost.

    Tying renewal to the mailbox loop would mean the lease expires precisely while the
    node is being careful — switched off after an incident is the longest it will ever go
    without polling, and the calendar does not pause for it.
    """
    object.__setattr__(node.settings, "mailbox_enabled", False)
    object.__setattr__(node.settings, "watcher_enabled", False)

    node.start_background()
    try:
        names = {t.get_name() for t in node._tasks}
    finally:
        for task in node._tasks:
            task.cancel()
        for task in node._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task

    assert "ownership" in names
    assert "mailbox" not in names


def test_the_renewal_cadence_leaves_room_for_failure() -> None:
    """Six hours against a seven-day expiry: a lease survives a day of outages.

    A cadence that only just fits the window is one that fails on the first bad day, and
    the failure is silent until the room is gone.
    """
    upstream_retention = 7 * 24 * 3600
    assert upstream_retention >= Node.OWNERSHIP_RENEWAL_SECONDS * 8


# ------------------------------------------------------- being visible


async def test_the_lease_age_is_published(node: Node, upstream: Upstream) -> None:
    """A lease nobody can watch is one nobody notices stalling.

    Reporting `owner == us` says everything is fine right up until the moment it is not:
    the room is ours on the sixth day and gone on the eighth, and nothing in between
    reads differently. The age of the last renewal is the number that changes first.
    """
    before = node.availability()["ownership_lease"]
    assert before["renewed_at"] is None
    assert before["renewed_seconds_ago"] is None
    assert before["upstream_expiry_seconds"] == 7 * 24 * 3600

    await node.maintain_result_room_ownership()

    after = node.availability()["ownership_lease"]
    assert after["renewed_at"] is not None
    assert 0 <= after["renewed_seconds_ago"] < 60


async def test_a_failed_renewal_does_not_backdate_the_lease(node: Node, upstream: Upstream) -> None:
    """The recorded time must mean "renewed", not "tried".

    A timestamp written on the attempt would make a lease that has been failing for six
    days look freshly renewed — the one reading that would let it expire unnoticed.
    """
    await node.maintain_result_room_ownership()
    renewed_at = node.availability()["ownership_lease"]["renewed_at"]

    upstream.owner = didkey.encode_did(Ed25519PrivateKey.generate().public_key())
    assert await node.maintain_result_room_ownership() == "owned_by_other"

    assert node.availability()["ownership_lease"]["renewed_at"] == renewed_at


def test_a_future_renewal_timestamp_is_not_reported_as_fresh(node: Node) -> None:
    """A clock that jumped backwards must not look like a renewal that just happened."""
    node.ledger.set_state("owned_room_renewed", "2099-01-01T00:00:00+00:00")

    assert node.availability()["ownership_lease"]["renewed_seconds_ago"] is None


# ------------------------------------------------------ failing safely


async def _nothing() -> None:
    """A stand-in that does not itself sleep — the sleeps are what is being measured."""


async def test_a_contended_nonce_is_retried_rather_than_treated_as_a_loss(
    node: Node, upstream: Upstream
) -> None:
    """409 means the replay counter moved, not that the room is gone.

    `/kv/room-nonce/<room>` is shared with the allow-list namespace and advances on every
    accepted signed write, so it can pass the read before this write lands. Giving up on
    a 409 would surrender a renewal to a race that a second, higher nonce settles.
    """
    real = upstream.handler
    seen = {"n": 0}

    def conflict_once(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.startswith("/kv/room-owners/"):
            seen["n"] += 1
            if seen["n"] == 1:
                return httpx.Response(409, text="nonce not advancing")
        return real(request)

    node.client._http = httpx.AsyncClient(  # type: ignore[attr-defined]
        transport=httpx.MockTransport(conflict_once), base_url="https://upstream.invalid"
    )

    assert await node.maintain_result_room_ownership() == "renewed"
    assert seen["n"] == 2


async def test_a_persistent_conflict_gives_up_without_claiming_a_renewal(
    node: Node, upstream: Upstream
) -> None:
    """Two attempts, then hand it back. Reporting success here would hide the expiry."""

    def always_conflict(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.startswith("/kv/room-owners/"):
            return httpx.Response(409, text="nonce not advancing")
        return upstream.handler(request)

    node.client._http = httpx.AsyncClient(  # type: ignore[attr-defined]
        transport=httpx.MockTransport(always_conflict), base_url="https://upstream.invalid"
    )

    assert await node.maintain_result_room_ownership() == "failed"
    assert node.availability()["ownership_lease"]["renewed_at"] is None


async def test_a_reclaim_resets_the_published_lease_age(node: Node, upstream: Upstream) -> None:
    """A claim writes the same note a renewal writes, so it resets the same clock."""
    upstream.owner = None

    assert await node.maintain_result_room_ownership() == "claimed"

    assert node.availability()["ownership_lease"]["renewed_at"] is not None


async def _drive(
    node: Node, monkeypatch: pytest.MonkeyPatch, outcomes: list[str], cycles: float
) -> list[float]:
    """Run the lease loop for `cycles` sleeps, returning the gap before each renewal.

    Sleeps are now observation-sized, so the interesting number is not any one of them —
    it is how much time passes between one renewal attempt and the next.
    """
    slept: list[float] = []
    gaps: list[float] = []
    since = 0.0
    clock = 0.0
    pending = iter(outcomes)
    loop = asyncio.get_running_loop()
    base = datetime(2026, 1, 1, tzinfo=UTC)

    class Clock:
        """Both clocks, moving together. Mixing a fake monotonic with the real wall clock
        leaves a sub-second residual that the loop spends an extra cycle on — an artefact
        of the harness, not of the code under test."""

        @staticmethod
        def now(tz: object = None) -> Any:
            return base + timedelta(seconds=clock)

    async def record(seconds: float) -> None:
        # A sleep that does not sleep still has to move the clock the loop reads, or the
        # deadline it computes never arrives and the test measures nothing.
        nonlocal since, clock
        slept.append(seconds)
        since += seconds
        clock += seconds
        if len(slept) >= cycles:
            raise asyncio.CancelledError

    async def renew() -> str:
        nonlocal since
        gaps.append(since)
        since = 0.0
        # Deliberately does NOT record a renewal. An earlier version of this helper did,
        # which made the wall-clock arm read fresh on every cycle and hid the defect it
        # was supposed to catch: a state the loop had chosen to wait out looked overdue
        # every five minutes.
        return next(pending)

    monkeypatch.setattr(asyncio, "sleep", record)
    monkeypatch.setattr(loop, "time", lambda: clock)
    monkeypatch.setattr("technocore_node.service.node.datetime", Clock)
    monkeypatch.setattr(node, "maintain_result_room_ownership", renew)
    monkeypatch.setattr(node, "observe_reachability", _nothing)

    with pytest.raises(asyncio.CancelledError):
        await node.run_ownership_lease()

    assert max(slept) <= Node.OWNERSHIP_OBSERVATION_SECONDS
    return gaps


async def test_a_failed_renewal_is_retried_in_seconds_not_hours(
    node: Node, upstream: Upstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fixed cadence waited longest exactly when waiting was worst.

    A node restarting on day six, whose first attempt met a 503, slept another six hours
    — past the seven-day expiry — before trying again. The renewal runs on a schedule;
    a failure has to run on a clock.
    """
    floor = Node.OWNERSHIP_RETRY_FLOOR_SECONDS
    # Enough cycles to cross a full renewal interval in observation-sized steps, so the
    # reset after the success is observed rather than assumed.
    cycles = 4 + Node.OWNERSHIP_RENEWAL_SECONDS // Node.OWNERSHIP_OBSERVATION_SECONDS
    gaps = await _drive(node, monkeypatch, ["failed", "failed", "renewed", "failed"], cycles)

    assert gaps[0] == 0  # the first attempt is immediate, on startup
    assert gaps[1] == floor
    assert gaps[2] == floor * 2
    # A success resets both the delay and the backoff, so the next failure starts over.
    assert gaps[3] == Node.OWNERSHIP_RENEWAL_SECONDS


async def test_ownership_is_observed_far_more_often_than_it_is_renewed(
    node: Node, upstream: Upstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two jobs, two clocks, and tying them together left the gate stale by default.

    A renewal is a write, and six hours between them is right against a seven-day expiry.
    An observation expires in fifteen minutes. A loop that only looked when it wrote left
    the gate reading `stale` for the rest of the interval — harmless while the mailbox
    loop is observing anyway, and the difference between working and not for any intake
    that runs without one behind it.
    """
    looks = 0

    async def observe() -> None:
        nonlocal looks
        looks += 1

    slept: list[float] = []
    clock = 0.0
    loop = asyncio.get_running_loop()

    async def record(seconds: float) -> None:
        nonlocal clock
        slept.append(seconds)
        clock += seconds
        if len(slept) >= 12:
            raise asyncio.CancelledError

    async def renew() -> str:
        return "renewed"

    monkeypatch.setattr(asyncio, "sleep", record)
    monkeypatch.setattr(loop, "time", lambda: clock)
    monkeypatch.setattr(node, "maintain_result_room_ownership", renew)
    monkeypatch.setattr(node, "observe_reachability", observe)

    with pytest.raises(asyncio.CancelledError):
        await node.run_ownership_lease()

    assert looks == 12
    assert max(slept) <= Node.OWNERSHIP_OBSERVATION_SECONDS
    # The observation interval must leave the gate's freshness limit real room, or the
    # gate closes between two consecutive looks and the loop is decorative.
    assert Node.OWNERSHIP_OBSERVATION_SECONDS * 2 <= Node.OWNERSHIP_MAX_AGE_SECONDS


async def test_a_state_only_the_upstream_can_change_is_not_hammered(
    node: Node, upstream: Upstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`owned_by_other` and `unclaimable` are not fixed by asking again in a minute."""
    cycles = 2 + Node.OWNERSHIP_RENEWAL_SECONDS // Node.OWNERSHIP_OBSERVATION_SECONDS
    gaps = await _drive(node, monkeypatch, ["owned_by_other", "unclaimable"], cycles)

    assert gaps[1] == Node.OWNERSHIP_RENEWAL_SECONDS


def test_the_backoff_can_never_exceed_the_renewal_interval() -> None:
    """Doubling forever would reinvent the bug it exists to fix."""
    floor, interval = Node.OWNERSHIP_RETRY_FLOOR_SECONDS, Node.OWNERSHIP_RENEWAL_SECONDS
    for failures in range(1, 40):
        assert min(floor * 2 ** (failures - 1), interval) <= interval


# ------------------------------------------------- the lease is a gate


def _owned_and_renewed(node: Node, renewed: str | None) -> None:
    node.ledger.set_state("owned_room_owner", node.did)
    node.ledger.set_state("owned_room_observed", "1")
    node.ledger.set_state("owned_room_error", None)
    node.ledger.set_state("owned_room_renewed", renewed)
    object.__setattr__(node.settings, "public_url", "https://example.invalid")
    object.__setattr__(node.settings, "mailbox_enabled", True)


def test_a_stalled_lease_closes_the_gate(node: Node) -> None:
    """Publishing the age was not enough. Nothing was acting on it.

    Ownership can be verified fresh and still be days from expiry: the observation says
    who owns the room now, and only the lease says whether it will be ours when a receipt
    published today is read tomorrow. With renewals failing, `observe_reachability` kept
    confirming ownership and the gate stayed open right up until the sweep — after which
    a fresh local observation would have let this node write to a room it no longer owned.
    That is the original accident, reached by a different road.
    """
    stale = (
        datetime.now(UTC) - timedelta(seconds=Node.OWNERSHIP_LEASE_MAX_AGE_SECONDS + 60)
    ).isoformat()
    _owned_and_renewed(node, stale)

    open_now, reasons = node.safety_state()

    assert open_now is False
    assert any("lease was last renewed" in r for r in reasons)
    assert node.availability()["accepting_third_party_jobs"] is False


def test_a_lease_never_renewed_closes_the_gate(node: Node) -> None:
    """An ownership record with no renewal behind it is a record, not a lease."""
    _owned_and_renewed(node, None)

    open_now, reasons = node.safety_state()

    assert open_now is False
    assert any("never been renewed" in r for r in reasons)


def test_a_live_lease_opens_it(node: Node) -> None:
    """The condition has to be satisfiable, or it is not a gate but a wall."""
    _owned_and_renewed(node, utcnow())

    assert node.safety_state() == (True, [])


def test_the_lease_limit_leaves_days_of_warning(node: Node) -> None:
    """Closing the gate on the last afternoon would be an alarm, not a safeguard.

    The point of refusing early is that somebody can still fix it: the gate shuts four
    missed renewals in, with six days left before the upstream deletes the note.
    """
    assert Node.OWNERSHIP_LEASE_MAX_AGE_SECONDS >= 4 * Node.OWNERSHIP_RENEWAL_SECONDS
    assert (
        Node.UPSTREAM_NOTE_RETENTION_SECONDS - Node.OWNERSHIP_LEASE_MAX_AGE_SECONDS >= 5 * 24 * 3600
    )


def test_a_room_owned_by_another_key_reports_that_first(node: Node) -> None:
    """A room that is not ours has a more immediate problem than an unrenewed lease."""
    _owned_and_renewed(node, None)
    node.ledger.set_state(
        "owned_room_owner", "did:key:z6MkfyqMqvC4QGbyMAzpL4haXspn1f1ZGUwhdPearjqPpnnc"
    )

    _, reasons = node.safety_state()

    assert any("owned by another key" in r for r in reasons)
    assert not any("lease" in r for r in reasons)


# ----------------------------------------------------- the sink, too


async def test_a_dead_lease_stops_the_write_itself_not_only_the_gate(
    node: Node, upstream: Upstream
) -> None:
    """`reconcile_audit_copies` runs while the gate is shut. On purpose.

    Receipts owed from before a closure are supposed to land once things recover, so the
    audit publisher is deliberately not behind the intake gate. Its guard is
    `owns_result_room()` — and while that checked only who owns the room, a node whose
    renewals had been failing for a week would have gone on writing audit copies right up
    to the sweep. The first of them turns a room that could have been reclaimed into one
    with messages in it, which can never be claimed again.
    """
    _owned_and_renewed(node, utcnow())
    assert node.owns_result_room() is True

    stale = (
        datetime.now(UTC) - timedelta(seconds=Node.OWNERSHIP_LEASE_MAX_AGE_SECONDS + 60)
    ).isoformat()
    node.ledger.set_state("owned_room_renewed", stale)

    assert node.owns_result_room() is False
    assert await node.publish(node.result_room, {"type": "receipt"}) is None
    assert await node.publish_audit_copy("job-1", {"type": "receipt", "job_id": "job-1"}) is None
    assert await node.sync_owned_room() == 0


async def test_a_failure_streak_stops_the_write_even_with_a_fresh_timestamp(
    node: Node, upstream: Upstream
) -> None:
    """The clock-independent half. An age is a subtraction from `now`.

    A clock moved backwards — or a ledger restored, or a row edited — makes a stale lease
    look freshly renewed, and every check built on that timestamp opens again. A count of
    consecutive failures cannot be walked back by changing the time.
    """
    _owned_and_renewed(node, utcnow())
    node.ledger.set_state(
        "owned_room_renewal_failures", str(Node.OWNERSHIP_MAX_CONSECUTIVE_FAILURES)
    )

    assert node.owns_result_room() is False
    assert node.safety_state()[0] is False
    assert any("times in a row" in r for r in node.safety_state()[1])
    assert await node.publish_audit_copy("job-2", {"type": "receipt", "job_id": "job-2"}) is None


async def test_a_successful_renewal_clears_the_streak(node: Node, upstream: Upstream) -> None:
    """Otherwise one bad week would shut the node permanently."""
    node.ledger.set_state("owned_room_renewal_failures", "9")

    assert await node.maintain_result_room_ownership() == "renewed"

    assert node.ledger.get_state("owned_room_renewal_failures")[0] == "0"
    assert node.availability()["ownership_lease"]["consecutive_failures"] == 0
    assert node.availability()["ownership_lease"]["live"] is True


async def test_every_failing_path_counts(node: Node, upstream: Upstream) -> None:
    """A failure that is not counted is a failure the clock-independent check cannot see."""

    def unavailable(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    node.client._http = httpx.AsyncClient(  # type: ignore[attr-defined]
        transport=httpx.MockTransport(unavailable), base_url="https://upstream.invalid"
    )

    for expected in range(1, 4):
        assert await node.maintain_result_room_ownership() == "failed"
        assert node.ledger.get_state("owned_room_renewal_failures")[0] == str(expected)


async def test_the_recovery_command_is_not_defeated_by_its_own_guard(
    node: Node, upstream: Upstream
) -> None:
    """Claim, then attest. The second step must not be refused because of the first.

    `recover-result-room --claim --attest` is the documented recovery: inspect, claim,
    read back, then publish the attestation. The sink guard added in this release requires
    a live lease — and a CLI claim recorded nothing, so the node had just taken the room
    and had no record saying so. The attestation was refused by the safety check meant to
    protect it, which is a safe failure and still a broken procedure.
    """
    upstream.owner = None
    assert node.owns_result_room() is False

    claimed = await node.client.claim_room(node.result_room)
    assert claimed is True
    node.record_lease_outcome(node.result_room, renewed=True)
    await node.observe_reachability()

    assert node.owns_result_room() is True
    assert node.availability()["ownership_lease"]["live"] is True


async def test_a_refused_claim_does_not_start_a_lease(node: Node, upstream: Upstream) -> None:
    """Only a write that happened may reset the clock.

    Recording on the attempt rather than the result would mark a lease live on a node that
    had just been told it cannot have the room — and the sink guard would then let it
    write there.
    """
    upstream.owner = None
    upstream.claim_succeeds = False

    assert await node.client.claim_room(node.result_room) is False
    assert node.availability()["ownership_lease"]["renewed_at"] is None
    assert node.owns_result_room() is False


async def test_claiming_an_unrelated_room_does_not_start_the_result_rooms_lease(
    node: Node, upstream: Upstream
) -> None:
    """`claim-room` takes whichever room it is given. There is one lease, and it is not that one.

    Recording the outcome without naming the room meant claiming any free `d-` room marked
    the *result* room's lease live — and the sink guard, which had just been taught to
    require a live lease, would then permit writes to a room nothing had renewed. The room
    is a required argument now, so the mistake is not one a caller has to remember not to
    make.
    """
    assert node.availability()["ownership_lease"]["renewed_at"] is None

    node.record_lease_outcome("d-some-other-room", renewed=True)

    assert node.availability()["ownership_lease"]["renewed_at"] is None
    assert node.owns_result_room() is False


async def test_a_failure_elsewhere_does_not_count_against_this_lease(node: Node) -> None:
    """The same argument in the other direction: one room's trouble is not another's."""
    node.record_lease_outcome("d-some-other-room", renewed=False)

    assert node.availability()["ownership_lease"]["consecutive_failures"] == 0


async def test_a_stalled_loop_does_not_carry_a_stale_deadline_forward(
    node: Node, upstream: Upstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Time passing and the loop noticing are not the same thing.

    The counter used to lose exactly the sleep it asked for. A `sleep(300)` that returns
    six days late — a suspended host, a blocked event loop — still cost it 300, so it went
    on believing hours remained while the lease expired underneath. The deadline is read
    from the clock now, so a late wake-up is due immediately.
    """
    clock = 0.0
    loop = asyncio.get_running_loop()
    renewals: list[float] = []

    async def record(seconds: float) -> None:
        nonlocal clock
        # The stall: asked for 300 seconds, gone for six days.
        clock += 6 * 24 * 3600 if len(renewals) == 1 else seconds
        if len(renewals) >= 2:
            raise asyncio.CancelledError

    async def renew() -> str:
        renewals.append(clock)
        return "renewed"

    monkeypatch.setattr(asyncio, "sleep", record)
    monkeypatch.setattr(loop, "time", lambda: clock)
    monkeypatch.setattr(node, "maintain_result_room_ownership", renew)
    monkeypatch.setattr(node, "observe_reachability", _nothing)

    with pytest.raises(asyncio.CancelledError):
        await node.run_ownership_lease()

    # Two renewals: one at startup, one the moment the loop came back — not one 300
    # seconds into a six-hour countdown it had already slept through.
    assert len(renewals) == 2
    assert renewals[1] >= 6 * 24 * 3600


async def test_a_suspended_host_renews_on_the_wall_clock_deadline(
    node: Node, upstream: Upstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`time.monotonic` does not advance while a Linux host is suspended.

    So the loop's own deadline cannot see that week: it would wake with the countdown it
    went to sleep with and a lease already gone. A wall-clock deadline, set from the same
    delay at the same moment, does see it — and because it was set from the same delay it
    can never shorten a wait that was chosen deliberately, which is what reading the
    recorded renewal time instead got wrong.

    Exercised inside one running loop, on the `wall_due` that loop is holding, rather than
    by starting a second one: a fresh start renews immediately and would pass either way.
    """
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "time", lambda: 0.0)  # a monotonic clock that never moves
    renewals = 0
    cycles = 0
    real_datetime = datetime
    offset = timedelta()

    class Clock:
        @staticmethod
        def now(tz: object = None) -> Any:
            return real_datetime.now(tz) + offset  # type: ignore[arg-type]

    async def renew() -> str:
        nonlocal renewals
        renewals += 1
        return "renewed"

    async def record(seconds: float) -> None:
        nonlocal cycles, offset
        cycles += 1
        if cycles == 1:
            # The suspend, while the monotonic clock stands still.
            offset = timedelta(days=7)
        if cycles >= 3:
            raise asyncio.CancelledError

    monkeypatch.setattr("technocore_node.service.node.datetime", Clock)
    monkeypatch.setattr(node, "maintain_result_room_ownership", renew)
    monkeypatch.setattr(node, "observe_reachability", _nothing)
    monkeypatch.setattr(asyncio, "sleep", record)

    with pytest.raises(asyncio.CancelledError):
        await node.run_ownership_lease()

    # One at startup, and one on waking — from the wall-clock deadline this same loop was
    # already holding, with `loop.time()` never having moved.
    assert renewals == 2


async def test_the_sleep_honours_whichever_deadline_is_nearer(
    node: Node, upstream: Upstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sleeping on the monotonic deadline alone kept the promise only to within 300s.

    Which is harmless at this cadence and still wrong: a docstring that overstates a
    safety property is how the next person comes to rely on one that is not there.
    """
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "time", lambda: 0.0)
    slept: list[float] = []
    base = datetime(2026, 1, 1, tzinfo=UTC)
    now = base

    class Clock:
        @staticmethod
        def now(tz: object = None) -> Any:
            return now

    async def renew() -> str:
        return "renewed"

    async def record(seconds: float) -> None:
        nonlocal now
        slept.append(seconds)
        # Six hours all but thirty seconds have passed on the wall clock; monotonic still
        # believes the full interval remains.
        now = base + timedelta(seconds=Node.OWNERSHIP_RENEWAL_SECONDS - 30)
        if len(slept) >= 2:
            raise asyncio.CancelledError

    monkeypatch.setattr("technocore_node.service.node.datetime", Clock)
    monkeypatch.setattr(node, "maintain_result_room_ownership", renew)
    monkeypatch.setattr(node, "observe_reachability", _nothing)
    monkeypatch.setattr(asyncio, "sleep", record)

    with pytest.raises(asyncio.CancelledError):
        await node.run_ownership_lease()

    assert slept[0] == Node.OWNERSHIP_OBSERVATION_SECONDS
    # The second wait is what the nearer deadline has left, not another full interval.
    assert slept[1] == 30


def test_the_backoff_counter_stops_at_the_ceiling() -> None:
    """A number that only goes up is one nobody can reason about a week into an outage."""
    floor, cap = Node.OWNERSHIP_RETRY_FLOOR_SECONDS, Node.OWNERSHIP_RENEWAL_SECONDS
    # It has to reach the ceiling, or the backoff would stop short of the interval.
    assert floor * 2 ** (Node._MAX_BACKOFF_DOUBLINGS - 1) >= cap
    # And it must not be so far past it that the shift is doing pointless work: the
    # largest delay it can compute stays within an order of magnitude of the cap.
    assert floor * 2 ** (Node._MAX_BACKOFF_DOUBLINGS - 1) <= cap * 10


async def test_a_state_only_the_upstream_can_change_is_not_written_to_every_cycle(
    node: Node, upstream: Upstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`unclaimable` means the upstream must change before anything here can.

    The deadline used to be derived from the recorded renewal time — which `unclaimable`
    never updates, because nothing was renewed. So the wait the loop had deliberately
    chosen looked overdue on the very next cycle, and the node sent a claim to somebody
    else's server every five minutes instead of every six hours.
    """
    attempts = 0

    async def unclaimable() -> str:
        nonlocal attempts
        attempts += 1
        return "unclaimable"

    node.ledger.set_state("owned_room_renewed", None)
    cycles = 3 + Node.OWNERSHIP_RENEWAL_SECONDS // Node.OWNERSHIP_OBSERVATION_SECONDS
    monkeypatch.setattr(node, "maintain_result_room_ownership", unclaimable)

    clock = 0.0
    loop = asyncio.get_running_loop()
    seen = 0

    async def record(seconds: float) -> None:
        nonlocal clock, seen
        clock += seconds
        seen += 1
        if seen >= cycles:
            raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "sleep", record)
    monkeypatch.setattr(loop, "time", lambda: clock)
    monkeypatch.setattr(node, "observe_reachability", _nothing)

    with pytest.raises(asyncio.CancelledError):
        await node.run_ownership_lease()

    # One at startup, one when six hours had actually passed. Not one per cycle.
    assert attempts == 2


async def test_an_observation_failure_does_not_push_out_a_renewal(
    node: Node, upstream: Upstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two concerns, two `try` blocks. A failed look says nothing about the lease."""
    attempts = 0

    async def renew() -> str:
        nonlocal attempts
        attempts += 1
        return "renewed"

    async def blind() -> None:
        raise TechnocoreError("upstream unavailable")

    clock = 0.0
    loop = asyncio.get_running_loop()
    seen = 0
    cycles = 2 + Node.OWNERSHIP_RENEWAL_SECONDS // Node.OWNERSHIP_OBSERVATION_SECONDS

    async def record(seconds: float) -> None:
        nonlocal clock, seen
        clock += seconds
        seen += 1
        if seen >= cycles:
            raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "sleep", record)
    monkeypatch.setattr(loop, "time", lambda: clock)
    monkeypatch.setattr(node, "maintain_result_room_ownership", renew)
    monkeypatch.setattr(node, "observe_reachability", blind)

    with pytest.raises(asyncio.CancelledError):
        await node.run_ownership_lease()

    # The renewal kept its own schedule: once at startup, once six hours later.
    assert attempts == 2


async def test_a_ledger_failure_does_not_kill_the_loop(
    node: Node, upstream: Upstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The task that protects the lease must not be the one that dies.

    An earlier version read the ledger to decide whether a renewal was due, and read it
    again inside the handler for the exception that read had raised. The second read
    raised the same way, out of the handler, and the loop ended — taking the renewal and
    the five-minute observation with it, silently.
    """
    calls = 0

    async def sometimes() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("ledger is unavailable")
        return "renewed"

    clock = 0.0
    loop = asyncio.get_running_loop()
    seen = 0

    async def record(seconds: float) -> None:
        nonlocal clock, seen
        clock += seconds
        seen += 1
        if seen >= 4:
            raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "sleep", record)
    monkeypatch.setattr(loop, "time", lambda: clock)
    monkeypatch.setattr(node, "maintain_result_room_ownership", sometimes)
    monkeypatch.setattr(node, "observe_reachability", _nothing)

    with pytest.raises(asyncio.CancelledError):
        await node.run_ownership_lease()

    # It survived the raise and retried on the backoff rather than ending.
    assert calls >= 2
