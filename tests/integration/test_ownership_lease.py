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
from pathlib import Path
from typing import Any

import httpx2 as httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_node.config import load_settings
from technocore_node.crypto import didkey, keystore
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
