"""What the node says about being reachable, and on what evidence.

`v0.1.0` told every reader — in the README, the release notes, `/v1/info` and the
dashboard — how to send it a job, while the room that would receive one did not exist and
could not be created. Nothing there was dishonest by intent; it was written when the code
was finished and never revisited when the deployment turned out not to be.

Prose cannot fix that, because prose is what failed. These tests hold the API to reporting
what the node has actually observed, so the page corrects itself when the situation does.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from technocore_node.api import create_app
from technocore_node.config import load_settings
from technocore_node.crypto import keystore
from technocore_node.ledger.db import Ledger, utcnow
from technocore_node.service.node import Node

PASSPHRASE = b"test-secret-do-not-use"
REQUESTER = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


@pytest.fixture
def node(env: dict[str, str]) -> Node:
    keystore.generate(Path(env["TCN_IDENTITY_PATH"]), PASSPHRASE)
    node = Node(load_settings())
    object.__setattr__(node.settings, "mailbox_enabled", True)
    return node


@pytest.fixture
def client(node: Node) -> TestClient:
    return TestClient(create_app(node), raise_server_exceptions=False)


def test_intake_is_never_available_on_a_node_nobody_has_used(node: Node) -> None:
    """`available` is the one state that cannot be produced by wishing.

    It requires a completed third-party job — evidence that somebody actually got an
    answer, rather than evidence that the code would give one.
    """
    assert node.availability()["third_party_intake"] != "available"
    assert node.availability()["third_party_jobs_completed"] == 0


def test_an_unobserved_node_says_so_rather_than_guessing(node: Node) -> None:
    """Before anything has been checked, the honest answer is `unverified`.

    Not `available` (nothing supports it) and not `unavailable` (nothing supports that
    either) — the node simply has not looked yet, and says which.
    """
    node.ledger.set_state("owned_room_owner", node.did)
    node.ledger.set_state("owned_room_renewed", utcnow())
    node.ledger.set_state("owned_room_observed", "1")
    availability = node.availability()
    assert availability["third_party_intake"] in {"unverified", "unavailable"}
    assert availability["owned_result_room"]["owned_by_this_node"] is True


async def test_a_real_publish_failure_is_what_records_the_blocker(node: Node) -> None:
    """Driven through `publish()`, not by seeding the state by hand.

    The first version of this test wrote the state itself and passed while the recording
    side was never wired up at all — it proved the reporting worked and nothing about
    whether anything would ever call it. A test that supplies its own precondition cannot
    tell you the production path exists.
    """
    from technocore_node.protocol.client import TechnocoreError

    _own_the_room(node)

    async def refuse(room: str, text: str, *, confirm: bool = True) -> object:
        raise TechnocoreError(
            "HTTP 400: 400 room limit reached (20480 is the cap, and this would be a new one)."
        )

    node.client.say_signed = refuse  # type: ignore[method-assign]
    assert await node.publish(node.result_room, {"type": "receipt", "job_id": "x"}) is None

    availability = node.availability()
    # The upstream's own sentence, kept and shown — in its own field, because a past
    # failure is context rather than a gate condition.
    assert "room limit reached" in (availability["last_publish_error"] or ""), availability


async def test_a_publish_that_succeeds_clears_the_blocker(node: Node) -> None:
    """The record has to be able to go away again, or it is a permanent scar."""
    from technocore_node.protocol.client import Confirmation, TechnocoreError

    _own_the_room(node)

    async def refuse(room: str, text: str, *, confirm: bool = True) -> object:
        raise TechnocoreError("HTTP 400: 400 room limit reached")

    node.client.say_signed = refuse  # type: ignore[method-assign]
    await node.publish(node.result_room, {"type": "receipt", "job_id": "x"})
    assert "room limit" in (node.availability()["last_publish_error"] or "")

    async def accept(room: str, text: str, *, confirm: bool = True) -> Confirmation:
        return Confirmation(
            room=room, did=node.did, nonce=1, text=text, sig="a" * 86, seq=9, ts="now"
        )

    node.client.say_signed = accept  # type: ignore[method-assign]
    await node.publish(node.result_room, {"type": "receipt", "job_id": "x"})
    assert node.availability()["last_publish_error"] is None


def test_a_missing_public_url_is_a_blocker_not_a_footnote(node: Node) -> None:
    assert node.settings.public_url == ""
    assert any("public URL" in b for b in node.availability()["blockers"])


def test_an_unowned_result_room_is_reported_once_it_has_been_looked_at(node: Node) -> None:
    """Observed absence and never-looked are different, and are reported differently."""
    before = node.availability()["owned_result_room"]
    assert before["observed_at"] is None, "nothing observed yet"

    node.ledger.set_state("owned_room_owner", None)  # what a successful 404 read records
    node.ledger.set_state("owned_room_observed", "1")
    after = node.availability()
    assert after["owned_result_room"]["observed_at"] is not None
    assert after["owned_result_room"]["owned_by_this_node"] is False
    assert any("has no owner" in b for b in after["blockers"])


def test_info_leads_with_availability_before_the_instructions(client: TestClient) -> None:
    """A reader who stops at the first useful-looking block still learns it does not work."""
    body = client.get("/v1/info").json()
    assert "availability" in body
    keys = list(body)
    assert keys.index("availability") < keys.index("how_to_submit")
    assert body["how_to_submit"]["status"].startswith("This describes the protocol")


def test_the_dashboard_says_so_before_telling_anyone_how_to_submit(client: TestClient) -> None:
    page = client.get("/").text
    assert "cannot accept a job right now" in page
    assert page.index("cannot accept a job right now") < page.index("Once intake is available")


def test_availability_reports_the_receipt_split(client: TestClient) -> None:
    receipts = client.get("/v1/info").json()["availability"]["receipts"]
    assert receipts == {
        "publicly_auditable": 0,
        "awaiting_public_copy": 0,
        "quarantined": 0,
    }


def _own_the_room(node: Node) -> None:
    """Confirm ownership locally, so a publish reaches the network at all.

    `publish()` refuses the result room outright when ownership is unconfirmed, which is
    the point of the guard — but these tests are about what happens when the *upstream*
    refuses, so they have to get past the local check first.
    """
    node.ledger.set_state("owned_room_owner", node.did)
    node.ledger.set_state("owned_room_renewed", utcnow())
    node.ledger.set_state("owned_room_observed", "1")
    node.ledger.set_state("owned_room_error", None)


def _completed_third_party_job(ledger: Ledger, node: Node, job_id: str = "real-job-0001") -> None:
    ledger.insert_job(
        job_id=job_id,
        protocol_version="1",
        requester_did=REQUESTER,
        provider_did=node.did,
        request_room=node.mailbox,
        reply_room="mb-p-somewhere",
        request_seq=1,
        request_hash="sha256:" + "0" * 64,
        task_type="canonical_json_sha256",
        status="completed",
        internal_test=False,
    )
    ledger.update_job(job_id, status="completed", latency_ms=12)


def test_past_success_does_not_override_a_current_blocker(node: Node, env: dict[str, str]) -> None:
    """Blockers are about now; a completed job is about the past.

    A node that once served somebody and is unreachable today is unreachable today. Left
    the other way round, one historical job would have pinned the banner to `available`
    for good.
    """
    _completed_third_party_job(Ledger(env["TCN_DB_PATH"]), node)
    availability = node.availability()
    assert availability["third_party_jobs_completed"] == 1
    assert availability["blockers"], "public_url is unset in this fixture"
    assert availability["third_party_intake"] == "unavailable"


def test_intake_reads_available_only_with_a_job_and_no_blockers(
    node: Node, env: dict[str, str]
) -> None:
    """Both halves are required, and each is checked without the other."""
    object.__setattr__(node.settings, "public_url", "https://example.invalid")
    node.ledger.set_state("owned_room_owner", node.did)
    node.ledger.set_state("owned_room_renewed", utcnow())
    node.ledger.set_state("owned_room_observed", "1")

    # No blockers, but nobody has used it: not `available`.
    assert node.availability()["blockers"] == []
    assert node.availability()["third_party_intake"] == "unverified"

    _completed_third_party_job(Ledger(env["TCN_DB_PATH"]), node)
    assert node.availability()["third_party_intake"] == "available"


def test_an_internal_test_job_does_not_flip_intake(node: Node, env: dict[str, str]) -> None:
    """The node's own tests are not somebody else using it — here as everywhere else."""
    ledger = Ledger(env["TCN_DB_PATH"])
    ledger.insert_job(
        job_id="internal-job-01",
        protocol_version="1",
        requester_did=REQUESTER,
        provider_did=node.did,
        request_room=node.mailbox,
        reply_room="mb-p-somewhere",
        request_seq=1,
        request_hash="sha256:" + "0" * 64,
        task_type="canonical_json_sha256",
        status="completed",
        internal_test=True,
    )
    assert node.availability()["third_party_intake"] != "available"


def test_a_result_room_held_by_someone_else_is_the_strongest_blocker(
    node: Node, env: dict[str, str]
) -> None:
    """Stronger than being unowned, not weaker.

    An unclaimed room can still be claimed; one held by another key never will be, and
    the entire value of that room is that only this node can write to it. Reported the
    other way round, a node whose audit room belonged to a stranger could still have
    announced itself `available`.
    """
    object.__setattr__(node.settings, "public_url", "https://example.invalid")
    _completed_third_party_job(Ledger(env["TCN_DB_PATH"]), node)
    stranger = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"
    node.ledger.set_state("owned_room_owner", stranger)
    node.ledger.set_state("owned_room_observed", "1")

    availability = node.availability()
    assert availability["owned_result_room"]["owned_by_this_node"] is False
    assert any("owned by another key" in b for b in availability["blockers"]), availability
    assert availability["third_party_intake"] == "unavailable"


def test_our_own_ownership_is_not_a_blocker(node: Node, env: dict[str, str]) -> None:
    object.__setattr__(node.settings, "public_url", "https://example.invalid")
    node.ledger.set_state("owned_room_owner", node.did)
    node.ledger.set_state("owned_room_renewed", utcnow())
    node.ledger.set_state("owned_room_observed", "1")
    assert node.availability()["blockers"] == []


async def test_a_failed_ownership_check_is_reported_as_not_knowing(node: Node) -> None:
    """ "I could not look" must never render as "there is nobody there".

    A read that fails on a timeout or a 500 once recorded the same state as a read that
    succeeded and found no owner — turning an unanswered question into a confident
    negative. That substitution is the whole reason this release exists, so it would be a
    poor place to make it.
    """
    from technocore_node.protocol.client import TechnocoreError

    async def refuse(room: str) -> str | None:
        raise TechnocoreError("HTTP 503: upstream unavailable")

    node.client.room_owner = refuse  # type: ignore[method-assign]
    await node.observe_reachability()

    room = node.availability()["owned_result_room"]
    assert room["observed"] is False, "nothing was successfully observed"
    assert room["read_error"] is not None
    assert any("could not be verified" in b for b in node.availability()["blockers"])
    assert not any("has no owner" in b for b in node.availability()["blockers"])


async def test_a_failed_check_does_not_erase_a_good_earlier_observation(node: Node) -> None:
    """A blip must not un-know something already established."""
    from technocore_node.protocol.client import TechnocoreError

    node.ledger.set_state("owned_room_owner", node.did)
    node.ledger.set_state("owned_room_renewed", utcnow())
    node.ledger.set_state("owned_room_observed", "1")

    async def refuse(room: str) -> str | None:
        raise TechnocoreError("HTTP 503: upstream unavailable")

    node.client.room_owner = refuse  # type: ignore[method-assign]
    await node.observe_reachability()

    room = node.availability()["owned_result_room"]
    assert room["owner"] == node.did, "the earlier observation survives"
    assert room["observed"] is True


async def test_a_successful_check_clears_an_earlier_failure(node: Node) -> None:
    async def succeed(room: str) -> str | None:
        return node.did

    node.ledger.set_state("owned_room_error", "HTTP 503: upstream unavailable")
    node.client.room_owner = succeed  # type: ignore[method-assign]
    await node.observe_reachability()

    room = node.availability()["owned_result_room"]
    assert room["read_error"] is None
    assert room["owned_by_this_node"] is True


def test_the_report_and_the_gate_share_one_vocabulary(node: Node) -> None:
    """They were two lists once, and they drifted.

    The report could read `available` from a stale ownership record the gate had already
    rejected — the status/action mismatch this release exists to remove, reappearing
    inside the fix for it. One source of truth, asserted rather than intended.
    """
    node.ledger.set_state("owned_room_owner", None)
    node.ledger.set_state("owned_room_observed", "1")

    availability = node.availability()

    assert availability["accepting_third_party_jobs"] is node.can_accept_third_party_jobs()
    # The invariant, in the form that survives having more than one lane: reasons are
    # listed exactly when nothing is accepted. A non-empty list beside `true` is the
    # drift this asserts against, whichever lane produced the entry.
    assert bool(availability["stop_reasons"]) is not availability["accepting_third_party_jobs"]
    for lane, reported in availability["lanes"].items():
        open_now, reasons = node.lane_is_open(lane)
        assert reported["open"] is open_now
        assert reported["stop_reasons"] == reasons


def test_an_open_lane_is_not_reported_as_stopped_by_a_closed_one(node: Node) -> None:
    """One lane switched off is a fact about that lane, not a stop for the node."""
    node.ledger.set_state("owned_room_owner", node.did)
    node.ledger.set_state("owned_room_observed", "1")
    node.ledger.set_state("owned_room_error", None)
    node.ledger.set_state("owned_room_renewed", utcnow())
    object.__setattr__(node.settings, "mailbox_enabled", True)
    object.__setattr__(node.settings, "http_job_intake_enabled", False)
    object.__setattr__(node.settings, "public_url", "https://example.invalid")

    availability = node.availability()

    assert availability["accepting_third_party_jobs"] is True
    assert availability["stop_reasons"] == []
    assert availability["lanes"]["mailbox"]["open"] is True
    assert availability["lanes"]["http"]["open"] is False
    assert any(
        "HTTP job intake is disabled" in r for r in availability["lanes"]["http"]["stop_reasons"]
    )
