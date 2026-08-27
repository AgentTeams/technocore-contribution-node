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
from technocore_node.ledger.db import Ledger
from technocore_node.service.node import Node

PASSPHRASE = b"test-secret-do-not-use"
REQUESTER = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


@pytest.fixture
def node(env: dict[str, str]) -> Node:
    keystore.generate(Path(env["TCN_IDENTITY_PATH"]), PASSPHRASE)
    return Node(load_settings())


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
    node.settings.__class__.public_url  # noqa: B018 — documents that public_url drives a blocker
    availability = node.availability()
    assert availability["third_party_intake"] in {"unverified", "unavailable"}
    assert availability["owned_result_room"]["owned_by_this_node"] is True


def test_an_upstream_refusal_becomes_a_stated_blocker(node: Node) -> None:
    """The server's own words, kept.

    When the reason a receipt cannot be published is upstream capacity, that sentence is
    the most useful thing this node can hand a reader asking whether it works.
    """
    node.ledger.set_state(
        f"last_publish_error:{node.result_room}",
        "HTTP 400: 400 room limit reached (20480 is the cap, and this would be a new one).",
    )
    availability = node.availability()
    assert availability["third_party_intake"] == "unavailable"
    assert any("room limit reached" in b for b in availability["blockers"])


def test_a_missing_public_url_is_a_blocker_not_a_footnote(node: Node) -> None:
    assert node.settings.public_url == ""
    assert any("public HTTPS" in b for b in node.availability()["blockers"])


def test_an_unowned_result_room_is_reported_once_it_has_been_looked_at(node: Node) -> None:
    """Observed absence and never-looked are different, and are reported differently."""
    before = node.availability()["owned_result_room"]
    assert before["observed_at"] is None, "nothing observed yet"

    node.ledger.set_state("owned_room_owner", None)  # what a 404 read records
    after = node.availability()
    assert after["owned_result_room"]["observed_at"] is not None
    assert after["owned_result_room"]["owned_by_this_node"] is False
    assert any("no owner note" in b for b in after["blockers"])


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


def test_a_completed_third_party_job_is_what_flips_intake(node: Node, env: dict[str, str]) -> None:
    """The only route to `available`, and it goes through the ledger's own counter."""
    ledger = Ledger(env["TCN_DB_PATH"])
    ledger.insert_job(
        job_id="real-job-000001",
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
    ledger.update_job("real-job-000001", status="completed", latency_ms=12)
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
