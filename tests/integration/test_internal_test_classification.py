"""A self-test must not be able to become somebody else's job.

`selftest` posts a real job into the production mailbox, signed by a throwaway key. At
intake it is indistinguishable from a stranger's — and the `internal_test` flag was
supplied by whichever caller ran it, so *which code path picked it up* decided whether it
counted as third-party use.

On 2026-08-30 that happened. The command's write landed and then the command died on a
read timeout before processing it; the mailbox loop found the orphan and ran it as a
normal job. This node published `third_party: 1 job, 1 requester` about itself — the one
number the whole project exists to be able to state honestly.

So the classification is declared before the job is sent, and decided in one place after
the `job_id` is known, rather than passed in by the caller who happens to win the race.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_node.config import load_settings
from technocore_node.crypto import didkey, keystore
from technocore_node.service.node import Node

PASSPHRASE = b"test-secret-do-not-use"


@pytest.fixture
def node(env: dict[str, str]) -> Node:
    keystore.generate(Path(env["TCN_IDENTITY_PATH"]), PASSPHRASE)
    return Node(load_settings())


def _job(job_id: str) -> str:
    return json.dumps(
        {
            "v": "1",
            "type": "job",
            "job_id": job_id,
            "task": "canonical_json_sha256",
            "reply_room": "p-tcn-selftest-abcdef0123456789",
            "input": {"value": {"a": 1}},
        },
        separators=(",", ":"),
        sort_keys=True,
    )


async def _run(node: Node, did: str, job_id: str, **kw: Any) -> Any:
    return await node.runner.handle(
        text=_job(job_id), requester_did=did, request_room="mb-test", request_seq=1, **kw
    )


async def test_a_declared_job_counts_as_internal_whoever_runs_it(node: Node) -> None:
    """The point. The loop calls `handle` with no flag, and it must still be ours."""
    did = didkey.encode_did(Ed25519PrivateKey.generate().public_key())
    node.ledger.expect_internal_test(did, "selftest-0000000000000001")

    outcome = await _run(node, did, "selftest-0000000000000001")

    assert outcome is not None
    assert outcome.internal_test is True
    m = node.ledger.metrics()
    assert m["total_jobs"] == 0  # third-party
    assert m["internal_test_jobs"] == 1


async def test_an_undeclared_job_is_third_party_however_it_is_named(node: Node) -> None:
    """`selftest-` in the id is not a claim this node honours. Anyone can type it."""
    did = didkey.encode_did(Ed25519PrivateKey.generate().public_key())

    outcome = await _run(node, did, "selftest-0000000000000002")

    assert outcome is not None
    assert outcome.internal_test is False
    assert node.ledger.metrics()["total_jobs"] == 1


async def test_a_declaration_is_bound_to_the_key_that_made_it(node: Node) -> None:
    """A stranger must not be reclassified by guessing an identifier.

    They would gain nothing — the effect is to undercount this node's usage — but a
    guessable exemption is still an exemption.
    """
    ours = didkey.encode_did(Ed25519PrivateKey.generate().public_key())
    stranger = didkey.encode_did(Ed25519PrivateKey.generate().public_key())
    node.ledger.expect_internal_test(ours, "selftest-0000000000000003")

    outcome = await _run(node, stranger, "selftest-0000000000000003")

    assert outcome is not None
    assert outcome.internal_test is False
    assert node.ledger.metrics()["total_jobs"] == 1


async def test_an_explicit_flag_still_wins(node: Node) -> None:
    """The command still passes it directly; the declaration is a floor, not a ceiling."""
    did = didkey.encode_did(Ed25519PrivateKey.generate().public_key())

    outcome = await _run(node, did, "selftest-0000000000000004", internal_test=True)

    assert outcome is not None
    assert outcome.internal_test is True
    assert node.ledger.metrics()["total_jobs"] == 0


async def test_an_internal_receipt_is_not_owed_to_the_public_room(node: Node) -> None:
    """Which is the other half of the damage: it was published there as third-party work."""
    did = didkey.encode_did(Ed25519PrivateKey.generate().public_key())
    node.ledger.expect_internal_test(did, "selftest-0000000000000005")

    await _run(node, did, "selftest-0000000000000005")

    row = node.ledger.get_receipt("selftest-0000000000000005")
    assert row is not None
    assert row["internal_test"] == 1
    # `owed` is what the reconciler publishes. An internal test is never owed.
    assert row["audit_state"] == "published"


async def test_the_http_lane_also_keeps_internal_receipts_out_of_the_public_room(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mailbox lane always had this check. The HTTP lane did not.

    The owned room is a public claim about work done for other people. Publishing one of
    this node's own tests there is what happened on 2026-08-30 — and this release, which
    exists to stop it, left the second lane able to do it again.
    """
    import hashlib
    from base64 import urlsafe_b64encode

    from fastapi.testclient import TestClient

    from technocore_node.api import create_app
    from technocore_node.protocol.canonical import canonical_bytes
    from technocore_node.protocol.http_envelope import HTTP_JOB_DOMAIN

    monkeypatch.setenv("TCN_HTTP_JOB_INTAKE_ENABLED", "true")
    monkeypatch.setenv("TCN_PUBLIC_URL", "https://example.invalid")
    keystore.generate(Path(env["TCN_IDENTITY_PATH"]), PASSPHRASE)
    node = Node(load_settings())
    for key, value in (
        ("owned_room_owner", node.did),
        ("owned_room_observed", "1"),
        ("owned_room_error", None),
        ("owned_room_renewed", __import__("technocore_node.ledger.db", fromlist=["x"]).utcnow()),
    ):
        node.ledger.set_state(key, value)

    published: list[str] = []

    async def record(room: str, payload: Any) -> int | None:
        published.append(room)
        return 1

    monkeypatch.setattr(node, "publish", record)

    key = Ed25519PrivateKey.generate()
    did = didkey.encode_did(key.public_key())
    job = {
        "v": "1",
        "type": "job",
        "job_id": "selftest-00000000000000ff",
        "task": "canonical_json_sha256",
        "reply_room": "p-tcn-selftest-0011223344556677",
        "input": {"value": {"a": 1}},
    }
    node.ledger.expect_internal_test(did, "selftest-00000000000000ff")

    digest = hashlib.sha256(canonical_bytes(job)).hexdigest()
    payload = f"{HTTP_JOB_DOMAIN}|{did}|1|sha256:{digest}"
    sig = urlsafe_b64encode(key.sign(payload.encode())).decode().rstrip("=")

    client = TestClient(create_app(node), raise_server_exceptions=False)
    response = client.post("/v1/jobs", json={"did": did, "sig": sig, "nonce": "1", "job": job})

    assert response.status_code == 200, response.json()
    assert response.json()["receipt"]["internal_test"] is True
    # Nothing went to the owned room.
    assert published == []


async def test_the_declaration_is_spent_by_the_insert_and_not_before(node: Node) -> None:
    """One transaction, because the row and the declaration are one fact.

    Spending it first opens a window in which the declaration is gone and the row does not
    exist — and a process that dies there leaves the next attempt with neither, which
    classifies this node's own test as somebody else's. That window is a crash, which is
    exactly how the misclassification happened.
    """
    did = didkey.encode_did(Ed25519PrivateKey.generate().public_key())
    node.ledger.expect_internal_test(did, "selftest-0000000000000006")

    def explode(*a: Any, **k: Any) -> None:
        raise RuntimeError("crash before the row is written")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(node.ledger, "insert_job", explode)
        with pytest.raises(RuntimeError):
            await _run(node, did, "selftest-0000000000000006")

    # The declaration survived, so the retry still knows whose job this is.
    assert node.ledger.is_expected_internal_test(did, "selftest-0000000000000006") is True

    outcome = await _run(node, did, "selftest-0000000000000006")

    assert outcome is not None and outcome.internal_test is True
    # And now it is spent, by the insert that recorded the classification.
    assert node.ledger.is_expected_internal_test(did, "selftest-0000000000000006") is False


async def test_a_declaration_whose_job_never_arrives_is_swept(node: Node) -> None:
    """The write failed, or the command died before sending. Nothing will ever spend it."""
    did = didkey.encode_did(Ed25519PrivateKey.generate().public_key())
    node.ledger.expect_internal_test(did, "selftest-000000000000000a")

    assert node.ledger.sweep_expected_internal_tests(older_than_seconds=3600) == 0
    assert node.ledger.is_expected_internal_test(did, "selftest-000000000000000a") is True

    assert node.ledger.sweep_expected_internal_tests(older_than_seconds=-1) == 1
    assert node.ledger.is_expected_internal_test(did, "selftest-000000000000000a") is False


async def test_a_resumed_job_keeps_the_classification_its_row_already_has(node: Node) -> None:
    """The declaration is spent by the first attempt; the row is what survives.

    Re-deriving it would make a job that crashed mid-flight come back as somebody else's —
    reintroducing the misclassification through the recovery path.
    """
    did = didkey.encode_did(Ed25519PrivateKey.generate().public_key())
    node.ledger.expect_internal_test(did, "selftest-0000000000000007")

    def explode(*a: Any, **k: Any) -> None:
        raise RuntimeError("crash after the row exists")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(node.ledger, "record_receipt", explode)
        with pytest.raises(RuntimeError):
            await _run(node, did, "selftest-0000000000000007")

    assert node.ledger.is_expected_internal_test(did, "selftest-0000000000000007") is False

    outcome = await _run(node, did, "selftest-0000000000000007")

    assert outcome is not None
    assert outcome.internal_test is True
    assert node.ledger.metrics()["total_jobs"] == 0


def _own_and_open(node: Node) -> None:
    from technocore_node.ledger.db import utcnow

    node.ledger.set_state("owned_room_owner", node.did)
    node.ledger.set_state("owned_room_observed", "1")
    node.ledger.set_state("owned_room_error", None)
    node.ledger.set_state("owned_room_renewed", utcnow())
    object.__setattr__(node.settings, "mailbox_enabled", True)
    object.__setattr__(node.settings, "public_url", "https://example.invalid")


def test_a_declaration_is_not_swept_while_its_job_may_still_be_waiting(node: Node) -> None:
    """The cleanup must not be able to cause the accident it cleans up after.

    With the gate shut the cursor holds and the message sits in the room unprocessed. A
    declaration dropped on a timer would be dropped out from under a job that is still
    coming — and the node would then run its own test as a stranger's and publish the
    receipt as third-party work.
    """
    did = didkey.encode_did(Ed25519PrivateKey.generate().public_key())
    node.ledger.expect_internal_test(did, "selftest-000000000000000b")
    object.__setattr__(node.settings, "mailbox_enabled", False)

    node.DECLARATION_MAX_AGE_SECONDS = -1  # type: ignore[misc]
    node._sweep_stale_declarations()

    assert node.ledger.is_expected_internal_test(did, "selftest-000000000000000b") is True


def test_it_is_swept_once_the_lane_that_would_consume_it_is_open(node: Node) -> None:
    """Then a waiting job is actually being read, and one this old is not coming."""
    did = didkey.encode_did(Ed25519PrivateKey.generate().public_key())
    node.ledger.expect_internal_test(did, "selftest-000000000000000c")
    _own_and_open(node)
    assert node.lane_is_open("mailbox")[0] is True

    node.DECLARATION_MAX_AGE_SECONDS = -1  # type: ignore[misc]
    node._sweep_stale_declarations()

    assert node.ledger.is_expected_internal_test(did, "selftest-000000000000000c") is False


def test_a_fresh_declaration_survives_a_sweep(node: Node) -> None:
    """The window is a day against the seconds the self-test takes to post."""
    did = didkey.encode_did(Ed25519PrivateKey.generate().public_key())
    node.ledger.expect_internal_test(did, "selftest-000000000000000d")
    _own_and_open(node)

    node._sweep_stale_declarations()

    assert node.ledger.is_expected_internal_test(did, "selftest-000000000000000d") is True
    assert Node.DECLARATION_MAX_AGE_SECONDS >= 24 * 3600


async def test_the_sweep_runs_from_the_loop_that_always_runs(
    node: Node, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not from the mailbox loop, which does not start when intake is disabled.

    That is the production default, and a cleanup that never runs there is not a cleanup.
    """
    swept = 0

    def count() -> None:
        nonlocal swept
        swept += 1

    async def stop(seconds: float) -> None:
        raise asyncio.CancelledError

    async def renew() -> str:
        return "renewed"

    monkeypatch.setattr(node, "_sweep_stale_declarations", count)
    monkeypatch.setattr(node, "maintain_result_room_ownership", renew)

    async def nothing() -> None:
        return None

    monkeypatch.setattr(node, "observe_reachability", nothing)
    monkeypatch.setattr(asyncio, "sleep", stop)

    with pytest.raises(asyncio.CancelledError):
        await node.run_ownership_lease()

    assert swept == 1
