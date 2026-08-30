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
