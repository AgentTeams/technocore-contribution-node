"""The validation gates — every one of them is a refusal a stranger will try to get past."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_node.jobs.runner import JobRunner, RejectedJob
from technocore_node.ledger.db import Ledger

from ..conftest import job_line, make_job


class StubContext:
    def latest_protocol_snapshot(self) -> dict[str, object] | None:
        return {"captured_at": "2026-01-01T00:00:00Z"}

    def receipt_chain_for(self, job_id: str) -> list[dict[str, object]]:
        return []


@pytest.fixture
def runner(ledger: Ledger, key: Ed25519PrivateKey, did: str) -> JobRunner:
    return JobRunner(ledger, did, key, StubContext())


def test_a_well_formed_job_validates(runner: JobRunner) -> None:
    job = runner.parse_and_validate(job_line())
    assert job["task"] == "canonical_json_sha256"


def test_non_json_is_refused(runner: JobRunner) -> None:
    with pytest.raises(RejectedJob) as exc:
        runner.parse_and_validate("this is not json")
    assert exc.value.code == "not_json"


def test_a_json_array_is_refused(runner: JobRunner) -> None:
    with pytest.raises(RejectedJob) as exc:
        runner.parse_and_validate('["job"]')
    assert exc.value.code == "not_an_object"


@pytest.mark.parametrize(
    ("override", "why"),
    [
        ({"v": "2"}, "wrong protocol version"),
        ({"type": "result"}, "wrong message type"),
        ({"job_id": "short"}, "job_id below the length floor"),
        ({"job_id": "has spaces in it"}, "job_id outside the pattern"),
        ({"task": "rm -rf /"}, "task not in the enum"),
        ({"task": "eval"}, "task not in the enum"),
        ({"reply_room": "Has-Capitals"}, "room outside the name pattern"),
        ({"reply_room": "../../etc/passwd"}, "path traversal in a room name"),
    ],
)
def test_malformed_jobs_are_refused(runner: JobRunner, override: dict, why: str) -> None:
    with pytest.raises(RejectedJob) as exc:
        runner.parse_and_validate(job_line(**override))
    assert exc.value.code in {"schema_invalid", "unknown_task"}, why


def test_unknown_fields_are_refused(runner: JobRunner) -> None:
    """`additionalProperties: false` — an unexpected field is a refusal, not something
    quietly ignored, because ignoring it is how a future field gets silently dropped."""
    job = make_job()
    job["callback_url"] = "http://attacker.example/x"
    with pytest.raises(RejectedJob) as exc:
        runner.parse_and_validate(json.dumps(job))
    assert exc.value.code == "schema_invalid"


@pytest.mark.parametrize(
    "room",
    [
        "lobby",
        "meta",
        "events",
        "d-someone-elses",
        "e-public",
        # `mb-` means signed writes only — NOT that this requester owns the room. Allowing
        # it let a stranger aim three messages at somebody else's public mailbox.
        "mb-somebody",
        "mb-tc-jobs-06e9de34",
    ],
)
def test_a_room_the_requester_cannot_prove_they_hold_is_refused(
    runner: JobRunner, room: str
) -> None:
    """Without this gate, anyone could make the node post three messages into a room of
    their choosing — a reflector, not a service."""
    with pytest.raises(RejectedJob) as exc:
        runner.parse_and_validate(job_line(reply_room=room))
    assert exc.value.code == "reply_room_not_allowed"


@pytest.mark.parametrize("room", ["mb-p-abc123", "p-unguessable", "e-p-decaying"])
def test_an_unlisted_reply_room_is_accepted(runner: JobRunner, room: str) -> None:
    """The `p-` class is never enumerated, so knowing the name is evidence of holding it."""
    assert runner.parse_and_validate(job_line(reply_room=room))["reply_room"] == room


def test_oversized_requests_are_refused_before_parsing(runner: JobRunner) -> None:
    with pytest.raises(RejectedJob) as exc:
        runner.parse_and_validate("x" * 100_000)
    assert exc.value.code == "request_too_large"


def test_oversized_input_is_refused(runner: JobRunner) -> None:
    with pytest.raises(RejectedJob) as exc:
        runner.parse_and_validate(job_line(input={"value": "x" * 5000}))
    assert exc.value.code in {"input_too_large", "request_too_large"}


def test_task_input_schema_is_enforced(runner: JobRunner) -> None:
    with pytest.raises(RejectedJob) as exc:
        runner.parse_and_validate(
            job_line(task="verify_technocore_signature", input={"room": "lobby"})
        )
    assert exc.value.code == "input_invalid"


def test_canonical_json_task_takes_exactly_one_input(runner: JobRunner) -> None:
    with pytest.raises(RejectedJob):
        runner.parse_and_validate(
            job_line(task="canonical_json_sha256", input={"value": 1, "json_text": "1"})
        )


def test_protocol_snapshot_task_refuses_a_url(runner: JobRunner) -> None:
    """The one task that concerns fetched documents must not accept a fetch target."""
    with pytest.raises(RejectedJob) as exc:
        runner.parse_and_validate(
            job_line(
                task="protocol_manifest_snapshot",
                input={"url": "http://169.254.169.254/latest/meta-data/"},
            )
        )
    assert exc.value.code == "input_invalid"


def test_rate_limit_counts_refusals_too(runner: JobRunner, ledger: Ledger, did: str) -> None:
    """A flood of malformed requests must not be free."""
    for _ in range(runner.requester_jobs_per_hour):
        ledger.record_rejection(
            job_id=None,
            requester_did=did,
            code="not_json",
            detail="",
            request_room="mb-test",
        )
    with pytest.raises(RejectedJob) as exc:
        runner.check_rate_limit(did)
    assert exc.value.code == "rate_limited"


def test_rate_limit_is_per_requester(runner: JobRunner, ledger: Ledger, did: str) -> None:
    other = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    for _ in range(runner.requester_jobs_per_hour):
        ledger.record_rejection(
            job_id=None, requester_did=did, code="not_json", detail="", request_room="mb-test"
        )
    runner.check_rate_limit(other)


def test_signature_payload_delimiters_cannot_be_shifted() -> None:
    """`|` separates the payload fields, and the trailing field may contain one.

    That is only unambiguous because every *earlier* field is drawn from a character set
    that excludes the separator. This asserts the property the scheme rests on, so a
    future loosening of the name or nonce pattern fails here rather than silently making
    two different messages share a signature.
    """
    import re

    from technocore_node.crypto.didkey import NONCE_PATTERN
    from technocore_node.protocol.envelope import message_payload, note_payload
    from technocore_node.protocol.sweep import NAME_RE

    assert not NAME_RE.fullmatch("has|pipe")
    assert not re.fullmatch(NONCE_PATTERN, "1|2")

    # Two messages whose fields differ must not collide, even when the trailing field
    # contains the separator. Without the constraint above, ("room", 1, "2|x") and
    # ("room", 12, "x") would both render as `room|1|2|x`.
    assert message_payload("room", 1, "2|x") == "room|1|2|x"
    assert message_payload("room", 12, "x") == "room|12|x"
    assert message_payload("room", 1, "2|x") != message_payload("room", 12, "x")
    assert note_payload("ns", "key", 1, "a|b") != note_payload("ns", "key", 1, "a|c")


def test_sweep_equivalent_values_share_one_payload_by_design() -> None:
    """Not a collision — the same stored bytes.

    The payload covers the value *after* the sweep, so two inputs the server would store
    identically are one message and legitimately carry one signature. Asserting this keeps
    a future reader from "fixing" it into signing pre-sweep text, which the server refuses.
    """
    from technocore_node.protocol.envelope import note_payload as np

    assert np("ns", "key", 1, "a|b ") == np("ns", "key", 1, "  a|b")
    assert np("ns", "key", 1, "a|b") == np("ns", "key", 1, "a|b\n")


async def test_claiming_a_room_with_a_pipe_in_the_name_is_refused(
    key: Ed25519PrivateKey, did: str
) -> None:
    """The ownership payload is `room-owners|<room>|<nonce>|<did>`; a room name outside
    the server's pattern must never reach it."""
    from technocore_node.protocol.client import TechnocoreClient, TechnocoreError

    client = TechnocoreClient("https://technocore.chat", private_key=key, did=did)
    try:
        for bad in ["d-a|b", "d-A", "d-" + "x" * 60, "d-has space"]:
            with pytest.raises(TechnocoreError, match="invalid room name"):
                await client.claim_room(bad)
    finally:
        await client.aclose()
