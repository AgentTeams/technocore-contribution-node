"""The full JOB → CLAIM → RESULT → RECEIPT lifecycle, with no network involved."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_node.jobs.runner import JobRunner, RejectedJob
from technocore_node.ledger.db import Ledger
from technocore_node.receipts import verify_receipt, verify_result
from technocore_node.receipts.receipt import canonical_hash, verify_chain

from ..conftest import job_line

REQUESTER = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"


class StubContext:
    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger

    def latest_protocol_snapshot(self) -> dict[str, object] | None:
        return {"captured_at": "2026-01-01T00:00:00Z", "service_version": "0.10.0"}

    def receipt_chain_for(self, job_id: str) -> list[dict[str, object]]:
        row = self._ledger.get_receipt(job_id)
        return [json.loads(row["receipt_json"])] if row else []


@pytest.fixture
def runner(ledger: Ledger, key: Ed25519PrivateKey, did: str) -> JobRunner:
    return JobRunner(ledger, did, key, StubContext(ledger))


async def test_a_job_runs_end_to_end(runner: JobRunner, ledger: Ledger, did: str) -> None:
    outcome = await runner.handle(
        text=job_line(), requester_did=REQUESTER, request_room="mb-test", request_seq=42
    )
    assert outcome is not None

    assert outcome.claim["type"] == "claim"
    assert outcome.claim["provider_did"] == did
    assert outcome.claim["request_hash"] == outcome.result["request_hash"]

    assert outcome.result["status"] == "ok"
    assert outcome.result["summary"]["scheme"] == "RFC8785"
    assert outcome.result["summary"]["canonical"] == '{"a":[1,2],"b":1}'

    assert outcome.receipt is not None
    assert outcome.receipt["request_seq"] == 42
    assert verify_receipt(outcome.receipt) == []
    verify_result(outcome.result)

    job = ledger.get_job(outcome.job_id)
    assert job is not None
    assert job["status"] == "completed"
    assert job["latency_ms"] is not None


async def test_the_same_job_id_is_never_executed_twice(runner: JobRunner) -> None:
    first = await runner.handle(
        text=job_line(), requester_did=REQUESTER, request_room="mb-test", request_seq=1
    )
    second = await runner.handle(
        text=job_line(), requester_did=REQUESTER, request_room="mb-test", request_seq=2
    )
    assert first is not None
    assert second is None, "a replayed job_id must be answered from the ledger, not rerun"


async def test_a_replayed_job_from_a_different_sender_is_refused_not_dropped(
    runner: JobRunner,
) -> None:
    """Capturing somebody else's signed job and re-posting it must not buy new work.

    It must also not *silently* buy nothing. This test used to assert `is None` — which
    was the bug: the same path meant a stranger could erase a legitimate job by claiming
    its `job_id` first, with nothing executed, answered or recorded. The refusal is now
    explicit and readable at `GET /v1/receipts/<job_id>`.
    """
    await runner.handle(
        text=job_line(), requester_did=REQUESTER, request_room="mb-test", request_seq=1
    )
    other = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"
    with pytest.raises(RejectedJob) as exc:
        await runner.handle(
            text=job_line(), requester_did=other, request_room="mb-test", request_seq=2
        )
    assert exc.value.code == "job_id_taken"


async def test_an_unsigned_sender_is_refused(runner: JobRunner) -> None:
    with pytest.raises(RejectedJob) as exc:
        await runner.handle(
            text=job_line(), requester_did="~nickname", request_room="mb-test", request_seq=1
        )
    assert exc.value.code == "unsigned_or_unverified_sender"


async def test_a_failing_task_still_produces_a_signed_result(runner: JobRunner) -> None:
    """A task that refuses its input owes the requester an answer, not silence."""
    outcome = await runner.handle(
        text=job_line(
            job_id="failing-job-0001",
            task="canonical_json_sha256",
            input={"json_text": "{not json"},
        ),
        requester_did=REQUESTER,
        request_room="mb-test",
        request_seq=1,
    )
    assert outcome is not None
    assert outcome.result["status"] == "error"
    assert "summary" not in outcome.result
    verify_result(outcome.result)
    assert outcome.receipt is not None
    assert verify_receipt(outcome.receipt) == []


async def test_tampering_with_a_result_breaks_its_signature(runner: JobRunner) -> None:
    outcome = await runner.handle(
        text=job_line(), requester_did=REQUESTER, request_room="mb-test", request_seq=1
    )
    assert outcome is not None
    tampered = {**outcome.result, "summary": {"scheme": "made-up"}}
    with pytest.raises(Exception, match="signature"):
        verify_result(tampered)


async def test_tampering_with_a_receipt_breaks_its_hash(runner: JobRunner) -> None:
    outcome = await runner.handle(
        text=job_line(), requester_did=REQUESTER, request_room="mb-test", request_seq=1
    )
    assert outcome is not None and outcome.receipt is not None
    tampered = {**outcome.receipt, "result_hash": canonical_hash({"lie": True})}
    problems = verify_receipt(tampered)
    assert any("receipt_hash" in p for p in problems)


async def test_a_receipt_resigned_by_another_key_is_caught(
    runner: JobRunner, key: Ed25519PrivateKey
) -> None:
    """Recomputing the hash is not enough on its own — the signature must bind the DID."""
    from technocore_node.crypto import didkey
    from technocore_node.protocol.canonical import canonical_bytes
    from technocore_node.receipts.receipt import RECEIPT_EXCLUDED
    from technocore_node.receipts.receipt import canonical_hash as ch

    outcome = await runner.handle(
        text=job_line(), requester_did=REQUESTER, request_room="mb-test", request_seq=1
    )
    assert outcome is not None and outcome.receipt is not None

    forger = Ed25519PrivateKey.generate()
    forged = {**outcome.receipt, "result_hash": ch({"lie": True})}
    forged["receipt_hash"] = ch({k: v for k, v in forged.items() if k not in RECEIPT_EXCLUDED})
    payload = canonical_bytes({k: v for k, v in forged.items() if k != "sig"})
    forged["sig"] = didkey.encode_signature(forger.sign(payload))

    problems = verify_receipt(forged)
    assert any("signature" in p for p in problems), problems


async def test_internal_test_jobs_are_excluded_from_third_party_metrics(
    runner: JobRunner, ledger: Ledger
) -> None:
    await runner.handle(
        text=job_line(job_id="internal-job-001"),
        requester_did=REQUESTER,
        request_room="mb-test",
        request_seq=1,
        internal_test=True,
    )
    metrics = ledger.metrics()
    assert metrics["internal_test_jobs"] == 1
    assert metrics["total_jobs"] == 0
    assert metrics["unique_requester_dids"] == 0
    assert metrics["completion_rate"] is None

    await runner.handle(
        text=job_line(job_id="external-job-001"),
        requester_did=REQUESTER,
        request_room="mb-test",
        request_seq=2,
    )
    metrics = ledger.metrics()
    assert metrics["internal_test_jobs"] == 1
    assert metrics["total_jobs"] == 1
    assert metrics["unique_requester_dids"] == 1


async def test_repeat_requesters_are_counted_separately(runner: JobRunner, ledger: Ledger) -> None:
    for i in range(3):
        await runner.handle(
            text=job_line(job_id=f"repeat-job-{i:04d}"),
            requester_did=REQUESTER,
            request_room="mb-test",
            request_seq=i,
        )
    other = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"
    await runner.handle(
        text=job_line(job_id="single-job-0001"),
        requester_did=other,
        request_room="mb-test",
        request_seq=9,
    )
    metrics = ledger.metrics()
    assert metrics["unique_requester_dids"] == 2
    assert metrics["repeat_requester_dids"] == 1


async def test_verify_receipt_chain_over_this_nodes_own_receipt(
    runner: JobRunner, ledger: Ledger
) -> None:
    first = await runner.handle(
        text=job_line(job_id="chain-job-000001"),
        requester_did=REQUESTER,
        request_room="mb-test",
        request_seq=1,
    )
    assert first is not None and first.receipt is not None
    ledger.record_receipt(
        first.receipt,
        json.dumps(first.receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True),
        99,
        False,
    )

    second = await runner.handle(
        text=job_line(
            job_id="chain-check-0001",
            task="verify_receipt_chain",
            input={"job_id": "chain-job-000001"},
        ),
        requester_did=REQUESTER,
        request_room="mb-test",
        request_seq=2,
    )
    assert second is not None
    assert second.result["status"] == "ok"
    assert second.result["summary"]["all_valid"] is True
    assert second.result["summary"]["source"] == "local_ledger"


def test_a_duplicate_job_id_in_a_chain_is_reported() -> None:
    receipt = {"v": "1", "type": "receipt", "job_id": "dup", "requester_did": "x"}
    report = verify_chain([receipt, receipt])
    assert report["duplicate_job_ids"] == ["dup"]
    assert report["all_valid"] is False


def test_a_chain_out_of_order_is_reported() -> None:
    base = {"job_id": "a", "created_at": "2026-01-02T00:00:00Z"}
    older = {"job_id": "b", "created_at": "2026-01-01T00:00:00Z"}
    assert verify_chain([base, older])["chronological"] is False
    assert verify_chain([older, base])["chronological"] is True
