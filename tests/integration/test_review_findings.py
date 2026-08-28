"""Regression tests for the findings of the pre-merge security review.

One test per finding, named for what it prevents rather than for the review. Each of these
passed silently before the fix, which is the reason they are here: every one was a defect
that no existing test could see.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_node.config import ConfigError, assert_allowed_origin
from technocore_node.jobs.runner import JobRunner, RejectedJob
from technocore_node.ledger.db import Ledger
from technocore_node.logging import redact, redact_value
from technocore_node.protocol.canonical import CanonicalJSONError, canonical_bytes, parse_strict

from ..conftest import job_line

REQUESTER = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
OTHER = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"


class StubContext:
    def latest_protocol_snapshot(self) -> dict[str, object] | None:
        return {"captured_at": "2026-01-01T00:00:00Z"}

    def receipt_chain_for(self, job_id: str) -> list[dict[str, object]]:
        return []


def _database_contains(path: Path, needle: str) -> bool:
    """True if `needle` appears anywhere in the database — main file, WAL or shm.

    Checking only the main file would be the flattering version of this assertion: in WAL
    mode a just-written value usually lives in `-wal` and has not reached `.db` yet, so a
    main-file-only check can pass while the bytes are plainly on disk next to it.
    """
    base = Path(path)
    for candidate in (base, base.with_name(base.name + "-wal"), base.with_name(base.name + "-shm")):
        if candidate.exists() and needle.encode() in candidate.read_bytes():
            return True
    return False


@pytest.fixture
def runner(ledger: Ledger, key: Ed25519PrivateKey, did: str) -> JobRunner:
    return JobRunner(ledger, did, key, StubContext())


# ------------------------------------------- P0: no stranger's payload on disk


async def test_no_request_or_result_text_is_ever_persisted(
    runner: JobRunner, ledger: Ledger
) -> None:
    """The ledger keeps hashes, not payloads.

    A request is a stranger's bytes and may carry anything. Persisting the result text
    accumulated other people's data on an operator's disk, indefinitely, for no reader —
    while the schema said the opposite.
    """
    # secret-scan: allow — a fixture standing in for what a stranger might send.
    secret = "correct-horse-battery-staple-9f3a"
    outcome = await runner.handle(
        text=job_line(input={"value": {"pii": secret}}),
        requester_did=REQUESTER,
        request_room="mb-test",
        request_seq=1,
    )
    assert outcome is not None
    assert secret in json.dumps(outcome.result), "the requester still gets their own data back"

    ledger.record_result(
        job_id=outcome.job_id,
        result_hash=outcome.result["result_hash"],
        status="ok",
        summary_bytes=123,
        provider_signature=outcome.result["sig"],
        result_seq=7,
    )
    ledger.record_message(
        local_event_id="out-mb-test-1",
        direction="out",
        room="mb-test",
        did=REQUESTER,
        nonce=1,
        normalized_text_sha256="sha256:" + "0" * 64,
        signature="a" * 86,
        status="confirmed",
    )

    assert not _database_contains(ledger.path, secret), "caller data reached the database file"


def test_the_schema_has_nowhere_to_put_a_payload(ledger: Ledger) -> None:
    """Structural, not conventional: the columns do not exist."""
    columns: set[str] = set()
    for (table,) in ledger.conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall():
        columns |= {row[1] for row in ledger.conn.execute(f"PRAGMA table_info({table})").fetchall()}
    assert "normalized_text" not in columns
    assert "result_summary" not in columns
    assert "normalized_text_sha256" in columns, "the hash is still kept"


def test_an_older_database_has_its_payload_columns_dropped(tmp_path: Path) -> None:
    """`CREATE TABLE IF NOT EXISTS` cannot retire a column, so the migration must.

    The legacy shape is built by creating today's schema and adding the columns back,
    which is exactly what an older deployment's file looks like.
    """
    path = tmp_path / "legacy.db"
    Ledger(path).close()

    legacy = sqlite3.connect(path)
    legacy.execute("ALTER TABLE messages ADD COLUMN normalized_text TEXT")
    legacy.execute("ALTER TABLE results ADD COLUMN result_summary TEXT")
    legacy.execute(
        "INSERT INTO messages (local_event_id, direction, room, did, "
        "normalized_text_sha256, status, created_at, normalized_text) "
        "VALUES ('a', 'out', 'mb-x', 'did:key:z', 'sha256:0', 'confirmed', 'now', "
        "'a stranger''s text')"
    )
    legacy.commit()
    legacy.close()
    assert _database_contains(path, "a stranger's text")

    reopened = Ledger(path)
    for table, column in (("messages", "normalized_text"), ("results", "result_summary")):
        names = {row[1] for row in reopened.conn.execute(f"PRAGMA table_info({table})").fetchall()}
        assert column not in names, f"{table}.{column} survived the migration"

    # The column is gone from the schema. That the *bytes* also go is a separate
    # property, asserted by test_retiring_a_payload_column_also_scrubs_the_file and by
    # test_a_file_already_stripped_by_an_older_build_is_still_scrubbed.
    row = reopened.conn.execute("SELECT * FROM messages WHERE local_event_id = 'a'").fetchone()
    assert row is not None
    assert "normalized_text" not in set(row.keys())


def test_an_older_database_gains_the_columns_the_code_now_writes(tmp_path: Path) -> None:
    """The other half of the migration, and the one that fails loudly in production.

    `CREATE TABLE IF NOT EXISTS` leaves an existing table alone, so a database from an
    earlier build kept the old `results` shape while the code had started naming `status`
    and `summary_bytes`. Nothing failed at startup — it would have failed on the first
    real job, on a live node.
    """
    path = tmp_path / "old.db"
    first = Ledger(path)
    for column in ("status", "summary_bytes"):
        first.conn.execute(f"ALTER TABLE results DROP COLUMN {column}")
    assert "status" not in {r[1] for r in first.conn.execute("PRAGMA table_info(results)")}
    first.close()

    reopened = Ledger(path)
    columns = {r[1] for r in reopened.conn.execute("PRAGMA table_info(results)")}
    assert {"status", "summary_bytes"} <= columns

    # And the code path that needs them actually works against the migrated table.
    reopened.insert_job(
        job_id="migrated-000001",
        protocol_version="1",
        requester_did=REQUESTER,
        provider_did=OTHER,
        request_room="mb-x",
        reply_room="mb-p-y",
        request_seq=1,
        request_hash="sha256:" + "0" * 64,
        task_type="canonical_json_sha256",
        status="completed",
        internal_test=False,
    )
    reopened.record_result(
        job_id="migrated-000001",
        result_hash="sha256:" + "1" * 64,
        status="ok",
        summary_bytes=42,
        provider_signature="c" * 86,
        result_seq=3,
    )
    stored = reopened.conn.execute(
        "SELECT status, summary_bytes FROM results WHERE job_id = 'migrated-000001'"
    ).fetchone()
    assert (stored["status"], stored["summary_bytes"]) == ("ok", 42)


def test_the_migration_is_idempotent_across_repeated_opens(tmp_path: Path) -> None:
    path = tmp_path / "repeat.db"
    for _ in range(3):
        Ledger(path).close()
    ledger = Ledger(path)
    assert ledger.integrity_ok()
    assert {"status", "summary_bytes"} <= {
        r[1] for r in ledger.conn.execute("PRAGMA table_info(results)")
    }


# ------------------------------- P1: canonicalisation failures are refusals


async def test_an_unpaired_surrogate_is_a_refusal_not_a_crash(
    runner: JobRunner, ledger: Ledger
) -> None:
    """It parses, it passes the schema, and it is not UTF-8.

    Uncaught it surfaced as an unhandled UnicodeEncodeError much later: no refusal record,
    no signed answer, and no rate-limit accounting for the sender.
    """
    with pytest.raises(RejectedJob) as exc:
        await runner.handle(
            text='{"v":"1","type":"job","job_id":"surrogate-000001",'
            '"task":"canonical_json_sha256","reply_room":"mb-p-r",'
            '"input":{"value":"\\ud800"}}',
            requester_did=REQUESTER,
            request_room="mb-test",
            request_seq=1,
        )
    assert exc.value.code == "input_not_canonical"


def test_duplicate_object_keys_are_refused(runner: JobRunner) -> None:
    """Python keeps the last key, so the node would hash a different document than a
    verifier that keeps the first — with the signature still verifying on both sides."""
    with pytest.raises(RejectedJob) as exc:
        runner.parse_and_validate(
            '{"v":"1","type":"job","job_id":"dupekey-0000001",'
            '"task":"protocol_manifest_snapshot","task":"canonical_json_sha256",'
            '"reply_room":"mb-p-r"}'
        )
    assert exc.value.code == "not_canonical_json"


@pytest.mark.parametrize("bad", ["NaN", "Infinity", "-Infinity"])
def test_json_extensions_are_refused_at_the_parse(bad: str) -> None:
    with pytest.raises(CanonicalJSONError):
        parse_strict(f'{{"value":{bad}}}')


def test_canonical_bytes_refuses_a_lone_surrogate() -> None:
    with pytest.raises(CanonicalJSONError, match="surrogate"):
        canonical_bytes({"value": "\ud800"})


# --------------------------------------------- P1: job_id cannot be squatted


async def test_another_requesters_job_id_is_refused_loudly(runner: JobRunner) -> None:
    """Silently dropping this let anyone erase another agent's job by guessing its id
    first: no execution, no reply, and nothing recorded anywhere."""
    first = await runner.handle(
        text=job_line(job_id="contested-000001"),
        requester_did=REQUESTER,
        request_room="mb-test",
        request_seq=1,
    )
    assert first is not None

    with pytest.raises(RejectedJob) as exc:
        await runner.handle(
            text=job_line(job_id="contested-000001"),
            requester_did=OTHER,
            request_room="mb-test",
            request_seq=2,
        )
    assert exc.value.code == "job_id_taken"


async def test_the_same_requester_repeating_a_job_id_is_still_idempotent(
    runner: JobRunner,
) -> None:
    """The genuine duplicate case must stay silent — that is the idempotency contract."""
    text = job_line(job_id="idempotent-0001")
    assert (
        await runner.handle(
            text=text, requester_did=REQUESTER, request_room="mb-test", request_seq=1
        )
        is not None
    )
    assert (
        await runner.handle(
            text=text, requester_did=REQUESTER, request_room="mb-test", request_seq=2
        )
        is None
    )


# ------------------------------- P1: the evidence column holds the right signature


async def test_the_receipt_row_stores_the_results_signature(
    runner: JobRunner, ledger: Ledger
) -> None:
    """`provider_signature` is the RESULT's signature. Storing the receipt's own there
    left the wrong value in the evidence column while receipt_json stayed right, so
    nothing looked broken."""
    outcome = await runner.handle(
        text=job_line(), requester_did=REQUESTER, request_room="mb-test", request_seq=1
    )
    assert outcome is not None and outcome.receipt is not None
    ledger.record_receipt(outcome.receipt, json.dumps(outcome.receipt), internal_test=False)

    row = ledger.get_receipt(outcome.job_id)
    assert row is not None
    assert row["provider_signature"] == outcome.result["sig"]
    assert row["provider_signature"] != outcome.receipt["sig"]


# ------------------------------------------------------- P1: redaction gaps


@pytest.mark.parametrize(
    ("line", "leak"),
    [
        ('{"token":"abc123def456"}', "abc123def456"),
        ('"api_key": "abcdef123456"', "abcdef123456"),
        ("Authorization: Bearer abcdef1234567890xyz", "abcdef1234567890xyz"),
        ('{"Authorization": "Bearer abcdef1234567890xyz"}', "abcdef1234567890xyz"),
        ("refresh_token=1//0gabcdefghijklmnop", "0gabcdefghijklmnop"),
        ("passphrase = hunter2xyz", "hunter2xyz"),
    ],
)
def test_json_encoded_credentials_are_redacted(line: str, leak: str) -> None:
    """The serialised form is the one most likely to be logged, and it passed through:
    the pattern required `key:` with no quote between them."""
    assert leak not in redact(line)


def test_redaction_leaves_ordinary_lines_and_dids_alone() -> None:
    """A filter that eats the DID would make the logs useless, which is its own failure."""
    assert redact(REQUESTER) == REQUESTER
    assert redact("mailbox poll returned 0 messages") == "mailbox poll returned 0 messages"
    assert redact_value({"did": REQUESTER, "seq": 12}) == {"did": REQUESTER, "seq": 12}


# ----------------------------------------- P1: one allowlist, not two


@pytest.mark.parametrize(
    "url",
    [
        "https://technocore.chat/llms.txt",
        "https://api.github.com/repos/flop-labs/technocore-chat/commits/main",
    ],
)
def test_every_origin_this_node_contacts_is_allowlisted(url: str) -> None:
    assert_allowed_origin(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://technocore.chat.attacker.example/x",
        "http://169.254.169.254/latest/meta-data/",
        "https://api.github.com.attacker.example/x",
        "http://localhost:5432/",
    ],
)
def test_lookalike_origins_are_refused(url: str) -> None:
    """Matching is on the parsed origin, never a prefix — `https://technocore.chat` is a
    prefix of `https://technocore.chat.attacker.example`."""
    with pytest.raises(ConfigError):
        assert_allowed_origin(url)


def test_the_watcher_checks_the_allowlist_on_its_one_request_method() -> None:
    """The gate is on the method that makes the request, so a future third URL has to
    pass through it too."""
    import inspect

    from technocore_node.service.watcher import ProtocolWatcher

    assert "assert_allowed_origin" in inspect.getsource(ProtocolWatcher._fetch)


def test_retiring_a_payload_column_also_scrubs_the_file(tmp_path: Path) -> None:
    """Dropping the column is half the job; the bytes were still in the file.

    SQLite keeps freed pages until they are reused, so a database upgraded from a build
    that stored payloads kept them readable to anyone with the file. The migration now
    VACUUMs after a retirement, which rewrites the database without them.
    """
    path = tmp_path / "payload.db"
    Ledger(path).close()

    legacy = sqlite3.connect(path)
    legacy.execute("ALTER TABLE messages ADD COLUMN normalized_text TEXT")
    legacy.execute(
        "INSERT INTO messages (local_event_id, direction, room, did, "
        "normalized_text_sha256, status, created_at, normalized_text) "
        "VALUES ('a', 'out', 'mb-x', 'did:key:z', 'sha256:0', 'confirmed', 'now', "
        "'a-strangers-private-payload-7c1f')"
    )
    legacy.commit()
    legacy.close()
    assert _database_contains(path, "a-strangers-private-payload-7c1f")

    Ledger(path).close()
    assert not _database_contains(path, "a-strangers-private-payload-7c1f")


async def test_losing_the_insert_race_still_refuses_a_foreign_job_id(
    runner: JobRunner, ledger: Ledger
) -> None:
    """Two requesters can both pass the ownership check before either has written.

    The loser of the insert must still be told, or the squatting problem simply moves
    inside the race window and becomes intermittent instead of fixed.
    """
    real_insert = ledger.insert_job

    def insert_then_lose(**fields: object) -> bool:
        # Stand in for the other requester winning between the check and the insert.
        real_insert(**{**fields, "requester_did": OTHER})
        return False

    ledger.insert_job = insert_then_lose  # type: ignore[method-assign]
    try:
        with pytest.raises(RejectedJob) as exc:
            await runner.handle(
                text=job_line(job_id="raced-00000001"),
                requester_did=REQUESTER,
                request_room="mb-test",
                request_seq=1,
            )
    finally:
        ledger.insert_job = real_insert  # type: ignore[method-assign]
    assert exc.value.code == "job_id_taken"


async def test_losing_the_race_to_yourself_stays_silently_idempotent(
    runner: JobRunner, ledger: Ledger
) -> None:
    """A redelivery of one's own job is not an error, however the race resolves.

    What it resolves *to* depends on whether the earlier attempt got as far as an answer.
    A row with a receipt is answered, and the redelivery is dropped. A row without one is
    only *seen*: an attempt died between inserting the job and writing its receipt, and
    treating that as a duplicate would spend the caller's `job_id` on work they can never
    be shown. So it resumes. Neither is an error, and that is the point.
    """
    real_insert = ledger.insert_job

    def insert_then_lose(**fields: object) -> bool:
        real_insert(**fields)
        return False

    ledger.insert_job = insert_then_lose  # type: ignore[method-assign]
    try:
        resumed = await runner.handle(
            text=job_line(job_id="selfrace-00001"),
            requester_did=REQUESTER,
            request_room="mb-test",
            request_seq=1,
        )
    finally:
        ledger.insert_job = real_insert  # type: ignore[method-assign]

    assert resumed is not None
    assert ledger.get_receipt("selfrace-00001") is not None

    # Now it is answered, so the next redelivery is dropped.
    assert (
        await runner.handle(
            text=job_line(job_id="selfrace-00001"),
            requester_did=REQUESTER,
            request_room="mb-test",
            request_seq=1,
        )
        is None
    )


def test_the_published_job_id_contract_says_globally_unique() -> None:
    """The schema is the public contract; it said per-requester while the code did not."""
    from technocore_node.jobs.schema import JOB_SCHEMA

    description = JOB_SCHEMA["properties"]["job_id"]["description"]
    assert "GLOBALLY unique" in description
    assert "per requester" not in description


def test_a_file_already_stripped_by_an_older_build_is_still_rewritten(tmp_path: Path) -> None:
    """The database most likely to still hold payloads is the half-upgraded one.

    Conditioning the rewrite on "did *this* startup drop a column" was the obvious rule
    and the wrong one: a file whose columns an earlier build had already dropped would
    never qualify again. The marker lives in the database instead, so the rewrite happens
    once per file whichever build dropped the columns.

    What is asserted is that the rewrite *runs* on such a file. Whether any bytes were
    still there to remove depends on SQLite's page reuse — on 3.45 `DROP COLUMN` rewrites
    the table and usually takes them with it — so this test does not claim otherwise.
    """
    path = tmp_path / "half-upgraded.db"
    Ledger(path).close()

    legacy = sqlite3.connect(path, isolation_level=None)
    legacy.execute("ALTER TABLE messages ADD COLUMN normalized_text TEXT")
    legacy.execute("ALTER TABLE messages DROP COLUMN normalized_text")
    legacy.execute("PRAGMA user_version = 0")  # the state the older build left behind
    legacy.close()

    reopened = Ledger(path)
    assert int(reopened.conn.execute("PRAGMA user_version").fetchone()[0]) == Ledger._SCRUB_VERSION
    assert reopened.integrity_ok()
    reopened.close()


def test_the_scrub_runs_once_and_records_that_it_did(tmp_path: Path) -> None:
    path = tmp_path / "once.db"
    first = Ledger(path)
    assert int(first.conn.execute("PRAGMA user_version").fetchone()[0]) == Ledger._SCRUB_VERSION
    first.close()

    reopened = Ledger(path)
    assert int(reopened.conn.execute("PRAGMA user_version").fetchone()[0]) == Ledger._SCRUB_VERSION
    assert reopened.integrity_ok()


def test_the_reserved_network_fields_are_declared_not_merely_described(tmp_path: Path) -> None:
    """`additionalProperties: false` means a documented-but-undeclared field is refused.

    The docs promised six optional settlement fields and the schema declared none, so the
    adapter written against the documented contract produced receipts invalid under it. A
    reservation the schema rejects is not a reservation.
    """
    import jsonschema

    from technocore_node.jobs.schema import RECEIPT_SCHEMA, RESERVED_NETWORK_FIELDS

    for field in RESERVED_NETWORK_FIELDS:
        assert field in RECEIPT_SCHEMA["properties"], field

    receipt = {
        "v": "1",
        "type": "receipt",
        "receipt_id": "rcpt-abcdef123456",
        "job_id": "job-abcdef12",
        "requester_did": REQUESTER,
        "provider_did": OTHER,
        "request_hash": "sha256:" + "0" * 64,
        "result_hash": "sha256:" + "1" * 64,
        "internal_test": False,
        "created_at": "2026-08-28T00:00:00Z",
        "receipt_hash": "sha256:" + "2" * 64,
        "sig": "a" * 86,
    }
    validator = jsonschema.Draft202012Validator(RECEIPT_SCHEMA)
    assert not list(validator.iter_errors(receipt))

    annotated = {
        **receipt,
        "network": "technocore",
        "tx_hash": "0x" + "a" * 64,
        "block_number": 1234,
        "testnet_job_id": "tn-1",
        "compute_units": 2.5,
        "verifier_did": OTHER,
    }
    assert not list(validator.iter_errors(annotated)), "an annotated receipt must validate"


def test_the_technocore_adapter_produces_a_valid_receipt(tmp_path: Path) -> None:
    """The adapter and the schema have to agree, or the seam is decorative."""
    import jsonschema

    from technocore_node.jobs.schema import RECEIPT_SCHEMA
    from technocore_node.testnet.technocore import TechnocoreAdapter

    receipt = {
        "v": "1",
        "type": "receipt",
        "receipt_id": "rcpt-abcdef123456",
        "job_id": "job-abcdef12",
        "requester_did": REQUESTER,
        "provider_did": OTHER,
        "request_hash": "sha256:" + "0" * 64,
        "result_hash": "sha256:" + "1" * 64,
        "internal_test": False,
        "created_at": "2026-08-28T00:00:00Z",
        "receipt_hash": "sha256:" + "2" * 64,
        "sig": "a" * 86,
    }
    annotated = TechnocoreAdapter.annotate_receipt(object.__new__(TechnocoreAdapter), receipt)
    assert annotated["network"] == "technocore"
    assert not list(jsonschema.Draft202012Validator(RECEIPT_SCHEMA).iter_errors(annotated))
    assert receipt is not annotated, "annotation must not mutate the signed receipt"
    assert "network" not in receipt


async def test_an_unpublished_audit_copy_is_recorded_as_owed_not_shrugged_off(
    runner: JobRunner, ledger: Ledger
) -> None:
    """A receipt only the requester can see does not meet the contract.

    The owned-room write can fail for reasons unrelated to the job — a rate limit, an
    upstream at capacity — and when it did, the job was still marked complete and the
    public copy was simply never written. Nothing recorded it, so nothing could retry it.
    """
    outcome = await runner.handle(
        text=job_line(job_id="owed-000000001"),
        requester_did=REQUESTER,
        request_room="mb-test",
        request_seq=1,
    )
    assert outcome is not None and outcome.receipt is not None

    ledger.record_receipt(outcome.receipt, json.dumps(outcome.receipt), internal_test=False)
    assert ledger.audit_backlog()["owed"] == 1
    assert [r["job_id"] for r in ledger.receipts_awaiting_audit_copy()] == ["owed-000000001"]

    ledger.set_audit_seq("owed-000000001", 42)
    assert ledger.audit_backlog()["owed"] == 0
    assert ledger.audit_backlog()["published"] == 1
    assert ledger.receipts_awaiting_audit_copy() == []
    assert ledger.get_receipt("owed-000000001")["audit_seq"] == 42


async def test_an_internal_test_receipt_is_never_counted_as_owed(
    runner: JobRunner, ledger: Ledger
) -> None:
    """It is deliberately not published to the owned room, so it is not a backlog item."""
    outcome = await runner.handle(
        text=job_line(job_id="internal-00001"),
        requester_did=REQUESTER,
        request_room="mb-test",
        request_seq=1,
        internal_test=True,
    )
    assert outcome is not None and outcome.receipt is not None
    ledger.record_receipt(outcome.receipt, json.dumps(outcome.receipt), internal_test=True)
    assert ledger.audit_backlog()["owed"] == 0


def test_the_reconciler_is_bounded(ledger: Ledger) -> None:
    """A backlog after an outage must not become a write storm on recovery."""
    assert len(ledger.receipts_awaiting_audit_copy(limit=3)) <= 3


# ------------------------------------- the receipt must survive a crash


async def test_a_receipt_is_durable_before_it_is_announced(
    runner: JobRunner, ledger: Ledger
) -> None:
    """A crash between finishing the work and announcing it must not lose the receipt.

    The job is already marked complete by the time a receipt exists, so if the row were
    written after publishing, a crash in between would leave a completed job whose
    receipt does not exist — and whose duplicate check suppresses every retry. It would
    be gone, silently and permanently.
    """
    outcome = await runner.handle(
        text=job_line(job_id="durable-000001"),
        requester_did=REQUESTER,
        request_room="mb-test",
        request_seq=1,
    )
    assert outcome is not None and outcome.receipt is not None

    # Exactly what process_message does before it publishes anything at all.
    ledger.record_receipt(outcome.receipt, json.dumps(outcome.receipt), internal_test=False)

    row = ledger.get_receipt("durable-000001")
    assert row is not None
    assert row["technocore_seq"] is None, "not yet announced to the requester"
    assert row["audit_seq"] is None, "not yet announced publicly"
    assert row["audit_state"] == "owed"
    assert [r["job_id"] for r in ledger.receipts_awaiting_audit_copy()] == ["durable-000001"]


def test_a_receipt_already_in_the_owned_room_is_not_published_again(ledger: Ledger) -> None:
    """The room is the authority on what is in it.

    Without consulting it, a crash between publishing and recording would republish on
    the next pass, and a database migrated from an older build would re-announce every
    receipt it had ever published.
    """
    receipt = {
        "type": "receipt",
        "receipt_id": "rcpt-abcdef123456",
        "job_id": "already-0000001",
        "requester_did": REQUESTER,
        "provider_did": OTHER,
        "request_hash": "sha256:" + "0" * 64,
        "result_hash": "sha256:" + "1" * 64,
        "provider_signature": "b" * 86,
        "receipt_hash": "sha256:" + "2" * 64,
        "sig": "a" * 86,
        "created_at": "2026-08-28T00:00:00Z",
    }
    ledger.insert_job(
        job_id="already-0000001",
        protocol_version="1",
        requester_did=REQUESTER,
        provider_did=OTHER,
        request_room="mb-x",
        reply_room="mb-p-y",
        request_seq=1,
        request_hash="sha256:" + "0" * 64,
        task_type="canonical_json_sha256",
        status="completed",
        internal_test=False,
    )
    ledger.record_receipt(receipt, json.dumps(receipt), internal_test=False)
    assert ledger.audit_backlog()["owed"] == 1

    # What sync_owned_room does after reading the room back.
    observed = {"already-0000001": (77, str(receipt["receipt_hash"]))}
    assert ledger.mark_published(observed) == 1
    assert ledger.audit_backlog()["owed"] == 0
    assert ledger.get_receipt("already-0000001")["audit_seq"] == 77
    assert ledger.receipts_awaiting_audit_copy() == []

    # Idempotent: seeing it again changes nothing.
    assert ledger.mark_published(observed) == 0


def test_a_receipt_that_never_publishes_is_quarantined_not_left_blocking(
    ledger: Ledger,
) -> None:
    """One unpublishable receipt at the head of an ordered queue would stall every
    receipt behind it. The backlog would stop being a backlog and become a blockage."""
    for i in range(2):
        job_id = f"stuck-{i:010d}"
        ledger.insert_job(
            job_id=job_id,
            protocol_version="1",
            requester_did=REQUESTER,
            provider_did=OTHER,
            request_room="mb-x",
            reply_room="mb-p-y",
            request_seq=i,
            request_hash="sha256:" + "0" * 64,
            task_type="canonical_json_sha256",
            status="completed",
            internal_test=False,
        )
        receipt = {
            "receipt_id": f"rcpt-{i:012d}",
            "job_id": job_id,
            "requester_did": REQUESTER,
            "provider_did": OTHER,
            "request_hash": "sha256:" + "0" * 64,
            "result_hash": "sha256:" + "1" * 64,
            "provider_signature": "b" * 86,
            "receipt_hash": "sha256:" + "2" * 64,
            "sig": "a" * 86,
            "created_at": f"2026-08-28T00:00:0{i}Z",
        }
        ledger.record_receipt(receipt, json.dumps(receipt), internal_test=False)

    for attempt in range(1, 6):
        quarantined = ledger.note_audit_attempt("stuck-0000000000", "upstream refused", 5)
        assert quarantined is (attempt == 5)

    assert ledger.audit_backlog() == {"owed": 1, "quarantined": 1, "published": 0}
    # The healthy receipt behind it is now at the head of the queue.
    assert [r["job_id"] for r in ledger.receipts_awaiting_audit_copy()] == ["stuck-0000000001"]


def test_the_queue_tries_the_least_failed_receipt_first(ledger: Ledger) -> None:
    """Ordering by age alone lets a struggling row hold the head slot until it is
    quarantined, delaying every fresh receipt behind it."""
    for i in range(2):
        job_id = f"order-{i:010d}"
        ledger.insert_job(
            job_id=job_id,
            protocol_version="1",
            requester_did=REQUESTER,
            provider_did=OTHER,
            request_room="mb-x",
            reply_room="mb-p-y",
            request_seq=i,
            request_hash="sha256:" + "0" * 64,
            task_type="canonical_json_sha256",
            status="completed",
            internal_test=False,
        )
        ledger.record_receipt(
            {
                "receipt_id": f"rcpt-o{i:011d}",
                "job_id": job_id,
                "requester_did": REQUESTER,
                "provider_did": OTHER,
                "request_hash": "sha256:" + "0" * 64,
                "result_hash": "sha256:" + "1" * 64,
                "provider_signature": "b" * 86,
                "receipt_hash": "sha256:" + "2" * 64,
                "sig": "a" * 86,
                "created_at": f"2026-08-28T00:00:0{i}Z",
            },
            "{}",
            internal_test=False,
        )

    ledger.note_audit_attempt("order-0000000000", "upstream refused", 5)
    assert [r["job_id"] for r in ledger.receipts_awaiting_audit_copy()] == [
        "order-0000000001",
        "order-0000000000",
    ]


# ------------------------------ the audit copy must not be re-announced


def _receipt(job_id: str, receipt_hash: str = "sha256:" + "2" * 64) -> dict[str, object]:
    return {
        "v": "1",
        "type": "receipt",
        "receipt_id": f"rcpt-{job_id[:12]:>012}",
        "job_id": job_id,
        "requester_did": REQUESTER,
        "provider_did": OTHER,
        "request_hash": "sha256:" + "0" * 64,
        "result_hash": "sha256:" + "1" * 64,
        "provider_signature": "b" * 86,
        "internal_test": False,
        "receipt_hash": receipt_hash,
        "sig": "a" * 86,
        "created_at": "2026-08-28T00:00:00Z",
    }


def _with_job(ledger: Ledger, job_id: str) -> None:
    ledger.insert_job(
        job_id=job_id,
        protocol_version="1",
        requester_did=REQUESTER,
        provider_did=OTHER,
        request_room="mb-x",
        reply_room="mb-p-y",
        request_seq=1,
        request_hash="sha256:" + "0" * 64,
        task_type="canonical_json_sha256",
        status="completed",
        internal_test=False,
    )


def test_a_migrated_database_does_not_re_announce_what_it_already_published(
    tmp_path: Path,
) -> None:
    """`ADD COLUMN ... DEFAULT 'owed'` writes that default into every existing row.

    Including receipts an earlier build had already published and recorded an audit_seq
    for — so the first reconciliation pass would have announced a whole ledger's worth of
    them again. The column that says which ones those are is right there, so it is asked.
    """
    path = tmp_path / "migrated.db"
    ledger = Ledger(path)
    _with_job(ledger, "published-0001")
    _with_job(ledger, "stillowed-0001")
    ledger.record_receipt(_receipt("published-0001"), json.dumps(_receipt("published-0001")), False)
    ledger.record_receipt(_receipt("stillowed-0001"), json.dumps(_receipt("stillowed-0001")), False)
    ledger.set_audit_seq("published-0001", 5)

    # Rewind to what the older build's migration produced: the state column absent, so
    # reopening re-adds it with its default for every row.
    ledger.conn.execute("ALTER TABLE receipts DROP COLUMN audit_state")
    ledger.close()

    reopened = Ledger(path)
    assert reopened.audit_backlog() == {"owed": 1, "quarantined": 0, "published": 1}
    assert [r["job_id"] for r in reopened.receipts_awaiting_audit_copy()] == ["stillowed-0001"]


def test_a_row_with_an_audit_seq_is_never_queued(tmp_path: Path) -> None:
    """Two ways of saying published, and either one must keep a row out of the queue."""
    ledger = Ledger(tmp_path / "belt.db")
    _with_job(ledger, "seqonly-000001")
    ledger.record_receipt(_receipt("seqonly-000001"), json.dumps(_receipt("seqonly-000001")), False)
    with ledger.tx() as conn:
        conn.execute("UPDATE receipts SET audit_seq = 9 WHERE job_id = 'seqonly-000001'")
    assert ledger.receipts_awaiting_audit_copy() == []


def test_sync_matches_the_receipt_not_merely_the_job_id(ledger: Ledger) -> None:
    """`publicly_auditable` is the claim that must not be taken on faith.

    Matching on job_id alone would let any message this key ever wrote carrying that id
    mark a *different* receipt as publicly auditable.
    """
    _with_job(ledger, "matched-0000001")
    stored = _receipt("matched-0000001", receipt_hash="sha256:" + "a" * 64)
    ledger.record_receipt(stored, json.dumps(stored), False)

    # A message with the right job_id but a different receipt changes nothing.
    assert ledger.mark_published({"matched-0000001": (3, "sha256:" + "f" * 64)}) == 0
    assert ledger.audit_backlog()["owed"] == 1

    assert ledger.mark_published({"matched-0000001": (3, "sha256:" + "a" * 64)}) == 1
    assert ledger.audit_backlog()["owed"] == 0


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        ("not json at all", "not valid JSON"),
        ("[]", "not an object"),
        ('"a string"', "not an object"),
        ("{}", "not a receipt"),
        ('{"type":"result","job_id":"bad-0000000001"}', "not a receipt"),
        ('{"type":"receipt","job_id":"someone-else","receipt_hash":"x"}', "different job_id"),
    ],
)
def test_a_stored_row_that_is_not_a_receipt_is_quarantined(stored: str, expected: str) -> None:
    """Checking only that the JSON parses let `{}`, `[]` and `"text"` through — each
    either posted into the audit room as something that is not a receipt, or raised
    inside the publisher without ever counting as an attempt."""
    from technocore_node.service.node import _unpublishable

    problem = _unpublishable(stored, "bad-0000000001", "sha256:" + "2" * 64)
    assert problem is not None
    assert expected in problem


def test_a_well_formed_receipt_is_publishable() -> None:
    from technocore_node.service.node import _unpublishable

    receipt = _receipt("good-0000000001")
    assert (
        _unpublishable(json.dumps(receipt), "good-0000000001", str(receipt["receipt_hash"])) is None
    )


def test_a_non_loopback_bind_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Three documents promised loopback-only and nothing enforced it.

    The node runs beside unrelated services on a shared host and is meant to be reached
    through a reverse proxy. A promise kept only by a default is not kept.
    """
    from technocore_node.config import load_settings

    for host in ("0.0.0.0", "::", "10.0.0.5", "example.com"):  # noqa: S104
        monkeypatch.setenv("TCN_BIND_HOST", host)
        with pytest.raises(ConfigError, match="loopback"):
            load_settings()

    for host in ("127.0.0.1", "::1", "localhost"):
        monkeypatch.setenv("TCN_BIND_HOST", host)
        assert load_settings().bind_host == host


async def test_a_receipt_carries_no_result_seq(runner: JobRunner) -> None:
    """A field that can only ever be null is worse than an absent one.

    The receipt is built and signed before the result is published, so the result's seq
    does not exist yet — and adding it afterwards would invalidate the signature that
    makes the receipt worth anything. The docs showed a number there.
    """
    from technocore_node.jobs.schema import RECEIPT_SCHEMA

    outcome = await runner.handle(
        text=job_line(job_id="noseq-00000001"),
        requester_did=REQUESTER,
        request_room="mb-test",
        request_seq=42,
    )
    assert outcome is not None and outcome.receipt is not None
    assert "result_seq" not in outcome.receipt
    assert "result_seq" not in RECEIPT_SCHEMA["properties"]
    assert outcome.receipt["request_seq"] == 42, "the one seq that IS known is kept"
