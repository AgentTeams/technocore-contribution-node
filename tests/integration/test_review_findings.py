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


def _file_contains(path: Path, needle: str) -> bool:
    """Read a temp file's bytes from sync code, so the async tests stay free of file IO."""
    return needle.encode() in Path(path).read_bytes()


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

    assert not _file_contains(ledger.path, secret), "caller data reached the database file"


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
    assert _file_contains(path, "a stranger's text")

    reopened = Ledger(path)
    for table, column in (("messages", "normalized_text"), ("results", "result_summary")):
        names = {row[1] for row in reopened.conn.execute(f"PRAGMA table_info({table})").fetchall()}
        assert column not in names, f"{table}.{column} survived the migration"

    # Readable through SQL is the property the migration actually delivers, and it is the
    # one asserted. Dropping a column does NOT scrub the bytes already written into the
    # file — freed pages keep their contents until reused or VACUUMed — so a database
    # that ran the old build should be treated as still holding whatever it stored.
    # docs/SECURITY.md says so rather than this test pretending otherwise.
    row = reopened.conn.execute("SELECT * FROM messages WHERE local_event_id = 'a'").fetchone()
    assert row is not None
    assert "normalized_text" not in set(row.keys())


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
    ledger.record_receipt(outcome.receipt, json.dumps(outcome.receipt), 5, internal_test=False)

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
