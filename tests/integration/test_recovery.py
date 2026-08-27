"""Restart and crash recovery.

The node is a long-running process that signs monotonically and reads a cursor. Both of
those have to survive an abrupt stop, because the failure mode when they do not is silent:
every write refused for a stale nonce, or a whole room reprocessed from its oldest
retained message.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from technocore_node.ledger.db import Ledger
from technocore_node.protocol.client import NonceAllocator


def test_the_ledger_uses_wal(tmp_path: Path) -> None:
    """WAL is what lets a reader see a consistent database while a write is in flight, and
    what makes an abrupt stop recoverable rather than a truncated file."""
    ledger = Ledger(tmp_path / "state.db")
    mode = ledger.conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"


def test_integrity_check_passes_on_a_fresh_database(ledger: Ledger) -> None:
    assert ledger.integrity_ok()


def test_state_survives_reopening(tmp_path: Path, did: str) -> None:
    path = tmp_path / "state.db"
    first = Ledger(path)
    first.insert_job(
        job_id="survives-job-001",
        protocol_version="1",
        requester_did=did,
        provider_did=did,
        request_room="mb-test",
        reply_room="mb-p-reply",
        request_seq=1,
        request_hash="sha256:" + "0" * 64,
        task_type="canonical_json_sha256",
        status="completed",
        internal_test=False,
    )
    first.set_cursor("mb-test", 17)
    first.close()

    second = Ledger(path)
    assert second.job_exists("survives-job-001")
    assert second.cursor("mb-test") == 17
    assert second.integrity_ok()


def test_an_uncommitted_transaction_leaves_no_partial_state(ledger: Ledger, did: str) -> None:
    """A crash mid-write must not leave a half-recorded job."""
    with pytest.raises(RuntimeError), ledger.tx() as conn:
        conn.execute(
            "INSERT INTO jobs (job_id, protocol_version, requester_did, provider_did, "
            "request_room, reply_room, request_hash, task_type, status, received_at, "
            "internal_test) VALUES (?, '1', ?, ?, 'mb-x', 'mb-p-y', 'sha256:0', "
            "'canonical_json_sha256', 'received', '2026-01-01T00:00:00Z', 0)",
            ("partial-job-0001", did, did),
        )
        raise RuntimeError("simulated crash")
    assert not ledger.job_exists("partial-job-0001")


def test_a_cursor_never_moves_backwards(ledger: Ledger) -> None:
    """A late or out-of-order update must not rewind the poller into replaying a room."""
    ledger.set_cursor("mb-test", 100)
    ledger.set_cursor("mb-test", 40)
    assert ledger.cursor("mb-test") == 100


def test_nonces_resume_above_the_stored_high_water_mark(tmp_path: Path, did: str) -> None:
    path = tmp_path / "state.db"
    ledger = Ledger(path)
    allocator = NonceAllocator(floor_lookup=ledger.last_nonce)
    used = [allocator.next(did, "mb-test") for _ in range(5)]
    for nonce in used:
        ledger.record_message(
            local_event_id=f"out-mb-test-{nonce}",
            direction="out",
            room="mb-test",
            did=did,
            nonce=nonce,
            normalized_text_sha256="sha256:" + "0" * 64,
            status="confirmed",
        )
    ledger.close()

    restarted = Ledger(path)
    resumed = NonceAllocator(floor_lookup=restarted.last_nonce)
    assert resumed.next(did, "mb-test") > max(used)


def test_last_nonce_ignores_inbound_messages(ledger: Ledger, did: str) -> None:
    """Somebody else's nonce in our mailbox must not raise our own floor — the counter is
    per key, and inflating ours from a stranger's would be theirs to control."""
    ledger.record_message(
        local_event_id="in-mb-test-1",
        direction="in",
        room="mb-test",
        did=did,
        nonce=999_999_999_999,
        normalized_text_sha256="sha256:" + "0" * 64,
        status="received",
    )
    assert ledger.last_nonce(did, "mb-test") == 0


def test_a_duplicate_job_insert_is_rejected_by_the_primary_key(ledger: Ledger, did: str) -> None:
    fields = {
        "protocol_version": "1",
        "requester_did": did,
        "provider_did": did,
        "request_room": "mb-test",
        "reply_room": "mb-p-reply",
        "request_seq": 1,
        "request_hash": "sha256:" + "0" * 64,
        "task_type": "canonical_json_sha256",
        "status": "received",
        "internal_test": False,
    }
    assert ledger.insert_job(job_id="dupe-job-00000001", **fields) is True
    assert ledger.insert_job(job_id="dupe-job-00000001", **fields) is False


def test_metrics_snapshots_accumulate(ledger: Ledger) -> None:
    ledger.snapshot_metrics()
    ledger.snapshot_metrics()
    rows = ledger.conn.execute("SELECT COUNT(*) n FROM metrics_snapshots").fetchone()
    assert rows["n"] == 2


def test_the_schema_migration_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    Ledger(path).close()
    Ledger(path).close()
    ledger = Ledger(path)
    tables = {
        r["name"]
        for r in ledger.conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    assert {"identities", "jobs", "results", "receipts", "messages", "rejections"} <= tables


def test_no_private_key_column_exists_anywhere(ledger: Ledger) -> None:
    """A schema-level guarantee, not a convention: there is nowhere to put a key."""
    columns: list[str] = []
    for (table,) in ledger.conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall():
        columns += [row[1] for row in ledger.conn.execute(f"PRAGMA table_info({table})").fetchall()]
    joined = " ".join(columns).lower()
    for forbidden in ("private", "secret", "passphrase", "password", "seed"):
        assert forbidden not in joined


def test_foreign_keys_are_enforced(ledger: Ledger) -> None:
    assert ledger.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    with pytest.raises(sqlite3.IntegrityError), ledger.tx() as conn:
        conn.execute(
            "INSERT INTO results (job_id, result_hash, status, summary_bytes, "
            "provider_signature, created_at) VALUES ('nope', 'h', 'ok', 0, 's', 'now')"
        )
