"""SQLite access for the evidence ledger.

Single-writer, WAL, and every write in an explicit transaction. The node is one process
with a small job concurrency, so a connection-per-thread with a short busy timeout is
plenty — and it keeps the failure mode obvious rather than hiding it behind a pool.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any


def utcnow() -> str:
    """A UTC timestamp in the one format this node writes, everywhere."""
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


#: The columns :meth:`Ledger.update_job` may set. Shared with the combined
#: complete-and-record write so the two cannot allow different things.
_JOB_UPDATE_FIELDS = frozenset(
    {
        "status",
        "claimed_at",
        "completed_at",
        "failed_at",
        "latency_ms",
        "failure_code",
        "request_seq",
    }
)


class Ledger:
    """The node's own record of what it did, and of what it can still prove."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_lock = threading.Lock()
        with self._init_lock:
            self._migrate()

    # ------------------------------------------------------------ connections

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA busy_timeout = 10000")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")

    def _migrate(self) -> None:
        sql = resources.files("technocore_node.ledger").joinpath("schema.sql").read_text()
        self.conn.executescript(sql)
        self._reconcile_columns()

    #: Columns that must not exist. Retired because they held request or result text.
    _RETIRED_COLUMNS = (("messages", "normalized_text"), ("results", "result_summary"))

    #: Columns added after a table's first release, with the backfill for existing rows.
    #: `CREATE TABLE IF NOT EXISTS` leaves an existing table alone, so without this a
    #: database from an earlier build keeps the old shape and the first INSERT that names
    #: a new column fails at runtime — on a live node, on somebody's first real job.
    _ADDED_COLUMNS = (
        ("results", "status", "TEXT NOT NULL DEFAULT 'ok'"),
        ("results", "summary_bytes", "INTEGER NOT NULL DEFAULT 0"),
        ("receipts", "audit_seq", "INTEGER"),
        ("receipts", "audit_state", "TEXT NOT NULL DEFAULT 'owed'"),
        ("receipts", "audit_attempts", "INTEGER NOT NULL DEFAULT 0"),
        ("receipts", "audit_error", "TEXT"),
    )

    def _columns(self, table: str) -> set[str]:
        return {row[1] for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()}

    def _table_exists(self, table: str) -> bool:
        return (
            self.conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
            ).fetchone()
            is not None
        )

    def _reconcile_columns(self) -> None:
        """Bring an existing database to the current shape.

        Drops first, then adds. Both are idempotent and both are checked against
        `PRAGMA table_info` rather than against a version number, so a database at any
        past shape converges — including one this code has never seen.
        """
        for table, column in self._RETIRED_COLUMNS:
            if self._table_exists(table) and column in self._columns(table):
                self.conn.execute(f"ALTER TABLE {table} DROP COLUMN {column}")

        for table, column, definition in self._ADDED_COLUMNS:
            if self._table_exists(table) and column not in self._columns(table):
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

        self._backfill_audit_state()
        self._scrub_once()

    def _backfill_audit_state(self) -> None:
        """Derive `audit_state` for rows that predate it.

        `ADD COLUMN ... DEFAULT 'owed'` writes that default into every existing row,
        including receipts an earlier build had already published and recorded an
        `audit_seq` for. Left alone, the first reconciliation pass would treat a whole
        ledger's worth of published receipts as outstanding and announce them all again.
        The column's own `audit_seq` says which ones those are, so it is asked.
        """
        if not self._table_exists("receipts"):
            return
        if "audit_state" not in self._columns("receipts"):
            return
        self.conn.execute(
            "UPDATE receipts SET audit_state = 'published' "
            "WHERE audit_state = 'owed' AND (audit_seq IS NOT NULL OR internal_test = 1)"
        )

    #: Bumped when a one-off maintenance step must run against every existing database,
    #: recorded in `PRAGMA user_version` so it runs exactly once per file.
    _SCRUB_VERSION = 1

    def _scrub_once(self) -> None:
        """Rewrite the database once, to retire bytes a dropped column left behind.

        Conditioning this on "did *this* startup drop a column" was the obvious thing and
        the wrong one: a database upgraded by a build that dropped the columns but did not
        vacuum would never qualify again, and that is exactly the file most likely to
        still hold payloads. The marker is stored in the database instead, so the scrub
        happens once per file regardless of which build did the dropping.

        Best effort. VACUUM needs room for a second copy, and a node that refuses to start
        because it could not tidy up would be a worse outcome than one that starts and
        says so.
        """
        current = int(self.conn.execute("PRAGMA user_version").fetchone()[0])
        if current >= self._SCRUB_VERSION:
            return
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.conn.execute("VACUUM")
        except sqlite3.OperationalError:
            logging.getLogger(__name__).warning(
                "could not VACUUM the ledger; bytes from any retired payload column "
                "remain in the database file until it is vacuumed or replaced"
            )
            return
        self.conn.execute(f"PRAGMA user_version = {self._SCRUB_VERSION}")

    def integrity_ok(self) -> bool:
        row = self.conn.execute("PRAGMA integrity_check").fetchone()
        return bool(row) and row[0] == "ok"

    # ------------------------------------------------------------- identities

    def record_identity(
        self, did: str, fingerprint: str, public_key_hash: str, label: str | None = None
    ) -> None:
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO identities (did, fingerprint, public_key_hash, created_at, "
                "active, label) VALUES (?, ?, ?, ?, 1, ?) ON CONFLICT (did) DO NOTHING",
                (did, fingerprint, public_key_hash, utcnow(), label),
            )

    def identity(self, did: str) -> sqlite3.Row | None:
        row = self.conn.execute("SELECT * FROM identities WHERE did = ?", (did,)).fetchone()
        return _row(row)

    # --------------------------------------------------------------- messages

    def record_message(self, **fields: Any) -> None:
        columns = (
            "local_event_id",
            "direction",
            "room",
            "did",
            "nonce",
            "normalized_text_sha256",
            "signature",
            "technocore_seq",
            "technocore_ts",
            "status",
            "error_code",
            "created_at",
            "confirmed_at",
        )
        row = {c: fields.get(c) for c in columns}
        row["created_at"] = row["created_at"] or utcnow()
        placeholders = ", ".join("?" for _ in columns)
        with self.tx() as conn:
            conn.execute(
                # Safe: `columns` is the literal tuple three lines up, never input.
                f"INSERT OR REPLACE INTO messages ({', '.join(columns)}) "  # noqa: S608
                f"VALUES ({placeholders})",
                tuple(row[c] for c in columns),
            )

    def last_nonce(self, did: str, room: str) -> int:
        row = self.conn.execute(
            "SELECT MAX(nonce) AS n FROM messages WHERE did = ? AND room = ? AND direction = 'out'",
            (did, room),
        ).fetchone()
        return int(row["n"] or 0)

    # ------------------------------------------------------------ http nonces

    def claim_http_nonce(self, requester_did: str, nonce: int) -> bool:
        """Record `nonce` for `requester_did` if it advances their counter.

        Returns False when it does not — which is a replay, or a submission that raced
        ahead of one already accepted. The check and the write are one transaction on
        purpose: split them and two concurrent requests can both read the old value, both
        decide they advance, and both be accepted.
        """
        with self.tx() as conn:
            row = conn.execute(
                "SELECT last_nonce FROM http_nonces WHERE requester_did = ?",
                (requester_did,),
            ).fetchone()
            if row is not None and nonce <= int(row["last_nonce"]):
                return False
            conn.execute(
                "INSERT INTO http_nonces (requester_did, last_nonce, updated_at) "
                "VALUES (?, ?, ?) ON CONFLICT (requester_did) DO UPDATE SET "
                "last_nonce = excluded.last_nonce, updated_at = excluded.updated_at",
                (requester_did, nonce, utcnow()),
            )
        return True

    def http_nonce_floor(self, requester_did: str) -> int:
        row = self.conn.execute(
            "SELECT last_nonce FROM http_nonces WHERE requester_did = ?", (requester_did,)
        ).fetchone()
        return int(row["last_nonce"]) if row else 0

    # ------------------------------------------------------- deployment state

    def set_state(self, key: str, value: str | None) -> None:
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO deployment_state (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT (key) DO UPDATE SET value = excluded.value, "
                "updated_at = excluded.updated_at",
                (key, value, utcnow()),
            )

    def get_state(self, key: str) -> tuple[str | None, str | None]:
        """`(value, updated_at)`, or `(None, None)` when never observed."""
        row = self.conn.execute(
            "SELECT value, updated_at FROM deployment_state WHERE key = ?", (key,)
        ).fetchone()
        return (row["value"], row["updated_at"]) if row else (None, None)

    # ---------------------------------------------------------------- cursors

    def cursor(self, room: str) -> int:
        row = self.conn.execute("SELECT last_seq FROM cursors WHERE room = ?", (room,)).fetchone()
        return int(row["last_seq"]) if row else 0

    def set_cursor(self, room: str, last_seq: int) -> None:
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO cursors (room, last_seq, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT (room) DO UPDATE SET last_seq = MAX(last_seq, excluded.last_seq), "
                "updated_at = excluded.updated_at",
                (room, last_seq, utcnow()),
            )

    # ------------------------------------------------------------------- jobs

    def job_exists(self, job_id: str) -> bool:
        return (
            self.conn.execute("SELECT 1 FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            is not None
        )

    def job_requester(self, job_id: str) -> str | None:
        """The DID that already holds `job_id`, or None when it is free."""
        row = self.conn.execute(
            "SELECT requester_did FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        return str(row["requester_did"]) if row else None

    def get_job(self, job_id: str) -> sqlite3.Row | None:
        return _row(self.conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone())

    def insert_job(self, **fields: Any) -> bool:
        """Insert a job, returning False when this `job_id` was already seen.

        The uniqueness of `job_id` is what makes the whole pipeline idempotent: a replayed
        or re-delivered request lands here and stops.
        """
        columns = (
            "job_id",
            "protocol_version",
            "requester_did",
            "provider_did",
            "request_room",
            "reply_room",
            "request_seq",
            "request_hash",
            "task_type",
            "status",
            "received_at",
            "internal_test",
        )
        row = {c: fields.get(c) for c in columns}
        row["received_at"] = row["received_at"] or utcnow()
        row["internal_test"] = int(bool(row["internal_test"]))
        try:
            with self.tx() as conn:
                conn.execute(
                    # Safe: `columns` is a literal tuple, and every value is bound.
                    f"INSERT INTO jobs ({', '.join(columns)}) "  # noqa: S608
                    f"VALUES ({', '.join('?' for _ in columns)})",
                    tuple(row[c] for c in columns),
                )
        except sqlite3.IntegrityError:
            return False
        return True

    def update_job(self, job_id: str, **fields: Any) -> None:
        updates = {k: v for k, v in fields.items() if k in _JOB_UPDATE_FIELDS}
        if not updates:
            return
        assignments = ", ".join(f"{k} = ?" for k in updates)
        with self.tx() as conn:
            conn.execute(
                # Safe: `assignments` names only keys that survived the `allowed`
                # allowlist above; the values themselves are bound parameters.
                f"UPDATE jobs SET {assignments} WHERE job_id = ?",  # noqa: S608
                (*updates.values(), job_id),
            )

    def requester_job_count_since(self, requester_did: str, since_iso: str) -> int:
        """Jobs *and* refusals in the window.

        Counting refusals is what stops a malformed-request flood from being free: a
        sender that never produces a valid job still spends the same budget.
        """
        jobs = self.conn.execute(
            "SELECT COUNT(*) AS n FROM jobs WHERE requester_did = ? AND received_at >= ?",
            (requester_did, since_iso),
        ).fetchone()["n"]
        rejected = self.conn.execute(
            "SELECT COUNT(*) AS n FROM rejections WHERE requester_did = ? AND received_at >= ?",
            (requester_did, since_iso),
        ).fetchone()["n"]
        return int(jobs) + int(rejected)

    def record_rejection(
        self,
        *,
        job_id: str | None,
        requester_did: str | None,
        code: str,
        detail: str,
        request_room: str | None,
    ) -> None:
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO rejections (job_id, requester_did, code, detail, request_room, "
                "received_at) VALUES (?, ?, ?, ?, ?, ?)",
                (job_id, requester_did, code, detail[:200], request_room, utcnow()),
            )

    def rejection_for(self, job_id: str) -> sqlite3.Row | None:
        return _row(
            self.conn.execute(
                "SELECT * FROM rejections WHERE job_id = ? ORDER BY id DESC LIMIT 1",
                (job_id,),
            ).fetchone()
        )

    def rejection_counts(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT code, COUNT(*) n FROM rejections GROUP BY code ORDER BY n DESC"
        ).fetchall()
        return {str(r["code"]): int(r["n"]) for r in rows}

    # ---------------------------------------------------------------- results

    def record_result(
        self,
        job_id: str,
        result_hash: str,
        status: str,
        summary_bytes: int,
        provider_signature: str,
        result_seq: int | None,
    ) -> None:
        """Record what a result *was*, not what it said.

        `summary_bytes` rather than the summary: the size is what an operator needs to
        reason about, and the content is a stranger's data this node has no reader for.
        The hash still binds the result, so nothing verifiable is lost by not keeping it.
        """
        with self.tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO results (job_id, result_hash, status, "
                "summary_bytes, provider_signature, result_seq, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    job_id,
                    result_hash,
                    status,
                    summary_bytes,
                    provider_signature,
                    result_seq,
                    utcnow(),
                ),
            )

    # --------------------------------------------------------------- receipts

    def expect_internal_test(self, requester_did: str, job_id: str) -> None:
        """Declare, before it is sent, that a job about to arrive is this node's own test.

        The self-test posts a real job into the production mailbox, signed by a throwaway
        key, and it is indistinguishable at intake from a stranger's. Which code path
        happens to pick it up decided whether it counted as third-party use — and on
        2026-08-30 the command timed out after the write landed, the mailbox loop found
        the orphan, and this node published `third_party: 1 job, 1 requester` about
        itself.

        Keyed on the requester DID as well as the `job_id` so that a stranger cannot have
        their job classified as ours by guessing an identifier. They would gain nothing by
        it — the effect is to *undercount* this node's usage — but a guessable exemption
        is still an exemption.
        """
        self.set_state(f"internal_test_expect:{requester_did}:{job_id}", utcnow())

    def is_expected_internal_test(self, requester_did: str, job_id: str) -> bool:
        """Whether this exact job was declared as this node's own before it was sent."""
        return self.get_state(f"internal_test_expect:{requester_did}:{job_id}")[0] is not None

    def record_receipt(
        self,
        receipt: dict[str, Any],
        receipt_json: str,
        internal_test: bool,
        *,
        complete_job: dict[str, Any] | None = None,
    ) -> None:
        """Persist a receipt before it is announced anywhere.

        Order matters and this is the whole reason for it: the job is already marked
        complete by the time a receipt exists, so if the row were written after
        publishing, a crash in between would leave a completed job whose receipt does not
        exist and whose duplicate check suppresses every retry. Written first, the worst
        a crash costs is a copy that has not been announced yet — which the row says.

        `complete_job` closes the last of that window. Marking the job finished and
        writing its receipt are one fact, so they are one transaction: a crash between two
        separate statements would leave a job whose duplicate check refuses every retry
        and whose receipt does not exist — the work done, paid for, and unprovable. The
        keys are the ones :meth:`update_job` accepts.
        """
        with self.tx() as conn:
            if complete_job:
                updates = {k: v for k, v in complete_job.items() if k in _JOB_UPDATE_FIELDS}
                if updates:
                    assignments = ", ".join(f"{k} = ?" for k in updates)
                    conn.execute(
                        # Safe: `assignments` names only allowlisted keys; values are bound.
                        f"UPDATE jobs SET {assignments} WHERE job_id = ?",  # noqa: S608
                        (*updates.values(), receipt["job_id"]),
                    )
            conn.execute(
                "INSERT OR REPLACE INTO receipts (receipt_id, job_id, requester_did, "
                "provider_did, request_hash, result_hash, provider_signature, receipt_hash, "
                "receipt_json, technocore_seq, audit_seq, audit_state, audit_attempts, "
                "internal_test, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, 0, ?, ?)",
                (
                    receipt["receipt_id"],
                    receipt["job_id"],
                    receipt["requester_did"],
                    receipt["provider_did"],
                    receipt["request_hash"],
                    receipt["result_hash"],
                    # The RESULT's detached signature, which is what this column is for.
                    receipt["provider_signature"],
                    receipt["receipt_hash"],
                    receipt_json,
                    # An internal test is never announced publicly, so it is not owed.
                    "published" if internal_test else "owed",
                    int(internal_test),
                    receipt["created_at"],
                ),
            )

    def record_receipt_reply_seq(self, job_id: str, seq: int) -> None:
        with self.tx() as conn:
            conn.execute("UPDATE receipts SET technocore_seq = ? WHERE job_id = ?", (seq, job_id))

    def set_audit_seq(self, job_id: str, audit_seq: int) -> None:
        """Record that the auditable copy landed in the owned room."""
        with self.tx() as conn:
            conn.execute(
                "UPDATE receipts SET audit_seq = ?, audit_state = 'published', "
                "audit_error = NULL WHERE job_id = ?",
                (audit_seq, job_id),
            )

    def note_audit_attempt(self, job_id: str, error: str, max_attempts: int) -> bool:
        """Count a failed attempt, quarantining the row once it has had enough.

        Returns True when the row was quarantined. Without this, one receipt that can
        never be published sits at the head of an ordered queue and every receipt behind
        it waits forever — the backlog stops being a backlog and becomes a blockage.
        """
        with self.tx() as conn:
            conn.execute(
                "UPDATE receipts SET audit_attempts = audit_attempts + 1, audit_error = ? "
                "WHERE job_id = ?",
                (error[:200], job_id),
            )
            row = conn.execute(
                "SELECT audit_attempts FROM receipts WHERE job_id = ?", (job_id,)
            ).fetchone()
            quarantine = row is not None and int(row["audit_attempts"]) >= max_attempts
            if quarantine:
                conn.execute(
                    "UPDATE receipts SET audit_state = 'quarantined' WHERE job_id = ?",
                    (job_id,),
                )
        return quarantine

    def quarantine_receipt(self, job_id: str, error: str) -> None:
        """Take a row out of the queue immediately — for one that can never succeed."""
        with self.tx() as conn:
            conn.execute(
                "UPDATE receipts SET audit_state = 'quarantined', audit_error = ? WHERE job_id = ?",
                (error[:200], job_id),
            )

    def receipts_awaiting_audit_copy(self, limit: int = 5) -> Sequence[sqlite3.Row]:
        """Receipts whose owned-room copy is still owed: fewest attempts first.

        Ordering by attempts rather than by age is what keeps a struggling row from
        starving the queue before it is quarantined — a fresh receipt is tried before one
        that has already failed twice.
        """
        return self.conn.execute(
            "SELECT job_id, receipt_json, receipt_hash, audit_attempts FROM receipts "
            # `audit_seq IS NULL` as well as the state: two ways of saying published, and
            # a row that satisfies either must never be announced a second time.
            "WHERE audit_state = 'owed' AND audit_seq IS NULL AND internal_test = 0 "
            "ORDER BY audit_attempts, created_at LIMIT ?",
            (limit,),
        ).fetchall()

    def audit_backlog(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT audit_state, COUNT(*) n FROM receipts WHERE internal_test = 0 "
            "GROUP BY audit_state"
        ).fetchall()
        counts = {str(r["audit_state"]): int(r["n"]) for r in rows}
        return {
            "owed": counts.get("owed", 0),
            "quarantined": counts.get("quarantined", 0),
            "published": counts.get("published", 0),
        }

    def mark_published(self, observed: dict[str, tuple[int, str]]) -> int:
        """Fill in `audit_seq` for receipts observed in the owned room.

        `observed` maps job_id to `(seq, receipt_hash)`. The hash has to match the stored
        row: matching on `job_id` alone would let any message this key ever wrote that
        happened to carry the same id mark a *different* receipt as publicly auditable —
        and "publicly auditable" is precisely the claim that must not be taken on faith.
        """
        if not observed:
            return 0
        updated = 0
        with self.tx() as conn:
            for job_id, (seq, receipt_hash) in observed.items():
                cur = conn.execute(
                    "UPDATE receipts SET audit_seq = ?, audit_state = 'published', "
                    "audit_error = NULL "
                    "WHERE job_id = ? AND receipt_hash = ? AND audit_state != 'published'",
                    (seq, job_id, receipt_hash),
                )
                updated += cur.rowcount
        return updated

    def get_receipt(self, job_id: str) -> sqlite3.Row | None:
        return _row(
            self.conn.execute("SELECT * FROM receipts WHERE job_id = ?", (job_id,)).fetchone()
        )

    def all_receipts(self, limit: int = 500) -> Sequence[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM receipts ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()

    # -------------------------------------------------------- protocol watch

    def record_snapshot(self, **fields: Any) -> int:
        columns = (
            "captured_at",
            "source",
            "sha256",
            "per_source_json",
            "upstream_commit",
            "service_version",
            "limits_json",
            "compatibility_status",
            "changed_from_prev",
            "diff_summary",
        )
        row = {c: fields.get(c) for c in columns}
        row["captured_at"] = row["captured_at"] or utcnow()
        row["changed_from_prev"] = int(bool(row["changed_from_prev"]))
        with self.tx() as conn:
            cur = conn.execute(
                # Safe: `columns` is a literal tuple, and every value is bound.
                f"INSERT INTO protocol_snapshots ({', '.join(columns)}) "  # noqa: S608
                f"VALUES ({', '.join('?' for _ in columns)})",
                tuple(row[c] for c in columns),
            )
        return int(cur.lastrowid or 0)

    def latest_snapshot(self) -> sqlite3.Row | None:
        return _row(
            self.conn.execute(
                "SELECT * FROM protocol_snapshots ORDER BY id DESC LIMIT 1"
            ).fetchone()
        )

    # ---------------------------------------------------------------- metrics

    def metrics(self) -> dict[str, Any]:
        """Contribution counters, with internal tests separated from third-party use.

        The separation is the point of this method. A node that counts its own test
        traffic as adoption is lying, and the lie is easy to tell by accident — so the
        split happens here, once, and every surface reads it from here.
        """
        c = self.conn
        total = int(c.execute("SELECT COUNT(*) n FROM jobs").fetchone()["n"])
        internal = int(
            c.execute("SELECT COUNT(*) n FROM jobs WHERE internal_test = 1").fetchone()["n"]
        )
        completed = int(
            c.execute(
                "SELECT COUNT(*) n FROM jobs WHERE internal_test = 0 AND status = 'completed'"
            ).fetchone()["n"]
        )
        failed = int(
            c.execute(
                "SELECT COUNT(*) n FROM jobs WHERE internal_test = 0 "
                "AND status IN ('failed', 'rejected')"
            ).fetchone()["n"]
        )
        unique = int(
            c.execute(
                "SELECT COUNT(DISTINCT requester_did) n FROM jobs WHERE internal_test = 0"
            ).fetchone()["n"]
        )
        repeat = int(
            c.execute(
                "SELECT COUNT(*) n FROM (SELECT requester_did FROM jobs "
                "WHERE internal_test = 0 GROUP BY requester_did HAVING COUNT(*) > 1)"
            ).fetchone()["n"]
        )
        latencies = [
            int(r["latency_ms"])
            for r in c.execute(
                "SELECT latency_ms FROM jobs WHERE internal_test = 0 "
                "AND latency_ms IS NOT NULL ORDER BY latency_ms"
            ).fetchall()
        ]
        external_total = total - internal
        return {
            "total_jobs": external_total,
            "completed_jobs": completed,
            "failed_jobs": failed,
            "internal_test_jobs": internal,
            "unique_requester_dids": unique,
            "repeat_requester_dids": repeat,
            "completion_rate": round(completed / external_total, 4) if external_total else None,
            "p50_latency_ms": _percentile(latencies, 50),
            "p95_latency_ms": _percentile(latencies, 95),
        }

    def snapshot_metrics(self) -> None:
        m = self.metrics()
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO metrics_snapshots (captured_at, total_jobs, completed_jobs, "
                "failed_jobs, unique_requester_dids, repeat_requester_dids, "
                "internal_test_jobs, p50_latency_ms, p95_latency_ms) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    utcnow(),
                    m["total_jobs"],
                    m["completed_jobs"],
                    m["failed_jobs"],
                    m["unique_requester_dids"],
                    m["repeat_requester_dids"],
                    m["internal_test_jobs"],
                    m["p50_latency_ms"],
                    m["p95_latency_ms"],
                ),
            )

    def task_breakdown(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT task_type, COUNT(*) n FROM jobs WHERE internal_test = 0 "
            "AND status = 'completed' GROUP BY task_type"
        ).fetchall()
        return {str(r["task_type"]): int(r["n"]) for r in rows}


def _row(value: Any) -> sqlite3.Row | None:
    """`fetchone()` is typed `Any`; narrow it once here rather than at every call site."""
    assert value is None or isinstance(value, sqlite3.Row)
    return value


def _percentile(sorted_values: list[int], pct: int) -> int | None:
    """Nearest-rank percentile. None on an empty series — never a fabricated zero."""
    if not sorted_values:
        return None
    rank = max(1, (pct * len(sorted_values) + 99) // 100)
    return sorted_values[min(rank, len(sorted_values)) - 1]


def as_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def json_or_none(text: str | None) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
