"""A cursor is a position in one lifetime of a room, and only a restart moves it back."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from technocore_node.ledger.db import Ledger


def test_a_cursor_never_moves_back_by_itself(ledger: Ledger) -> None:
    """Within one lifetime a lower number is a stale write losing a race, not a rewind."""
    ledger.set_cursor("mb-room", 5)
    ledger.set_cursor("mb-room", 2)
    assert ledger.cursor("mb-room") == 5


def test_a_room_never_read_has_no_recorded_lifetime(ledger: Ledger) -> None:
    assert ledger.cursor("mb-room") == 0
    assert ledger.cursor_epoch("mb-room") is None


def test_adopting_a_lifetime_leaves_the_position_alone(ledger: Ledger) -> None:
    ledger.set_cursor("mb-room", 5)
    ledger.adopt_cursor_epoch("mb-room", 4)
    assert (ledger.cursor("mb-room"), ledger.cursor_epoch("mb-room")) == (5, 4)


def test_a_restart_returns_to_the_start_of_the_new_lifetime(ledger: Ledger) -> None:
    ledger.set_cursor("mb-room", 5)
    ledger.adopt_cursor_epoch("mb-room", 4)

    ledger.restart_cursor("mb-room", 5)
    assert (ledger.cursor("mb-room"), ledger.cursor_epoch("mb-room")) == (0, 5)

    # And the new lifetime advances like any other.
    ledger.set_cursor("mb-room", 1)
    assert (ledger.cursor("mb-room"), ledger.cursor_epoch("mb-room")) == (1, 5)


def test_a_restart_may_record_that_the_lifetime_is_unknown(ledger: Ledger) -> None:
    """An upstream that reports no generation still has rooms that get replaced."""
    ledger.set_cursor("mb-room", 5)
    ledger.adopt_cursor_epoch("mb-room", 4)
    ledger.restart_cursor("mb-room", None)
    assert (ledger.cursor("mb-room"), ledger.cursor_epoch("mb-room")) == (0, None)


def test_a_ledger_from_before_lifetimes_keeps_its_cursor(tmp_path: Path) -> None:
    """Production's ledger: a cursor at 3, written by a build that knew no generations."""
    path = tmp_path / "state.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE cursors (room TEXT PRIMARY KEY, last_seq INTEGER NOT NULL, "
        "updated_at TEXT NOT NULL)"
    )
    conn.execute("INSERT INTO cursors VALUES ('mb-room', 3, '2026-08-30T18:00:00Z')")
    conn.commit()
    conn.close()

    ledger = Ledger(path)
    assert ledger.cursor("mb-room") == 3
    assert ledger.cursor_epoch("mb-room") is None, "an unrecorded lifetime is not lifetime 0"
