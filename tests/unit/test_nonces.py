"""Nonce allocation — what makes a captured signed write single-use."""

from __future__ import annotations

import time

from technocore_node.ledger.db import Ledger
from technocore_node.protocol.client import NonceAllocator


def test_nonces_strictly_increase(did: str) -> None:
    allocator = NonceAllocator()
    seen = [allocator.next(did, "lobby") for _ in range(50)]
    assert seen == sorted(seen)
    assert len(set(seen)) == 50


def test_nonces_are_per_room(did: str) -> None:
    """The server's counter is per key *per room*, so two rooms must not share one."""
    allocator = NonceAllocator()
    first = allocator.next(did, "room-a")
    second = allocator.next(did, "room-b")
    assert allocator.next(did, "room-a") > first
    assert allocator.next(did, "room-b") > second


def test_a_millisecond_clock_is_the_floor(did: str) -> None:
    allocator = NonceAllocator()
    before = int(time.time() * 1000)
    assert allocator.next(did, "lobby") >= before


def test_nonce_never_exceeds_the_19_digit_ceiling(did: str) -> None:
    allocator = NonceAllocator()
    allocator.seed(did, "lobby", 9_999_999_999_999_999_998)
    assert allocator.next(did, "lobby") <= 9_999_999_999_999_999_999


def test_a_restart_does_not_rewind(did: str, ledger: Ledger) -> None:
    """The scenario this exists for: the process dies, and the next nonce must still be
    greater than the last one the server saw — otherwise every write is refused."""
    first = NonceAllocator(floor_lookup=ledger.last_nonce)
    used = first.next(did, "lobby")
    ledger.record_message(
        local_event_id="out-lobby-1",
        direction="out",
        room="lobby",
        did=did,
        nonce=used,
        normalized_text_sha256="sha256:" + "0" * 64,
        status="confirmed",
    )

    restarted = NonceAllocator(floor_lookup=ledger.last_nonce)
    assert restarted.next(did, "lobby") > used


def test_a_backwards_clock_does_not_rewind(did: str) -> None:
    """A stored high-water mark covers the case the clock cannot."""
    allocator = NonceAllocator()
    far_future = int(time.time() * 1000) + 10_000_000
    allocator.seed(did, "lobby", far_future)
    assert allocator.next(did, "lobby") > far_future


def test_seed_never_lowers_the_floor(did: str) -> None:
    allocator = NonceAllocator()
    allocator.seed(did, "lobby", 5_000)
    allocator.seed(did, "lobby", 10)
    assert allocator.next(did, "lobby") > 5_000
