"""The Technocore client against a mocked transport.

Covers the paths that are hard to trigger against the live service and expensive to get
wrong: a write the server did not actually store, a rate limit, a duplicate refusal, and
a room claim that somebody else already owns.
"""

from __future__ import annotations

import json
from typing import Any

import httpx2 as httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_node.crypto import didkey
from technocore_node.protocol.client import (
    DuplicateRefused,
    RateLimited,
    TechnocoreClient,
    WriteUnconfirmed,
)
from technocore_node.protocol.envelope import SignedMessage

ORIGIN = "https://technocore.chat"


def make_client(handler: Any, key: Ed25519PrivateKey, did: str) -> TechnocoreClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(base_url=ORIGIN, transport=transport)
    return TechnocoreClient(ORIGIN, private_key=key, did=did, client=http)


class FakeRoom:
    """A minimal stand-in for one room: it stores what it is given, and hands it back."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []
        self.seq = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            body = json.loads(request.content)
            self.seq += 1
            self.messages.append(
                {
                    "seq": self.seq,
                    "ts": "2026-08-27T00:00:00.000000Z",
                    "from": body.get("did", "~anon"),
                    "text": body["text"],
                    "nonce": int(body["nonce"]) if "nonce" in body else None,
                }
            )
            return httpx.Response(200, text="ok")
        return httpx.Response(
            200,
            json={
                "room": "mb-test",
                "count": len(self.messages),
                "first_seq": 1 if self.messages else None,
                "last_seq": self.seq,
                "messages": self.messages,
            },
        )


async def test_a_signed_write_is_read_back_and_verified(key: Ed25519PrivateKey, did: str) -> None:
    room = FakeRoom()
    client = make_client(room.handler, key, did)
    try:
        confirmation = await client.say_signed("mb-test", "hello world")
    finally:
        await client.aclose()

    assert confirmation.seq == 1
    assert confirmation.text == "hello world"
    assert SignedMessage(
        room="mb-test",
        did=did,
        nonce=confirmation.nonce,
        text=confirmation.text,
        sig=confirmation.sig,
    ).verify_ok()


async def test_the_text_is_swept_before_signing(key: Ed25519PrivateKey, did: str) -> None:
    """The bytes signed must be the bytes stored, or the record stops re-verifying."""
    room = FakeRoom()
    client = make_client(room.handler, key, did)
    try:
        confirmation = await client.say_signed("mb-test", "  a\nb  ")
    finally:
        await client.aclose()

    assert confirmation.text == "a b"
    assert room.messages[0]["text"] == "a b"
    didkey.verify(did, confirmation.sig, f"mb-test|{confirmation.nonce}|a b")


async def test_a_write_the_server_did_not_store_is_not_confirmed(
    key: Ed25519PrivateKey, did: str
) -> None:
    """A 200 says the server accepted a request, not that it stored our bytes."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, text="ok")
        return httpx.Response(
            200, json={"room": "mb-test", "count": 0, "last_seq": 0, "messages": []}
        )

    client = make_client(handler, key, did)
    try:
        with pytest.raises(WriteUnconfirmed):
            await client.say_signed("mb-test", "hello")
    finally:
        await client.aclose()


async def test_a_substituted_message_is_not_confirmed(key: Ed25519PrivateKey, did: str) -> None:
    """Read-back has to match the text, not merely find *a* message from us."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, text="ok")
        return httpx.Response(
            200,
            json={
                "room": "mb-test",
                "count": 1,
                "last_seq": 1,
                "messages": [
                    {
                        "seq": 1,
                        "ts": "2026-08-27T00:00:00Z",
                        "from": did,
                        "text": "something else entirely",
                        "nonce": 1,
                    }
                ],
            },
        )

    client = make_client(handler, key, did)
    try:
        with pytest.raises(WriteUnconfirmed):
            await client.say_signed("mb-test", "hello")
    finally:
        await client.aclose()


async def test_a_duplicate_refusal_is_not_retried(key: Ed25519PrivateKey, did: str) -> None:
    """422 means resending the same bytes is refused again — retrying only spends budget."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(422, text="duplicate text in this room")

    client = make_client(handler, key, did)
    try:
        with pytest.raises(DuplicateRefused):
            await client.say_signed("mb-test", "same text")
    finally:
        await client.aclose()
    assert calls["n"] == 1


async def test_a_rate_limit_is_retried_then_surfaced(
    key: Ed25519PrivateKey, did: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr("technocore_node.protocol.client.asyncio.sleep", no_sleep)

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(429, headers={"retry-after": "2"}, text="slow down")

    client = make_client(handler, key, did)
    try:
        with pytest.raises(RateLimited) as exc:
            await client.say_signed("mb-test", "hello")
    finally:
        await client.aclose()

    assert calls["n"] == 3, "two retries, then surfaced"
    assert exc.value.retry_after == 2.0


async def test_a_long_retry_after_is_surfaced_rather_than_slept_through(
    key: Ed25519PrivateKey, did: str
) -> None:
    """A room-creation 429 answers with thousands of seconds. Sleeping on it parks the
    caller for minutes and still fails, so it is handed back on the first response."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(
            429, headers={"retry-after": "3709"}, text="room-creation budget spent"
        )

    client = make_client(handler, key, did)
    try:
        with pytest.raises(RateLimited):
            await client.say_signed("p-new-room", "hello")
    finally:
        await client.aclose()
    assert calls["n"] == 1, "a long Retry-After must not be retried in-line"


async def test_an_absurd_retry_after_is_clamped(key: Ed25519PrivateKey, did: str) -> None:
    """Retry-After is a stranger's number; a client that obeys it blindly can be parked."""
    client = make_client(lambda r: httpx.Response(200), key, did)
    try:
        response = httpx.Response(429, headers={"retry-after": "999999"})
        assert client._retry_after(response) == 120.0
        assert client._retry_after(httpx.Response(429, headers={"retry-after": "junk"})) == 5.0
    finally:
        await client.aclose()


async def test_claiming_a_room_somebody_else_owns_returns_false(
    key: Ed25519PrivateKey, did: str
) -> None:
    """This node never takes a room from an existing owner."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/kv/room-nonce/"):
            return httpx.Response(200, text="7")
        if request.method == "POST":
            return httpx.Response(409, text="already exists")
        return httpx.Response(200, text="did:key:z6MkSomebodyElse")

    client = make_client(handler, key, did)
    try:
        assert await client.claim_room("d-tc-contrib-abc") is False
    finally:
        await client.aclose()


async def test_a_room_claim_is_signed_by_the_key_being_stored(
    key: Ed25519PrivateKey, did: str
) -> None:
    """The initial claim must be signed by the very key it stores — parsing a key is not
    proof of holding it."""
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/kv/room-nonce/"):
            return httpx.Response(200, text="7")
        if request.method == "POST":
            captured.update(json.loads(request.content))
            return httpx.Response(200, text="ok")
        return httpx.Response(404)

    client = make_client(handler, key, did)
    try:
        assert await client.claim_room("d-tc-contrib-abc") is True
    finally:
        await client.aclose()

    assert captured["value"] == did
    assert captured["if_absent"] is True
    assert int(captured["nonce"]) > 7, "must exceed the shared /kv/room-nonce counter"
    didkey.verify(did, captured["sig"], f"room-owners|d-tc-contrib-abc|{captured['nonce']}|{did}")


async def test_only_d_rooms_can_be_claimed(key: Ed25519PrivateKey, did: str) -> None:
    client = make_client(lambda r: httpx.Response(200), key, did)
    try:
        with pytest.raises(Exception, match="d- rooms"):
            await client.claim_room("lobby")
    finally:
        await client.aclose()
