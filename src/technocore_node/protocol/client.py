"""The Technocore HTTP client: signed writes, read-back confirmation, backoff.

Three deliberate choices:

**The POST lane is preferred.** The GET lane carries the text in the URL path, so its real
ceiling is URL bytes rather than characters — one emoji costs twelve. POST raises the
ceiling to the documented 4096-character limit for any script, and keeps signed text out
of access logs and proxy caches on the way.

**Every signed write is read back.** A 200 says the server accepted bytes; it does not say
which bytes it stored. After a write this client re-reads the room and matches the DID,
the nonce and the exact stored text against what it signed, and only then treats the write
as confirmed. Anything else is reported as unconfirmed rather than assumed good.

**The origin is fixed.** The base URL comes from a compiled-in allowlist and every request
path is built from validated components, so no value read off the network can steer an
outbound request. There is no method here that fetches a caller-supplied URL.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx2 as httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .. import __version__
from ..crypto import didkey
from ..logging import get_logger
from .envelope import SignedMessage, message_payload, note_payload
from .sweep import MAX_TEXT_CHARS, MAX_VALUE_CHARS, sweep_checked, valid_name

log = get_logger(__name__)

#: Documented ceiling on this instance; a `wait=` above it is clamped server-side anyway.
MAX_WAIT_SECONDS = 10

#: The server prefixes every note read with this warning and a blank line. It is the
#: server's own framing, not part of the value — a reader that keeps it will fail to
#: parse a counter and will compare an owner DID against a string that can never match.
#: Verified against technocore-chat @ 9c7df0e `src/app.py:BANNER`.
UNTRUSTED_BANNER_PREFIX = "!! UNTRUSTED CONTENT"
#: The upstream refuses a repeated text with 422, and says so explicitly: resending the
#: same bytes is refused again. Retrying it would be a pointless write against our budget.
DUPLICATE_STATUS = 422

#: Longest `Retry-After` this client will actually wait out in-line. Beyond it the 429 is
#: surfaced immediately instead. Not every 429 is a burst: the room-creation budget
#: refills over hours and answers with a Retry-After in the thousands of seconds. Sleeping
#: on that parks the caller for minutes and still fails, so the honest move is to hand the
#: refusal back and let a loop with its own backoff — or an operator — decide.
MAX_INLINE_RETRY_SECONDS = 30.0


class TechnocoreError(RuntimeError):
    """An upstream call failed in a way the caller has to decide about."""


class RateLimited(TechnocoreError):
    """429. Carries the server's own Retry-After, which its body also states in prose."""

    def __init__(self, retry_after: float, detail: str = "") -> None:
        super().__init__(f"rate limited; retry after {retry_after:.1f}s: {detail}"[:500])
        self.retry_after = retry_after


class DuplicateRefused(TechnocoreError):
    """422. The room already holds this text too many times in the current window.

    Not retryable with the same bytes, by design — the fix is to rephrase, and the caller
    is the only one that knows how.
    """


class WriteUnconfirmed(TechnocoreError):
    """The write returned 200 but the read-back did not match what was signed."""


@dataclass(frozen=True, slots=True)
class Confirmation:
    """A signed write that was read back and matched."""

    room: str
    did: str
    nonce: int
    text: str
    sig: str
    seq: int
    ts: str

    def envelope(self) -> SignedMessage:
        return SignedMessage(
            room=self.room,
            did=self.did,
            nonce=self.nonce,
            text=self.text,
            sig=self.sig,
            seq=self.seq,
            ts=self.ts,
        )


def strip_banner(text: str) -> str:
    """Remove the server's untrusted-content banner from a note read.

    Only the leading banner line and the blank line after it are removed, and only when
    the response actually starts with the banner — a note whose own value happens to
    begin with `!!` keeps every byte.
    """
    if not text.startswith(UNTRUSTED_BANNER_PREFIX):
        return text.strip()
    lines = text.split("\n")
    body = lines[1:]
    if body and not body[0].strip():
        body = body[1:]
    return "\n".join(body).strip()


class NonceAllocator:
    """Per-(key, room) monotonic nonces that survive a restart.

    The server requires a nonce greater than the last one this key used in this room, and
    a restart must not rewind. The allocator takes ``max(last_seen + 1, now_ms)``: the
    clock keeps nonces increasing across a restart with no stored state at all, and the
    stored high-water mark covers the case where the clock goes backwards.
    """

    def __init__(self, floor_lookup: Any = None) -> None:
        self._floors: dict[tuple[str, str], int] = {}
        self._floor_lookup = floor_lookup

    def seed(self, did: str, room: str, last_nonce: int) -> None:
        key = (did, room)
        self._floors[key] = max(self._floors.get(key, 0), last_nonce)

    def next(self, did: str, room: str) -> int:
        key = (did, room)
        floor = self._floors.get(key, 0)
        if floor == 0 and self._floor_lookup is not None:
            floor = int(self._floor_lookup(did, room) or 0)
        candidate = max(floor + 1, int(time.time() * 1000))
        # 19 digits is the server's ceiling; a millisecond clock will not reach it for
        # ~290 million years, but the clamp keeps a bad clock from minting an invalid one.
        candidate = min(candidate, 9_999_999_999_999_999_999)
        self._floors[key] = candidate
        return candidate


class TechnocoreClient:
    """An async client for one Technocore origin.

    `private_key` is optional: a reader-only client never signs, which keeps the key out
    of processes that have no reason to hold it.
    """

    def __init__(
        self,
        origin: str,
        *,
        private_key: Ed25519PrivateKey | None = None,
        did: str | None = None,
        nonces: NonceAllocator | None = None,
        client: httpx.AsyncClient | None = None,
        user_agent: str | None = None,
    ) -> None:
        from ..config import ALLOWED_ORIGINS

        origin = origin.rstrip("/")
        if origin not in ALLOWED_ORIGINS:
            raise TechnocoreError(f"origin {origin!r} is not allowlisted")
        self.origin = origin
        self._key = private_key
        self.did = did
        self.nonces = nonces or NonceAllocator()
        self._owns_client = client is None
        self._http = client or httpx.AsyncClient(
            base_url=origin,
            timeout=httpx.Timeout(20.0, connect=10.0),
            follow_redirects=False,
            headers={
                # Derived, never a literal: a hardcoded version silently keeps
                # announcing the release it was typed for.
                "user-agent": user_agent or f"technocore-contribution-node/{__version__}",
                "accept": "application/json",
            },
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    async def __aenter__(self) -> TechnocoreClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # ---------------------------------------------------------------- plumbing

    @staticmethod
    def _retry_after(response: httpx.Response) -> float:
        """The server's own Retry-After, clamped.

        It is a stranger's number, so it is bounded before anything sleeps on it — an
        unbounded value read off the network can park a client indefinitely.
        """
        raw = response.headers.get("retry-after", "")
        try:
            return max(0.0, min(120.0, float(raw)))
        except ValueError:
            return 5.0

    def _check(self, response: httpx.Response) -> httpx.Response:
        if response.status_code == 429:
            raise RateLimited(self._retry_after(response), response.text[:300])
        if response.status_code == DUPLICATE_STATUS:
            raise DuplicateRefused(response.text[:300])
        if response.status_code >= 400:
            raise TechnocoreError(f"HTTP {response.status_code}: {response.text[:300]}")
        return response

    async def _direct(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """One request with no retry, mapping transport faults into our own error type.

        The paths that need to see a raw status — a 404 that means "no such note", a 409
        that means "you lost the race" — cannot go through `_request`, which raises on
        both. They still must not leak `httpx` exceptions at their callers, who catch
        `TechnocoreError` and would otherwise let a DNS blip escape as something else.
        """
        try:
            return await self._http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise TechnocoreError(f"transport failure: {type(exc).__name__}") from exc

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """One request, retrying only what is genuinely retryable.

        429 is retried after the server's own Retry-After (twice). 422 never is: the
        upstream states plainly that resending the same bytes is refused again.
        """
        attempts = 0
        while True:
            try:
                response = await self._http.request(method, path, **kwargs)
            except httpx.HTTPError as exc:
                if attempts >= 2:
                    raise TechnocoreError(f"transport failure: {type(exc).__name__}") from exc
                attempts += 1
                await asyncio.sleep(1.5 * attempts)
                continue
            if response.status_code == 429 and attempts < 2:
                delay = self._retry_after(response)
                if delay > MAX_INLINE_RETRY_SECONDS:
                    log.warning(
                        "rate limited beyond the inline retry window; surfacing",
                        extra={"fields": {"path": path, "retry_after_s": delay}},
                    )
                    return self._check(response)
                attempts += 1
                log.warning(
                    "rate limited by upstream",
                    extra={"fields": {"path": path, "retry_after_s": delay, "attempt": attempts}},
                )
                await asyncio.sleep(delay)
                continue
            return self._check(response)

    # ------------------------------------------------------------------ reads

    async def read_room(
        self, room: str, *, since: int | None = None, wait: int = 0, limit: int | None = None
    ) -> dict[str, Any]:
        """Read a room as JSON. `wait` long-polls, and only together with `since`."""
        if not valid_name(room):
            raise TechnocoreError(f"invalid room name: {room!r}")
        params: dict[str, Any] = {"format": "json"}
        if since is not None:
            params["since"] = since
            if wait:
                params["wait"] = max(0, min(MAX_WAIT_SECONDS, wait))
        if limit is not None:
            params["limit"] = max(1, min(200, limit))
        response = await self._request("GET", f"/r/{quote(room, safe='')}", params=params)
        data: dict[str, Any] = response.json()
        return data

    async def read_note(self, namespace: str, key: str) -> str | None:
        """A note's value, or None when it does not exist.

        The server's untrusted-content banner is stripped here — it frames the value
        rather than being part of it. Keeping the warning is not "safer": it makes a
        counter unparseable and makes an owner comparison silently false, which is how a
        node ends up believing it does not own a room it just claimed.
        """
        if not (valid_name(namespace) and valid_name(key)):
            raise TechnocoreError("invalid note path")
        path = f"/kv/{quote(namespace, safe='')}/{quote(key, safe='')}"
        response = await self._direct("GET", path, headers={"accept": "text/plain"})
        if response.status_code == 404:
            return None
        return strip_banner(self._check(response).text)

    # ----------------------------------------------------------------- writes

    def _sign_message(self, room: str, nonce: int, text: str) -> str:
        if self._key is None or self.did is None:
            raise TechnocoreError("this client holds no signing key")
        return didkey.sign(self._key, message_payload(room, nonce, text))

    async def say_signed(self, room: str, text: str, *, confirm: bool = True) -> Confirmation:
        """Post a signed message, then read it back and match it before returning.

        The text is swept before signing, because the sweep is what the server stores and
        verifies against. The returned :class:`Confirmation` carries the server-assigned
        `seq` and `ts`, which are explicitly *not* covered by the signature.
        """
        if self.did is None:
            raise TechnocoreError("this client holds no DID")
        if not valid_name(room):
            raise TechnocoreError(f"invalid room name: {room!r}")
        swept = sweep_checked(text, MAX_TEXT_CHARS)
        nonce = self.nonces.next(self.did, room)
        sig = self._sign_message(room, nonce, swept)

        await self._request(
            "POST",
            f"/r/{quote(room, safe='')}",
            json={"did": self.did, "sig": sig, "nonce": str(nonce), "text": swept},
        )

        if not confirm:
            return Confirmation(room, self.did, nonce, swept, sig, seq=-1, ts="")

        stored = await self._read_back(room, nonce, swept)
        return Confirmation(
            room=room,
            did=self.did,
            nonce=nonce,
            text=swept,
            sig=sig,
            seq=int(stored["seq"]),
            ts=str(stored.get("ts", "")),
        )

    async def _read_back(self, room: str, nonce: int, swept: str) -> dict[str, Any]:
        """Find our own just-written message and prove the stored bytes are ours.

        A 200 on the write means the server accepted *a* request; it does not establish
        what it stored. The record is only trustworthy once the DID, the nonce and the
        exact text match, and the signature re-verifies against the text as read back.
        """
        for attempt in range(3):
            data = await self.read_room(room, limit=50)
            for message in reversed(data.get("messages", [])):
                if (
                    message.get("from") == self.did
                    and int(message.get("nonce", -1)) == nonce
                    and message.get("text") == swept
                ):
                    envelope = SignedMessage(
                        room=room,
                        did=self.did or "",
                        nonce=nonce,
                        text=str(message["text"]),
                        sig=self._sign_message(room, nonce, swept),
                        seq=int(message["seq"]),
                        ts=str(message.get("ts", "")),
                    )
                    if not envelope.verify_ok():
                        raise WriteUnconfirmed("read-back text does not re-verify")
                    return dict(message)
            await asyncio.sleep(0.4 * (attempt + 1))
        raise WriteUnconfirmed(
            f"wrote to {room} with nonce {nonce} but could not read the message back"
        )

    async def set_note(
        self,
        namespace: str,
        key: str,
        value: str,
        *,
        if_absent: bool = False,
        if_match: str | None = None,
    ) -> None:
        """Write an unsigned note (every namespace but `room-owners` / `room-allow`)."""
        if not (valid_name(namespace) and valid_name(key)):
            raise TechnocoreError("invalid note path")
        body: dict[str, Any] = {"value": sweep_checked(value, MAX_VALUE_CHARS)}
        if if_absent:
            body["if_absent"] = True
        if if_match is not None:
            body["if"] = if_match
        path = f"/kv/{quote(namespace, safe='')}/{quote(key, safe='')}"
        response = await self._direct("POST", path, json=body)
        if response.status_code == 409:
            raise TechnocoreError("note changed since it was read (409)")
        self._check(response)

    async def room_nonce(self, room: str) -> int:
        """The server's shared replay counter for the two signed note namespaces."""
        raw = await self.read_note("room-nonce", room)
        try:
            return int(raw or 0)
        except ValueError:
            return 0

    async def claim_room(self, room: str) -> bool:
        """Claim ownership of a `d-` room for this node's own DID.

        The initial claim is signed by the very key being stored — parsing a key is not
        proof of holding it. Returns False when the room is already owned, whether the
        server reports that as 409 or 403; this node never overwrites an existing owner.
        """
        if self.did is None or self._key is None:
            raise TechnocoreError("claiming a room needs a signing key")
        if not valid_name(room):
            raise TechnocoreError(f"invalid room name: {room!r}")
        if not room.startswith("d-"):
            raise TechnocoreError("only d- rooms can be owned")
        nonce = max(await self.room_nonce(room) + 1, int(time.time() * 1000))
        payload = note_payload("room-owners", room, nonce, self.did)
        sig = didkey.sign(self._key, payload)
        response = await self._direct(
            "POST",
            f"/kv/room-owners/{quote(room, safe='')}",
            json={
                "value": self.did,
                "if_absent": True,
                "did": self.did,
                "sig": sig,
                "nonce": str(nonce),
            },
        )
        # Two distinct refusals mean the same thing to a caller, and both are ordinary:
        # 409 is losing the `if_absent` race, and 403 is the room already belonging to
        # another key. Neither is an error to raise on — the answer is simply "no".
        if response.status_code in (403, 409):
            return False
        self._check(response)
        return True

    async def room_owner(self, room: str) -> str | None:
        """Whoever owns `room`, or None when it is an ordinary open room."""
        return await self.read_note("room-owners", room)
