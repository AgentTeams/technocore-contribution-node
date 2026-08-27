"""The Technocore adapter — the one lane that is real today."""

from __future__ import annotations

from typing import Any

from ..protocol.client import TechnocoreClient
from .base import NetworkAdapter


class TechnocoreAdapter(NetworkAdapter):
    name = "technocore"

    def __init__(self, client: TechnocoreClient, mailbox: str) -> None:
        self._client = client
        self._mailbox = mailbox

    @property
    def enabled(self) -> bool:
        return True

    async def receive(self, since: int | None = None) -> list[dict[str, Any]]:
        data = await self._client.read_room(self._mailbox, since=since, wait=10 if since else 0)
        messages: list[dict[str, Any]] = data.get("messages", [])
        return messages

    async def publish(self, destination: str, payload: dict[str, Any]) -> int | None:
        import json

        text = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        confirmation = await self._client.say_signed(destination, text)
        return confirmation.seq

    def annotate_receipt(self, receipt: dict[str, Any]) -> dict[str, Any]:
        """Technocore settles nothing, so the only honest annotation is the network name.

        Returned as a new object, and deliberately **not** re-signed or re-hashed: the
        receipt's signature covers the receipt as the provider made it. A caller that
        wants an annotated receipt to stay verifiable must re-derive `receipt_hash` and
        `sig` with the provider key, which this adapter does not hold.
        """
        return {**receipt, "network": self.name}
