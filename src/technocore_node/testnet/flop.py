"""FLOP testnet adapter — deliberately unimplemented.

At the time of writing there is no published FLOP testnet specification: no RPC endpoint,
no chain id, no faucet, no wallet binding, no job or settlement schema. This file
therefore contains no endpoint, no chain id and no address. Not as an oversight — as the
point.

Inventing any of those would produce a node that looks integrated and is not, and a
receipt carrying a fabricated `tx_hash` is indistinguishable from a forged one. So the
adapter exists as a seam with a real shape, refuses to run, and names exactly what would
have to be published before it could be written.

To implement it later: fill in :meth:`receive`, :meth:`publish` and
:meth:`annotate_receipt` against the published specification, populate only fields the
network actually returns, and flip `FLOP_TESTNET_ENABLED` on deliberately.
"""

from __future__ import annotations

from typing import Any

from .base import NetworkAdapter, NotImplementedYet

#: Mirrors `jobs.schema.RESERVED_NETWORK_FIELDS`, which is where they are declared.
#: What would have to exist upstream before this adapter could be written honestly.
REQUIRED_BEFORE_IMPLEMENTATION = (
    "a published RPC endpoint and chain identifier",
    "a published job submission and settlement schema",
    "a published verifier/attestation model, so a receipt can name a verifier",
    "a documented account or wallet binding for an agent's did:key",
    "a testnet faucet or funding path that does not require a paid API",
)


class FlopTestnetAdapter(NetworkAdapter):
    name = "flop-testnet"

    def __init__(self, *, enabled: bool = False) -> None:
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _refuse(self, operation: str) -> NotImplementedYet:
        return NotImplementedYet(
            f"{operation} is not implemented: no FLOP testnet specification has been "
            "published. This adapter will not guess an endpoint or a schema. Missing "
            "upstream: " + "; ".join(REQUIRED_BEFORE_IMPLEMENTATION)
        )

    async def receive(self, since: int | None = None) -> list[dict[str, Any]]:
        raise self._refuse("receive")

    async def publish(self, destination: str, payload: dict[str, Any]) -> int | None:
        raise self._refuse("publish")

    def annotate_receipt(self, receipt: dict[str, Any]) -> dict[str, Any]:
        raise self._refuse("annotate_receipt")

    def status(self) -> dict[str, Any]:
        """A machine-readable statement that this lane is not live."""
        return {
            "network": self.name,
            "enabled": self._enabled,
            "implemented": False,
            "reason": "no published specification",
            "required_before_implementation": list(REQUIRED_BEFORE_IMPLEMENTATION),
            "reserved_receipt_fields": [
                "network",
                "tx_hash",
                "block_number",
                "testnet_job_id",
                "compute_units",
                "verifier_did",
            ],
        }
