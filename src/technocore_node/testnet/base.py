"""The seam a second network would plug into.

This interface exists so that adding a network later is an implementation, not a rewrite.
It does not exist to imply a second network is coming, or that this node is ready for one:
see :class:`~technocore_node.testnet.flop.FlopTestnetAdapter`, which is a stub that fails
loudly rather than a lane that half-works.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class NotImplementedYet(RuntimeError):
    """A network whose specification is not published cannot be implemented against.

    Raised instead of guessing an endpoint. A plausible-looking wrong integration is worse
    than none: it produces receipts that reference a network that never saw the work.
    """


class NetworkAdapter(ABC):
    """One network this node can accept work from and publish results to."""

    #: Stable identifier written into a receipt's optional `network` field.
    name: str = "unknown"

    @property
    @abstractmethod
    def enabled(self) -> bool:
        """Whether this adapter may be used at all."""

    @abstractmethod
    async def receive(self, since: int | None = None) -> list[dict[str, Any]]:
        """Inbound work items, oldest first."""

    @abstractmethod
    async def publish(self, destination: str, payload: dict[str, Any]) -> int | None:
        """Publish one payload; return the network's own sequence number if it has one."""

    @abstractmethod
    def annotate_receipt(self, receipt: dict[str, Any]) -> dict[str, Any]:
        """Add this network's provenance fields to a receipt.

        Optional receipt fields reserved for a settlement network — `network`, `tx_hash`,
        `block_number`, `testnet_job_id`, `compute_units`, `verifier_did` — are populated
        only from values a network actually returned. An adapter that cannot observe a
        field leaves it absent rather than filling in a plausible number: a receipt with
        an invented block height is a forged receipt, however well-meant.
        """
