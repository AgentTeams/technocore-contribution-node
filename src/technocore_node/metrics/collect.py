"""Assemble the published metrics document.

One rule governs this module: **a number this node's own tests produced is never counted
as somebody else using it.** Internal end-to-end traffic is reported, clearly labelled and
separately, and the third-party figures stand alone. When nobody has used the node, the
answer is zero — an honest zero is the whole point of publishing the number at all.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .. import __version__
from ..ledger.db import Ledger


def _uptime_seconds(started_at: str) -> int:
    try:
        started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    except ValueError:
        return 0
    return max(0, int((datetime.now(UTC) - started).total_seconds()))


def build_metrics(ledger: Ledger, *, started_at: str, source_commit: str = "") -> dict[str, Any]:
    counts = ledger.metrics()
    snapshot = ledger.latest_snapshot()

    return {
        "third_party": {
            "total_jobs": counts["total_jobs"],
            "completed_jobs": counts["completed_jobs"],
            "failed_jobs": counts["failed_jobs"],
            "independent_requester_dids": counts["unique_requester_dids"],
            "repeat_requester_dids": counts["repeat_requester_dids"],
            "completion_rate": counts["completion_rate"],
            "note": (
                "Jobs from DIDs other than this node's own test identities. This node's "
                "internal end-to-end tests are excluded here and reported separately. "
                "Zero means zero."
            ),
        },
        "internal_test": {
            "jobs": counts["internal_test_jobs"],
            "note": "This node's own end-to-end verification. Never counted as adoption.",
        },
        "latency_ms": {
            "p50": counts["p50_latency_ms"],
            "p95": counts["p95_latency_ms"],
            "note": "Third-party jobs only. Null until at least one has completed.",
        },
        "completed_by_task": ledger.task_breakdown(),
        "receipts_awaiting_audit_copy": {
            "count": ledger.audit_backlog(),
            "note": (
                "Receipts published to the requester but not yet to this node's owned "
                "room. Until that copy lands, a third party has nothing to check them "
                "against. Retried automatically; a number that does not fall is a fault."
            ),
        },
        "rejections_by_code": ledger.rejection_counts(),
        "service": {
            "software_version": __version__,
            "source_commit": source_commit or None,
            "uptime_seconds": _uptime_seconds(started_at),
            "started_at": started_at,
        },
        "protocol": {
            "last_snapshot_at": snapshot["captured_at"] if snapshot else None,
            "upstream_service_version": snapshot["service_version"] if snapshot else None,
            "upstream_commit": snapshot["upstream_commit"] if snapshot else None,
            "compatibility": snapshot["compatibility_status"] if snapshot else "unknown",
            "changed_since_previous": bool(snapshot["changed_from_prev"]) if snapshot else None,
        },
    }
