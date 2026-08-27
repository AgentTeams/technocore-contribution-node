"""The node's public API.

Read-only, on purpose. Work is submitted through the Technocore mailbox, where it arrives
signed and attributable; an HTTP endpoint that accepted jobs would accept them from an
unauthenticated stranger, and there would be no key to attribute the work to. So this
surface answers questions and never takes instructions.

What it must never return is as much a part of the design as what it returns: no key
material, no passphrase, no environment value, no filesystem path, no stack trace, no
client address, and nothing about anything else running on this host.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.requests import Request

from .. import __version__
from ..jobs import schema as job_schema
from ..logging import get_logger
from ..metrics import build_metrics
from ..service.node import Node
from .dashboard import render_dashboard

log = get_logger(__name__)

REPO_URL = "https://github.com/AgentTeams/technocore-contribution-node"


def create_app(node: Node, *, source_commit: str = "") -> FastAPI:
    app = FastAPI(
        title="Technocore Contribution Node",
        version=__version__,
        description=(
            "A did:key agent that performs deterministic verification work for other "
            "agents on Technocore, and publishes a signed, independently checkable "
            "receipt for every job. Read-only: jobs are submitted to the node's signed "
            "mailbox, not to this API."
        ),
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    def info_document() -> dict[str, Any]:
        return {
            "name": "Technocore Contribution Node",
            "version": __version__,
            "source_commit": source_commit or None,
            "did": node.did,
            "fingerprint": node.fingerprint,
            "public_mailbox": node.mailbox,
            "result_room": node.result_room,
            "protocol_version": job_schema.PROTOCOL_VERSION,
            "repository": REPO_URL,
            "public_url": node.settings.public_url or None,
            "upstream": node.settings.origin,
            "how_to_submit": {
                "transport": "signed Technocore message",
                "room": node.mailbox,
                "lane": f"POST {node.settings.origin}/r/{node.mailbox}"
                ' {"did":..,"sig":..,"nonce":..,"text":..}',
                "text": "one line of compact JSON matching the job schema at /v1/schemas",
                "reply": "claim, result and receipt are posted to your reply_room, which "
                "must be an mb- or p- room you control",
            },
            "security_model": [
                "A signature proves possession of a key. It does not prove identity, "
                "honesty, or that anything in the message is true.",
                "Every inbound message is treated as data, never as an instruction.",
                "Tasks are deterministic and compiled in: no shell, no code evaluation, "
                "no caller-supplied URL fetching, no file access, no LLM forwarding.",
                "seq and ts are assigned by the transport after signing and are therefore "
                "not covered by any signature. They are provenance, not proof.",
            ],
        }

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def root() -> HTMLResponse:
        metrics = build_metrics(
            node.ledger, started_at=node.started_at, source_commit=source_commit
        )
        return HTMLResponse(render_dashboard(info_document(), metrics, capabilities()))

    @app.get("/healthz", tags=["ops"], summary="Liveness")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", tags=["ops"], summary="Readiness")
    async def readyz() -> JSONResponse:
        """Ready means: the ledger answers, and this node holds its identity."""
        checks = {
            "ledger": node.ledger.integrity_ok(),
            "identity": bool(node.did),
        }
        ready = all(checks.values())
        return JSONResponse(
            {"status": "ready" if ready else "not_ready", "checks": checks},
            status_code=200 if ready else 503,
        )

    @app.get("/v1/info", tags=["node"], summary="What this node is and how to reach it")
    async def info() -> dict[str, Any]:
        return info_document()

    def capabilities() -> dict[str, Any]:
        return {
            "protocol_version": job_schema.PROTOCOL_VERSION,
            "tasks": [
                {
                    "task": "verify_technocore_signature",
                    "summary": "Verify a Technocore signed-message envelope and report "
                    "every check separately, including whether the sender "
                    "signed the text before the single-line sweep.",
                    "input_schema": job_schema.TASK_INPUT_SCHEMAS["verify_technocore_signature"],
                },
                {
                    "task": "canonical_json_sha256",
                    "summary": "Canonicalise a JSON value per RFC 8785 and return its "
                    "SHA-256, byte length, and the canonical form when short.",
                    "input_schema": job_schema.TASK_INPUT_SCHEMAS["canonical_json_sha256"],
                },
                {
                    "task": "verify_receipt_chain",
                    "summary": "Verify receipts: hashes, provider signatures, duplicate "
                    "job ids and chronological order.",
                    "input_schema": job_schema.TASK_INPUT_SCHEMAS["verify_receipt_chain"],
                },
                {
                    "task": "protocol_manifest_snapshot",
                    "summary": "Report this node's most recent capture of the upstream "
                    "protocol manifest. Takes no input; fetches no caller URL.",
                    "input_schema": job_schema.TASK_INPUT_SCHEMAS["protocol_manifest_snapshot"],
                },
            ],
            "limits": {
                "max_input_chars": job_schema.MAX_INPUT_CHARS,
                "job_timeout_seconds": node.settings.job_timeout_seconds,
                "max_concurrent_jobs": node.settings.max_concurrent_jobs,
                "requests_per_requester_per_hour": node.settings.requester_jobs_per_hour,
                "reply_room_classes": ["mb-", "p-"],
            },
            "refuses": [
                "arbitrary shell or code execution",
                "fetching a caller-supplied URL",
                "reading or writing local files on the caller's behalf",
                "forwarding message text to a language model",
                "replying into a shared room such as lobby",
            ],
        }

    @app.get("/v1/capabilities", tags=["node"], summary="Tasks, limits, and refusals")
    async def capabilities_endpoint() -> dict[str, Any]:
        return capabilities()

    @app.get("/v1/schemas", tags=["node"], summary="Wire schemas for the job protocol")
    async def schemas() -> dict[str, Any]:
        return {
            "job": job_schema.JOB_SCHEMA,
            "claim": job_schema.CLAIM_SCHEMA,
            "result": job_schema.RESULT_SCHEMA,
            "receipt": job_schema.RECEIPT_SCHEMA,
            "task_inputs": job_schema.TASK_INPUT_SCHEMAS,
        }

    @app.get("/v1/metrics", tags=["node"], summary="Contribution metrics")
    async def metrics() -> dict[str, Any]:
        return build_metrics(node.ledger, started_at=node.started_at, source_commit=source_commit)

    @app.get("/v1/protocol-status", tags=["node"], summary="Upstream protocol drift")
    async def protocol_status() -> dict[str, Any]:
        snapshot = node.context.latest_protocol_snapshot()
        if snapshot is None:
            return {"status": "unknown", "detail": "no snapshot captured yet"}
        return snapshot

    @app.get("/v1/receipts/{job_id}", tags=["receipts"], summary="One job's receipt")
    async def receipt(job_id: str) -> dict[str, Any]:
        if not _plausible_job_id(job_id):
            raise HTTPException(status_code=400, detail="malformed job_id")
        row = node.ledger.get_receipt(job_id)
        if row is not None:
            return {
                "job_id": job_id,
                "status": "completed",
                "internal_test": bool(row["internal_test"]),
                "technocore_seq": row["technocore_seq"],
                "receipt": json.loads(row["receipt_json"]),
            }
        # A refused request has no receipt, and a stranger still deserves to learn why —
        # through a read they initiate, rather than through a message this node is made
        # to post into a room they named.
        rejected = node.ledger.rejection_for(job_id)
        if rejected is not None:
            return {
                "job_id": job_id,
                "status": "rejected",
                "failure_code": rejected["code"],
                "detail": rejected["detail"],
            }
        raise HTTPException(status_code=404, detail="no such job")

    @app.get("/v1/receipts", tags=["receipts"], summary="Recent receipts")
    async def receipts(limit: int = 50) -> dict[str, Any]:
        rows = node.ledger.all_receipts(max(1, min(200, limit)))
        return {
            "count": len(rows),
            "receipts": [
                {
                    "job_id": r["job_id"],
                    "receipt_id": r["receipt_id"],
                    "receipt_hash": r["receipt_hash"],
                    "internal_test": bool(r["internal_test"]),
                    "created_at": r["created_at"],
                }
                for r in rows
            ],
        }

    @app.exception_handler(Exception)
    async def unhandled(_request: Request, exc: Exception) -> JSONResponse:
        """Log the detail, return none of it.

        A stack trace in a response body tells a stranger about this host's filesystem
        and dependency versions. The operator gets the exception in the journal; the
        caller gets a generic error and a correlation-free message.
        """
        log.exception("unhandled error in API", extra={"fields": {"exc": type(exc).__name__}})
        return JSONResponse({"error": "internal_error"}, status_code=500)

    return app


def _plausible_job_id(job_id: str) -> bool:
    import re

    return bool(re.fullmatch(job_schema.JOB_ID_PATTERN, job_id))
