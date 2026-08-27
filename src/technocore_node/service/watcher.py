"""Read-only protocol-change watcher.

Once a day it re-fetches the upstream manifest documents from the compiled-in origin,
hashes them, and records whether anything moved. It **does not** change code, open a pull
request, or enable anything — a protocol change is a fact for an operator to act on, and
an agent that edits itself in response to a document it fetched is an agent that a
document can rewrite.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

import httpx2 as httpx

from ..config import assert_allowed_origin
from ..ledger.db import Ledger, utcnow
from ..logging import get_logger

log = get_logger(__name__)

#: Paths on the allowlisted origin, and the upstream repository. Fixed, not configurable,
#: and both origins appear in the central allowlist in `config.py`.
MANIFEST_PATHS = ("/llms.txt", "/openapi.json", "/.well-known/agent.json", "/config")
UPSTREAM_REPO_API = "https://api.github.com/repos/flop-labs/technocore-chat"

WATCH_INTERVAL_SECONDS = 24 * 60 * 60


class ProtocolWatcher:
    def __init__(self, ledger: Ledger, origin: str, *, client: httpx.AsyncClient | None = None):
        from ..config import ALLOWED_ORIGINS

        if origin.rstrip("/") not in ALLOWED_ORIGINS:
            raise ValueError("watcher origin is not allowlisted")
        self.origin = origin.rstrip("/")
        self.ledger = ledger
        self._client = client

    async def _fetch(self, url: str) -> tuple[int, bytes]:
        """Fetch one allowlisted URL.

        The check is here, on the one method that makes a request, rather than trusted to
        the two call sites below. Both URLs are compiled in and neither is caller-derived,
        so this is not stopping an attack today — it is making sure that a future edit
        that adds a third URL has to go through the same gate.
        """
        assert_allowed_origin(url)
        assert self._client is not None
        response = await self._client.get(url, timeout=30.0)
        return response.status_code, response.content

    async def capture(self) -> dict[str, Any]:
        """Fetch the manifest set once, hash it, and record it against the last capture."""
        owns = self._client is None
        if owns:
            self._client = httpx.AsyncClient(
                headers={"user-agent": "technocore-contribution-node/0.1.0 (protocol-watcher)"}
            )
        try:
            per_source: dict[str, str] = {}
            service_version: str | None = None
            limits: dict[str, Any] | None = None

            for path in MANIFEST_PATHS:
                status, body = await self._fetch(f"{self.origin}{path}")
                if status != 200:
                    per_source[path] = f"unavailable:{status}"
                    continue
                per_source[path] = hashlib.sha256(body).hexdigest()
                if path == "/.well-known/agent.json":
                    try:
                        manifest = json.loads(body)
                        service_version = str(manifest.get("version"))
                        limits = manifest.get("limits")
                    except json.JSONDecodeError:
                        per_source[path] = "unparseable"

            upstream_commit: str | None = None
            try:
                status, body = await self._fetch(f"{UPSTREAM_REPO_API}/commits/main")
                if status == 200:
                    upstream_commit = str(json.loads(body).get("sha"))
            except (httpx.HTTPError, json.JSONDecodeError):
                # The upstream repository is a nice-to-have for provenance; the manifest
                # hashes are the signal, and a GitHub outage must not blank a capture.
                log.warning("upstream commit unavailable for this capture")

            aggregate = hashlib.sha256(
                json.dumps(per_source, sort_keys=True).encode("utf-8")
            ).hexdigest()

            previous = self.ledger.latest_snapshot()
            changed = previous is not None and previous["sha256"] != aggregate
            diff_summary = None
            if changed and previous is not None:
                before = json.loads(previous["per_source_json"])
                moved = [k for k, v in per_source.items() if before.get(k) != v]
                diff_summary = "changed: " + ", ".join(sorted(moved)) if moved else "aggregate only"

            status_word = "unknown" if previous is None else ("changed" if changed else "ok")
            self.ledger.record_snapshot(
                captured_at=utcnow(),
                source=self.origin,
                sha256=aggregate,
                per_source_json=json.dumps(per_source, sort_keys=True),
                upstream_commit=upstream_commit,
                service_version=service_version,
                limits_json=json.dumps(limits) if limits else None,
                compatibility_status="compatible" if not changed else "changed",
                changed_from_prev=changed,
                diff_summary=diff_summary,
            )
            if changed:
                log.warning(
                    "upstream protocol documents changed",
                    extra={"fields": {"diff": diff_summary, "service_version": service_version}},
                )
            else:
                log.info(
                    "protocol snapshot captured",
                    extra={"fields": {"status": status_word, "service_version": service_version}},
                )

            return {
                "captured_at": utcnow(),
                "sha256": aggregate,
                "per_source": per_source,
                "upstream_commit": upstream_commit,
                "service_version": service_version,
                "changed_from_previous": changed,
                "diff_summary": diff_summary,
            }
        finally:
            if owns and self._client is not None:
                await self._client.aclose()
                self._client = None

    async def run_forever(self, interval: int = WATCH_INTERVAL_SECONDS) -> None:
        while True:
            try:
                await self.capture()
            except Exception:
                # A watcher fault must never stop the node: this loop is informational.
                log.exception("protocol capture failed")
            await asyncio.sleep(interval)
