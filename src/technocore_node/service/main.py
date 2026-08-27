"""Service entrypoint: build the node, start the background loops, serve the API."""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
from collections.abc import AsyncIterator

import uvicorn
from fastapi import FastAPI

from ..config import load_settings
from ..logging import configure, get_logger
from .node import Node

log = get_logger(__name__)


def build_app() -> FastAPI:
    from ..api import create_app

    settings = load_settings()
    node = Node(settings)
    app = create_app(node, source_commit=os.environ.get("TCN_SOURCE_COMMIT", "")[:40])

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        node.start_background()
        log.info(
            "node started",
            extra={
                "fields": {
                    "did": node.did,
                    "mailbox": node.mailbox,
                    "result_room": node.result_room,
                    "mailbox_enabled": settings.mailbox_enabled,
                    "watcher_enabled": settings.watcher_enabled,
                }
            },
        )
        try:
            yield
        finally:
            await node.aclose()
            log.info("node stopped")

    app.router.lifespan_context = lifespan
    return app


def main() -> None:
    configure(os.environ.get("TCN_LOG_LEVEL", "INFO"))
    settings = load_settings()
    app = build_app()
    config = uvicorn.Config(
        app,
        host=settings.bind_host,
        port=settings.bind_port,
        log_config=None,
        access_log=False,
        server_header=False,
        date_header=True,
    )
    server = uvicorn.Server(config)

    async def run() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, server.handle_exit, sig, None)
        await server.serve()

    asyncio.run(run())


if __name__ == "__main__":
    main()
