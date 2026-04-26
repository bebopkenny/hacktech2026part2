"""
WebSocket connection manager — broadcasts pipeline events to all connected clients.

The scan pipeline runs in a background threading.Thread (sync code), but FastAPI
WebSocket sends are async. We capture the FastAPI event loop in main.py's
lifespan handler and use asyncio.run_coroutine_threadsafe() to schedule sends
from sync threads.

Single global broadcast: every connected client receives every event from every
scan. Acceptable for the demo since events are not user-scoped. Per-scan
isolation can be layered on later by filtering on scan_id client-side — every
event payload already carries it.

Failure mode: if send_text raises on a client (closed socket, network error),
that client is dropped from the set and others keep receiving events.
"""
import asyncio
import json
import logging
import threading
from typing import Any

from fastapi import WebSocket

log = logging.getLogger("ws")


class ConnectionManager:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        with self._lock:
            self._clients.add(ws)
        log.info("ws client connected (total=%d)", len(self._clients))

    def disconnect(self, ws: WebSocket) -> None:
        with self._lock:
            self._clients.discard(ws)

    def broadcast(self, event: dict[str, Any]) -> None:
        """Schedule an async fan-out to every connected client. Thread-safe."""
        if self._loop is None:
            log.warning("broadcast before loop bound; dropping %s", event.get("type"))
            return
        with self._lock:
            clients = list(self._clients)
        if not clients:
            return
        asyncio.run_coroutine_threadsafe(self._fanout(clients, event), self._loop)

    async def _fanout(self, clients: list[WebSocket], event: dict[str, Any]) -> None:
        payload = json.dumps(event)
        for ws in clients:
            try:
                await ws.send_text(payload)
            except Exception as e:
                log.info("dropping ws client after send error: %s", e)
                self.disconnect(ws)


manager = ConnectionManager()
