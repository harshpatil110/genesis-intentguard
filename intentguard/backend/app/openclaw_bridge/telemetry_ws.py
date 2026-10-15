"""
IntentGuard X-Ray Telemetry WebSocket Manager
===============================================
GENESIS 2.0 | Track: EVA 03 | PS 01

Manages live WebSocket connections for the Forensic X-Ray UI dashboard at
/ws/xray-stream and maintains a ring-buffer of recent events so newly
connected clients get historical context.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from typing import Deque, List

from fastapi import WebSocket

from app.openclaw_bridge.models import XRayTelemetryEvent

logger = logging.getLogger(__name__)


class XRayTelemetryManager:
    """
    Manages all /ws/xray-stream WebSocket connections.

    Features:
    - Thread-safe connection list management (connect/disconnect).
    - Broadcasts every XRayTelemetryEvent as JSON to all active clients.
    - Maintains a 200-event FIFO ring buffer (history) so the UI and tests
      can query recent events via GET /internal/intercept/telemetry-history.
    """

    def __init__(self, history_maxlen: int = 200) -> None:
        self._connections: List[WebSocket] = []
        self._history: Deque[XRayTelemetryEvent] = deque(maxlen=history_maxlen)

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection and register it."""
        await websocket.accept()
        self._connections.append(websocket)
        logger.info(
            "X-Ray WebSocket connected. Active clients: %d", len(self._connections)
        )

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket from the active connections list."""
        if websocket in self._connections:
            self._connections.remove(websocket)
        logger.info(
            "X-Ray WebSocket disconnected. Active clients: %d", len(self._connections)
        )

    # ------------------------------------------------------------------
    # Broadcast & history
    # ------------------------------------------------------------------

    async def broadcast_event(self, event: XRayTelemetryEvent) -> None:
        """
        Append event to ring buffer and send it as JSON to all live clients.
        Stale/closed connections are silently pruned.
        """
        self._history.append(event)
        payload = event.model_dump_json()

        dead: List[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_text(payload)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Pruning dead WebSocket connection: %s", exc)
                dead.append(ws)

        for ws in dead:
            self.disconnect(ws)

    def get_history(self) -> List[XRayTelemetryEvent]:
        """Return a snapshot of the ring buffer (oldest first)."""
        return list(self._history)

    @property
    def active_client_count(self) -> int:
        return len(self._connections)


# ---------------------------------------------------------------------------
# Module-level singleton shared by interceptor.py and main.py
# ---------------------------------------------------------------------------
telemetry_manager = XRayTelemetryManager()
