import json
import logging
from typing import List, Dict, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger("websockets")

router = APIRouter(tags=["WebSockets"])


class ConnectionManager:
    """Manages active WebSocket connections for real-time SOC dashboard alerts and live notifications."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        payload = json.dumps(message)
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception as e:
                logger.warning(f"Error broadcasting to WebSocket client: {e}")
                disconnected.append(connection)

        for connection in disconnected:
            self.disconnect(connection)


ws_manager = ConnectionManager()


@router.websocket("/ws/notifications")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint streaming live threat alerts, task status, and case updates to the SOC dashboard."""
    await ws_manager.connect(websocket)
    try:
        # Send initial welcome message
        await websocket.send_text(json.dumps({
            "event_type": "CONNECTED",
            "message": "Connected to CyberShield-AI-SOC real-time notification stream.",
            "timestamp": "2026-08-01T22:29:07Z"
        }))
        while True:
            # Keep connection alive & handle incoming client pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"event_type": "PONG"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        ws_manager.disconnect(websocket)
