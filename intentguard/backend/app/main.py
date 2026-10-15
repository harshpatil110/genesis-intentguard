"""
IntentGuard Hidden First-Layer Security Agent - Main Application
================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Main FastAPI entry point mounting:
- CORS middleware
- Interceptor router (/internal/intercept/*)
- Forensic X-Ray real-time telemetry WebSocket (/ws/xray-stream)
- Health check endpoint (/health)
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.openclaw_bridge.interceptor import interceptor_router
from app.openclaw_bridge.telemetry_ws import telemetry_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("intentguard")

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="IntentGuard Hidden First-Layer Security Agent & Policy Gateway",
)

# ---------------------------------------------------------------------------
# CORS Configuration
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Router Mounting
# ---------------------------------------------------------------------------
app.include_router(interceptor_router)


# ---------------------------------------------------------------------------
# Health & Status Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Returns system status, active OpenClaw primary LLM model,
    and interceptor bridge readiness status.
    """
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "openclaw_primary_model": settings.OPENCLAW_PRIMARY_MODEL,
        "interceptor_bridge_ready": True,
        "active_telemetry_subscribers": telemetry_manager.active_client_count,
    }


# ---------------------------------------------------------------------------
# Layer 3 Policy & Resource Budget Endpoints
# ---------------------------------------------------------------------------
from app.layer3_policy.resource_budget import resource_budget_enforcer


@app.get("/internal/policy/budget/{session_id}")
async def get_policy_budget(session_id: str) -> Dict[str, Any]:
    """Expose session budget metrics under Layer 3 Policy Gateway."""
    return resource_budget_enforcer.get_session_metrics(session_id)


@app.post("/internal/policy/budget/{session_id}/reset")
async def reset_policy_budget(session_id: str) -> Dict[str, Any]:
    """Reset session budget metrics under Layer 3 Policy Gateway."""
    resource_budget_enforcer.reset_session(session_id)
    return {
        "session_id": session_id,
        "status": "reset_successful",
        "message": f"Policy budget for session '{session_id}' has been reset.",
    }


# ---------------------------------------------------------------------------
# Layer 1 Document De-Cloak Direct Inspection Endpoint
# ---------------------------------------------------------------------------
import base64
from app.layer1_decloaker.audio_video_decloaker import audio_video_decloaker
from app.layer1_decloaker.image_decloaker import image_decloaker
from app.layer1_decloaker.pdf_docx_decloaker import DocumentDeCloakResult, pdf_docx_decloaker
from app.layer1_decloaker.web_dom_decloaker import web_dom_decloaker
from app.openclaw_bridge.interceptor import DocumentDeCloakRequest


@app.post("/internal/decloak/document", response_model=DocumentDeCloakResult)
async def decloak_document_root(req: DocumentDeCloakRequest) -> DocumentDeCloakResult:
    """
    Direct inspection endpoint for Forensic X-Ray UI and testing.
    Runs Pre-OCR De-Cloaker on base64-encoded PDF, DOCX, Image, Audio, Video, or Web DOM file.
    """
    file_bytes = base64.b64decode(req.raw_content_base64)
    if req.modality in ("image", "screenshot", "receipt") or req.filename.lower().endswith(
        (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff")
    ):
        return image_decloaker.decloak_image_bytes(file_bytes=file_bytes, filename=req.filename)
    elif req.modality in ("audio", "video") or req.filename.lower().endswith(
        (".mp3", ".wav", ".ogg", ".mp4", ".mov", ".m4a", ".webm")
    ):
        mod_str = req.modality or ("video" if req.filename.lower().endswith((".mp4", ".mov", ".m4a", ".webm")) else "audio")
        return audio_video_decloaker.decloak_media_bytes(file_bytes=file_bytes, modality=mod_str, filename=req.filename)
    elif req.modality in ("web_dom", "html") or req.filename.lower().endswith((".html", ".htm")):
        return web_dom_decloaker.decloak_web_dom_bytes(html_input=file_bytes, filename=req.filename)
    return pdf_docx_decloaker.decloak_document(
        file_bytes=file_bytes,
        filename=req.filename,
        modality=req.modality,
    )


# ---------------------------------------------------------------------------
# WebSocket Telemetry Stream Endpoint
# ---------------------------------------------------------------------------
@app.websocket("/ws/xray-stream")
async def xray_telemetry_stream(websocket: WebSocket) -> None:
    """
    Live WebSocket feed broadcasting all 4 interception hooks to the Forensic
    X-Ray UI in real-time.
    """
    await telemetry_manager.connect(websocket)
    try:
        while True:
            # Keep socket alive; clients can send heartbeat/ping messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        telemetry_manager.disconnect(websocket)
    except Exception as exc:  # noqa: BLE001
        logger.warning("WebSocket client disconnected with exception: %s", exc)
        telemetry_manager.disconnect(websocket)
