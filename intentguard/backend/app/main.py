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
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
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
app.include_router(interceptor_router)

# Mount Mock Hyperledger Fabric HTTP Server (Task 23)
from app.blockchain_client.mock_fabric_server import mock_fabric_router

if settings.BLOCKCHAIN_USE_MOCK:
    app.include_router(
        mock_fabric_router,
        prefix="/mock-blockchain/api/v1",
        tags=["Mock Blockchain"],
    )


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
# Layer 3 Step-Back Human Approval Card Endpoints (Task 20)
# ---------------------------------------------------------------------------
from app.layer3_policy.step_back_approval import (
    ApprovalResolutionRequest,
    ApprovalResolutionResponse,
    PendingApprovalCard,
)
from app.openclaw_bridge.interceptor import interceptor_bridge


@app.get("/api/approvals/pending")
async def get_pending_approvals(session_id: Optional[str] = None) -> Dict[str, Any]:
    """Exposes all pending approval cards for human reviewer visibility."""
    cards = interceptor_bridge.step_back_approval_engine.get_pending_cards(session_id=session_id)
    return {
        "pending_count": len(cards),
        "cards": [c.model_dump() for c in cards],
    }


@app.get("/api/approvals/{card_id}", response_model=PendingApprovalCard)
async def get_approval_card(card_id: str) -> PendingApprovalCard:
    """Retrieves a specific approval card by ID."""
    card = interceptor_bridge.step_back_approval_engine.get_card(card_id)
    if not card:
        raise HTTPException(status_code=404, detail=f"Approval card '{card_id}' not found")
    return card


@app.post("/api/approvals/{card_id}/resolve", response_model=ApprovalResolutionResponse)
async def resolve_approval_card(card_id: str, req: ApprovalResolutionRequest) -> ApprovalResolutionResponse:
    """
    Human operator resolution endpoint (APPROVE or REJECT).
    Approvals generate cryptographic execution tokens; both decisions emit Fabric audit records.
    """
    try:
        res = interceptor_bridge.step_back_approval_engine.resolve_card(card_id, req)
        if hasattr(res, "__await__"):
            return await res
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Approval card '{card_id}' not found")



# ---------------------------------------------------------------------------
# Layer 1 Document De-Cloak Direct Inspection Endpoint
# ---------------------------------------------------------------------------
import base64
from typing import Union
from app.layer1_decloaker.archive_file_scanner import archive_file_scanner
from app.layer1_decloaker.audio_video_decloaker import audio_video_decloaker
from app.layer1_decloaker.email_chat_scanner import email_chat_scanner
from app.layer1_decloaker.image_decloaker import image_decloaker
from app.layer1_decloaker.pdf_docx_decloaker import DocumentDeCloakResult, pdf_docx_decloaker
from app.layer1_decloaker.web_dom_decloaker import web_dom_decloaker
from app.openclaw_bridge.interceptor import DocumentDeCloakRequest


@app.post("/internal/decloak/document", response_model=DocumentDeCloakResult)
async def decloak_document_root(req: DocumentDeCloakRequest) -> DocumentDeCloakResult:
    """
    Direct inspection endpoint for Forensic X-Ray UI and testing.
    Runs Pre-OCR De-Cloaker on base64-encoded PDF, DOCX, Image, Audio, Video, Web DOM, Email, Chat, Archive, or Spreadsheet file.
    """
    if req.modality in ("email", "chat") or req.filename.lower().endswith((".eml", ".msg")):
        raw_in: Union[bytes, str] = (
            base64.b64decode(req.raw_content_base64)
            if req.raw_content_base64
            else (req.raw_content_text or "")
        )
        return email_chat_scanner.scan_message_bytes(
            raw_input=raw_in,
            metadata=req.metadata,
            modality=req.modality or "email",
            filename=req.filename,
        )

    if req.modality in ("archive", "zip", "csv_xlsx", "xlsx", "csv") or req.filename.lower().endswith(
        (".zip", ".tar", ".gz", ".7z", ".rar", ".xlsx", ".xlsm", ".csv")
    ):
        file_bytes = (
            base64.b64decode(req.raw_content_base64)
            if req.raw_content_base64
            else (req.raw_content_text or "").encode("utf-8")
        )
        return archive_file_scanner.scan_file_bytes(
            file_bytes=file_bytes,
            filename=req.filename,
            modality=req.modality,
        )

    file_bytes = base64.b64decode(req.raw_content_base64) if req.raw_content_base64 else b""
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
