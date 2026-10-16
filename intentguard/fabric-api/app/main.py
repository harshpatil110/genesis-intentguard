"""FastAPI Gateway Service for Hyperledger Fabric 2.5.16.

Provides high-speed REST endpoints connecting client applications to the
Hyperledger Fabric `intentguard` smart contract.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Header, Request, status
from fastapi.responses import JSONResponse

from app.auth_acl import (
    filter_audit_events_by_role,
    get_current_role_context,
    verify_api_key_or_token,
)
from app.config import get_fabric_settings
from app.error_handlers import register_exception_handlers
from app.gateway_client import FabricGatewayClient
from app.schemas import AuditEventCreate, AuditRecordResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("intentguard.fabric_api.main")


async def optional_api_key_verify(
    request: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> Optional[str]:
    """Verify API key or token if provided, rejecting invalid credentials with 401."""
    if authorization or x_api_key:
        return await verify_api_key_or_token(request, authorization, x_api_key)
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage lifecycle of the Hyperledger Fabric gRPC Gateway connection."""
    settings = get_fabric_settings()
    gateway = FabricGatewayClient(settings=settings)
    try:
        gateway.connect()
        logger.info("Successfully connected to Hyperledger Fabric peer: %s", settings.FABRIC_PEER_ENDPOINT)
    except Exception as exc:
        logger.warning(
            "Could not establish live Hyperledger Fabric gRPC connection at startup: %s. "
            "Running with offline/mock gateway state for testing.",
            exc,
        )

    app.state.gateway = gateway
    yield
    try:
        await gateway.close()
        logger.info("Hyperledger Fabric gRPC Gateway connection closed.")
    except Exception as exc:
        logger.warning("Error closing Fabric gateway: %s", exc)


app = FastAPI(
    title="IntentGuard Hyperledger Fabric 2.5.16 Gateway Service",
    version="1.0.1",
    description="REST API Gateway translating HTTP requests into secure gRPC chaincode invocations on Hyperledger Fabric.",
    lifespan=lifespan,
)

register_exception_handlers(app)


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint."""
    is_connected = getattr(getattr(app.state, "gateway", None), "is_connected", False)
    return {
        "status": "ok",
        "service": "fabric-api",
        "fabric_connected": is_connected,
    }


async def _handle_record_audit_event(payload: AuditEventCreate) -> AuditRecordResponse:
    """Core logic for recording an audit event."""
    gateway: FabricGatewayClient = app.state.gateway
    json_str = json.dumps(payload.to_chaincode_dict())
    tx_id = await gateway.submit_record_audit_event(json_str)
    return AuditRecordResponse(
        event_id=payload.event_id,
        recorded=True,
        transaction_id=str(tx_id),
    )


@app.post("/audit-events", response_model=AuditRecordResponse, status_code=status.HTTP_201_CREATED)
async def record_audit_event(
    payload: AuditEventCreate,
    _token: Optional[str] = Depends(optional_api_key_verify),
) -> AuditRecordResponse:
    """Record an audit event on the Hyperledger Fabric ledger."""
    return await _handle_record_audit_event(payload)


@app.post("/api/v1/audit-events", response_model=AuditRecordResponse, status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def record_audit_event_v1_alias(
    payload: AuditEventCreate,
    _token: Optional[str] = Depends(optional_api_key_verify),
) -> AuditRecordResponse:
    """Alias for POST /audit-events."""
    return await _handle_record_audit_event(payload)


async def _handle_get_audit_event(event_id: str) -> Dict[str, Any]:
    """Core logic for reading an audit event from the ledger."""
    gateway: FabricGatewayClient = app.state.gateway
    record = await gateway.evaluate_read_audit_event(event_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit event '{event_id}' does not exist on ledger.",
        )
    return record


@app.get("/audit-events/{event_id}", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
async def get_audit_event(
    event_id: str,
    _token: Optional[str] = Depends(optional_api_key_verify),
) -> Dict[str, Any]:
    """Read a specific audit event from the Hyperledger Fabric ledger by event_id."""
    return await _handle_get_audit_event(event_id)


@app.get("/api/v1/audit-events/{event_id}", response_model=Dict[str, Any], status_code=status.HTTP_200_OK, include_in_schema=False)
async def get_audit_event_v1_alias(
    event_id: str,
    _token: Optional[str] = Depends(optional_api_key_verify),
) -> Dict[str, Any]:
    """Alias for GET /audit-events/{event_id}."""
    return await _handle_get_audit_event(event_id)


async def _handle_get_all_audit_events(role_context: Dict[str, Any]) -> Dict[str, Any]:
    """Core logic for listing audit events with RBAC filtering."""
    gateway: FabricGatewayClient = app.state.gateway
    raw_events = await gateway.evaluate_get_all_audit_events()
    if not isinstance(raw_events, list):
        raw_events = []
    filtered = filter_audit_events_by_role(
        raw_events,
        role_context["role"],
        role_context.get("party_id"),
    )
    return {
        "events": filtered,
        "total": len(filtered),
        "role": role_context["role"],
        "party_id": role_context.get("party_id"),
    }


@app.get("/audit-events", status_code=status.HTTP_200_OK)
async def get_all_audit_events(
    role_context: Dict[str, Any] = Depends(get_current_role_context),
) -> Dict[str, Any]:
    """Retrieve all audit events filtered by caller role and party ID."""
    return await _handle_get_all_audit_events(role_context)


@app.get("/api/v1/audit-events", status_code=status.HTTP_200_OK, include_in_schema=False)
async def get_all_audit_events_v1_alias(
    role_context: Dict[str, Any] = Depends(get_current_role_context),
) -> Dict[str, Any]:
    """Alias for GET /audit-events."""
    return await _handle_get_all_audit_events(role_context)
