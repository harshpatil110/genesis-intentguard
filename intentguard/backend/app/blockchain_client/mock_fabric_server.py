"""
IntentGuard — Built-In Mock Hyperledger Fabric HTTP Server
===========================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Task 23: Drop-in local FastAPI router mimicking the deployed Hyperledger Fabric
`intentguard` chaincode (v1.0.1, sequence 2) and REST Gateway.

Enables standalone development & automated testing of the backend and frontend
without requiring a live WSL2 / Docker Fabric network.

Supported Endpoints:
  - POST /audit-events       — Chaincode schema validation, duplicate 409 check,
                               minting transaction ID and recorded_at timestamp.
  - GET  /audit-events/{id}  — Retrieve individual audit record by event_id.
  - GET  /audit-events       — List audit events with RBAC role/party filtering.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import ValidationError

from app.blockchain_client.event_builder import FabricAuditEventPayload
from app.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thread-safe In-Memory Ledger State
# ---------------------------------------------------------------------------
_mock_ledger: Dict[str, Dict[str, Any]] = {}


def get_mock_ledger() -> Dict[str, Dict[str, Any]]:
    """Return a reference to the active mock ledger state."""
    return _mock_ledger


def clear_mock_ledger() -> None:
    """Clear all records from the in-memory mock ledger (for test isolation)."""
    _mock_ledger.clear()
    logger.debug("[Mock Fabric] Mock ledger cleared.")


# ---------------------------------------------------------------------------
# Authentication Dependency
# ---------------------------------------------------------------------------

def verify_auth_header(authorization: Optional[str] = Header(None)) -> str:
    """
    Validate the incoming Authorization Bearer token against configured API keys.
    Raises HTTP 401 Unauthorized if missing, malformed, or unrecognized.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header must start with 'Bearer '",
        )
    token = authorization[len("Bearer "):].strip()
    valid_tokens = {
        "intentguard_local_dev_key",
        "intentguard-fabric-gateway-dev-key-2026",
        getattr(settings, "BLOCKCHAIN_API_KEY", "intentguard_local_dev_key"),
    }
    if token not in valid_tokens and not token.startswith("intentguard"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Bearer token for Fabric Gateway",
        )
    return token


# ---------------------------------------------------------------------------
# Mock Fabric APIRouter
# ---------------------------------------------------------------------------

mock_fabric_router = APIRouter()


@mock_fabric_router.post(
    "/audit-events",
    status_code=status.HTTP_201_CREATED,
    summary="Record Audit Event to Mock Fabric Ledger",
)
async def record_audit_event(
    payload: Dict[str, Any],
    auth: str = Depends(verify_auth_header),
) -> Dict[str, Any]:
    """
    Simulates Hyperledger Fabric chaincode invocation to record an audit event.
    Enforces strict 12-field schema and chaincode rules (Tasks 21-22).
    """
    # 1. Enforce 12-field chaincode schema and safety rules
    try:
        event = FabricAuditEventPayload(**payload)
    except ValidationError as err:
        logger.warning("[Mock Fabric] Chaincode validation rejected payload: %s", err)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "chaincode_validation_failed",
                "message": f"Fabric chaincode rejected payload: {err}",
            },
        ) from err

    # 2. Check for duplicate event_id (idempotency enforcement)
    if event.event_id in _mock_ledger:
        logger.warning("[Mock Fabric] Duplicate event_id detected: %s", event.event_id)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Duplicate event_id '{event.event_id}' already exists on Hyperledger Fabric ledger.",
        )

    # 3. Mint transaction ID and UTC record timestamp
    tx_hash = hashlib.sha256(f"{event.event_id}-{uuid.uuid4()}".encode("utf-8")).hexdigest()
    tx_id = f"mock-fabric-tx-{tx_hash}"
    recorded_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    record = event.model_dump()
    record["recorded_at"] = recorded_at
    record["transaction_id"] = tx_id
    record["ledger_height"] = len(_mock_ledger) + 1

    _mock_ledger[event.event_id] = record
    logger.info("[Mock Fabric] Event %s committed to ledger (tx=%s)", event.event_id, tx_id)

    return {
        "event_id": event.event_id,
        "recorded": True,
        "transaction_id": tx_id,
        "recorded_at": recorded_at,
    }


@mock_fabric_router.get(
    "/audit-events/{event_id}",
    status_code=status.HTTP_200_OK,
    summary="Get Audit Event by ID from Mock Fabric Ledger",
)
async def get_audit_event(
    event_id: str,
    auth: str = Depends(verify_auth_header),
) -> Dict[str, Any]:
    """Retrieve an audit record by event_id. Returns 404 if not found."""
    if event_id not in _mock_ledger:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' not found on Hyperledger Fabric ledger.",
        )
    return _mock_ledger[event_id]


@mock_fabric_router.get(
    "/audit-events",
    status_code=status.HTTP_200_OK,
    summary="List Audit Events with RBAC filtering from Mock Fabric Ledger",
)
async def list_audit_events(
    auth: str = Depends(verify_auth_header),
    x_fabric_role: Optional[str] = Header(None, alias="X-Fabric-Role"),
    x_fabric_party_id: Optional[str] = Header(None, alias="X-Fabric-Party-Id"),
) -> Dict[str, Any]:
    """
    Lists audit events with RBAC role and party filtering:
      - Requires X-Fabric-Role and X-Fabric-Party-Id headers.
      - 'admin' / 'auditor': Returns all events.
      - 'buyer' / 'supplier': Only returns events where buyer_id or supplier_id matches party_id.
    """
    if not x_fabric_role or not x_fabric_party_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required X-Fabric-Role or X-Fabric-Party-Id header for blockchain audit access.",
        )

    role_norm = x_fabric_role.lower().strip()
    party_norm = x_fabric_party_id.strip()

    if role_norm in ("admin", "auditor"):
        matched = list(_mock_ledger.values())
    elif role_norm in ("buyer", "supplier"):
        matched = [
            ev for ev in _mock_ledger.values()
            if ev.get("buyer_id") == party_norm or ev.get("supplier_id") == party_norm
        ]
    else:
        # Fallback party match
        matched = [
            ev for ev in _mock_ledger.values()
            if ev.get("buyer_id") == party_norm or ev.get("supplier_id") == party_norm
        ]

    return {
        "events": matched,
        "total": len(matched),
    }
