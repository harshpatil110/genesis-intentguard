"""Authentication and Role-Based Access Control (RBAC) for Fabric REST API."""

from __future__ import annotations

import hmac
from typing import Any, Dict, List, Optional

from fastapi import Depends, Header, HTTPException, Request, status

from app.config import get_fabric_settings

VALID_ROLES = {"buyer", "supplier", "auditor", "admin"}


async def verify_api_key_or_token(
    request: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> str:
    """Validate Bearer token or X-API-Key against configured FABRIC_API_KEY.

    Raises:
        HTTPException(401): If the token/key is missing or invalid.
    """
    settings = get_fabric_settings()
    expected_key = settings.FABRIC_API_KEY

    token = None
    if authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        elif len(parts) == 1:
            token = parts[0]
    elif x_api_key:
        token = x_api_key.strip()

    if not token or not hmac.compare_digest(token, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token


async def get_current_role_context(
    token: str = Depends(verify_api_key_or_token),
    x_intentguard_role: Optional[str] = Header(None, alias="X-IntentGuard-Role"),
    x_fabric_role: Optional[str] = Header(None, alias="X-Fabric-Role"),
    x_party_id: Optional[str] = Header(None, alias="X-Party-ID"),
    x_fabric_party_id: Optional[str] = Header(None, alias="X-Fabric-Party-Id"),
) -> Dict[str, Optional[str]]:
    """Extract and validate the caller's role and party ID.

    Raises:
        HTTPException(403): If the role is invalid or required party ID is missing.
    """
    role = (x_intentguard_role or x_fabric_role or "").strip().lower()
    party_id = (x_party_id or x_fabric_party_id or "").strip() or None

    if not role or role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Insufficient or invalid role permissions (role={role!r})",
        )

    if role in {"buyer", "supplier"} and not party_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Missing X-Party-ID header required for role '{role}'",
        )

    return {
        "role": role,
        "party_id": party_id,
    }


def filter_audit_events_by_role(
    events: List[Dict[str, Any]],
    role: str,
    party_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter ledger audit events according to role-based access rules.

    - Buyer: Only events matching buyer_id == party_id
    - Supplier: Only events matching supplier_id == party_id
    - Auditor / Admin: All events across all parties
    """
    role_norm = (role or "").strip().lower()
    if role_norm in {"auditor", "admin"}:
        return list(events)

    if role_norm == "buyer":
        return [e for e in events if e.get("buyer_id") == party_id]

    if role_norm == "supplier":
        return [e for e in events if e.get("supplier_id") == party_id]

    return []
