"""Integration tests for Task 28 Fabric-to-HTTP Error Handlers."""

from pathlib import Path
import sys
from unittest.mock import AsyncMock, MagicMock

import grpc
import pytest
from fastapi.testclient import TestClient

# Ensure fabric-api root is on sys.path
FABRIC_API_ROOT = Path(__file__).resolve().parent.parent
if str(FABRIC_API_ROOT) not in sys.path:
    sys.path.insert(0, str(FABRIC_API_ROOT))

from app.main import app

AUTH_HEADER = {"Authorization": "Bearer intentguard_local_dev_key"}

VALID_PAYLOAD = {
    "event_id": "evt-task28-001",
    "timestamp": "2026-10-16T12:00:00Z",
    "buyer_id": "buyer-01",
    "supplier_id": "supplier-01",
    "input_modality": "pdf",
    "action_taken": "SURGICALLY_REDACTED",
    "policy_reference": "POLICY_PO_VERIFY",
    "raw_evidence_sha256": "a" * 64,
    "redacted_diff_sha256": "b" * 64,
    "intent_hmac_hash": "c" * 64,
    "risk_category_ids": [1, 2],
    "threat_detected": True,
}


class MockRpcError(grpc.RpcError):
    """Custom gRPC RpcError mock for testing exception handlers."""

    def __init__(self, code: grpc.StatusCode, details: str = ""):
        super().__init__()
        self._code = code
        self._details = details

    def code(self) -> grpc.StatusCode:
        return self._code

    def details(self) -> str:
        return self._details

    def __str__(self) -> str:
        return f"MockRpcError(code={self._code}, details={self._details})"


@pytest.fixture
def client():
    """Create test client with mocked gateway."""
    with TestClient(app, raise_server_exceptions=False) as c:
        mock_gateway = MagicMock()
        mock_gateway.submit_record_audit_event = AsyncMock(return_value="tx-mock")
        mock_gateway.evaluate_read_audit_event = AsyncMock(return_value={"event_id": "evt-001"})
        mock_gateway.evaluate_get_all_audit_events = AsyncMock(return_value=[])
        mock_gateway.is_connected = True
        app.state.gateway = mock_gateway
        yield c


def test_pydantic_validation_translates_to_400(client: TestClient):
    """Post an empty payload to /audit-events. Assert HTTP 400 (not 422)."""
    response = client.post("/audit-events", json={}, headers=AUTH_HEADER)
    assert response.status_code == 400
    data = response.json()
    assert "validation" in data["error"].lower() or "schema" in data["error"].lower()


def test_pydantic_validation_translates_to_400_no_auth(client: TestClient):
    """Post an empty payload to /audit-events with no auth header. Assert HTTP 400."""
    response = client.post("/audit-events", json={})
    assert response.status_code == 400


def test_grpc_not_found_translates_to_404(client: TestClient):
    """Mock evaluate_read_audit_event to raise grpc.RpcError with StatusCode.NOT_FOUND. Assert HTTP 404."""
    mock_gateway = app.state.gateway
    mock_gateway.evaluate_read_audit_event = AsyncMock(
        side_effect=MockRpcError(grpc.StatusCode.NOT_FOUND, "Asset evt-missing does not exist")
    )

    response = client.get("/audit-events/evt-missing", headers=AUTH_HEADER)
    assert response.status_code == 404
    assert "not found" in response.text.lower() or "does not exist" in response.text.lower()


def test_grpc_already_exists_translates_to_409(client: TestClient):
    """Mock submit_record_audit_event to raise Exception containing 'already exists'. Assert HTTP 409."""
    mock_gateway = app.state.gateway
    mock_gateway.submit_record_audit_event = AsyncMock(
        side_effect=Exception("The audit event with key evt-task28-001 already exists in ledger")
    )

    response = client.post("/audit-events", json=VALID_PAYLOAD, headers=AUTH_HEADER)
    assert response.status_code == 409
    assert "already exists" in response.text.lower()


def test_grpc_unavailable_translates_to_503(client: TestClient):
    """Mock submit_record_audit_event to raise grpc.RpcError with StatusCode.UNAVAILABLE. Assert HTTP 503."""
    mock_gateway = app.state.gateway
    mock_gateway.submit_record_audit_event = AsyncMock(
        side_effect=MockRpcError(grpc.StatusCode.UNAVAILABLE, "failed to connect to all addresses")
    )

    response = client.post("/audit-events", json=VALID_PAYLOAD, headers=AUTH_HEADER)
    assert response.status_code == 503
    assert "unreachable" in response.text.lower() or "unavailable" in response.text.lower()


def test_grpc_deadline_exceeded_translates_to_503(client: TestClient):
    """Mock evaluate_read_audit_event to raise DEADLINE_EXCEEDED. Assert HTTP 503."""
    mock_gateway = app.state.gateway
    mock_gateway.evaluate_read_audit_event = AsyncMock(
        side_effect=MockRpcError(grpc.StatusCode.DEADLINE_EXCEEDED, "Deadline exceeded")
    )

    response = client.get("/audit-events/evt-timeout", headers=AUTH_HEADER)
    assert response.status_code == 503


def test_grpc_unauthenticated_translates_to_401(client: TestClient):
    """Mock evaluate_read_audit_event to raise UNAUTHENTICATED. Assert HTTP 401."""
    mock_gateway = app.state.gateway
    mock_gateway.evaluate_read_audit_event = AsyncMock(
        side_effect=MockRpcError(grpc.StatusCode.UNAUTHENTICATED, "Identity certificate expired")
    )

    response = client.get("/audit-events/evt-001", headers=AUTH_HEADER)
    assert response.status_code == 401


def test_grpc_permission_denied_translates_to_403(client: TestClient):
    """Mock evaluate_read_audit_event to raise PERMISSION_DENIED. Assert HTTP 403."""
    mock_gateway = app.state.gateway
    mock_gateway.evaluate_read_audit_event = AsyncMock(
        side_effect=MockRpcError(grpc.StatusCode.PERMISSION_DENIED, "Access denied by channel policy")
    )

    response = client.get("/audit-events/evt-001", headers=AUTH_HEADER)
    assert response.status_code == 403
