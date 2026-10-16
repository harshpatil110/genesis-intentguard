"""Integration tests for Task 26 Core REST API Endpoints."""

import json
from pathlib import Path
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

# Ensure fabric-api root is on sys.path
FABRIC_API_ROOT = Path(__file__).resolve().parent.parent
if str(FABRIC_API_ROOT) not in sys.path:
    sys.path.insert(0, str(FABRIC_API_ROOT))

from app.main import app

VALID_HEX_64_A = "a" * 64
VALID_HEX_64_B = "b" * 64
VALID_HEX_64_C = "c" * 64

VALID_PAYLOAD = {
    "event_id": "evt-task26-001",
    "timestamp": "2026-10-16T12:00:00Z",
    "buyer_id": "buyer-01",
    "supplier_id": "supplier-01",
    "input_modality": "pdf",
    "action_taken": "SURGICALLY_REDACTED",
    "policy_reference": "POLICY_PO_VERIFY",
    "raw_evidence_sha256": VALID_HEX_64_A,
    "redacted_diff_sha256": VALID_HEX_64_B,
    "intent_hmac_hash": VALID_HEX_64_C,
    "risk_category_ids": [1, 2],
    "threat_detected": True,
}


@pytest.fixture
def client():
    """Create test client with mocked gateway on app.state."""
    with TestClient(app, raise_server_exceptions=False) as c:
        mock_gateway = MagicMock()
        mock_gateway.submit_record_audit_event = AsyncMock(return_value="tx123")
        mock_gateway.evaluate_read_audit_event = AsyncMock(
            return_value={**VALID_PAYLOAD, "recorded_at": "2026-10-16T12:00:01Z"}
        )
        mock_gateway.is_connected = True
        app.state.gateway = mock_gateway
        yield c


def test_health_endpoint(client: TestClient):
    """Test health check route."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "fabric-api"


def test_post_audit_event_returns_201(client: TestClient):
    """Mock submit_record_audit_event to return 'tx123'. POST valid payload. Assert 201 Created."""
    response = client.post("/audit-events", json=VALID_PAYLOAD)
    assert response.status_code == 201
    data = response.json()
    assert data["event_id"] == "evt-task26-001"
    assert data["recorded"] is True
    assert data["transaction_id"] == "tx123"

    # Verify gateway was called with serialized json containing the 12 fields
    mock_gateway = app.state.gateway
    mock_gateway.submit_record_audit_event.assert_awaited_once()
    called_json_str = mock_gateway.submit_record_audit_event.call_args[0][0]
    called_dict = json.loads(called_json_str)
    assert called_dict["event_id"] == "evt-task26-001"
    assert called_dict["threat_detected"] is True


def test_get_audit_event_returns_200(client: TestClient):
    """Mock evaluate_read_audit_event to return sample dict. GET /audit-events/evt-001. Assert 200 OK."""
    response = client.get("/audit-events/evt-task26-001")
    assert response.status_code == 200
    data = response.json()
    assert data["event_id"] == "evt-task26-001"
    assert data["recorded_at"] == "2026-10-16T12:00:01Z"
    assert data["buyer_id"] == "buyer-01"


def test_get_audit_event_404_not_found(client: TestClient):
    """Mock evaluate_read_audit_event to raise exception with 'does not exist'. Assert 404."""
    mock_gateway = app.state.gateway
    mock_gateway.evaluate_read_audit_event = AsyncMock(
        side_effect=Exception("Audit event 'evt-missing' does not exist on ledger")
    )

    response = client.get("/audit-events/evt-missing")
    assert response.status_code == 404
    assert "does not exist" in response.json()["detail"].lower()


def test_post_audit_event_409_conflict(client: TestClient):
    """Mock submit_record_audit_event to raise 'already exists'. Assert 409 Conflict."""
    mock_gateway = app.state.gateway
    mock_gateway.submit_record_audit_event = AsyncMock(
        side_effect=Exception("Audit event 'evt-task26-001' already exists on ledger")
    )

    response = client.post("/audit-events", json=VALID_PAYLOAD)
    assert response.status_code == 409
    assert "already exists" in response.json()["detail"].lower()


def test_post_audit_event_threat_detected_safe_executed_rejected(client: TestClient):
    """Assert rejection when threat_detected=True and action_taken='SAFE_EXECUTED'."""
    invalid_payload = {**VALID_PAYLOAD, "threat_detected": True, "action_taken": "SAFE_EXECUTED"}
    response = client.post("/audit-events", json=invalid_payload)
    assert response.status_code in [400, 422]


def test_post_audit_event_invalid_hash_rejected(client: TestClient):
    """Assert rejection when hash is not 64 hex chars."""
    invalid_payload = {**VALID_PAYLOAD, "raw_evidence_sha256": "short_hash"}
    response = client.post("/audit-events", json=invalid_payload)
    assert response.status_code in [400, 422]


def test_api_v1_aliases(client: TestClient):
    """Assert /api/v1/audit-events routes work identically."""
    response_post = client.post("/api/v1/audit-events", json=VALID_PAYLOAD)
    assert response_post.status_code == 201

    response_get = client.get("/api/v1/audit-events/evt-task26-001")
    assert response_get.status_code == 200
    assert response_get.json()["event_id"] == "evt-task26-001"
