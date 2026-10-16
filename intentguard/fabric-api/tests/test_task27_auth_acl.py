"""Integration tests for Task 27 Role-Based Access Control and Authentication."""

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

AUTH_TOKEN = "intentguard_local_dev_key"
AUTH_HEADER = {"Authorization": f"Bearer {AUTH_TOKEN}"}

SAMPLE_EVENTS = [
    {
        "event_id": "evt-001",
        "buyer_id": "buyer-01",
        "supplier_id": "supplier-01",
        "action_taken": "SAFE_EXECUTED",
        "threat_detected": False,
    },
    {
        "event_id": "evt-002",
        "buyer_id": "buyer-01",
        "supplier_id": "supplier-02",
        "action_taken": "SURGICALLY_REDACTED",
        "threat_detected": True,
    },
    {
        "event_id": "evt-003",
        "buyer_id": "buyer-02",
        "supplier_id": "supplier-01",
        "action_taken": "BLOCKED",
        "threat_detected": True,
    },
    {
        "event_id": "evt-004",
        "buyer_id": "buyer-02",
        "supplier_id": "supplier-02",
        "action_taken": "SAFE_EXECUTED",
        "threat_detected": False,
    },
]


@pytest.fixture
def client():
    """Create test client with mocked gateway returning sample events."""
    with TestClient(app, raise_server_exceptions=False) as c:
        mock_gateway = MagicMock()
        mock_gateway.evaluate_get_all_audit_events = AsyncMock(return_value=list(SAMPLE_EVENTS))
        mock_gateway.is_connected = True
        app.state.gateway = mock_gateway
        yield c


def test_missing_auth_header_returns_401(client: TestClient):
    """Make a request to GET /audit-events with no headers. Assert HTTP 401."""
    response = client.get("/audit-events")
    assert response.status_code == 401
    assert "authentication token" in response.json()["detail"].lower()


def test_invalid_api_key_returns_401(client: TestClient):
    """Pass invalid token. Assert HTTP 401."""
    response = client.get("/audit-events", headers={"Authorization": "Bearer wrong_key"})
    assert response.status_code == 401


def test_invalid_role_returns_403(client: TestClient):
    """Pass valid auth but X-IntentGuard-Role: hacker. Assert HTTP 403."""
    response = client.get(
        "/audit-events",
        headers={
            **AUTH_HEADER,
            "X-IntentGuard-Role": "hacker",
            "X-Party-ID": "buyer-01",
        },
    )
    assert response.status_code == 403
    assert "invalid role" in response.json()["detail"].lower()


def test_missing_party_id_for_buyer_returns_403(client: TestClient):
    """Pass role buyer with missing party id. Assert HTTP 403."""
    response = client.get(
        "/audit-events",
        headers={
            **AUTH_HEADER,
            "X-IntentGuard-Role": "buyer",
        },
    )
    assert response.status_code == 403
    assert "missing x-party-id" in response.json()["detail"].lower()


def test_buyer_role_filters_correctly(client: TestClient):
    """Pass role: buyer and party_id: buyer-01. Assert returned list only contains buyer-01 events."""
    response = client.get(
        "/audit-events",
        headers={
            **AUTH_HEADER,
            "X-IntentGuard-Role": "buyer",
            "X-Party-ID": "buyer-01",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "buyer"
    assert data["party_id"] == "buyer-01"
    assert data["total"] == 2
    assert all(e["buyer_id"] == "buyer-01" for e in data["events"])
    event_ids = {e["event_id"] for e in data["events"]}
    assert event_ids == {"evt-001", "evt-002"}


def test_supplier_role_filters_correctly(client: TestClient):
    """Pass role: supplier and party_id: supplier-01. Assert supplier-02 events are stripped out."""
    response = client.get(
        "/audit-events",
        headers={
            **AUTH_HEADER,
            "X-IntentGuard-Role": "supplier",
            "X-Party-ID": "supplier-01",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "supplier"
    assert data["party_id"] == "supplier-01"
    assert data["total"] == 2
    assert all(e["supplier_id"] == "supplier-01" for e in data["events"])
    event_ids = {e["event_id"] for e in data["events"]}
    assert event_ids == {"evt-001", "evt-003"}


def test_auditor_role_sees_all_events(client: TestClient):
    """Pass role: auditor. Assert returned total equals unfiltered mock array size."""
    response = client.get(
        "/audit-events",
        headers={
            **AUTH_HEADER,
            "X-IntentGuard-Role": "auditor",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "auditor"
    assert data["total"] == len(SAMPLE_EVENTS)
    assert len(data["events"]) == len(SAMPLE_EVENTS)


def test_header_aliases_fabric_role_and_party_id(client: TestClient):
    """Test compatibility with X-Fabric-Role and X-Fabric-Party-Id aliases."""
    response = client.get(
        "/audit-events",
        headers={
            "X-API-Key": AUTH_TOKEN,
            "X-Fabric-Role": "supplier",
            "X-Fabric-Party-Id": "supplier-02",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "supplier"
    assert data["party_id"] == "supplier-02"
    assert data["total"] == 2
    assert all(e["supplier_id"] == "supplier-02" for e in data["events"])
