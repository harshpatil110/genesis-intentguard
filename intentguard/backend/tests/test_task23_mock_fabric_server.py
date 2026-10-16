"""
IntentGuard Automated Pytest Suite — Task 23: Built-In Mock Fabric HTTP Server
================================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Tests the complete mock Hyperledger Fabric HTTP Server mounted at
`/mock-blockchain/api/v1`:

1. test_mock_fabric_post_success_and_409
   - Valid 12-field payload returns 201 Created with recorded=True and transaction_id.
   - Exact same payload posted again returns 409 Conflict.
2. test_mock_fabric_post_chaincode_validation_rejection
   - threat_detected=True + action_taken="SAFE_EXECUTED" returns 400/422.
   - Invalid 64-char hex hashes return 400/422.
   - Missing required string fields return 400/422.
3. test_mock_fabric_get_event
   - GET /audit-events/{event_id} returns 200 OK with recorded_at timestamp.
   - GET nonexistent event returns 404 Not Found.
4. test_mock_fabric_get_list_rbac
   - Post events for buyer-A and buyer-B.
   - GET with X-Fabric-Role: buyer and X-Fabric-Party-Id: buyer-A returns only buyer-A.
   - GET with X-Fabric-Role: admin returns all events.
   - Missing RBAC headers return 401 Unauthorized.
5. test_mock_fabric_auth_rejection
   - Missing Authorization header returns 401 Unauthorized.
   - Invalid Bearer token returns 401 Unauthorized.
6. test_mock_fabric_with_task22_http_client
   - End-to-end integration: FabricGatewayHttpClient records an event into the
     mock server and retrieves it successfully.
"""

import pytest
from fastapi.testclient import TestClient

from app.blockchain_client.event_builder import FabricAuditEventPayload
from app.blockchain_client.mock_fabric_server import clear_mock_ledger
from app.main import app

CLIENT = TestClient(app)
BASE_URL = "/mock-blockchain/api/v1"
DEV_AUTH_HEADER = {"Authorization": "Bearer intentguard_local_dev_key"}

HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64


@pytest.fixture(autouse=True)
def clean_ledger():
    """Clear the mock ledger before each test."""
    clear_mock_ledger()
    yield
    clear_mock_ledger()


def make_valid_payload_dict(
    event_id: str = "evt-mock-001",
    buyer_id: str = "buyer-01",
    supplier_id: str = "supplier-01",
    action_taken: str = "BLOCKED",
    threat_detected: bool = True,
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": "2026-10-15T12:00:00Z",
        "buyer_id": buyer_id,
        "supplier_id": supplier_id,
        "input_modality": "text",
        "action_taken": action_taken,
        "policy_reference": "policy-v1",
        "raw_evidence_sha256": HEX_A,
        "redacted_diff_sha256": HEX_B,
        "intent_hmac_hash": HEX_C,
        "risk_category_ids": [2, 18],
        "threat_detected": threat_detected,
    }


# ---------------------------------------------------------------------------
# Test 1: POST success and 409 conflict
# ---------------------------------------------------------------------------

def test_mock_fabric_post_success_and_409():
    """
    Post a valid 12-field payload to /mock-blockchain/api/v1/audit-events.
    Assert 201 Created, recorded == True, and transaction_id is present.
    Post the exact same payload again and assert 409 Conflict.
    """
    payload = make_valid_payload_dict(event_id="evt-post-409-test")

    # 1. First POST: 201 Created
    response1 = CLIENT.post(
        f"{BASE_URL}/audit-events",
        json=payload,
        headers=DEV_AUTH_HEADER,
    )
    assert response1.status_code == 201, f"Expected 201, got {response1.status_code}: {response1.text}"
    data1 = response1.json()
    assert data1.get("recorded") is True
    assert "transaction_id" in data1
    assert data1["transaction_id"].startswith("mock-fabric-tx-")
    assert data1.get("event_id") == "evt-post-409-test"
    assert "recorded_at" in data1

    # 2. Duplicate POST: 409 Conflict
    response2 = CLIENT.post(
        f"{BASE_URL}/audit-events",
        json=payload,
        headers=DEV_AUTH_HEADER,
    )
    assert response2.status_code == 409, f"Expected 409, got {response2.status_code}: {response2.text}"
    assert "duplicate" in response2.text.lower() or "already exists" in response2.text.lower()


# ---------------------------------------------------------------------------
# Test 2: POST chaincode validation rejection
# ---------------------------------------------------------------------------

def test_mock_fabric_post_chaincode_validation_rejection():
    """
    Post a payload where threat_detected=True but action_taken='SAFE_EXECUTED'.
    Assert 400/422 (validation error from the mock server mimicking chaincode rejection).
    """
    # Rule E violation: threat_detected=True cannot have action_taken="SAFE_EXECUTED"
    invalid_threat_payload = make_valid_payload_dict(
        event_id="evt-threat-viol",
        action_taken="SAFE_EXECUTED",
        threat_detected=True,
    )

    response = CLIENT.post(
        f"{BASE_URL}/audit-events",
        json=invalid_threat_payload,
        headers=DEV_AUTH_HEADER,
    )
    assert response.status_code in (400, 422), (
        f"Expected 400 or 422 for Rule E violation, got {response.status_code}: {response.text}"
    )

    # Rule C violation: invalid 64-char hash
    bad_hash_payload = make_valid_payload_dict(event_id="evt-bad-hash")
    bad_hash_payload["raw_evidence_sha256"] = "short-hash"
    response_bad_hash = CLIENT.post(
        f"{BASE_URL}/audit-events",
        json=bad_hash_payload,
        headers=DEV_AUTH_HEADER,
    )
    assert response_bad_hash.status_code in (400, 422)

    # Rule A violation: empty buyer_id
    empty_buyer_payload = make_valid_payload_dict(event_id="evt-empty-buyer")
    empty_buyer_payload["buyer_id"] = "   "
    response_empty = CLIENT.post(
        f"{BASE_URL}/audit-events",
        json=empty_buyer_payload,
        headers=DEV_AUTH_HEADER,
    )
    assert response_empty.status_code in (400, 422)


# ---------------------------------------------------------------------------
# Test 3: GET event by ID
# ---------------------------------------------------------------------------

def test_mock_fabric_get_event():
    """Post an event, then GET it by event_id. Assert 200 OK and recorded_at timestamp."""
    event_id = "evt-get-test-101"
    payload = make_valid_payload_dict(event_id=event_id, buyer_id="buyer-xyz")

    post_resp = CLIENT.post(
        f"{BASE_URL}/audit-events",
        json=payload,
        headers=DEV_AUTH_HEADER,
    )
    assert post_resp.status_code == 201

    # GET existing event
    get_resp = CLIENT.get(
        f"{BASE_URL}/audit-events/{event_id}",
        headers=DEV_AUTH_HEADER,
    )
    assert get_resp.status_code == 200
    event_data = get_resp.json()
    assert event_data["event_id"] == event_id
    assert event_data["buyer_id"] == "buyer-xyz"
    assert "recorded_at" in event_data
    assert "transaction_id" in event_data

    # GET non-existent event
    missing_resp = CLIENT.get(
        f"{BASE_URL}/audit-events/evt-does-not-exist",
        headers=DEV_AUTH_HEADER,
    )
    assert missing_resp.status_code == 404


# ---------------------------------------------------------------------------
# Test 4: GET list with RBAC filtering
# ---------------------------------------------------------------------------

def test_mock_fabric_get_list_rbac():
    """
    Post events for buyer-A and buyer-B.
    GET list with X-Fabric-Role: buyer, X-Fabric-Party-Id: buyer-A.
    Assert only buyer-A events are returned.
    Assert 401 is returned if RBAC headers are missing.
    """
    ev_a1 = make_valid_payload_dict(event_id="evt-a1", buyer_id="buyer-A", supplier_id="supplier-X")
    ev_a2 = make_valid_payload_dict(event_id="evt-a2", buyer_id="buyer-A", supplier_id="supplier-Y")
    ev_b1 = make_valid_payload_dict(event_id="evt-b1", buyer_id="buyer-B", supplier_id="supplier-X")

    for ev in (ev_a1, ev_a2, ev_b1):
        r = CLIENT.post(f"{BASE_URL}/audit-events", json=ev, headers=DEV_AUTH_HEADER)
        assert r.status_code == 201

    # 1. GET with missing RBAC headers -> 401 Unauthorized
    missing_rbac_resp = CLIENT.get(
        f"{BASE_URL}/audit-events",
        headers=DEV_AUTH_HEADER,
    )
    assert missing_rbac_resp.status_code == 401

    # 2. GET for buyer-A -> returns only buyer-A events (2 events)
    buyer_a_headers = {
        **DEV_AUTH_HEADER,
        "X-Fabric-Role": "buyer",
        "X-Fabric-Party-Id": "buyer-A",
    }
    resp_buyer_a = CLIENT.get(f"{BASE_URL}/audit-events", headers=buyer_a_headers)
    assert resp_buyer_a.status_code == 200
    data_a = resp_buyer_a.json()
    assert data_a["total"] == 2
    returned_ids = {e["event_id"] for e in data_a["events"]}
    assert returned_ids == {"evt-a1", "evt-a2"}

    # 3. GET for buyer-B -> returns only buyer-B events (1 event)
    buyer_b_headers = {
        **DEV_AUTH_HEADER,
        "X-Fabric-Role": "buyer",
        "X-Fabric-Party-Id": "buyer-B",
    }
    resp_buyer_b = CLIENT.get(f"{BASE_URL}/audit-events", headers=buyer_b_headers)
    assert resp_buyer_b.status_code == 200
    data_b = resp_buyer_b.json()
    assert data_b["total"] == 1
    assert data_b["events"][0]["event_id"] == "evt-b1"

    # 4. GET for admin -> returns all events (3 events)
    admin_headers = {
        **DEV_AUTH_HEADER,
        "X-Fabric-Role": "admin",
        "X-Fabric-Party-Id": "admin-01",
    }
    resp_admin = CLIENT.get(f"{BASE_URL}/audit-events", headers=admin_headers)
    assert resp_admin.status_code == 200
    data_admin = resp_admin.json()
    assert data_admin["total"] == 3


# ---------------------------------------------------------------------------
# Test 5: Authentication rejection tests
# ---------------------------------------------------------------------------

def test_mock_fabric_auth_rejection():
    """Verify endpoints reject requests with missing or invalid Authorization tokens."""
    payload = make_valid_payload_dict(event_id="evt-auth-test")

    # Missing Authorization header
    resp_no_auth = CLIENT.post(f"{BASE_URL}/audit-events", json=payload)
    assert resp_no_auth.status_code == 401

    # Invalid token
    resp_bad_token = CLIENT.post(
        f"{BASE_URL}/audit-events",
        json=payload,
        headers={"Authorization": "Bearer invalid_unauthorized_token"},
    )
    assert resp_bad_token.status_code == 401

    # Malformed header (no Bearer prefix)
    resp_malformed = CLIENT.post(
        f"{BASE_URL}/audit-events",
        json=payload,
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert resp_malformed.status_code == 401


# ---------------------------------------------------------------------------
# Test 6: Integration with Task 22 FabricGatewayHttpClient
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mock_fabric_with_task22_http_client():
    """
    End-to-end integration: FabricGatewayHttpClient records an event into the
    mock server and retrieves it successfully using an httpx client routed to TestClient.
    """
    from app.blockchain_client.http_client import FabricGatewayHttpClient

    event = FabricAuditEventPayload(
        event_id="evt-e2e-task22-23",
        timestamp="2026-10-15T12:00:00Z",
        buyer_id="buyer-e2e",
        supplier_id="supplier-e2e",
        input_modality="json",
        action_taken="BLOCKED",
        policy_reference="policy-v1",
        raw_evidence_sha256=HEX_A,
        redacted_diff_sha256=HEX_B,
        intent_hmac_hash=HEX_C,
        risk_category_ids=[1, 2],
        threat_detected=True,
    )

    # Use httpx.AsyncClient with TestClient ASGI transport
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver/mock-blockchain") as raw_http:
        # Wrap our client with this transport
        client = FabricGatewayHttpClient(
            api_base_url="http://testserver/mock-blockchain",
            api_key="intentguard_local_dev_key",
        )
        # Point client's inner httpx client to our ASGI transport
        await client._client.aclose()
        client._client = raw_http

        # 1. Record event
        res = await client.record_audit_event(event)
        assert res["recorded"] is True
        assert "transaction_id" in res

        # 2. Get event
        retrieved = await client.get_audit_event(event.event_id)
        assert retrieved is not None
        assert retrieved["event_id"] == event.event_id
        assert retrieved["buyer_id"] == "buyer-e2e"

        # 3. List events
        events_list = await client.list_audit_events(role="buyer", party_id="buyer-e2e")
        assert len(events_list) == 1
        assert events_list[0]["event_id"] == event.event_id
