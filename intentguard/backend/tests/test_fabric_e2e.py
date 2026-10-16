"""
IntentGuard End-to-End Application-to-Fabric Integration Test Suite
====================================================================
Task 38: Rigorously verifies the 7 mandatory blockchain scenarios defined
in the GENESIS 2.0 PS 01 project specification against the live/mock
Hyperledger Fabric Gateway service.

1. Test 1: Valid Security Event Commit (201 Created + transaction_id)
2. Test 2: Ledger Read & Timestamp Verification (all 12 fields + recorded_at)
3. Test 3: Duplicate Event ID Handling (409 Conflict)
4. Test 4: Invalid Input & Chaincode Constraints Rejection (400/422)
5. Test 5: Missing Event Lookup (404 Not Found)
6. Test 6: Role Authorization & RBAC Filtering (401/403 + party isolation)
7. Test 7: Network Failure / Fail-Closed Lockdown (Risk #33)
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.blockchain_client.mock_fabric_server import clear_mock_ledger
from app.layer3_policy.fail_closed_guard import (
    FailClosedCircuitBreaker,
    fail_closed_breaker,
)

CLIENT = TestClient(app)
MOCK_API_PREFIX = "/mock-blockchain/api/v1"
DEV_AUTH = {"Authorization": "Bearer intentguard_local_dev_key"}

HEX_RAW = "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5"
HEX_DIFF = "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2"
HEX_HMAC = "a9f8e43d2c1b50678e90f2345bcdae018273645fe1029384756abcde12345678"


@pytest.fixture(autouse=True)
def reset_ledger_and_circuits():
    """Ensure a clean mock ledger and healthy circuit breaker for each test."""
    clear_mock_ledger()
    fail_closed_breaker.reset_circuit()
    yield
    clear_mock_ledger()
    fail_closed_breaker.reset_circuit()


def make_test_payload(
    event_id: str = "evt-e2e-001",
    buyer_id: str = "buyer-01",
    supplier_id: str = "supplier-01",
    action_taken: str = "BLOCKED",
    threat_detected: bool = True,
    risk_category_ids: list = None,
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": "2026-10-16T19:00:00Z",
        "buyer_id": buyer_id,
        "supplier_id": supplier_id,
        "input_modality": "pdf",
        "action_taken": action_taken,
        "policy_reference": "RULE-L1-PRE-OCR-01",
        "raw_evidence_sha256": HEX_RAW,
        "redacted_diff_sha256": HEX_DIFF,
        "intent_hmac_hash": HEX_HMAC,
        "risk_category_ids": risk_category_ids if risk_category_ids is not None else [1, 2, 14, 18],
        "threat_detected": threat_detected,
    }


# ---------------------------------------------------------------------------
# Test 1: Valid Security Event Commit
# ---------------------------------------------------------------------------
def test_e2e_scenario1_valid_security_event_commit():
    """Submit a blocked PDF injection event payload; assert 201 Created and transaction_id."""
    payload = make_test_payload(event_id="evt-e2e-scenario-01")

    res = CLIENT.post(
        f"{MOCK_API_PREFIX}/audit-events",
        json=payload,
        headers=DEV_AUTH,
    )
    assert res.status_code == 201, f"Failed to commit valid audit event: {res.text}"
    data = res.json()
    assert data.get("recorded") is True
    assert "transaction_id" in data
    assert len(data["transaction_id"]) > 0


# ---------------------------------------------------------------------------
# Test 2: Ledger Read & Timestamp Verification
# ---------------------------------------------------------------------------
def test_e2e_scenario2_ledger_read_and_timestamp_verification():
    """Read event from ledger; assert all 12 fields match and recorded_at is appended."""
    event_id = "evt-e2e-scenario-02"
    payload = make_test_payload(event_id=event_id)

    # First commit
    post_res = CLIENT.post(
        f"{MOCK_API_PREFIX}/audit-events",
        json=payload,
        headers=DEV_AUTH,
    )
    assert post_res.status_code == 201

    # Query back
    get_res = CLIENT.get(
        f"{MOCK_API_PREFIX}/audit-events/{event_id}",
        headers=DEV_AUTH,
    )
    assert get_res.status_code == 200, f"Failed to read audit event: {get_res.text}"
    record = get_res.json()

    # Verify strict 12 fields
    assert record["event_id"] == event_id
    assert record["buyer_id"] == "buyer-01"
    assert record["supplier_id"] == "supplier-01"
    assert record["input_modality"] == "pdf"
    assert record["action_taken"] == "BLOCKED"
    assert record["policy_reference"] == "RULE-L1-PRE-OCR-01"
    assert record["raw_evidence_sha256"] == HEX_RAW
    assert record["redacted_diff_sha256"] == HEX_DIFF
    assert record["intent_hmac_hash"] == HEX_HMAC
    assert record["risk_category_ids"] == [1, 2, 14, 18]
    assert record["threat_detected"] is True

    # Verify Fabric commit metadata
    assert "recorded_at" in record
    assert "transaction_id" in record


# ---------------------------------------------------------------------------
# Test 3: Duplicate Event ID Handling
# ---------------------------------------------------------------------------
def test_e2e_scenario3_duplicate_event_id_handling():
    """Re-submitting the exact same event_id must trigger HTTP 409 Conflict."""
    payload = make_test_payload(event_id="evt-e2e-dup-01")

    # First commit: 201
    res1 = CLIENT.post(f"{MOCK_API_PREFIX}/audit-events", json=payload, headers=DEV_AUTH)
    assert res1.status_code == 201

    # Second commit: 409 Conflict
    res2 = CLIENT.post(f"{MOCK_API_PREFIX}/audit-events", json=payload, headers=DEV_AUTH)
    assert res2.status_code == 409, f"Expected 409 Conflict, got {res2.status_code}: {res2.text}"


# ---------------------------------------------------------------------------
# Test 4: Invalid Input & Chaincode Constraints Rejection
# ---------------------------------------------------------------------------
def test_e2e_scenario4_invalid_input_and_chaincode_constraints():
    """
    Submitting an invalid 63-char hash, or threat_detected=True + SAFE_EXECUTED,
    must be rejected with HTTP 400 Bad Request or 422 Unprocessable Entity.
    """
    # Case A: Invalid hash length (63 characters)
    bad_hash_payload = make_test_payload(event_id="evt-bad-hash")
    bad_hash_payload["raw_evidence_sha256"] = "a" * 63
    res_a = CLIENT.post(f"{MOCK_API_PREFIX}/audit-events", json=bad_hash_payload, headers=DEV_AUTH)
    assert res_a.status_code in (400, 422), f"Expected 400/422 on bad hash, got {res_a.status_code}"

    # Case B: Invariant violation (threat_detected=True with action_taken=SAFE_EXECUTED)
    invalid_contract_payload = make_test_payload(
        event_id="evt-invalid-contract",
        action_taken="SAFE_EXECUTED",
        threat_detected=True,
    )
    res_b = CLIENT.post(f"{MOCK_API_PREFIX}/audit-events", json=invalid_contract_payload, headers=DEV_AUTH)
    assert res_b.status_code in (400, 422), f"Expected 400/422 on invariant violation, got {res_b.status_code}"


# ---------------------------------------------------------------------------
# Test 5: Missing Event Lookup 404
# ---------------------------------------------------------------------------
def test_e2e_scenario5_missing_event_lookup_404():
    """Querying a nonexistent event must return HTTP 404 Not Found."""
    res = CLIENT.get(f"{MOCK_API_PREFIX}/audit-events/evt-nonexistent-999", headers=DEV_AUTH)
    assert res.status_code == 404, f"Expected 404, got {res.status_code}"


# ---------------------------------------------------------------------------
# Test 6: Role Authorization & RBAC Filtering
# ---------------------------------------------------------------------------
def test_e2e_scenario6_role_authorization_and_acl():
    """
    Assert missing auth returns 401.
    Seed events for supplier-01 and supplier-02.
    Assert supplier-01 view only contains supplier-01 events.
    Assert auditor view returns all events.
    """
    # 1. Missing auth
    unauth_res = CLIENT.get(f"{MOCK_API_PREFIX}/audit-events")
    assert unauth_res.status_code == 401

    # 2. Seed events
    p1 = make_test_payload(event_id="evt-supp-01", supplier_id="supplier-01")
    p2 = make_test_payload(event_id="evt-supp-02", supplier_id="supplier-02")
    CLIENT.post(f"{MOCK_API_PREFIX}/audit-events", json=p1, headers=DEV_AUTH)
    CLIENT.post(f"{MOCK_API_PREFIX}/audit-events", json=p2, headers=DEV_AUTH)

    # 3. Query as Supplier-01
    supplier_headers = {
        **DEV_AUTH,
        "X-Fabric-Role": "supplier",
        "X-Fabric-Party-Id": "supplier-01",
    }
    supp_res = CLIENT.get(f"{MOCK_API_PREFIX}/audit-events", headers=supplier_headers)
    assert supp_res.status_code == 200
    supp_data = supp_res.json()
    assert supp_data["total"] == 1
    assert supp_data["events"][0]["supplier_id"] == "supplier-01"

    # 4. Query as Auditor
    auditor_headers = {
        **DEV_AUTH,
        "X-Fabric-Role": "auditor",
        "X-Fabric-Party-Id": "auditor-01",
    }
    aud_res = CLIENT.get(f"{MOCK_API_PREFIX}/audit-events", headers=auditor_headers)
    assert aud_res.status_code == 200
    aud_data = aud_res.json()
    assert aud_data["total"] >= 2


# ---------------------------------------------------------------------------
# Test 7: Network Failure / Fail-Closed Behavior (Risk #33)
# ---------------------------------------------------------------------------
def test_e2e_scenario7_network_failure_fail_closed_behavior():
    """
    When the Fabric blockchain API reports an outage (HTTP 503 / 500),
    IntentGuard must trip its circuit breaker into FAIL_CLOSED_LOCKDOWN
    and refuse to fail open on sensitive payment/bank tools (Risk #33).
    """
    # 1. Simulate blockchain outage
    fail_closed_breaker.record_service_status(
        service_name="fabric_blockchain_api",
        status_code=503,
        error_msg="Hyperledger Fabric peer unreachable: StatusCode.UNAVAILABLE",
    )

    # 2. Check circuit status
    snapshot = fail_closed_breaker.get_circuit_snapshot()
    assert snapshot["fabric_blockchain_api"]["healthy"] is False
    assert snapshot["fabric_blockchain_api"]["last_status_code"] == 503

    # 3. Attempt sensitive payment tool call
    fail_closed_decision = fail_closed_breaker.enforce_fail_closed_before_action(
        tool_name="schedule_verified_payment"
    )

    assert fail_closed_decision is not None
    assert fail_closed_decision.allow_sandbox_execution is False
    assert fail_closed_decision.action_taken == "BLOCKED"
    assert fail_closed_decision.threat_detected is True
    assert fail_closed_decision.fail_closed_triggered is True
    assert 33 in fail_closed_decision.risk_category_ids
    assert "Risk #33 Fail-Closed Protection triggered" in fail_closed_decision.reason
