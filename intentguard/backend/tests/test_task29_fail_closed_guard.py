"""
Unit and Integration Tests for Task 29: Fail-Closed Security Circuit Breaker & Anti-Bypass Guard
================================================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Validates:
  1. Valid ExecutionPermitToken issuance and verification (SAFE_EXECUTED)
  2. Missing ExecutionPermitToken blocked (Risk #30 Security-Control Bypass)
  3. Replay attack with previously consumed token blocked (Risk #30)
  4. Expired ExecutionPermitToken blocked (Risk #30 TTL Expiry)
  5. Parameter / Tool Tampering blocked (Risk #18 Integrity & Risk #30 Bypass)
  6. HTTP 500/503 Dependency Outage triggers Fail-Closed Lockdown (Risk #33 Fail-Open Prevention)
  7. FastAPI integration: /openclaw/verify-execution-token and /openclaw/circuit-status
"""

import time
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.layer3_policy.fail_closed_guard import (
    AntiBypassTokenVerifier,
    FailClosedCircuitBreaker,
    ExecutionPermitToken,
    SandboxToolVerifyRequest,
    SandboxToolVerifyResponse,
    anti_bypass_verifier,
    fail_closed_breaker,
)


@pytest.fixture(autouse=True)
def reset_guards():
    """Reset the verifier and circuit breaker before and after every test."""
    anti_bypass_verifier.reset()
    fail_closed_breaker.reset_circuit()
    yield
    anti_bypass_verifier.reset()
    fail_closed_breaker.reset_circuit()


# ---------------------------------------------------------------------------
# Test 1: Valid ExecutionPermitToken Issuance and Verification
# ---------------------------------------------------------------------------
def test_valid_token_issuance_and_verification():
    verifier = AntiBypassTokenVerifier(secret_key="test-secret-key")
    session_id = "session-task29-01"
    tool_name = "schedule_payment"
    tool_args = {"amount": 5000, "currency": "INR", "recipient": "ACME Supplies"}
    intent_hash = "a" * 64

    token = verifier.issue_permit_token(
        session_id=session_id,
        tool_name=tool_name,
        tool_arguments=tool_args,
        intent_hmac_hash=intent_hash,
        ttl_seconds=30,
    )

    assert token.token_id.startswith("tok-")
    assert token.session_id == session_id
    assert token.tool_name == tool_name
    assert len(token.signature_hmac) == 64

    # Verify token
    req = SandboxToolVerifyRequest(
        session_id=session_id,
        tool_name=tool_name,
        tool_arguments=tool_args,
        permit_token=token,
    )
    res = verifier.verify_permit_token(req)

    assert res.verified is True
    assert res.allow_sandbox_execution is True
    assert res.action_taken == "SAFE_EXECUTED"
    assert res.threat_detected is False
    assert res.bypass_attempt_detected is False


# ---------------------------------------------------------------------------
# Test 2: Missing Token Blocked (Risk #30 Security-Control Bypass)
# ---------------------------------------------------------------------------
def test_missing_token_blocked():
    verifier = AntiBypassTokenVerifier(secret_key="test-secret-key")
    req = SandboxToolVerifyRequest(
        session_id="session-task29-02",
        tool_name="schedule_payment",
        tool_arguments={"amount": 1000},
        permit_token=None,
        raw_execution_token_hmac=None,
    )
    res = verifier.verify_permit_token(req)

    assert res.verified is False
    assert res.allow_sandbox_execution is False
    assert res.action_taken == "BLOCKED"
    assert res.threat_detected is True
    assert res.bypass_attempt_detected is True
    assert 30 in res.risk_category_ids
    assert "Risk #30 Security-Control Bypass" in res.reason


# ---------------------------------------------------------------------------
# Test 3: Token Replay Blocked (Risk #30)
# ---------------------------------------------------------------------------
def test_replay_attack_blocked():
    verifier = AntiBypassTokenVerifier(secret_key="test-secret-key")
    token = verifier.issue_permit_token(
        session_id="session-replay",
        tool_name="bash",
        tool_arguments={"command": "ls -la"},
        intent_hmac_hash="b" * 64,
    )

    req = SandboxToolVerifyRequest(
        session_id="session-replay",
        tool_name="bash",
        tool_arguments={"command": "ls -la"},
        permit_token=token,
    )

    # First attempt: succeeds
    res1 = verifier.verify_permit_token(req)
    assert res1.verified is True

    # Second attempt (replay): blocked
    res2 = verifier.verify_permit_token(req)
    assert res2.verified is False
    assert res2.allow_sandbox_execution is False
    assert res2.bypass_attempt_detected is True
    assert 30 in res2.risk_category_ids
    assert "Replay" in res2.reason


# ---------------------------------------------------------------------------
# Test 4: Expired Token Blocked (Risk #30 TTL Expiry)
# ---------------------------------------------------------------------------
def test_expired_token_blocked():
    verifier = AntiBypassTokenVerifier(secret_key="test-secret-key")
    token = verifier.issue_permit_token(
        session_id="session-expired",
        tool_name="write_file",
        tool_arguments={"filename": "output.txt"},
        intent_hmac_hash="c" * 64,
        ttl_seconds=-5,  # Issued already expired
    )

    req = SandboxToolVerifyRequest(
        session_id="session-expired",
        tool_name="write_file",
        tool_arguments={"filename": "output.txt"},
        permit_token=token,
    )
    res = verifier.verify_permit_token(req)

    assert res.verified is False
    assert res.allow_sandbox_execution is False
    assert res.bypass_attempt_detected is True
    assert 30 in res.risk_category_ids
    assert "Expired" in res.reason


# ---------------------------------------------------------------------------
# Test 5: Parameter and Tool Tampering Blocked (Risk #18 & #30)
# ---------------------------------------------------------------------------
def test_parameter_tampering_blocked():
    verifier = AntiBypassTokenVerifier(secret_key="test-secret-key")
    token = verifier.issue_permit_token(
        session_id="session-tamper",
        tool_name="schedule_payment",
        tool_arguments={"amount": 1000, "beneficiary": "Supplier A"},
        intent_hmac_hash="d" * 64,
    )

    # Tamper with amount from 1000 to 1000000
    req_tampered_args = SandboxToolVerifyRequest(
        session_id="session-tamper",
        tool_name="schedule_payment",
        tool_arguments={"amount": 1000000, "beneficiary": "Supplier A"},
        permit_token=token,
    )
    res_args = verifier.verify_permit_token(req_tampered_args)

    assert res_args.verified is False
    assert res_args.allow_sandbox_execution is False
    assert res_args.bypass_attempt_detected is True
    assert 18 in res_args.risk_category_ids
    assert 30 in res_args.risk_category_ids
    assert "Parameter Tampering" in res_args.reason

    # Tamper with tool name
    req_tampered_tool = SandboxToolVerifyRequest(
        session_id="session-tamper",
        tool_name="exec_shell",
        tool_arguments={"amount": 1000, "beneficiary": "Supplier A"},
        permit_token=token,
    )
    res_tool = verifier.verify_permit_token(req_tampered_tool)

    assert res_tool.verified is False
    assert res_tool.allow_sandbox_execution is False
    assert res_tool.bypass_attempt_detected is True
    assert 30 in res_tool.risk_category_ids


# ---------------------------------------------------------------------------
# Test 6: HTTP 500/503 Outage Triggers Fail-Closed Lockdown (Risk #33)
# ---------------------------------------------------------------------------
def test_circuit_breaker_fail_closed_lockdown():
    breaker = FailClosedCircuitBreaker()

    # Before outage: sensitive action not blocked by circuit breaker
    res_before = breaker.enforce_fail_closed_before_action("schedule_payment")
    assert res_before is None

    # Downstream policy engine suffers 503 outage
    breaker.record_service_status("policy_engine", 503, "Gateway service temporarily unavailable")

    # Sensitive payment action must immediately trip fail-closed lockdown
    res_after = breaker.enforce_fail_closed_before_action("schedule_payment")
    assert res_after is not None
    assert res_after.verified is False
    assert res_after.allow_sandbox_execution is False
    assert res_after.action_taken == "BLOCKED"
    assert res_after.fail_closed_triggered is True
    assert 33 in res_after.risk_category_ids
    assert "Fail-Closed Protection triggered" in res_after.reason

    # Non-sensitive read operation (e.g., read_file or ping) is not halted by circuit breaker
    res_read = breaker.enforce_fail_closed_before_action("read_document")
    assert res_read is None

    # Service recovers
    breaker.record_service_status("policy_engine", 200)
    res_recovered = breaker.enforce_fail_closed_before_action("schedule_payment")
    assert res_recovered is None


# ---------------------------------------------------------------------------
# Test 7: FastAPI Endpoints: /openclaw/verify-execution-token and /openclaw/circuit-status
# ---------------------------------------------------------------------------
def test_fastapi_endpoints_integration():
    client = TestClient(app)

    # 1. Issue token via verifier
    token = anti_bypass_verifier.issue_permit_token(
        session_id="session-fastapi",
        tool_name="change_vendor_bank",
        tool_arguments={"iban": "DE89370400440532013000"},
        intent_hmac_hash="e" * 64,
    )

    # 2. POST to /openclaw/verify-execution-token
    resp = client.post(
        "/openclaw/verify-execution-token",
        json={
            "session_id": "session-fastapi",
            "tool_name": "change_vendor_bank",
            "tool_arguments": {"iban": "DE89370400440532013000"},
            "raw_execution_token_hmac": token.signature_hmac,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verified"] is True
    assert data["allow_sandbox_execution"] is True
    assert data["action_taken"] == "SAFE_EXECUTED"

    # 3. GET /openclaw/circuit-status
    status_resp = client.get("/openclaw/circuit-status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["status"] == "active"
    assert "fabric_blockchain_api" in status_data["services"]

    # 4. POST /openclaw/circuit-status to trip a dependency into 500 error
    trip_resp = client.post(
        "/openclaw/circuit-status",
        json={
            "service_name": "fabric_blockchain_api",
            "status_code": 500,
            "error_msg": "Hyperledger peer connection timeout",
        },
    )
    assert trip_resp.status_code == 200

    # 5. Verify sensitive tool is now locked down under Risk #33
    lockdown_resp = client.post(
        "/openclaw/verify-execution-token",
        json={
            "session_id": "session-fastapi-2",
            "tool_name": "schedule_payment",
            "tool_arguments": {"amount": 2500},
            "raw_execution_token_hmac": "dummy",
        },
    )
    assert lockdown_resp.status_code == 200
    lockdown_data = lockdown_resp.json()
    assert lockdown_data["verified"] is False
    assert lockdown_data["allow_sandbox_execution"] is False
    assert lockdown_data["fail_closed_triggered"] is True
    assert 33 in lockdown_data["risk_category_ids"]

    # 6. Reset circuit breaker
    reset_resp = client.post(
        "/openclaw/circuit-status",
        json={"reset": True},
    )
    assert reset_resp.status_code == 200
    assert reset_resp.json()["status"] == "reset"
