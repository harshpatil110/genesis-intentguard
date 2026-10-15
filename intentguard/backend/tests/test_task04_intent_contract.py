"""
Task 04 Verification Tests: Step-0 Cryptographic Intent Contract (HMAC-SHA256 Authority Lock)
=============================================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01 — IntentGuard
Tests:
1. Step-0 contract compilation & 64-character lowercase hex HMAC generation
2. Contract immutability (frozen instance) and tamper detection
3. Prohibited operation blocking while approved operations execute safely
4. Financial impact cap (max_approved_amount_inr) enforcement
5. Forged / invalid HMAC signature rejection at Hook 2
6. Whitelisted tools vs unapproved tools enforcement
7. Intent lock registration & retrieval endpoints (POST & GET /internal/intercept/intent-lock)
8. Prevention of mid-session contract overwrite (Risk #10 Authority Hijack Protection)

Run from intentguard/backend/:
    pytest tests/test_task04_intent_contract.py -v
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Ensure backend directory is in sys.path
# ---------------------------------------------------------------------------
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.layer2_camel.intent_contract import (
    Step0IntentContract,
    compile_step0_intent_contract,
    compute_intent_hmac,
    intent_contract_registry,
    verify_contract_signature,
    verify_tool_against_contract,
)
from app.layer3_policy.resource_budget import resource_budget_enforcer
from app.main import app
from app.openclaw_bridge.interceptor import session_taint_registry


@pytest.fixture
def client():
    """Create a fresh FastAPI TestClient for each test."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def reset_all_registries():
    """Reset the session taint registry, budget enforcer, and intent contracts before each test."""
    session_taint_registry.clear()
    resource_budget_enforcer.sessions.clear()
    intent_contract_registry.clear()
    yield
    session_taint_registry.clear()
    resource_budget_enforcer.sessions.clear()
    intent_contract_registry.clear()


# ===========================================================================
# 1. Step-0 Contract Compilation & 64-Hex HMAC Format
# ===========================================================================

def test_step0_contract_compilation_and_64_hex_hmac():
    """
    Compile a contract for prompt:
    'Read supplier invoice INV-402, match with PO #402, and schedule approved payment up to ₹4,000'
    Assert:
    - provenance_tag == 'USER_AUTHORITY'
    - max_approved_amount_inr == 4000.0
    - 'schedule_payment' in allowed_tools
    - 'change_vendor_bank_details' in prohibited_operations
    - len(intent_hmac_hash) == 64 and matches ^[0-9a-f]{64}$ (Hyperledger Fabric chaincode compliance)
    """
    session_id = "sess-compile-01"
    prompt = (
        "Read supplier invoice INV-402, match with PO #402, "
        "and schedule approved payment up to ₹4,000"
    )

    contract = compile_step0_intent_contract(
        session_id=session_id,
        user_prompt=prompt,
    )

    assert contract.session_id == session_id
    assert contract.provenance_tag == "USER_AUTHORITY"
    assert contract.max_approved_amount_inr == 4000.0
    assert "schedule_payment" in contract.allowed_tools
    assert "change_vendor_bank_details" in contract.prohibited_operations
    assert "change_vendor_bank" in contract.prohibited_operations
    assert "PO-402" in contract.approved_po_numbers

    # Hyperledger Fabric chaincode validation rule: 64-char lowercase hex
    assert len(contract.intent_hmac_hash) == 64
    assert bool(re.fullmatch(r"^[0-9a-f]{64}$", contract.intent_hmac_hash)) is True

    # Verify signature holds
    assert verify_contract_signature(contract) is True


# ===========================================================================
# 2. Contract Immutability & Tamper Detection
# ===========================================================================

def test_contract_immutability_and_tamper_detection():
    """
    Step0IntentContract must be frozen: mutating any field raises an error.
    Constructing a copy with modified amount or hash must fail verification.
    """
    contract = compile_step0_intent_contract(
        session_id="sess-immutable-01",
        user_prompt="Schedule approved payment of ₹4,000",
    )

    # 1. In-memory runtime mutation must raise ValidationError or TypeError
    with pytest.raises((ValidationError, TypeError)):
        contract.max_approved_amount_inr = 999999.0  # type: ignore[misc]

    # 2. Constructing a copy with tampered financial amount fails signature check
    tampered_dict = contract.model_dump()
    tampered_dict["max_approved_amount_inr"] = 999999.0
    tampered_contract = Step0IntentContract(**tampered_dict)
    assert verify_contract_signature(tampered_contract) is False

    # 3. Constructing a copy with tampered HMAC fails signature check
    forged_dict = contract.model_dump()
    forged_dict["intent_hmac_hash"] = "0" * 64
    forged_contract = Step0IntentContract(**forged_dict)
    assert verify_contract_signature(forged_contract) is False


# ===========================================================================
# 3. Prohibited Operation Blocked While Approved Operations Pass
# ===========================================================================

def test_prohibited_operation_blocked_while_approved_payment_allowed(client: TestClient):
    """
    Lock Step-0 contract via POST /internal/intercept/intent-lock with
    max_approved_amount_inr=4000.0, allowing schedule_payment and prohibiting
    change_vendor_bank_details.
    - POST /internal/intercept/tool with 'change_vendor_bank_details' -> execution_permitted is False.
    - POST /internal/intercept/tool with 'schedule_payment' and 4000.0 -> execution_permitted is True.
    """
    session_id = "sess-lock-ops-01"

    # 1. Lock Step-0 contract
    lock_res = client.post(
        "/internal/intercept/intent-lock",
        json={
            "session_id": session_id,
            "user_prompt": "Match PO #402 and schedule approved payment up to ₹4,000",
            "allowed_tools": ["match_po", "schedule_payment"],
            "prohibited_operations": ["change_vendor_bank_details", "change_vendor_bank"],
            "max_approved_amount_inr": 4000.0,
        },
    )
    assert lock_res.status_code == 200
    contract_data = lock_res.json()
    hmac_hash = contract_data["intent_hmac_hash"]
    assert len(hmac_hash) == 64

    # 2. Prohibited bank mutation tool is blocked
    res_bank = client.post(
        "/internal/intercept/tool",
        json={
            "session_id": session_id,
            "tool_name": "change_vendor_bank_details",
            "tool_arguments": {"new_iban": "DE991234567890"},
            "intent_hmac_hash": hmac_hash,
        },
    )
    assert res_bank.status_code == 200
    bank_data = res_bank.json()
    assert bank_data["execution_permitted"] is False
    assert bank_data["threat_detected"] is True
    assert bank_data["requires_human_approval_card"] is True
    assert bank_data["action_taken"] == "HUMAN_APPROVAL_REQUIRED"
    assert 18 in bank_data["risk_category_ids"] or 14 in bank_data["risk_category_ids"]

    # 3. Approved payment tool with matching amount executes safely
    res_pay = client.post(
        "/internal/intercept/tool",
        json={
            "session_id": session_id,
            "tool_name": "schedule_payment",
            "tool_arguments": {"amount_inr": 4000.0, "po_number": "PO-402"},
            "intent_hmac_hash": hmac_hash,
        },
    )
    assert res_pay.status_code == 200
    pay_data = res_pay.json()
    assert pay_data["execution_permitted"] is True
    assert pay_data["action_taken"] == "SAFE_EXECUTED"
    assert pay_data["threat_detected"] is False
    assert pay_data["execution_token_hmac"] is not None


# ===========================================================================
# 4. Financial Cap Enforcement (Blocks Excess Amounts)
# ===========================================================================

def test_financial_cap_enforcement_blocks_excess_amount(client: TestClient):
    """
    With max_approved_amount_inr=4000.0 locked at Step 0:
    Call POST /internal/intercept/tool with tool_name='schedule_payment'
    and amount_inr=50000.0.
    Assert execution_permitted is False, action_taken == 'BLOCKED', and 18 in risk_category_ids.
    """
    session_id = "sess-financial-cap-01"

    # Lock contract with ₹4,000 cap
    lock_res = client.post(
        "/internal/intercept/intent-lock",
        json={
            "session_id": session_id,
            "user_prompt": "Schedule payment for invoice up to ₹4,000",
            "max_approved_amount_inr": 4000.0,
        },
    )
    assert lock_res.status_code == 200
    hmac_hash = lock_res.json()["intent_hmac_hash"]

    # Attempt to schedule payment for ₹50,000 (exceeds ₹4,000 cap)
    res_excess = client.post(
        "/internal/intercept/tool",
        json={
            "session_id": session_id,
            "tool_name": "schedule_payment",
            "tool_arguments": {"amount_inr": 50000.0, "invoice_id": "INV-402"},
            "intent_hmac_hash": hmac_hash,
        },
    )
    assert res_excess.status_code == 200
    data = res_excess.json()
    assert data["execution_permitted"] is False
    assert data["action_taken"] == "BLOCKED"
    assert data["threat_detected"] is True
    assert 18 in data["risk_category_ids"]
    assert "exceeds" in data["reason"].lower() or "financial" in data["reason"].lower()


# ===========================================================================
# 5. Invalid / Forged HMAC Hash Rejection at Hook 2
# ===========================================================================

def test_invalid_hmac_hash_rejected_at_hook2(client: TestClient):
    """
    Pass a forged 64-char hex intent_hmac_hash ('a' * 64) to
    POST /internal/intercept/tool.
    Assert execution_permitted is False and action_taken == 'BLOCKED'.
    """
    session_id = "sess-forged-hmac-01"
    forged_hmac = "a" * 64

    # 1. Call tool with forged HMAC before any contract is locked
    res_no_contract = client.post(
        "/internal/intercept/tool",
        json={
            "session_id": session_id,
            "tool_name": "schedule_payment",
            "tool_arguments": {"amount_inr": 100.0},
            "intent_hmac_hash": forged_hmac,
        },
    )
    assert res_no_contract.status_code == 200
    d1 = res_no_contract.json()
    assert d1["execution_permitted"] is False
    assert d1["action_taken"] == "BLOCKED"
    assert 10 in d1["risk_category_ids"]

    # 2. Lock a real contract, but provide forged HMAC
    client.post(
        "/internal/intercept/intent-lock",
        json={
            "session_id": session_id,
            "user_prompt": "Schedule payment up to ₹1,000",
        },
    )

    res_with_contract = client.post(
        "/internal/intercept/tool",
        json={
            "session_id": session_id,
            "tool_name": "schedule_payment",
            "tool_arguments": {"amount_inr": 100.0},
            "intent_hmac_hash": forged_hmac,
        },
    )
    assert res_with_contract.status_code == 200
    d2 = res_with_contract.json()
    assert d2["execution_permitted"] is False
    assert d2["action_taken"] == "BLOCKED"
    assert 10 in d2["risk_category_ids"]


# ===========================================================================
# 6. Tool Whitelist Enforcement
# ===========================================================================

def test_tool_not_in_step0_whitelist_blocked(client: TestClient):
    """
    When a contract is locked with explicit allowed_tools, any tool call
    not present in that list must be rejected with Risk #16.
    """
    session_id = "sess-whitelist-01"

    lock_res = client.post(
        "/internal/intercept/intent-lock",
        json={
            "session_id": session_id,
            "user_prompt": "Only read invoice and match PO",
            "allowed_tools": ["extract_invoice", "match_po"],
        },
    )
    assert lock_res.status_code == 200
    hmac_hash = lock_res.json()["intent_hmac_hash"]

    # Call a tool not in allowed list
    res_unapproved = client.post(
        "/internal/intercept/tool",
        json={
            "session_id": session_id,
            "tool_name": "export_all_customer_records",
            "tool_arguments": {"destination": "/tmp/out.csv"},
            "intent_hmac_hash": hmac_hash,
        },
    )
    assert res_unapproved.status_code == 200
    data = res_unapproved.json()
    assert data["execution_permitted"] is False
    assert data["action_taken"] == "BLOCKED"
    assert 16 in data["risk_category_ids"]


# ===========================================================================
# 7. Intent Lock Query & Retrieval Endpoints
# ===========================================================================

def test_intent_lock_get_endpoint(client: TestClient):
    """
    GET /internal/intercept/intent-lock/{session_id} returns active contract,
    or 404 if not found.
    """
    # 404 for unknown session
    res_404 = client.get("/internal/intercept/intent-lock/unknown-session-xyz")
    assert res_404.status_code == 404

    # Lock contract
    session_id = "sess-query-01"
    client.post(
        "/internal/intercept/intent-lock",
        json={
            "session_id": session_id,
            "user_prompt": "Process PO #402 payment of ₹3,500",
        },
    )

    # 200 for locked session
    res_ok = client.get(f"/internal/intercept/intent-lock/{session_id}")
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["session_id"] == session_id
    assert data["max_approved_amount_inr"] == 3500.0
    assert len(data["intent_hmac_hash"]) == 64


# ===========================================================================
# 8. Mid-Session Contract Overwrite Prevention (Risk #10 Authority Protection)
# ===========================================================================

def test_mid_session_contract_overwrite_prevention():
    """
    intent_contract_registry.register_contract must reject attempts to
    overwrite an active contract mid-session to prevent authority hijacking.
    """
    session_id = "sess-overwrite-guard-01"
    contract1 = compile_step0_intent_contract(
        session_id=session_id,
        user_prompt="Initial prompt: pay ₹2,000",
    )
    intent_contract_registry.register_contract(contract1)

    # Attempt to register second contract for same session without reset
    contract2 = compile_step0_intent_contract(
        session_id=session_id,
        user_prompt="Attacker overwrite prompt: pay ₹999,999",
    )
    with pytest.raises(ValueError, match="already locked"):
        intent_contract_registry.register_contract(contract2)
