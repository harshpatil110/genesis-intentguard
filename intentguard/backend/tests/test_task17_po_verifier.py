"""
Task 17 Verification Tests: Supply-Chain PO-vs-Invoice Bank & Amount Verifier
=============================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01 — IntentGuard

Tests:
1. test_purchase_orders_json_loaded_correctly: Verify trusted database loads with PO-402 records.
2. test_valid_po_402_invoice_payment_authorized: Valid invoice matching PO-402 passes SAFE_EXECUTED.
3. test_spoofed_bank_account_blocked_with_pdf_line_number: Spoofed IBAN flagged with exact line attribution.
4. test_excessive_invoice_amount_escalates_to_approval_card: Over-budget invoice flagged with AMOUNT_EXCEEDS_PO_LIMIT.
5. test_unverified_delivery_receipt_blocked: Unverified delivery receipt (PO-501 PENDING) blocks automatic payment.
6. test_po_alias_normalization: Normalizes 'PO #402', 'po-402', and '402' to match PO-402.
7. test_hook2_interceptor_po_verifier_integration: FastAPI Hook 2 blocks spoofed IBAN & permits authorized payment.
"""

from __future__ import annotations

import json
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
from app.layer3_policy.po_verifier import (
    POVerificationResult,
    PurchaseOrderVerifier,
    StepBackApprovalCardPayload,
    TrustedPORecord,
    purchase_order_verifier,
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


# ===========================================================================
# 1. Database Loading Verification
# ===========================================================================

def test_purchase_orders_json_loaded_correctly():
    """
    Verify ./intentguard/backend/data/purchase_orders.json exists and contains PO-402
    with buyer_id="buyer-01", supplier_id="supplier-01", approved_amount_inr=4000.0,
    approved_bank_account="HDFC0001234_99887766", and delivery_receipt="VERIFIED".
    """
    verifier = PurchaseOrderVerifier()
    assert "PO-402" in verifier._po_by_id
    po = verifier._po_by_id["PO-402"]

    assert po.buyer_id == "buyer-01"
    assert po.supplier_id == "supplier-01"
    assert po.approved_amount_inr == 4000.0
    assert po.currency == "INR"
    assert po.approved_bank_account == "HDFC0001234_99887766"
    assert po.delivery_receipt == "VERIFIED"
    assert "INV-402" in po.allowed_invoices
    assert po.origin == "TRUSTED_PO_DB"


# ===========================================================================
# 2. Valid PO-402 Payment Authorization
# ===========================================================================

def test_valid_po_402_invoice_payment_authorized():
    """
    Verify an extracted invoice for PO-402 with amount_inr=4000,
    iban_account="HDFC0001234_99887766", supplier_id="supplier-01" returns
    verified=True, execution_permitted=True, action_taken="SAFE_EXECUTED",
    and requires_human_approval_card=False.
    """
    invoice_payload = {
        "po_id": "PO-402",
        "invoice_id": "INV-402",
        "supplier_id": "supplier-01",
        "amount_inr": 4000.0,
        "iban_account": "HDFC0001234_99887766",
    }
    result = purchase_order_verifier.verify_invoice_against_po(invoice_payload)

    assert result.verified is True
    assert result.execution_permitted is True
    assert result.action_taken == "SAFE_EXECUTED"
    assert result.requires_human_approval_card is False
    assert result.approval_card is None
    assert len(result.discrepancies) == 0
    assert result.matched_po is not None
    assert result.matched_po.po_id == "PO-402"


# ===========================================================================
# 3. Spoofed Bank Account Blocked with PDF Line Attribution
# ===========================================================================

def test_spoofed_bank_account_blocked_with_pdf_line_number():
    """
    Pass an invoice for PO-402 with amount_inr=4000, spoofed iban_account="HACK0009999_00001111",
    and provenance showing source_file="poisoned_invoice_INV402.pdf", page_number=1, line_number=18.
    Assert verified is False, execution_permitted is False, requires_human_approval_card is True,
    approval_card.source_line_number == 18, approval_card.expected_bank_account == "HDFC0001234_99887766",
    approval_card.proposed_bank_account == "HACK0009999_00001111", and Risk IDs [10, 16, 18] are flagged.
    """
    invoice_payload = {
        "po_id": "PO-402",
        "invoice_id": "INV-402",
        "supplier_id": "supplier-01",
        "amount_inr": 4000.0,
        "iban_account": "HACK0009999_00001111",
    }
    provenance_map = {
        "iban_account": {
            "source_file": "poisoned_invoice_INV402.pdf",
            "page_number": 1,
            "line_number": 18,
        }
    }
    result = purchase_order_verifier.verify_invoice_against_po(
        invoice_data=invoice_payload,
        provenance_map=provenance_map,
    )

    assert result.verified is False
    assert result.execution_permitted is False
    assert result.requires_human_approval_card is True
    assert result.action_taken == "HUMAN_APPROVAL_REQUIRED"
    assert 10 in result.risk_category_ids
    assert 16 in result.risk_category_ids
    assert 18 in result.risk_category_ids

    card = result.approval_card
    assert card is not None
    assert card.escalation_type == "BANK_ACCOUNT_MISMATCH"
    assert card.source_line_number == 18
    assert card.source_page_number == 1
    assert card.source_file == "poisoned_invoice_INV402.pdf"
    assert card.expected_bank_account == "HDFC0001234_99887766"
    assert card.proposed_bank_account == "HACK0009999_00001111"
    assert "CRITICAL" in card.human_prompt_summary


# ===========================================================================
# 4. Excessive Amount Escalates to Human Approval Card
# ===========================================================================

def test_excessive_invoice_amount_escalates_to_approval_card():
    """
    Pass PO-402 with amount_inr=9500.0 and iban_account="HDFC0001234_99887766",
    source_line_number=22. Assert verified is False, requires_human_approval_card is True,
    approval_card.escalation_type == "AMOUNT_EXCEEDS_PO_LIMIT", and approval_card.source_line_number == 22.
    """
    invoice_payload = {
        "po_id": "PO-402",
        "invoice_id": "INV-402",
        "supplier_id": "supplier-01",
        "amount_inr": 9500.0,
        "iban_account": "HDFC0001234_99887766",
        "source_line_number": 22,
        "source_page_number": 2,
        "source_file": "over_invoiced_doc.pdf",
    }
    result = purchase_order_verifier.verify_invoice_against_po(invoice_payload)

    assert result.verified is False
    assert result.execution_permitted is False
    assert result.requires_human_approval_card is True
    assert result.action_taken == "HUMAN_APPROVAL_REQUIRED"

    card = result.approval_card
    assert card is not None
    assert card.escalation_type == "AMOUNT_EXCEEDS_PO_LIMIT"
    assert card.source_line_number == 22
    assert card.source_page_number == 2
    assert card.source_file == "over_invoiced_doc.pdf"
    assert card.expected_amount_inr == 4000.0
    assert card.proposed_amount_inr == 9500.0


# ===========================================================================
# 5. Unverified Delivery Receipt Blocked (PO-501 PENDING)
# ===========================================================================

def test_unverified_delivery_receipt_blocked():
    """
    Test against PO-501 (where delivery_receipt == "PENDING") and assert
    automatic payment is blocked and escalated to the Step-Back Human Approval Card.
    """
    invoice_payload = {
        "po_id": "PO-501",
        "invoice_id": "INV-501",
        "supplier_id": "supplier-02",
        "amount_inr": 15000.0,
        "iban_account": "ICIC0005678_11223344",
    }
    result = purchase_order_verifier.verify_invoice_against_po(invoice_payload)

    assert result.verified is False
    assert result.execution_permitted is False
    assert result.requires_human_approval_card is True
    assert result.action_taken == "HUMAN_APPROVAL_REQUIRED"

    card = result.approval_card
    assert card is not None
    assert card.escalation_type == "UNVERIFIED_DELIVERY_RECEIPT"
    assert card.po_id == "PO-501"
    assert 10 in result.risk_category_ids
    assert 18 in result.risk_category_ids


# ===========================================================================
# 6. PO Alias Normalization
# ===========================================================================

def test_po_alias_normalization():
    """
    Verify that 'PO #402', 'po-402', and '402' all resolve correctly to PO-402.
    """
    verifier = purchase_order_verifier
    for alias in ["PO-402", "PO #402", "po-402", "PO#402", "402"]:
        res = verifier.verify_invoice_against_po({
            "po_id": alias,
            "amount_inr": 4000.0,
            "iban_account": "HDFC0001234_99887766",
        })
        assert res.verified is True, f"Failed on alias: {alias}"
        assert res.execution_permitted is True
        assert res.po_id == "PO-402"


# ===========================================================================
# 7. Hook 2 Interceptor Integration with PO Verifier
# ===========================================================================

def test_hook2_interceptor_po_verifier_integration(client: TestClient):
    """
    Lock a Step-0 contract for PO #402 up to INR 4,000, then invoke
    POST /internal/intercept/tool for schedule_payment once with a spoofed iban_account
    (assert blocked with HUMAN_APPROVAL_REQUIRED) and once with HDFC0001234_99887766
    and 4000.0 (assert SAFE_EXECUTED).
    """
    session_id = "sess-task17-hook2-po-test"

    # 1. Lock Step-0 contract allowing schedule_payment up to 4000 INR
    contract = compile_step0_intent_contract(
        session_id=session_id,
        user_prompt="Pay invoice for PO #402 up to ₹4,000",
        explicit_allowed_tools=["schedule_payment"],
        explicit_max_amount_inr=4000.0,
    )
    reg_res = client.post("/internal/intercept/register-intent", json=contract.model_dump())
    assert reg_res.status_code == 200

    # 2. Invoke Hook 2 with a spoofed bank account
    spoofed_tool_payload = {
        "session_id": session_id,
        "tool_name": "schedule_payment",
        "tool_arguments": {
            "po_number": "PO-402",
            "amount_inr": 4000.0,
            "iban_account": "HACK_ATTACKER_IBAN_999",
            "source_line_number": 19,
            "source_file": "trojan_invoice.pdf",
        },
        "intent_hmac_hash": contract.intent_hmac_hash,
    }
    spoof_resp = client.post("/internal/intercept/tool", json=spoofed_tool_payload)
    assert spoof_resp.status_code == 200
    spoof_data = spoof_resp.json()

    assert spoof_data["execution_permitted"] is False
    assert spoof_data["requires_human_approval_card"] is True
    assert spoof_data["action_taken"] == "HUMAN_APPROVAL_REQUIRED"
    assert spoof_data["approval_card_id"] is not None
    assert "HACK_ATTACKER_IBAN_999" in spoof_data["reason"]
    assert 10 in spoof_data["risk_category_ids"] or 18 in spoof_data["risk_category_ids"]

    # 3. Invoke Hook 2 with legitimate approved bank account & matching amount
    legit_tool_payload = {
        "session_id": session_id,
        "tool_name": "schedule_payment",
        "tool_arguments": {
            "po_number": "PO-402",
            "amount_inr": 4000.0,
            "iban_account": "HDFC0001234_99887766",
        },
        "intent_hmac_hash": contract.intent_hmac_hash,
    }
    legit_resp = client.post("/internal/intercept/tool", json=legit_tool_payload)
    assert legit_resp.status_code == 200
    legit_data = legit_resp.json()

    assert legit_data["execution_permitted"] is True
    assert legit_data["requires_human_approval_card"] is False
    assert legit_data["action_taken"] == "SAFE_EXECUTED"
    assert legit_data["threat_detected"] is False
    assert legit_data["execution_token_hmac"] is not None
    assert len(legit_data["execution_token_hmac"]) == 64
