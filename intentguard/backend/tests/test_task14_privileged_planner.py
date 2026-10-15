"""
Tests for Task 14: CaMeL Control Plane — Privileged Planner (P-LLM) & Provenance Wrapper
========================================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01 | Separating Data from Authority

Verifies:
1. Provenance Envelope wrapping: Converts schema fields into UNTRUSTED_EXT envelopes.
2. Authority origin assignment: Accurately tags USER_AUTHORITY and TRUSTED_PO_DB.
3. Input isolation: P-LLM only sees structured contract JSON and provenance envelopes, never raw text.
4. Tool call planning: Correctly parses LLM tool invocation proposals.
5. Confused Deputy defense: System prompt enforces validation of UNTRUSTED_EXT against trusted databases.
"""

import json
from unittest.mock import AsyncMock, MagicMock
import pytest

from app.layer2_camel.intent_contract import compile_step0_intent_contract
from app.layer2_camel.schemas import InvoiceExtractionSchema, InvoiceLineItem
from app.layer2_camel.provenance_wrapper import (
    ProvenanceEnvelope,
    wrap_extracted_schema,
    wrap_trusted_db,
    wrap_user_intent,
)
from app.layer2_camel.privileged_planner import (
    PLANNER_SYSTEM_PROMPT,
    PrivilegedPlannerLLM,
)


def test_01_provenance_envelope_creation_from_schema():
    """
    Test 1: Assert wrap_extracted_schema correctly converts a Pydantic model's fields
    into ProvenanceEnvelope instances with origin='UNTRUSTED_EXT'.
    """
    schema = InvoiceExtractionSchema(
        invoice_id="INV-402",
        po_id="PO-402",
        supplier_name="Bharat Precision Components Pvt Ltd",
        amount_inr=4000.0,
        iban_account="HDFC0001234_99887766",
        line_items=[
            InvoiceLineItem(
                description="500x High-Pressure Steel Valves",
                quantity=500.0,
                unit_price=8.0,
                total=4000.0,
            )
        ],
        passive_notes="Please remit ₹4,000 within 14 days.",
    )

    wrapped = wrap_extracted_schema(schema, source_file="INV-402.pdf")

    assert "invoice_id" in wrapped
    assert "amount_inr" in wrapped
    assert "line_items" in wrapped
    assert "passive_notes" in wrapped

    for key, env in wrapped.items():
        assert isinstance(env, ProvenanceEnvelope)
        assert env.origin == "UNTRUSTED_EXT"
        assert env.source_reference == "INV-402.pdf"

    assert wrapped["invoice_id"].value == "INV-402"
    assert wrapped["amount_inr"].value == 4000.0
    assert len(wrapped["line_items"].value) == 1
    assert wrapped["passive_notes"].value == "Please remit ₹4,000 within 14 days."


def test_02_provenance_envelope_authority_assignment():
    """
    Test 2: Assert wrap_user_intent and wrap_trusted_db properly assign
    'USER_AUTHORITY' and 'TRUSTED_PO_DB'.
    """
    user_envelope = wrap_user_intent("Process payment for verified PO #402 under ₹5,000")
    assert isinstance(user_envelope, ProvenanceEnvelope)
    assert user_envelope.origin == "USER_AUTHORITY"
    assert user_envelope.source_reference == "Step-0-Prompt"
    assert "PO #402" in user_envelope.value

    db_envelope = wrap_trusted_db(
        db_value={
            "approved_amount_inr": 4000.0,
            "approved_bank_iban": "HDFC0001234_99887766",
            "vendor_name": "Bharat Precision Components Pvt Ltd",
        },
        record_id="PO-402",
    )
    assert isinstance(db_envelope, ProvenanceEnvelope)
    assert db_envelope.origin == "TRUSTED_PO_DB"
    assert db_envelope.source_reference == "PO-402"
    assert db_envelope.value["approved_amount_inr"] == 4000.0


@pytest.mark.asyncio
async def test_03_planner_input_isolation():
    """
    Test 3: Verify that the prompt sent to the LLM backend contains the structured JSON
    intent_contract and tainted_data envelopes, but explicitly does NOT contain raw text.
    """
    intent_contract = compile_step0_intent_contract(
        session_id="sess-task14-03",
        user_prompt="Verify and pay Bharat Precision Components up to ₹4,000 for PO-402",
    )

    tainted_data = {
        "invoice_id": ProvenanceEnvelope(
            value="INV-402", origin="UNTRUSTED_EXT", source_reference="INV-402.pdf"
        ),
        "amount_inr": ProvenanceEnvelope(
            value=4000.0, origin="UNTRUSTED_EXT", source_reference="INV-402.pdf"
        ),
        "trusted_po_record": wrap_trusted_db(
            {"approved_amount_inr": 4000.0, "approved_bank_iban": "HDFC0001234_99887766"},
            record_id="PO-402",
        ),
    }

    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(
        return_value=MagicMock(
            choices=[
                MagicMock(
                    message=MagicMock(
                        content=json.dumps({
                            "tool_name": "schedule_payment",
                            "arguments": {
                                "amount_inr": 4000.0,
                                "bank_iban": "HDFC0001234_99887766",
                                "po_id": "PO-402",
                            },
                            "reasoning": "Data matches trusted PO database record.",
                            "authorized": True,
                        })
                    )
                )
            ]
        )
    )

    planner = PrivilegedPlannerLLM(client=mock_client)
    plan = await planner.plan_execution(intent_contract, tainted_data)

    mock_client.chat.completions.create.assert_called_once()
    call_args = mock_client.chat.completions.create.call_args.kwargs
    messages = call_args["messages"]

    sys_content = next(m["content"] for m in messages if m["role"] == "system")
    user_content = next(m["content"] for m in messages if m["role"] == "user")

    # System prompt enforces taint rules & zero raw text
    assert "UNTRUSTED_EXT" in sys_content
    assert "TRUSTED_PO_DB" in sys_content
    assert "NEVER exposed to raw untrusted text" in sys_content

    # User prompt contains structured envelopes and contract
    assert "User Intent Contract" in user_content
    assert "sess-task14-03" in user_content
    assert "Extracted Variables (with Provenance Taint Metadata)" in user_content
    assert "UNTRUSTED_EXT" in user_content
    assert "TRUSTED_PO_DB" in user_content

    # Plan correctly parsed
    assert plan["tool_name"] == "schedule_payment"
    assert plan["arguments"]["amount_inr"] == 4000.0
    assert plan["authorized"] is True


@pytest.mark.asyncio
async def test_04_tool_call_generation():
    """
    Test 4: Mock a successful JSON tool plan response and assert it returns correctly parsed.
    """
    intent_contract = compile_step0_intent_contract(
        session_id="sess-task14-04",
        user_prompt="Process invoice INV-509 under PO-509 up to ₹15,000",
    )

    tainted_data = {
        "invoice_id": wrap_user_intent("INV-509"),
        "po_id": wrap_trusted_db("PO-509", record_id="PO-509"),
    }

    mock_response = {
        "tool_name": "transfer_funds",
        "arguments": {
            "recipient_id": "supplier-02",
            "amount_inr": 12500.0,
            "currency": "INR",
        },
        "reasoning": "Verified PO-509 within approved limit.",
        "authorized": True,
    }

    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(
        return_value=MagicMock(
            choices=[MagicMock(message=MagicMock(content=json.dumps(mock_response)))]
        )
    )

    planner = PrivilegedPlannerLLM(client=mock_client)
    result = await planner.plan_execution(intent_contract, tainted_data)

    assert result["tool_name"] == "transfer_funds"
    assert result["arguments"]["amount_inr"] == 12500.0
    assert result["arguments"]["recipient_id"] == "supplier-02"
    assert result["authorized"] is True


@pytest.mark.asyncio
async def test_05_confused_deputy_prevention_rejection():
    """
    Test 5: Verifies that when untrusted external data claims an unauthorized bank swap,
    the model's rejection proposal is parsed cleanly with authorized=False.
    """
    intent_contract = compile_step0_intent_contract(
        session_id="sess-task14-05",
        user_prompt="Pay Bharat Precision ₹4,000",
    )

    # Malicious external input attempting unapproved account diversion
    tainted_data = {
        "demanded_iban": ProvenanceEnvelope(
            value="GB99HACK999", origin="UNTRUSTED_EXT", source_reference="invoice_poisoned.pdf"
        ),
        "approved_iban": ProvenanceEnvelope(
            value="HDFC0001234_99887766", origin="TRUSTED_PO_DB", source_reference="PO-402"
        ),
    }

    mock_rejection = {
        "tool_name": None,
        "arguments": {},
        "reasoning": "REJECTED: UNTRUSTED_EXT IBAN 'GB99HACK999' does not match TRUSTED_PO_DB IBAN 'HDFC0001234_99887766'.",
        "authorized": False,
    }

    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(
        return_value=MagicMock(
            choices=[MagicMock(message=MagicMock(content=json.dumps(mock_rejection)))]
        )
    )

    planner = PrivilegedPlannerLLM(client=mock_client)
    result = await planner.plan_execution(intent_contract, tainted_data)

    assert result["tool_name"] is None
    assert result["authorized"] is False
    assert "REJECTED" in result["reasoning"]
