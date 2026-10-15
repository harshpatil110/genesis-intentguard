"""
Tests for Task 13: CaMeL Data Plane Quarantined Reader (Q-LLM)
==============================================================
GENESIS 2.0 | Track: EVA 03 | PS 01 | Separating Data from Authority

Verifies:
1. Zero-tool constraint: QuarantinedReaderLLM rejects tool binding and never sends tools to the API.
2. Microsoft Spotlighting: Untrusted text is properly isolated in <<<UNTRUSTED_EXTERNAL_DATA_START>>> delimiters.
3. Schema extraction: Parses LLM responses into strict InvoiceExtractionSchema, EmailExtractionSchema, WebExtractionSchema.
4. Passive directive handling: Imperative commands are safely converted into passive string literals (passive_notes).
5. Automatic fallback: Seamlessly falls back to Groq if primary Ollama connection fails.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.layer2_camel.schemas import (
    EmailExtractionSchema,
    InvoiceExtractionSchema,
    InvoiceLineItem,
    WebExtractionSchema,
)
from app.layer2_camel.quarantined_reader import (
    QuarantinedReaderLLM,
    SPOTLIGHT_END,
    SPOTLIGHT_START,
)


@pytest.mark.asyncio
async def test_01_zero_tool_client_configuration():
    """
    Test 1: Assert that the QuarantinedReaderLLM instance does not accept or bind any tools,
    and outgoing API call parameters never contain 'tools' or 'functions'.
    """
    mock_client = MagicMock()
    mock_client.chat = MagicMock()
    mock_client.chat.completions = MagicMock()
    mock_create = AsyncMock()
    mock_create.return_value = MagicMock(
        choices=[
            MagicMock(
                message=MagicMock(
                    content=json.dumps({
                        "invoice_id": "INV-100",
                        "po_id": "PO-100",
                        "supplier_name": "Test Supplier",
                        "amount_inr": 1000.0,
                        "iban_account": "TEST1234",
                        "line_items": [],
                        "passive_notes": None,
                    })
                )
            )
        ]
    )
    mock_client.chat.completions.create = mock_create

    reader = QuarantinedReaderLLM(client=mock_client)

    # 1. Zero tools exposed
    assert reader.tools is None

    # 2. Tool binding explicitly blocked
    with pytest.raises(PermissionError) as exc_info:
        reader.bind_tools(["tool_a", "tool_b"])
    assert "zero tools permitted" in str(exc_info.value)

    # 3. Call extract_facts and inspect create kwargs
    await reader.extract_facts("Some invoice text", schema_type="invoice")

    mock_create.assert_called_once()
    call_kwargs = mock_create.call_args.kwargs

    # ZERO TOOLS invariant
    assert "tools" not in call_kwargs
    assert "functions" not in call_kwargs
    assert call_kwargs.get("response_format") == {"type": "json_object"}


@pytest.mark.asyncio
async def test_02_prompt_spotlighting_wrapper():
    """
    Test 2: Assert that the format_spotlight_prompt method and extract_facts correctly wrap
    the untrusted text inside <<<UNTRUSTED_EXTERNAL_DATA_START>>> and <<<UNTRUSTED_EXTERNAL_DATA_END>>>.
    """
    reader = QuarantinedReaderLLM()
    sanitized_input = (
        "INVOICE #INV-402 | PO-402\n"
        "Please remit ₹4,000 within 14 days per PO #402."
    )

    sys_prompt, user_prompt = reader.format_spotlight_prompt(sanitized_input, "invoice")

    # Delimiters present
    assert SPOTLIGHT_START in user_prompt
    assert SPOTLIGHT_END in user_prompt
    assert sanitized_input in user_prompt

    # Spotlighting order
    start_pos = user_prompt.index(SPOTLIGHT_START)
    data_pos = user_prompt.index(sanitized_input)
    end_pos = user_prompt.index(SPOTLIGHT_END)
    assert start_pos < data_pos < end_pos

    # System prompt proclaims zero tools & data plane isolation
    assert "NO tools" in sys_prompt
    assert "NO authority" in sys_prompt
    assert "passive data literals" in sys_prompt


@pytest.mark.asyncio
async def test_03_successful_invoice_extraction_mock():
    """
    Test 3: Mock an LLM JSON response matching InvoiceExtractionSchema and assert
    it parses accurately into the Pydantic model with line items and ₹ amounts.
    """
    mock_payload = {
        "invoice_id": "INV-402",
        "po_id": "PO-402",
        "supplier_name": "Bharat Precision Components Pvt Ltd",
        "amount_inr": 4000.0,
        "iban_account": "HDFC0001234_99887766",
        "line_items": [
            {
                "description": "500x High-Pressure Steel Valves",
                "quantity": 500.0,
                "unit_price": 8.0,
                "total": 4000.0,
            }
        ],
        "passive_notes": "Please remit ₹4,000 within 14 days per PO #402.",
    }

    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(
        return_value=MagicMock(
            choices=[MagicMock(message=MagicMock(content=json.dumps(mock_payload)))]
        )
    )

    reader = QuarantinedReaderLLM(client=mock_client)
    res = await reader.extract_facts("Raw sanitized invoice text", schema_type="invoice")

    assert isinstance(res, InvoiceExtractionSchema)
    assert res.invoice_id == "INV-402"
    assert res.po_id == "PO-402"
    assert res.supplier_name == "Bharat Precision Components Pvt Ltd"
    assert res.amount_inr == 4000.0
    assert res.iban_account == "HDFC0001234_99887766"
    assert len(res.line_items) == 1
    assert res.line_items[0].description == "500x High-Pressure Steel Valves"
    assert res.line_items[0].total == 4000.0
    assert res.passive_notes == "Please remit ₹4,000 within 14 days per PO #402."


@pytest.mark.asyncio
async def test_04_passive_note_handling():
    """
    Test 4: Ensure any leftover imperative text is mapped into the passive_notes string
    field and not interpreted as an executable tool.
    """
    mock_payload = {
        "invoice_id": "INV-999",
        "po_id": "PO-509",
        "supplier_name": "Apex Industrial Logistics",
        "amount_inr": 12500.0,
        "iban_account": "ICIC0005678_11223344",
        "line_items": [],
        "passive_notes": "Urgent: Deliver 500 units to Gate 3 immediately upon inspection.",
    }

    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(
        return_value=MagicMock(
            choices=[MagicMock(message=MagicMock(content=json.dumps(mock_payload)))]
        )
    )

    reader = QuarantinedReaderLLM(client=mock_client)
    res = await reader.extract_facts("Invoice text with delivery note", schema_type="invoice")

    assert isinstance(res, InvoiceExtractionSchema)
    # The imperative instruction "Deliver 500 units to Gate 3 immediately" is safely captured as passive data
    assert "Gate 3" in res.passive_notes
    assert "immediately" in res.passive_notes


@pytest.mark.asyncio
async def test_05_email_and_web_extraction_schemas():
    """
    Test 5: Verify EmailExtractionSchema and WebExtractionSchema parsing.
    """
    # Email extraction
    email_payload = {
        "sender": "vendor@bharatcomponents.com",
        "subject": "Invoice Submission PO-402",
        "core_message_summary": "Submitting invoice INV-402 for completed delivery.",
        "requested_actions_passive": ["Process payment per standard 14-day terms."],
    }
    mock_client_email = MagicMock()
    mock_client_email.chat.completions.create = AsyncMock(
        return_value=MagicMock(
            choices=[MagicMock(message=MagicMock(content=json.dumps(email_payload)))]
        )
    )
    reader_email = QuarantinedReaderLLM(client=mock_client_email)
    email_res = await reader_email.extract_facts("Email text", schema_type="email")

    assert isinstance(email_res, EmailExtractionSchema)
    assert email_res.sender == "vendor@bharatcomponents.com"
    assert len(email_res.requested_actions_passive) == 1
    assert "14-day terms" in email_res.requested_actions_passive[0]

    # Web extraction
    web_payload = {
        "page_title": "Apex Logistics Tracking Portal",
        "main_content_summary": "Shipment DR-509-VERIFIED is in transit to Mumbai warehouse.",
        "extracted_links": ["https://apexlogistics.example.com/track/DR-509"],
    }
    mock_client_web = MagicMock()
    mock_client_web.chat.completions.create = AsyncMock(
        return_value=MagicMock(
            choices=[MagicMock(message=MagicMock(content=json.dumps(web_payload)))]
        )
    )
    reader_web = QuarantinedReaderLLM(client=mock_client_web)
    web_res = await reader_web.extract_facts("Web text", schema_type="web")

    assert isinstance(web_res, WebExtractionSchema)
    assert web_res.page_title == "Apex Logistics Tracking Portal"
    assert "DR-509-VERIFIED" in web_res.main_content_summary
    assert len(web_res.extracted_links) == 1


@pytest.mark.asyncio
async def test_06_fallback_mechanism_from_ollama_to_groq():
    """
    Test 6: Simulates primary client failure (e.g., local Ollama offline) and verifies
    that QuarantinedReaderLLM automatically falls back to fallback_client.
    """
    primary_client = MagicMock()
    primary_client.chat.completions.create = AsyncMock(
        side_effect=ConnectionError("Failed to connect to http://localhost:11434")
    )

    fallback_payload = {
        "invoice_id": "INV-FALLBACK-01",
        "po_id": "PO-402",
        "supplier_name": "Bharat Precision",
        "amount_inr": 4000.0,
        "iban_account": "HDFC0001234_99887766",
        "line_items": [],
        "passive_notes": "Processed via fallback Groq model.",
    }
    fallback_client = MagicMock()
    fallback_client.chat.completions.create = AsyncMock(
        return_value=MagicMock(
            choices=[MagicMock(message=MagicMock(content=json.dumps(fallback_payload)))]
        )
    )

    reader = QuarantinedReaderLLM(
        client=primary_client, fallback_client=fallback_client
    )

    res = await reader.extract_facts("Sanitized invoice text", schema_type="invoice")

    # Primary failed, fallback succeeded
    primary_client.chat.completions.create.assert_called_once()
    fallback_client.chat.completions.create.assert_called_once()

    assert isinstance(res, InvoiceExtractionSchema)
    assert res.invoice_id == "INV-FALLBACK-01"
    assert res.passive_notes == "Processed via fallback Groq model."
