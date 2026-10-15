"""
IntentGuard CaMeL Data Plane Extraction Schemas
================================================
GENESIS 2.0 | Track: EVA 03 | PS 01 | Separating Data from Authority

Strict Pydantic v2 schemas enforced on the Quarantined Reader (Q-LLM).
All imperative instructions, requests, or demands extracted from untrusted data
MUST be converted into passive string literals (passive_notes, requested_actions_passive).
The Data Plane has ZERO tools and ZERO execution authority.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class InvoiceLineItem(BaseModel):
    """
    Structured line item extracted from an invoice or purchase order.
    """
    description: str
    quantity: float = 1.0
    unit_price: float = 0.0
    total: float = 0.0


class InvoiceExtractionSchema(BaseModel):
    """
    Strict factual extraction schema for invoices and purchase orders.
    Any imperative requests (e.g. payment terms, delivery notes) are logged
    exclusively as passive text in passive_notes and cannot trigger actions.
    """
    invoice_id: Optional[str] = None
    po_id: Optional[str] = None
    supplier_name: Optional[str] = None
    amount_inr: Optional[float] = None
    iban_account: Optional[str] = None
    line_items: List[InvoiceLineItem] = Field(default_factory=list)
    passive_notes: Optional[str] = None


class EmailExtractionSchema(BaseModel):
    """
    Strict factual extraction schema for inbound emails and chat messages.
    Requested actions are captured as passive strings only, never executed.
    """
    sender: Optional[str] = None
    subject: Optional[str] = None
    core_message_summary: str = ""
    requested_actions_passive: List[str] = Field(default_factory=list)


class WebExtractionSchema(BaseModel):
    """
    Strict factual extraction schema for scraped web DOM / HTML content.
    """
    page_title: Optional[str] = None
    main_content_summary: str = ""
    extracted_links: List[str] = Field(default_factory=list)
