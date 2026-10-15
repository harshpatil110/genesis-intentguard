"""
IntentGuard Runtime Provenance Taint Wrapper
=============================================
GENESIS 2.0 | Track: EVA 03 | PS 01 | Separating Data from Authority

Defines ProvenanceEnvelope and tagging utilities that securely encapsulate
all runtime variables with immutable origin metadata:
- UNTRUSTED_EXT: Extracted from untrusted documents, emails, or web pages (Q-LLM).
- USER_AUTHORITY: Directly specified by the authenticated human user in Step-0.
- TRUSTED_PO_DB: Retrieved from verified internal corporate databases.

Prevents "Confused Deputy" attacks by ensuring the Privileged Planner (P-LLM)
knows the exact source and trust boundary of every variable.
"""

from __future__ import annotations

from typing import Any, Dict, Generic, Literal, Optional, TypeVar
from pydantic import BaseModel, Field

T = TypeVar("T")

ProvenanceOrigin = Literal["UNTRUSTED_EXT", "USER_AUTHORITY", "TRUSTED_PO_DB"]


class ProvenanceEnvelope(BaseModel, Generic[T]):
    """
    Runtime security envelope wrapping a typed variable with its provenance origin.
    """
    value: T
    origin: ProvenanceOrigin
    source_reference: Optional[str] = None
    page_number: Optional[int] = None
    line_number: Optional[int] = None


def wrap_extracted_schema(
    schema: BaseModel, source_file: str = "untrusted_input"
) -> Dict[str, ProvenanceEnvelope[Any]]:
    """
    Takes an entire parsed schema from Q-LLM and wraps every extracted field
    into a ProvenanceEnvelope with origin='UNTRUSTED_EXT'.
    """
    wrapped: Dict[str, ProvenanceEnvelope[Any]] = {}
    for field_name, val in schema:
        wrapped[field_name] = ProvenanceEnvelope(
            value=val,
            origin="UNTRUSTED_EXT",
            source_reference=source_file,
        )
    return wrapped


def wrap_user_intent(intent_value: Any, reference: str = "Step-0-Prompt") -> ProvenanceEnvelope[Any]:
    """
    Wraps an authenticated user input with origin='USER_AUTHORITY'.
    """
    return ProvenanceEnvelope(
        value=intent_value,
        origin="USER_AUTHORITY",
        source_reference=reference,
    )


def wrap_trusted_db(db_value: Any, record_id: str) -> ProvenanceEnvelope[Any]:
    """
    Wraps verified data from purchase_orders.json or trusted database
    with origin='TRUSTED_PO_DB'.
    """
    return ProvenanceEnvelope(
        value=db_value,
        origin="TRUSTED_PO_DB",
        source_reference=record_id,
    )
