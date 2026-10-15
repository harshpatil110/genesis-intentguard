"""
IntentGuard OpenClaw Bridge — Pydantic v2 Models
==================================================
GENESIS 2.0 | Track: EVA 03 | PS 01

Defines strictly-typed request/response schemas for all 4 interception hooks
and real-time X-Ray telemetry WebSocket events.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Input Modality Enum
# ---------------------------------------------------------------------------

class InputModality(str, Enum):
    """Supported modalities for Hook 1 inbound data interception."""
    EMAIL     = "email"
    PDF       = "pdf"
    DOCX      = "docx"
    IMAGE     = "image"
    AUDIO     = "audio"
    VIDEO     = "video"
    WEB_DOM   = "web_dom"
    CSV_XLSX  = "csv_xlsx"
    ARCHIVE   = "archive"
    TEXT      = "text"


# ---------------------------------------------------------------------------
# Hook 1: Inbound Data Interception
# ---------------------------------------------------------------------------

class InboundInterceptRequest(BaseModel):
    """
    Hook 1 — intercept_inbound_data
    Sent by OpenClaw's ingestion pipeline before any external input is
    processed by the reasoning engine.
    """
    session_id:            str
    buyer_id:              str = "buyer-01"
    supplier_id:           str = "supplier-01"
    modality:              InputModality
    source_uri_or_filename: str  # e.g. "INV-402.pdf", "smtp://ceo@evil.com"
    raw_content_text:      Optional[str] = None
    raw_content_base64:    Optional[str] = None
    metadata:              Dict[str, Any] = Field(default_factory=dict)


class InboundInterceptResponse(BaseModel):
    """
    Hook 1 — intercept_inbound_data response
    Returned by IntentGuard after scanning and optionally redacting the input.
    """
    intercept_id:           str
    session_id:             str
    allowed_to_proceed:     bool
    provenance_tag:         Literal["UNTRUSTED_EXT", "USER_AUTHORITY"] = "UNTRUSTED_EXT"
    sanitized_text:         str
    cloaked_threats_removed: List[Dict[str, Any]] = Field(default_factory=list)
    surgical_redactions:    List[Dict[str, Any]] = Field(default_factory=list)
    raw_evidence_sha256:    str   # 64-char hex SHA-256 of raw incoming payload
    redacted_diff_sha256:   str   # 64-char hex SHA-256 of the redaction diff
    risk_category_ids:      List[int] = Field(default_factory=list)
    threat_detected:        bool = False
    action_taken:           str = "SAFE_EXECUTED"


# ---------------------------------------------------------------------------
# Hook 2: Tool Call Interception
# ---------------------------------------------------------------------------

class ToolCallInterceptRequest(BaseModel):
    """
    Hook 2 — intercept_tool_call
    Sent before any tool execution proposed by OpenClaw's reasoning engine.
    """
    session_id:          str
    tool_name:           str  # e.g. "schedule_payment", "change_vendor_bank", "bash"
    tool_arguments:      Dict[str, Any]
    argument_provenance: Dict[str, str] = Field(default_factory=dict)  # arg -> "USER_AUTHORITY"|"UNTRUSTED_EXT"
    intent_hmac_hash:    Optional[str] = None


class ToolCallInterceptResponse(BaseModel):
    """
    Hook 2 — intercept_tool_call response
    Returned by IntentGuard after policy evaluation.
    """
    intercept_id:                str
    session_id:                  str
    execution_permitted:         bool
    requires_human_approval_card: bool = False
    approval_card_id:            Optional[str] = None
    action_taken:                Literal["SAFE_EXECUTED", "BLOCKED", "HUMAN_APPROVAL_REQUIRED"]
    policy_reference:            str
    reason:                      str
    execution_token_hmac:        Optional[str] = None  # HMAC token required by Layer 4 Sandbox
    risk_category_ids:           List[int] = Field(default_factory=list)
    threat_detected:             bool = False


# ---------------------------------------------------------------------------
# Hook 3: Memory Write Interception
# ---------------------------------------------------------------------------

class MemoryWriteInterceptRequest(BaseModel):
    """
    Hook 3 — intercept_memory_write
    Sent before any write to ./openclaw/workspace/MEMORY.md.
    """
    session_id:                      str
    target_memory_file:              str = "MEMORY.md"
    proposed_memory_content:         str
    session_tainted_by_untrusted_ext: bool = True
    source_reference:                Optional[str] = None


class MemoryWriteInterceptResponse(BaseModel):
    """
    Hook 3 — intercept_memory_write response
    Returned by IntentGuard after quarantine/block decision.
    """
    intercept_id:           str
    persistent_write_allowed: bool
    routed_to_redis_quarantine: bool
    quarantine_key:         Optional[str] = None
    ttl_seconds:            int
    action_taken:           Literal["SAFE_EXECUTED", "QUARANTINED_MEMORY", "BLOCKED"]
    threat_detected:        bool
    risk_category_ids:      List[int] = Field(default_factory=list)
    reason:                 str


# ---------------------------------------------------------------------------
# Hook 4: Outbound Output Interception
# ---------------------------------------------------------------------------

class OutboundOutputInterceptRequest(BaseModel):
    """
    Hook 4 — intercept_outbound_output
    Sent before OpenClaw streams its final response or any outbound network call.
    """
    session_id:          str
    raw_agent_response:  str
    outbound_urls:       List[str] = Field(default_factory=list)


class OutboundOutputInterceptResponse(BaseModel):
    """
    Hook 4 — intercept_outbound_output response
    Returned by IntentGuard after scanning and redacting outbound content.
    """
    intercept_id:            str
    sanitized_agent_response: str
    blocked_urls:            List[str] = Field(default_factory=list)
    stripped_forged_tags:    List[str] = Field(default_factory=list)
    action_taken:            Literal["SAFE_EXECUTED", "SURGICALLY_REDACTED", "BLOCKED"]
    threat_detected:         bool
    risk_category_ids:       List[int] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# X-Ray Telemetry WebSocket Event
# ---------------------------------------------------------------------------

class XRayTelemetryEvent(BaseModel):
    """
    Real-time telemetry event broadcast over /ws/xray-stream.
    Every hook execution emits one of these for the Forensic X-Ray UI.
    """
    event_id:            str
    timestamp:           str   # ISO-8601 UTC
    session_id:          str
    hook_stage:          Literal[
                             "HOOK_1_INBOUND",
                             "HOOK_2_TOOL_CALL",
                             "HOOK_3_MEMORY_WRITE",
                             "HOOK_4_OUTBOUND",
                         ]
    modality_or_tool:    str
    threat_detected:     bool
    action_taken:        str
    risk_category_ids:   List[int]
    summary:             str
    details:             Dict[str, Any]
