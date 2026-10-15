"""
IntentGuard OpenClaw Hidden First-Layer Interceptor Bridge
===========================================================
GENESIS 2.0 | Track: EVA 03 | PS 01

Implements the 4 mandatory interception hooks as a FastAPI APIRouter.
OpenClaw must call these endpoints before ingesting any external data,
executing any tool, writing to MEMORY.md, or streaming any output.

Hook 1: POST /internal/intercept/input    (inbound data)
Hook 2: POST /internal/intercept/tool     (tool call)
Hook 3: POST /internal/intercept/memory   (memory write)
Hook 4: POST /internal/intercept/output   (outbound output)
Extra:  GET  /internal/intercept/telemetry-history
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.config import settings
from app.layer1_decloaker.audio_video_decloaker import (
    AudioVideoDeCloaker,
    audio_video_decloaker,
)
from app.layer1_decloaker.image_decloaker import (
    ImageDeCloaker,
    image_decloaker,
)
from app.layer1_decloaker.pdf_docx_decloaker import (
    DocumentDeCloakResult,
    pdf_docx_decloaker,
)
from app.layer2_camel.intent_contract import (
    Step0IntentContract,
    compile_step0_intent_contract,
    intent_contract_registry,
    verify_tool_against_contract,
)
from app.layer3_policy.resource_budget import resource_budget_enforcer
from app.openclaw_bridge.models import (
    InboundInterceptRequest,
    InboundInterceptResponse,
    InputModality,
    MemoryWriteInterceptRequest,
    MemoryWriteInterceptResponse,
    OutboundOutputInterceptRequest,
    OutboundOutputInterceptResponse,
    ToolCallInterceptRequest,
    ToolCallInterceptResponse,
    XRayTelemetryEvent,
)
from app.openclaw_bridge.telemetry_ws import telemetry_manager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

# High-risk tool names that mutate financial / identity state
_HIGH_RISK_BANK_TOOLS = frozenset(
    {
        "change_vendor_bank",
        "update_iban",
        "update_bank_account",
        "set_payment_destination",
    }
)

_HIGH_RISK_EXEC_TOOLS = frozenset(
    {
        "bash",
        "exec_shell",
        "delete_file",
        "run_script",
    }
)

_HIGH_RISK_PAYMENT_TOOLS = frozenset({"transfer_funds", "schedule_payment"})

# Prompt-injection detection patterns
_INJECTION_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"ignore\s+(previous|all|buyer)\s+(instructions?|restrictions?)", re.I),
    re.compile(r"\[SYSTEM", re.I),
    re.compile(r"font-size\s*:\s*0", re.I),
    re.compile(r"color\s*:\s*white\b.*color\s*:\s*white", re.I),
    re.compile(r"override\s+(previous\s+)?instructions?", re.I),
    re.compile(r"disregard\s+(all\s+)?(previous\s+)?instructions?", re.I),
    re.compile(r"you\s+are\s+now\s+a", re.I),
]

# Sleeper-rule patterns in memory writes
_SLEEPER_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"\balways\b", re.I),
    re.compile(r"\bwhenever\b", re.I),
    re.compile(r"in\s+future\s+tasks?", re.I),
    re.compile(r"change\s+bank", re.I),
    re.compile(r"\bbcc\b", re.I),
    re.compile(r"\bfrom\s+now\s+on\b", re.I),
]

# EchoLeak / exfiltration detection
_MARKDOWN_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\((https?://[^)]+)\)", re.I)
_SSRF_IP_RE = re.compile(r"(169\.254\.169\.254|127\.0\.0\.1|0\.0\.0\.0)", re.I)
_FORGED_TAG_RE = re.compile(r"\[SYSTEM\s+TOOL\s+OUTPUT\]", re.I)

# Modalities that immediately taint a session
_EXTERNAL_MODALITIES = frozenset(
    {
        InputModality.EMAIL,
        InputModality.PDF,
        InputModality.DOCX,
        InputModality.IMAGE,
        InputModality.SCREENSHOT,
        InputModality.RECEIPT,
        InputModality.AUDIO,
        InputModality.VIDEO,
        InputModality.WEB_DOM,
        InputModality.CSV_XLSX,
        InputModality.ARCHIVE,
    }
)

# Magic bytes for MZ (executable) detection
_MZ_MAGIC = b"MZ"


# ---------------------------------------------------------------------------
# Per-session taint registry (in-memory; reset on process restart)
# ---------------------------------------------------------------------------

session_taint_registry: Dict[str, bool] = {}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _sha256_hex(data: str | bytes) -> str:
    """Return 64-char lowercase hex SHA-256 digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256(key: str, message: str) -> str:
    """Generate HMAC-SHA256 hex digest for execution token signing."""
    return _hmac.new(
        key.encode("utf-8"),
        message.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def _detect_injections(text: str) -> List[Dict]:
    """Scan text for prompt-injection patterns; return list of findings."""
    findings = []
    for pat in _INJECTION_PATTERNS:
        if pat.search(text):
            findings.append({"pattern": pat.pattern, "match": pat.search(text).group(0)})  # type: ignore[union-attr]
    # Executable magic bytes check
    if text.encode("latin-1", errors="ignore")[:2] == _MZ_MAGIC:
        findings.append({"pattern": "MZ_MAGIC_BYTES", "match": "MZ"})
    return findings


def _is_domain_allowed(url: str) -> bool:
    """Return True if URL's hostname is in the configured allowed domains."""
    for domain in settings.allowed_domains_list:
        if domain and domain in url:
            return True
    return False


def _telemetry_event(
    session_id: str,
    hook_stage: str,
    modality_or_tool: str,
    threat_detected: bool,
    action_taken: str,
    risk_category_ids: List[int],
    summary: str,
    details: dict,
) -> XRayTelemetryEvent:
    return XRayTelemetryEvent(
        event_id=_new_id(),
        timestamp=_now_iso(),
        session_id=session_id,
        hook_stage=hook_stage,  # type: ignore[arg-type]
        modality_or_tool=modality_or_tool,
        threat_detected=threat_detected,
        action_taken=action_taken,
        risk_category_ids=risk_category_ids,
        summary=summary,
        details=details,
    )


# ---------------------------------------------------------------------------
# Intent Lock Request Schema
# ---------------------------------------------------------------------------

class IntentLockRequest(BaseModel):
    """Payload to compile and lock a Step-0 Intent Contract."""
    session_id: str
    user_prompt: str
    buyer_id: Optional[str] = None
    supplier_id: Optional[str] = None
    allowed_tools: Optional[List[str]] = None
    prohibited_operations: Optional[List[str]] = None
    max_approved_amount_inr: Optional[float] = None
    allowed_recipients: Optional[List[str]] = None
    approved_po_numbers: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# FastAPI router
# ---------------------------------------------------------------------------

interceptor_router = APIRouter(prefix="/internal/intercept", tags=["interceptor"])


# ========================= HOOK 1: INBOUND DATA ============================

@interceptor_router.post("/input", response_model=InboundInterceptResponse)
async def intercept_inbound_data(req: InboundInterceptRequest) -> InboundInterceptResponse:
    """
    Hook 1 — Hidden First-Layer Inbound Interceptor.
    Scans any external input before OpenClaw's reasoning engine sees it.
    """
    intercept_id = _new_id()

    # ── 1. Compute raw evidence SHA-256 ─────────────────────────────────────
    raw_payload = (
        req.raw_content_text or ""
    ) + (req.raw_content_base64 or "") + req.source_uri_or_filename
    raw_evidence_sha256 = _sha256_hex(raw_payload)

    # ── 1b. Step-0 Inbound Payload & Resource Budget Check ──────────────────
    declared_size = req.metadata.get("file_size_bytes") or req.metadata.get("file_size")
    budget_res = resource_budget_enforcer.check_inbound_payload_budget(
        session_id=req.session_id,
        raw_text=req.raw_content_text,
        raw_base64=req.raw_content_base64,
        declared_size_bytes=declared_size,
    )
    if not budget_res.allowed:
        event = _telemetry_event(
            session_id=req.session_id,
            hook_stage="HOOK_1_INBOUND",
            modality_or_tool=req.modality.value,
            threat_detected=True,
            action_taken="BLOCKED",
            risk_category_ids=budget_res.risk_category_ids,
            summary=f"[BUDGET BLOCKED] {budget_res.reason}",
            details={
                "intercept_id": intercept_id,
                "violation_type": budget_res.violation_type,
                "reason": budget_res.reason,
                "metrics": budget_res.current_metrics,
                "raw_sha256": raw_evidence_sha256,
            },
        )
        await telemetry_manager.broadcast_event(event)
        logger.warning(
            "Hook1 [%s] session=%s BLOCKED by budget engine: %s",
            intercept_id, req.session_id, budget_res.reason,
        )
        return InboundInterceptResponse(
            intercept_id=intercept_id,
            session_id=req.session_id,
            allowed_to_proceed=False,
            provenance_tag="UNTRUSTED_EXT",
            sanitized_text=f"[BLOCKED BY RESOURCE BUDGET ENGINE: {budget_res.reason}]",
            cloaked_threats_removed=[],
            surgical_redactions=[],
            raw_evidence_sha256=raw_evidence_sha256,
            redacted_diff_sha256=_sha256_hex(f"BLOCKED:{raw_evidence_sha256}"),
            risk_category_ids=budget_res.risk_category_ids,
            threat_detected=True,
            action_taken="BLOCKED",
        )

    # ── 2. Mark session as tainted if external modality ─────────────────────
    if req.modality in _EXTERNAL_MODALITIES:
        session_taint_registry[req.session_id] = True
        resource_budget_enforcer.downgrade_permissions_for_untrusted_data(req.session_id)

    # ── 3. Pre-OCR Document De-Cloaker (PDF & DOCX) ──────────────────────────
    cloaked_threats: List[Dict] = []
    surgical_redactions: List[Dict] = []
    text_to_scan = req.raw_content_text or ""
    threat_detected = False
    risk_category_ids: List[int] = []

    is_doc_modality = (
        req.modality in (InputModality.PDF, InputModality.DOCX)
        or req.source_uri_or_filename.lower().endswith((".pdf", ".docx"))
    )

    is_image_modality = (
        req.modality in (InputModality.IMAGE, InputModality.SCREENSHOT, InputModality.RECEIPT, "image", "screenshot", "receipt")
        or req.source_uri_or_filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff"))
    )

    is_media_modality = (
        req.modality in (InputModality.AUDIO, InputModality.VIDEO, "audio", "video")
        or req.source_uri_or_filename.lower().endswith((".mp3", ".wav", ".ogg", ".mp4", ".mov", ".m4a", ".webm"))
    )

    if is_doc_modality and req.raw_content_base64:
        try:
            decoded_bytes = base64.b64decode(req.raw_content_base64)
            # Check for disguised Windows executable header (MZ)
            if decoded_bytes.startswith(_MZ_MAGIC):
                threat_detected = True
                risk_category_ids.append(2)
                cloaked_threats.append({
                    "pattern": "MZ_HEADER",
                    "match": "Disguised Windows executable (MZ header) detected",
                    "position": 0,
                })
            else:
                mod_str = req.modality.value if hasattr(req.modality, "value") else str(req.modality)
                decloak_res = pdf_docx_decloaker.decloak_document(
                    file_bytes=decoded_bytes,
                    filename=req.source_uri_or_filename,
                    modality=mod_str,
                )
                raw_evidence_sha256 = decloak_res.raw_evidence_sha256
                if decloak_res.threat_detected:
                    threat_detected = True
                    for r_id in decloak_res.risk_category_ids:
                        if r_id not in risk_category_ids:
                            risk_category_ids.append(r_id)
                    for finding in decloak_res.cloaked_findings:
                        cloaked_threats.append(finding.model_dump())
                text_to_scan = decloak_res.visible_clean_text
        except Exception as exc:
            logger.warning("Error running PDF/DOCX de-cloaker: %s", exc)

    elif is_image_modality and req.raw_content_base64:
        try:
            decoded_bytes = base64.b64decode(req.raw_content_base64)
            # Check for disguised Windows executable header (MZ)
            if decoded_bytes.startswith(_MZ_MAGIC):
                threat_detected = True
                if 2 not in risk_category_ids:
                    risk_category_ids.append(2)
                cloaked_threats.append({
                    "pattern": "MZ_HEADER",
                    "match": "Disguised Windows executable (MZ header) detected",
                    "position": 0,
                })
            else:
                decloak_res = image_decloaker.decloak_image_bytes(
                    file_bytes=decoded_bytes,
                    filename=req.source_uri_or_filename,
                )
                raw_evidence_sha256 = decloak_res.raw_evidence_sha256
                if decloak_res.threat_detected:
                    threat_detected = True
                    for r_id in decloak_res.risk_category_ids:
                        if r_id not in risk_category_ids:
                            risk_category_ids.append(r_id)
                    for finding in decloak_res.cloaked_findings:
                        cloaked_threats.append(finding.model_dump())
                text_to_scan = decloak_res.visible_clean_text
        except Exception as exc:
            logger.warning("Error running Image de-cloaker: %s", exc)

    elif is_media_modality and req.raw_content_base64:
        try:
            decoded_bytes = base64.b64decode(req.raw_content_base64)
            # Check for disguised Windows executable header (MZ)
            if decoded_bytes.startswith(_MZ_MAGIC):
                threat_detected = True
                if 2 not in risk_category_ids:
                    risk_category_ids.append(2)
                cloaked_threats.append({
                    "pattern": "MZ_HEADER",
                    "match": "Disguised Windows executable (MZ header) detected",
                    "position": 0,
                })
            else:
                mod_str = req.modality.value if hasattr(req.modality, "value") else str(req.modality)
                decloak_res = audio_video_decloaker.decloak_media_bytes(
                    file_bytes=decoded_bytes,
                    modality=mod_str,
                    filename=req.source_uri_or_filename,
                    metadata=req.metadata,
                )
                raw_evidence_sha256 = decloak_res.raw_evidence_sha256
                if decloak_res.threat_detected:
                    threat_detected = True
                    for r_id in decloak_res.risk_category_ids:
                        if r_id not in risk_category_ids:
                            risk_category_ids.append(r_id)
                    for finding in decloak_res.cloaked_findings:
                        cloaked_threats.append(finding.model_dump())
                text_to_scan = decloak_res.visible_clean_text
        except Exception as exc:
            logger.warning("Error running Audio/Video de-cloaker: %s", exc)

    # Check for disguised Windows executable header (MZ) when modality is not PDF/DOCX/IMAGE
    elif req.raw_content_base64:
        try:
            decoded_bytes = base64.b64decode(req.raw_content_base64)
            if decoded_bytes.startswith(_MZ_MAGIC):
                threat_detected = True
                if 2 not in risk_category_ids:
                    risk_category_ids.append(2)
                cloaked_threats.append({
                    "pattern": "MZ_HEADER",
                    "match": "Disguised Windows executable (MZ header) detected",
                    "position": 0,
                })
        except Exception:
            pass

    # ── 3b. Baseline threat scan on visible text ─────────────────────────────
    injection_findings = _detect_injections(text_to_scan)
    if injection_findings:
        threat_detected = True
        for rid in [10, 11]:
            if rid not in risk_category_ids:
                risk_category_ids.append(rid)
        for inf in injection_findings:
            cloaked_threats.append(inf)

    sanitized_text = text_to_scan
    for pat in _INJECTION_PATTERNS:
        if pat.search(sanitized_text):
            original = pat.search(sanitized_text).group(0)  # type: ignore[union-attr]
            sanitized_text = pat.sub("[REDACTED_INJECTION]", sanitized_text)
            surgical_redactions.append({
                "original": original,
                "replacement": "[REDACTED_INJECTION]",
            })

    # ── 4. Compute redacted diff SHA-256 ────────────────────────────────────
    diff_record = f"ORIGINAL:{raw_evidence_sha256}|SANITIZED:{sanitized_text}"
    redacted_diff_sha256 = _sha256_hex(diff_record)

    # ── 5. Build response ────────────────────────────────────────────────────
    action_taken = "SURGICALLY_REDACTED" if (surgical_redactions or cloaked_threats) else "SAFE_EXECUTED"
    response = InboundInterceptResponse(
        intercept_id=intercept_id,
        session_id=req.session_id,
        allowed_to_proceed=True,  # Layer 1 decloaker may override in deeper tasks
        provenance_tag="UNTRUSTED_EXT",
        sanitized_text=sanitized_text,
        cloaked_threats_removed=cloaked_threats,
        surgical_redactions=surgical_redactions,
        raw_evidence_sha256=raw_evidence_sha256,
        redacted_diff_sha256=redacted_diff_sha256,
        risk_category_ids=risk_category_ids,
        threat_detected=threat_detected,
        action_taken=action_taken,
    )

    # ── 6. Broadcast X-Ray telemetry ────────────────────────────────────────
    event = _telemetry_event(
        session_id=req.session_id,
        hook_stage="HOOK_1_INBOUND",
        modality_or_tool=req.modality.value,
        threat_detected=threat_detected,
        action_taken=action_taken,
        risk_category_ids=risk_category_ids,
        summary=(
            f"[THREAT DETECTED] Injection in {req.modality.value} from "
            f"{req.source_uri_or_filename}" if threat_detected
            else f"Safe {req.modality.value} input from {req.source_uri_or_filename}"
        ),
        details={
            "intercept_id": intercept_id,
            "source": req.source_uri_or_filename,
            "threats_found": len(cloaked_threats),
            "redactions": len(surgical_redactions),
            "raw_sha256": raw_evidence_sha256,
        },
    )
    await telemetry_manager.broadcast_event(event)

    logger.info(
        "Hook1 [%s] session=%s modality=%s threat=%s action=%s",
        intercept_id, req.session_id, req.modality.value, threat_detected, action_taken,
    )
    return response


# ========================= HOOK 2: TOOL CALL ================================

@interceptor_router.post("/tool", response_model=ToolCallInterceptResponse)
async def intercept_tool_call(req: ToolCallInterceptRequest) -> ToolCallInterceptResponse:
    """
    Hook 2 — Tool Call Interceptor.
    Evaluates every tool invocation against the Deterministic Policy Gateway.
    """
    intercept_id = _new_id()

    # ── 0. Step-0 Deterministic Policy & Resource Budget Check ───────────────
    budget_res = resource_budget_enforcer.check_tool_call_budget(
        session_id=req.session_id,
        tool_name=req.tool_name,
        tool_arguments=req.tool_arguments,
    )
    if not budget_res.allowed:
        event = _telemetry_event(
            session_id=req.session_id,
            hook_stage="HOOK_2_TOOL_CALL",
            modality_or_tool=req.tool_name,
            threat_detected=True,
            action_taken="BLOCKED",
            risk_category_ids=budget_res.risk_category_ids,
            summary=f"[BUDGET BLOCKED] Tool '{req.tool_name}' blocked: {budget_res.reason}",
            details={
                "intercept_id": intercept_id,
                "tool": req.tool_name,
                "violation_type": budget_res.violation_type,
                "metrics": budget_res.current_metrics,
                "reason": budget_res.reason,
            },
        )
        await telemetry_manager.broadcast_event(event)
        logger.warning(
            "Hook2 [%s] session=%s tool=%s BLOCKED by budget engine: %s",
            intercept_id, req.session_id, req.tool_name, budget_res.reason,
        )
        return ToolCallInterceptResponse(
            intercept_id=intercept_id,
            session_id=req.session_id,
            execution_permitted=False,
            requires_human_approval_card=False,
            approval_card_id=None,
            action_taken="BLOCKED",
            policy_reference=budget_res.policy_reference,
            reason=budget_res.reason,
            execution_token_hmac=None,
            risk_category_ids=budget_res.risk_category_ids,
            threat_detected=True,
        )

    # ── 0b. Step-0 Cryptographic Intent Contract Verification ─────────────────
    contract = intent_contract_registry.get_contract(req.session_id)
    if contract is not None or req.intent_hmac_hash is not None:
        if contract is None:
            # Provided an HMAC hash but no contract is registered for this session
            event = _telemetry_event(
                session_id=req.session_id,
                hook_stage="HOOK_2_TOOL_CALL",
                modality_or_tool=req.tool_name,
                threat_detected=True,
                action_taken="BLOCKED",
                risk_category_ids=[10, 12, 30],
                summary=f"[HMAC REJECTED] Unrecognized or forged HMAC hash '{req.intent_hmac_hash}'",
                details={
                    "tool": req.tool_name,
                    "reason": "No registered Step-0 contract matches provided hash",
                },
            )
            await telemetry_manager.broadcast_event(event)
            return ToolCallInterceptResponse(
                intercept_id=intercept_id,
                session_id=req.session_id,
                execution_permitted=False,
                requires_human_approval_card=False,
                approval_card_id=None,
                action_taken="BLOCKED",
                policy_reference="RISK_10_SPOOFED_AUTHORITY_HMAC_FAIL",
                reason="Forged or unrecognized intent_hmac_hash. Risk #10 (Spoofed Authorization).",
                execution_token_hmac=None,
                risk_category_ids=[10, 12, 30],
                threat_detected=True,
            )

        verification = verify_tool_against_contract(
            contract=contract,
            tool_name=req.tool_name,
            tool_arguments=req.tool_arguments,
            argument_provenance=req.argument_provenance,
            provided_hmac_hash=req.intent_hmac_hash,
        )
        if not verification.allowed:
            card_id = verification.approval_card_id or (
                _new_id() if verification.requires_human_approval_card else None
            )
            event = _telemetry_event(
                session_id=req.session_id,
                hook_stage="HOOK_2_TOOL_CALL",
                modality_or_tool=req.tool_name,
                threat_detected=True,
                action_taken=verification.action_taken,
                risk_category_ids=verification.risk_category_ids,
                summary=f"[CONTRACT VIOLATION] {verification.reason}",
                details={
                    "intercept_id": intercept_id,
                    "contract_id": contract.contract_id,
                    "violation_type": verification.violation_type,
                    "reason": verification.reason,
                    "approval_card_id": card_id,
                },
            )
            await telemetry_manager.broadcast_event(event)
            return ToolCallInterceptResponse(
                intercept_id=intercept_id,
                session_id=req.session_id,
                execution_permitted=False,
                requires_human_approval_card=verification.requires_human_approval_card,
                approval_card_id=card_id,
                action_taken=verification.action_taken,
                policy_reference=verification.policy_reference,
                reason=verification.reason,
                execution_token_hmac=None,
                risk_category_ids=verification.risk_category_ids,
                threat_detected=True,
            )

    # ── 1. Determine if any argument carries UNTRUSTED_EXT provenance ────────
    has_untrusted_arg = any(
        prov == "UNTRUSTED_EXT" for prov in req.argument_provenance.values()
    )
    is_bank_mutation = req.tool_name in _HIGH_RISK_BANK_TOOLS
    is_exec_tool     = req.tool_name in _HIGH_RISK_EXEC_TOOLS
    is_payment_tool  = req.tool_name in _HIGH_RISK_PAYMENT_TOOLS

    # ── 2. Policy decision ──────────────────────────────────────────────────
    threat_detected = False
    risk_category_ids: List[int] = []
    execution_permitted = True
    requires_approval  = False
    action_taken       = "SAFE_EXECUTED"
    approval_card_id: Optional[str] = None
    execution_token_hmac: Optional[str] = None
    reason = "Tool call is authorized and safe."

    if is_bank_mutation and has_untrusted_arg:
        # Financial mutation driven by untrusted data → block + human approval
        threat_detected  = True
        risk_category_ids = [16, 18]
        execution_permitted = False
        requires_approval   = True
        action_taken        = "HUMAN_APPROVAL_REQUIRED"
        approval_card_id    = _new_id()
        reason = (
            f"HIGH-RISK: Tool '{req.tool_name}' modifies payment/bank details "
            "using argument(s) sourced from UNTRUSTED_EXT. "
            "Human approval required before execution."
        )
    elif is_exec_tool:
        # Shell/exec tools are always blocked
        threat_detected   = True
        risk_category_ids = [17]
        execution_permitted = False
        action_taken        = "BLOCKED"
        reason = (
            f"BLOCKED: Shell/exec tool '{req.tool_name}' is not permitted "
            "inside the IntentGuard sandbox."
        )
    elif is_payment_tool and has_untrusted_arg:
        # Payment tools with untrusted args need human approval
        threat_detected   = True
        risk_category_ids = [16]
        execution_permitted = False
        requires_approval   = True
        action_taken        = "HUMAN_APPROVAL_REQUIRED"
        approval_card_id    = _new_id()
        reason = (
            f"HIGH-RISK: Payment tool '{req.tool_name}' carries UNTRUSTED_EXT "
            "arguments. Human approval required."
        )
    else:
        # Safe → issue HMAC execution token for Layer 4 Sandbox
        token_message = f"{req.session_id}:{req.tool_name}:{intercept_id}"
        execution_token_hmac = _hmac_sha256(settings.HMAC_MASTER_SECRET, token_message)

    response = ToolCallInterceptResponse(
        intercept_id=intercept_id,
        session_id=req.session_id,
        execution_permitted=execution_permitted,
        requires_human_approval_card=requires_approval,
        approval_card_id=approval_card_id,
        action_taken=action_taken,  # type: ignore[arg-type]
        policy_reference=settings.DEFAULT_POLICY_REFERENCE,
        reason=reason,
        execution_token_hmac=execution_token_hmac,
        risk_category_ids=risk_category_ids,
        threat_detected=threat_detected,
    )

    event = _telemetry_event(
        session_id=req.session_id,
        hook_stage="HOOK_2_TOOL_CALL",
        modality_or_tool=req.tool_name,
        threat_detected=threat_detected,
        action_taken=action_taken,
        risk_category_ids=risk_category_ids,
        summary=(
            f"[THREAT] Tool '{req.tool_name}' blocked/flagged" if threat_detected
            else f"Tool '{req.tool_name}' approved"
        ),
        details={
            "intercept_id": intercept_id,
            "tool": req.tool_name,
            "execution_permitted": execution_permitted,
            "reason": reason,
        },
    )
    await telemetry_manager.broadcast_event(event)

    logger.info(
        "Hook2 [%s] session=%s tool=%s permitted=%s action=%s",
        intercept_id, req.session_id, req.tool_name, execution_permitted, action_taken,
    )
    return response


# ========================= HOOK 3: MEMORY WRITE =============================

@interceptor_router.post("/memory", response_model=MemoryWriteInterceptResponse)
async def intercept_memory_write(req: MemoryWriteInterceptRequest) -> MemoryWriteInterceptResponse:
    """
    Hook 3 — Memory Write Interceptor.
    Guards MEMORY.md against sleeper-rule injection and tainted session writes.
    """
    intercept_id = _new_id()

    # ── 1. Determine taint ──────────────────────────────────────────────────
    is_tainted = (
        req.session_tainted_by_untrusted_ext
        or session_taint_registry.get(req.session_id, False)
    )

    # ── 2. Scan for sleeper-rule patterns ────────────────────────────────────
    content = req.proposed_memory_content
    sleeper_hits = [p.pattern for p in _SLEEPER_PATTERNS if p.search(content)]
    has_sleeper  = len(sleeper_hits) > 0

    # ── 3. Decision ─────────────────────────────────────────────────────────
    threat_detected = has_sleeper
    risk_category_ids: List[int] = [12, 13, 20] if has_sleeper else ([14] if is_tainted else [])

    if is_tainted or has_sleeper:
        persistent_write_allowed = False
        routed_to_quarantine     = True
        quarantine_key           = f"intentguard:quarantine:{req.session_id}"
        ttl                      = settings.MEMORY_QUARANTINE_TTL_SECONDS
        action_taken             = "QUARANTINED_MEMORY"
        reason = (
            "Memory write quarantined: "
            + (f"sleeper patterns detected {sleeper_hits}; " if has_sleeper else "")
            + ("session is tainted by UNTRUSTED_EXT input." if is_tainted else "")
        )
    else:
        persistent_write_allowed = True
        routed_to_quarantine     = False
        quarantine_key           = None
        ttl                      = 0
        action_taken             = "SAFE_EXECUTED"
        reason                   = "Memory write is from a clean USER_AUTHORITY session."

    response = MemoryWriteInterceptResponse(
        intercept_id=intercept_id,
        persistent_write_allowed=persistent_write_allowed,
        routed_to_redis_quarantine=routed_to_quarantine,
        quarantine_key=quarantine_key,
        ttl_seconds=ttl,
        action_taken=action_taken,  # type: ignore[arg-type]
        threat_detected=threat_detected,
        risk_category_ids=risk_category_ids,
        reason=reason,
    )

    event = _telemetry_event(
        session_id=req.session_id,
        hook_stage="HOOK_3_MEMORY_WRITE",
        modality_or_tool=req.target_memory_file,
        threat_detected=threat_detected,
        action_taken=action_taken,
        risk_category_ids=risk_category_ids,
        summary=(
            f"[QUARANTINED] Memory write blocked for session {req.session_id}"
            if not persistent_write_allowed
            else f"Memory write approved for session {req.session_id}"
        ),
        details={
            "intercept_id": intercept_id,
            "tainted": is_tainted,
            "sleeper_patterns": sleeper_hits,
            "quarantine_key": quarantine_key,
            "ttl": ttl,
        },
    )
    await telemetry_manager.broadcast_event(event)

    logger.info(
        "Hook3 [%s] session=%s allowed=%s action=%s",
        intercept_id, req.session_id, persistent_write_allowed, action_taken,
    )
    return response


# ========================= HOOK 4: OUTBOUND OUTPUT ==========================

@interceptor_router.post("/output", response_model=OutboundOutputInterceptResponse)
async def intercept_outbound_output(req: OutboundOutputInterceptRequest) -> OutboundOutputInterceptResponse:
    """
    Hook 4 — Outbound Output / Zero-Click Exfiltration Firewall.
    Scans agent responses for EchoLeak, SSRF, and forged tool output tags.
    """
    intercept_id   = _new_id()
    response_text  = req.raw_agent_response
    blocked_urls:  List[str] = []
    forged_tags:   List[str] = []
    threat_detected = False
    risk_category_ids: List[int] = []

    # ── 1. EchoLeak: Markdown image exfiltration ─────────────────────────────
    for match in _MARKDOWN_IMAGE_RE.finditer(response_text):
        url = match.group(2)
        if not _is_domain_allowed(url):
            blocked_urls.append(url)
            response_text = response_text.replace(
                match.group(0), f"![{match.group(1)}]([REDACTED_EXFILTRATION_LINK])"
            )
            threat_detected = True
            if 21 not in risk_category_ids:
                risk_category_ids.append(21)

    # ── 2. Unauthorized outbound URLs (from outbound_urls list) ──────────────
    for url in req.outbound_urls:
        if not _is_domain_allowed(url):
            if url not in blocked_urls:
                blocked_urls.append(url)
                threat_detected = True
                if 22 not in risk_category_ids:
                    risk_category_ids.append(22)

    # ── 3. SSRF internal IP detection ────────────────────────────────────────
    if _SSRF_IP_RE.search(response_text):
        threat_detected = True
        if 23 not in risk_category_ids:
            risk_category_ids.append(23)
        response_text = _SSRF_IP_RE.sub("[REDACTED_SSRF_IP]", response_text)

    # ── 4. Forged tool output tags ────────────────────────────────────────────
    for match in _FORGED_TAG_RE.finditer(response_text):
        forged_tags.append(match.group(0))
        threat_detected = True
        if 24 not in risk_category_ids:
            risk_category_ids.append(24)
    if forged_tags:
        response_text = _FORGED_TAG_RE.sub("[REDACTED_FORGED_TAG]", response_text)

    action_taken = "SURGICALLY_REDACTED" if (blocked_urls or forged_tags) else "SAFE_EXECUTED"
    if threat_detected and action_taken == "SAFE_EXECUTED":
        action_taken = "SURGICALLY_REDACTED"

    response = OutboundOutputInterceptResponse(
        intercept_id=intercept_id,
        sanitized_agent_response=response_text,
        blocked_urls=blocked_urls,
        stripped_forged_tags=forged_tags,
        action_taken=action_taken,  # type: ignore[arg-type]
        threat_detected=threat_detected,
        risk_category_ids=risk_category_ids,
    )

    event = _telemetry_event(
        session_id=req.session_id,
        hook_stage="HOOK_4_OUTBOUND",
        modality_or_tool="agent_response",
        threat_detected=threat_detected,
        action_taken=action_taken,
        risk_category_ids=risk_category_ids,
        summary=(
            f"[EXFILTRATION BLOCKED] {len(blocked_urls)} URL(s) stripped from output"
            if threat_detected
            else "Outbound output is clean"
        ),
        details={
            "intercept_id": intercept_id,
            "blocked_urls": blocked_urls,
            "forged_tags": forged_tags,
        },
    )
    await telemetry_manager.broadcast_event(event)

    logger.info(
        "Hook4 [%s] session=%s threat=%s action=%s blocked_urls=%d",
        intercept_id, req.session_id, threat_detected, action_taken, len(blocked_urls),
    )
    return response


# ========================= TELEMETRY HISTORY ================================

@interceptor_router.get("/telemetry-history")
async def get_telemetry_history() -> dict:
    """
    Return the last 200 X-Ray telemetry events from the ring buffer.
    Useful for UI replay and test assertions without a live WebSocket.
    """
    history = telemetry_manager.get_history()
    return {
        "total": len(history),
        "events": [e.model_dump() for e in history],
    }


# ========================= RESOURCE BUDGET OBSERVABILITY =====================

@interceptor_router.get("/budget/{session_id}")
async def get_session_budget(session_id: str) -> dict:
    """Return real-time resource budget metrics and loop counters for a session."""
    return resource_budget_enforcer.get_session_metrics(session_id)


@interceptor_router.post("/budget/{session_id}/reset")
async def reset_session_budget(session_id: str) -> dict:
    """Reset budget counters and unlock an aborted session."""
    resource_budget_enforcer.reset_session(session_id)
    intent_contract_registry.reset_session(session_id)
    return {
        "session_id": session_id,
        "status": "reset_successful",
        "message": f"Resource budget and intent contract for session '{session_id}' have been reset.",
    }


# ========================= STEP-0 INTENT CONTRACT ENDPOINTS ==================

@interceptor_router.post("/intent-lock", response_model=Step0IntentContract)
async def lock_step0_intent(req: IntentLockRequest) -> Step0IntentContract:
    """
    Step-0 Intent Contract Lock.
    Compiles user prompt into an immutable HMAC-SHA256 signed authority contract.
    """
    contract = compile_step0_intent_contract(
        session_id=req.session_id,
        user_prompt=req.user_prompt,
        buyer_id=req.buyer_id,
        supplier_id=req.supplier_id,
        explicit_allowed_tools=req.allowed_tools,
        explicit_prohibited_operations=req.prohibited_operations,
        explicit_max_amount_inr=req.max_approved_amount_inr,
        explicit_allowed_recipients=req.allowed_recipients,
        explicit_approved_po_numbers=req.approved_po_numbers,
    )
    intent_contract_registry.force_register_contract(contract)

    # Broadcast real-time X-Ray telemetry
    event = _telemetry_event(
        session_id=req.session_id,
        hook_stage="HOOK_1_INBOUND",
        modality_or_tool="intent_lock",
        threat_detected=False,
        action_taken="SAFE_EXECUTED",
        risk_category_ids=[],
        summary=f"[STEP-0 INTENT LOCKED] Contract {contract.contract_id} locked with HMAC {contract.intent_hmac_hash[:16]}...",
        details={
            "contract_id": contract.contract_id,
            "intent_hmac_hash": contract.intent_hmac_hash,
            "max_approved_amount_inr": contract.max_approved_amount_inr,
            "allowed_tools": contract.allowed_tools,
            "prohibited_operations": contract.prohibited_operations,
        },
    )
    await telemetry_manager.broadcast_event(event)

    return contract


@interceptor_router.get("/intent-lock/{session_id}", response_model=Step0IntentContract)
async def get_step0_intent(session_id: str) -> Step0IntentContract:
    """Return the active Step-0 Intent Contract for a session."""
    contract = intent_contract_registry.get_contract(session_id)
    if not contract:
        raise HTTPException(
            status_code=404,
            detail=f"No Step-0 Intent Contract locked for session '{session_id}'.",
        )
    return contract


# ========================= DOCUMENT DE-CLOAK INSPECTION ENDPOINT ============

class DocumentDeCloakRequest(BaseModel):
    """Payload to de-cloak a document for X-Ray inspection."""
    filename: str = "document.pdf"
    modality: Optional[str] = None
    raw_content_base64: str


@interceptor_router.post("/decloak/document", response_model=DocumentDeCloakResult)
async def decloak_document_endpoint(req: DocumentDeCloakRequest) -> DocumentDeCloakResult:
    """
    Direct inspection endpoint for Forensic X-Ray UI and testing.
    Runs Pre-OCR De-Cloaker on base64-encoded PDF, DOCX, or Image file.
    """
    file_bytes = base64.b64decode(req.raw_content_base64)
    if req.modality in ("image", "screenshot", "receipt") or req.filename.lower().endswith(
        (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff")
    ):
        return image_decloaker.decloak_image_bytes(file_bytes=file_bytes, filename=req.filename)
    elif req.modality in ("audio", "video") or req.filename.lower().endswith(
        (".mp3", ".wav", ".ogg", ".mp4", ".mov", ".m4a", ".webm")
    ):
        mod_str = req.modality or ("video" if req.filename.lower().endswith((".mp4", ".mov", ".m4a", ".webm")) else "audio")
        return audio_video_decloaker.decloak_media_bytes(file_bytes=file_bytes, modality=mod_str, filename=req.filename)
    return pdf_docx_decloaker.decloak_document(
        file_bytes=file_bytes,
        filename=req.filename,
        modality=req.modality,
    )



