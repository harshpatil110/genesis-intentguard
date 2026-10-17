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
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.config import settings
from app.layer1_decloaker.archive_file_scanner import (
    ArchiveFileScanner,
    archive_file_scanner,
)
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
from app.layer1_decloaker.email_chat_scanner import (
    EmailChatScanner,
    email_chat_scanner,
)
from app.layer1_decloaker.web_dom_decloaker import (
    WebDOMDeCloaker,
    web_dom_decloaker,
)
from app.layer2_camel.business_disambiguator import (
    BusinessCommandDisambiguator,
    business_disambiguator,
)
from app.layer2_camel.surgical_redactor import (
    SurgicalRedactor,
    surgical_redactor,
)
from app.layer2_camel.memory_quarantine import (
    MemoryQuarantineVault,
    memory_quarantine_vault,
)
from app.layer2_camel.intent_contract import (
    Step0IntentContract,
    compile_step0_intent_contract,
    intent_contract_registry,
    verify_tool_against_contract,
)
from app.layer3_policy import (
    DeterministicPolicyGateway,
    PolicyEvaluationRequest,
    PolicyEvaluationResult,
    deterministic_policy_gateway,
)
from app.layer3_policy.micro_privilege import (
    MicroPrivilegeSandbox,
    PermissionMask,
    micro_privilege_sandbox,
)
from app.layer3_policy.outbound_firewall import (
    ZeroClickOutboundFirewall,
    outbound_firewall,
)

from app.layer3_policy.po_verifier import (
    PurchaseOrderVerifier,
    POVerificationResult,
    purchase_order_verifier,
)
from app.layer3_policy.step_back_approval import (
    StepBackApprovalEngine,
    step_back_approval_engine,
)
from app.layer3_policy.resource_budget import resource_budget_enforcer
from app.blockchain_client.audit_dispatcher import (
    AuditDispatcher,
    audit_dispatcher,
)
from app.layer3_policy.fail_closed_guard import (
    AntiBypassTokenVerifier,
    FailClosedCircuitBreaker,
    SandboxToolVerifyRequest,
    SandboxToolVerifyResponse,
    anti_bypass_verifier,
    fail_closed_breaker,
)
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
        "change_vendor_bank_details",
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
    re.compile(r"ignore\s+(?:all\s+|previous\s+|prior\s+|buyer\s+)*(?:instructions?|restrictions?|guidelines?|constraints?|prompts?|rules?)", re.I),
    re.compile(r"\[SYSTEM", re.I),
    re.compile(r"font-size\s*:\s*0", re.I),
    re.compile(r"color\s*:\s*white\b.*color\s*:\s*white", re.I),
    re.compile(r"override\s+(?:all\s+|previous\s+)?(?:instructions?|guidelines?|policy|policies)", re.I),
    re.compile(r"disregard\s+(?:all\s+)?(?:previous\s+)?(?:instructions?|restrictions?)", re.I),
    re.compile(r"you\s+are\s+now\s+a", re.I),
    re.compile(r"<\s*INFORMATION\s*>", re.I),
    re.compile(r"before\s+you\s+can\s+solve\s+the\s+task", re.I),
    re.compile(r"send\s+(?:money|funds|payment)\s+to\s+[A-Z0-9]+", re.I),
    re.compile(r"\b(?:new\s+system\s+instruction|system\s+prompt\s+override|developer\s+mode|developer\s+override)\b", re.I),
    re.compile(r"\b(?:in\s+future\s+tasks?|from\s+now\s+on\s+always|silently\s+bcc)\b", re.I),
    re.compile(r"!\[[^\]]*\]\((?:https?://)?(?:169\.254\.169\.254|127\.0\.0\.1|0\.0\.0\.0|localhost)", re.I),
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
        InputModality.CHAT,
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


class OpenClawInterceptorBridge:
    """Active session registry and interceptor bridge coordinator."""
    session_intent_contracts: Dict[str, dict] = {}
    micro_privilege_sandbox: MicroPrivilegeSandbox = micro_privilege_sandbox
    outbound_firewall: ZeroClickOutboundFirewall = outbound_firewall
    step_back_approval_engine: StepBackApprovalEngine = step_back_approval_engine
    audit_dispatcher: AuditDispatcher = audit_dispatcher



session_intent_contracts = OpenClawInterceptorBridge.session_intent_contracts
interceptor_bridge = OpenClawInterceptorBridge()



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

    # ── 2. Mark session as tainted & downgrade privilege mask (Task 18) ─────
    sandbox_state = None
    if (
        req.modality in _EXTERNAL_MODALITIES
        or getattr(req, "provenance_tag", "UNTRUSTED_EXT") == "UNTRUSTED_EXT"
        or bool(req.source_uri_or_filename)
    ):
        session_taint_registry[req.session_id] = True
        resource_budget_enforcer.downgrade_permissions_for_untrusted_data(req.session_id)
        sandbox_state = micro_privilege_sandbox.taint_session_on_inbound(
            session_id=req.session_id,
            source_uri=req.source_uri_or_filename,
            modality=req.modality.value if hasattr(req.modality, "value") else str(req.modality),
        )


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

    is_web_dom_modality = (
        req.modality in (InputModality.WEB_DOM, "web_dom")
        or req.source_uri_or_filename.lower().endswith((".html", ".htm"))
        or bool(req.raw_content_text and ("<html" in req.raw_content_text.lower() or "<body" in req.raw_content_text.lower()))
    )

    is_email_or_chat_modality = (
        req.modality in (InputModality.EMAIL, InputModality.CHAT, "email", "chat")
        or req.source_uri_or_filename.lower().endswith((".eml", ".msg"))
        or req.source_uri_or_filename.lower().startswith(("smtp://", "imap://", "slack://", "teams://"))
    )

    is_archive_modality = (
        req.modality in (InputModality.ARCHIVE, "archive")
        or req.source_uri_or_filename.lower().endswith((".zip", ".tar", ".gz", ".7z", ".rar"))
    )

    is_spreadsheet_modality = (
        req.modality in (InputModality.CSV_XLSX, "csv_xlsx")
        or req.source_uri_or_filename.lower().endswith((".xlsx", ".xlsm", ".csv"))
    )

    # ── 3a. Deep-Packet File, Executable Disguise & Archive Bomb Check ───────
    decoded_file_bytes: Optional[bytes] = None
    if req.raw_content_base64:
        try:
            decoded_file_bytes = base64.b64decode(req.raw_content_base64)
            file_scan_res = archive_file_scanner.scan_file_bytes(
                file_bytes=decoded_file_bytes,
                filename=req.source_uri_or_filename,
                modality=req.modality.value if hasattr(req.modality, "value") else str(req.modality),
            )
            raw_evidence_sha256 = file_scan_res.raw_evidence_sha256
            if file_scan_res.threat_detected:
                reasons = [f.cloak_reason for f in file_scan_res.cloaked_findings]
                # Hard block on disguised executable or decompression bomb
                if any(r in reasons for r in ("DISGUISED_EXECUTABLE", "DECOMPRESSION_BOMB_DETECTED", "ARCHIVE_EXCEEDS_SIZE_LIMIT")):
                    hard_block_threats: List[Dict] = []
                    if decoded_file_bytes.startswith(_MZ_MAGIC):
                        hard_block_threats.append({
                            "pattern": "MZ_HEADER",
                            "match": "Disguised Windows executable (MZ header) detected",
                            "position": 0,
                            "cloak_reason": "DISGUISED_EXECUTABLE",
                        })
                    for f in file_scan_res.cloaked_findings:
                        hard_block_threats.append(f.model_dump())

                    event = _telemetry_event(
                        session_id=req.session_id,
                        hook_stage="HOOK_1_INBOUND",
                        modality_or_tool=req.modality.value if hasattr(req.modality, "value") else str(req.modality),
                        threat_detected=True,
                        action_taken="BLOCKED",
                        risk_category_ids=file_scan_res.risk_category_ids,
                        summary=f"[MALWARE/ARCHIVE BLOCKED] {file_scan_res.summary}",
                        details={
                            "intercept_id": intercept_id,
                            "reasons": reasons,
                            "findings": hard_block_threats,
                            "raw_sha256": raw_evidence_sha256,
                        },
                    )
                    await telemetry_manager.broadcast_event(event)
                    logger.warning(
                        "Hook1 [%s] session=%s BLOCKED by file security scanner: %s",
                        intercept_id, req.session_id, file_scan_res.summary,
                    )
                    return InboundInterceptResponse(
                        intercept_id=intercept_id,
                        session_id=req.session_id,
                        allowed_to_proceed=False,
                        provenance_tag="UNTRUSTED_EXT",
                        sanitized_text=f"[BLOCKED BY FILE SECURITY SCANNER: {file_scan_res.summary}]",
                        cloaked_threats_removed=hard_block_threats,
                        surgical_redactions=[],
                        raw_evidence_sha256=raw_evidence_sha256,
                        redacted_diff_sha256=_sha256_hex(f"BLOCKED:{raw_evidence_sha256}"),
                        risk_category_ids=file_scan_res.risk_category_ids,
                        threat_detected=True,
                        action_taken="BLOCKED",
                    )
                else:
                    # Non-hard-block threats (e.g. spreadsheet formulas / hidden sheets)
                    threat_detected = True
                    for rid in file_scan_res.risk_category_ids:
                        if rid not in risk_category_ids:
                            risk_category_ids.append(rid)
                    for finding in file_scan_res.cloaked_findings:
                        cloaked_threats.append(finding.model_dump())
                    text_to_scan = file_scan_res.visible_clean_text
                    sanitized_b64 = file_scan_res.metadata_sanitized.get("sanitized_bytes_b64")
                    if sanitized_b64:
                        req.raw_content_base64 = sanitized_b64
                        decoded_file_bytes = base64.b64decode(sanitized_b64)
        except Exception as exc:
            logger.warning("Error running ArchiveFileScanner in Hook 1: %s", exc)

    if is_doc_modality and req.raw_content_base64:
        try:
            decoded_bytes = decoded_file_bytes if decoded_file_bytes is not None else base64.b64decode(req.raw_content_base64)
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

    elif is_media_modality and (req.raw_content_base64 or req.raw_content_text):
        try:
            if req.raw_content_base64:
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
            elif req.raw_content_text:
                mod_str = req.modality.value if hasattr(req.modality, "value") else str(req.modality)
                sanitized_text, findings = audio_video_decloaker.redact_malicious_transcript(
                    req.raw_content_text, modality=mod_str
                )
                if findings:
                    threat_detected = True
                    for f in findings:
                        for rid in f.risk_category_ids:
                            if rid not in risk_category_ids:
                                risk_category_ids.append(rid)
                        cloaked_threats.append(f.model_dump())
                text_to_scan = sanitized_text
        except Exception as exc:
            logger.warning("Error running Audio/Video de-cloaker: %s", exc)

    elif is_web_dom_modality and (req.raw_content_base64 or req.raw_content_text):
        try:
            if req.raw_content_base64:
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
                else:
                    decloak_res = web_dom_decloaker.decloak_web_dom_bytes(
                        html_input=decoded_bytes,
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
            elif req.raw_content_text:
                decloak_res = web_dom_decloaker.decloak_web_dom_bytes(
                    html_input=req.raw_content_text,
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
            logger.warning("Error running Web DOM de-cloaker: %s", exc)

    elif is_email_or_chat_modality and (req.raw_content_text or req.raw_content_base64 or req.metadata):
        try:
            raw_input_data: Union[bytes, str] = ""
            if req.raw_content_base64:
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
                else:
                    raw_input_data = decoded_bytes
            elif req.raw_content_text:
                raw_input_data = req.raw_content_text

            if not threat_detected:
                mod_str = req.modality.value if hasattr(req.modality, "value") else str(req.modality)
                decloak_res = email_chat_scanner.scan_message_bytes(
                    raw_input=raw_input_data,
                    metadata=req.metadata,
                    modality=mod_str,
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
            logger.warning("Error running Email/Chat scanner: %s", exc)

    elif is_spreadsheet_modality and req.raw_content_text:
        try:
            san_bytes, sheet_findings, sheet_preview = archive_file_scanner.scan_spreadsheet_safety(
                req.raw_content_text.encode("utf-8"),
                req.source_uri_or_filename,
            )
            if sheet_findings:
                threat_detected = True
                for f in sheet_findings:
                    for rid in f.risk_category_ids:
                        if rid not in risk_category_ids:
                            risk_category_ids.append(rid)
                    cloaked_threats.append(f.model_dump())
            text_to_scan = sheet_preview
        except Exception as exc:
            logger.warning("Error running Spreadsheet scanner for raw text: %s", exc)

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

    # ── 3c. Context-Aware Business vs Hacker Command Disambiguator (Task 11) ─
    disambig_res = business_disambiguator.disambiguate_document(
        text=text_to_scan,
        document_id=intercept_id,
        po_hint=req.metadata.get("po_id") or req.metadata.get("po_reference"),
    )

    # ── 3d. Surgical Redactor & Deterministic Diff Hasher (Task 12) ──────────
    redaction_res = surgical_redactor.redact(
        document_id=intercept_id,
        raw_or_decloaked_text=text_to_scan,
        layer1_cloaked_spans=cloaked_threats,
        disambiguation_result=disambig_res,
        po_hint=req.metadata.get("po_id") or req.metadata.get("po_reference"),
    )

    sanitized_text = redaction_res.clean_business_text
    redacted_diff_sha256 = redaction_res.redacted_diff_sha256

    if redaction_res.threat_detected:
        threat_detected = True
        for rid in redaction_res.risk_category_ids:
            if rid not in risk_category_ids:
                risk_category_ids.append(rid)

    # Format surgical redactions list for InboundInterceptResponse
    for span in redaction_res.diff_record.removed_malicious_spans:
        span_dict = span.model_dump()
        span_dict["original"] = span.exact_removed_text
        span_dict["replacement"] = "[REDACTED_AUTHORITY_OVERRIDE]"
        span_dict["risk_ids"] = span.risk_category_ids
        span_dict["reason"] = span.threat_reason
        surgical_redactions.append(span_dict)

    # ── 3e. Baseline pattern redactions fallback (if any remain) ────────────
    for pat in _INJECTION_PATTERNS:
        if pat.search(sanitized_text):
            original = pat.search(sanitized_text).group(0)  # type: ignore[union-attr]
            if "quote" in original.lower() or "draft" in original.lower():
                continue
            threat_detected = True
            if 14 not in risk_category_ids:
                risk_category_ids.append(14)
            sanitized_text = pat.sub("[REDACTED_INJECTION]", sanitized_text)
            surgical_redactions.append({
                "original": original,
                "replacement": "[REDACTED_INJECTION]",
            })

    # ── 4. Build response with Hyperledger Fabric Invariant ──────────────────
    action_taken = "SURGICALLY_REDACTED" if (threat_detected or redaction_res.threat_detected) else "SAFE_EXECUTED"
    perm_mask_val = (
        sandbox_state.permission_mask.value
        if sandbox_state
        else (
            PermissionMask.RESTRICTED_UNTRUSTED_CONTEXT.value
            if session_taint_registry.get(req.session_id, False)
            else PermissionMask.FULL_TRUSTED_CONTEXT.value
        )
    )
    stripped_list = sandbox_state.stripped_tools if sandbox_state else []

    response = InboundInterceptResponse(
        intercept_id=intercept_id,
        session_id=req.session_id,
        allowed_to_proceed=True,  # Legitimate business workflow continues with sanitized text
        provenance_tag="UNTRUSTED_EXT",
        sanitized_text=sanitized_text,
        cloaked_threats_removed=cloaked_threats,
        surgical_redactions=surgical_redactions,
        raw_evidence_sha256=raw_evidence_sha256,
        redacted_diff_sha256=redacted_diff_sha256,
        risk_category_ids=risk_category_ids,
        threat_detected=threat_detected,
        action_taken=action_taken,
        session_permission_mask=perm_mask_val,
        stripped_tools=stripped_list,
    )

    # ── 5. Broadcast X-Ray telemetry with visual diff segments ───────────────
    event = _telemetry_event(
        session_id=req.session_id,
        hook_stage="HOOK_1_INBOUND",
        modality_or_tool=req.modality.value if hasattr(req.modality, "value") else str(req.modality),
        threat_detected=threat_detected,
        action_taken=action_taken,
        risk_category_ids=risk_category_ids,
        summary=(
            f"[THREAT DETECTED] Injection in {req.modality.value if hasattr(req.modality, 'value') else req.modality} from "
            f"{req.source_uri_or_filename}" if threat_detected
            else f"Safe {req.modality.value if hasattr(req.modality, 'value') else req.modality} input from {req.source_uri_or_filename}"
        ),
        details={
            "intercept_id": intercept_id,
            "source": req.source_uri_or_filename,
            "session_permission_mask": perm_mask_val,
            "stripped_tools": stripped_list,
            "threats_found": len(cloaked_threats),
            "redactions": len(surgical_redactions),
            "redaction_count": redaction_res.diff_record.redaction_count,
            "xray_diff_segments": [seg.model_dump() for seg in redaction_res.xray_diff_segments],
            "raw_sha256": raw_evidence_sha256,
            "redacted_diff_sha256": redacted_diff_sha256,
            "false_positives_prevented_count": disambig_res.false_positives_prevented_count,
            "safe_business_directives_count": len(disambig_res.safe_business_directives_kept),
            "task_continuity_preserved": redaction_res.task_continuity_preserved,
        },

    )
    await telemetry_manager.broadcast_event(event)

    # Task 24: End-to-End Hook Wiring into Hyperledger Fabric Audit Event Pipeline
    try:
        dispatcher = getattr(interceptor_bridge, "audit_dispatcher", audit_dispatcher)
        await dispatcher.dispatch_audit_event(
            session_id=req.session_id,
            buyer_id=req.metadata.get("buyer_id") or getattr(settings, "DEFAULT_BUYER_ID", "buyer-01"),
            supplier_id=req.metadata.get("supplier_id") or getattr(settings, "DEFAULT_SUPPLIER_ID", "supplier-01"),
            input_modality=req.modality.value if hasattr(req.modality, "value") else str(req.modality),
            action_taken=action_taken,
            threat_detected=threat_detected,
            raw_evidence_sha256=raw_evidence_sha256,
            redacted_diff_sha256=redacted_diff_sha256,
            risk_category_ids=risk_category_ids,
            policy_reference="HOOK1_INBOUND_DE_CLOAK",
            metadata={
                "source": req.source_uri_or_filename,
                "hook_stage": "HOOK_1_INBOUND",
            },
            broadcast_telemetry=False,
        )
    except Exception as exc:
        logger.warning("Hook 1 audit dispatch failed: %s", exc)

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

    # ── 0a. Task 29 Fail-Closed Circuit Breaker Check (Risk #33) ─────────────
    fail_closed_res = fail_closed_breaker.enforce_fail_closed_before_action(req.tool_name)
    if fail_closed_res is not None and not fail_closed_res.allow_sandbox_execution:
        event = _telemetry_event(
            session_id=req.session_id,
            hook_stage="HOOK_2_TOOL_CALL",
            modality_or_tool=req.tool_name,
            threat_detected=True,
            action_taken="BLOCKED",
            risk_category_ids=fail_closed_res.risk_category_ids,
            summary=f"[FAIL-CLOSED LOCKDOWN] Tool '{req.tool_name}' blocked: {fail_closed_res.reason}",
            details={
                "intercept_id": intercept_id,
                "tool": req.tool_name,
                "reason": fail_closed_res.reason,
                "circuit_snapshot": fail_closed_breaker.get_circuit_snapshot(),
            },
        )
        await telemetry_manager.broadcast_event(event)
        logger.warning(
            "Hook2 [%s] session=%s tool=%s BLOCKED by fail-closed circuit breaker: %s",
            intercept_id, req.session_id, req.tool_name, fail_closed_res.reason,
        )
        return ToolCallInterceptResponse(
            intercept_id=intercept_id,
            session_id=req.session_id,
            execution_permitted=False,
            requires_human_approval_card=False,
            approval_card_id=None,
            action_taken="BLOCKED",
            policy_reference="TASK29_FAIL_CLOSED_CIRCUIT_BREAKER_RISK_33",
            reason=fail_closed_res.reason,
            execution_token_hmac=None,
            risk_category_ids=fail_closed_res.risk_category_ids,
            threat_detected=True,
        )

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

    # ── 0b. Task 18 Micro-Privilege Task Sandboxing Engine Check ─────────────
    norm_tool = req.tool_name.strip().lower()
    sandbox_res = micro_privilege_sandbox.evaluate_tool_call(
        session_id=req.session_id,
        tool_name=req.tool_name,
    )
    if not sandbox_res.allowed and norm_tool not in _HIGH_RISK_BANK_TOOLS:
        event = _telemetry_event(
            session_id=req.session_id,
            hook_stage="HOOK_2_TOOL_CALL",
            modality_or_tool=req.tool_name,
            threat_detected=True,
            action_taken="BLOCKED",
            risk_category_ids=sandbox_res.risk_category_ids,
            summary=f"[MICRO-PRIVILEGE BLOCKED] Tool '{req.tool_name}' blocked: {sandbox_res.reason}",
            details={
                "intercept_id": intercept_id,
                "tool": req.tool_name,
                "permission_mask": sandbox_res.permission_mask.value,
                "violated_category": sandbox_res.violated_category,
                "stripped_tools": sandbox_res.stripped_tools,
                "active_tool_bindings": sandbox_res.active_tool_bindings,
                "reason": sandbox_res.reason,
            },
        )
        await telemetry_manager.broadcast_event(event)
        logger.warning(
            "Hook2 [%s] session=%s tool=%s BLOCKED by micro-privilege sandbox: %s",
            intercept_id, req.session_id, req.tool_name, sandbox_res.reason,
        )
        return ToolCallInterceptResponse(
            intercept_id=intercept_id,
            session_id=req.session_id,
            execution_permitted=False,
            requires_human_approval_card=False,
            approval_card_id=None,
            action_taken="BLOCKED",
            policy_reference=f"TASK18_MICRO_PRIVILEGE_{sandbox_res.violated_category or 'SANDBOX'}",
            reason=sandbox_res.reason,
            execution_token_hmac=None,
            risk_category_ids=sandbox_res.risk_category_ids,
            threat_detected=True,
        )

    # ── 0c. Task 19 Zero-Click Outbound Exfiltration, URL/DNS & SSRF Firewall Check ───
    fw_tool_res = outbound_firewall.inspect_tool_call_urls(req.tool_name, req.tool_arguments)
    if not fw_tool_res.allowed:
        event = _telemetry_event(
            session_id=req.session_id,
            hook_stage="HOOK_2_TOOL_CALL",
            modality_or_tool=req.tool_name,
            threat_detected=True,
            action_taken="BLOCKED",
            risk_category_ids=fw_tool_res.risk_category_ids,
            summary=f"[FIREWALL BLOCKED] Tool '{req.tool_name}' blocked: {fw_tool_res.reason}",
            details={
                "intercept_id": intercept_id,
                "tool": req.tool_name,
                "urls_inspected": [f.model_dump() for f in fw_tool_res.urls_inspected],
                "reason": fw_tool_res.reason,
            },
        )
        await telemetry_manager.broadcast_event(event)
        logger.warning(
            "Hook2 [%s] session=%s tool=%s BLOCKED by outbound firewall: %s",
            intercept_id, req.session_id, req.tool_name, fw_tool_res.reason,
        )
        return ToolCallInterceptResponse(
            intercept_id=intercept_id,
            session_id=req.session_id,
            execution_permitted=False,
            requires_human_approval_card=False,
            approval_card_id=None,
            action_taken="BLOCKED",
            policy_reference="TASK19_OUTBOUND_FIREWALL_SSRF_OR_EXFIL",
            reason=fw_tool_res.reason,
            execution_token_hmac=None,
            risk_category_ids=fw_tool_res.risk_category_ids,
            threat_detected=True,
        )

    # ── 1. Layer 3 Deterministic Policy Gateway & Pydantic IFC Check ─────────
    contract_data = session_intent_contracts.get(req.session_id)


    if contract_data is None:
        reg_contract = intent_contract_registry.get_contract(req.session_id)
        if reg_contract is not None:
            contract_data = reg_contract.model_dump()

    eval_req = PolicyEvaluationRequest(
        session_id=req.session_id,
        tool_name=req.tool_name,
        tool_arguments=req.tool_arguments,
        argument_provenance=req.argument_provenance,
        intent_contract=contract_data,
        provided_intent_hmac_hash=req.intent_hmac_hash,
    )

    eval_res = deterministic_policy_gateway.evaluate_tool_call(eval_req)

    # ── 2. Task 17 — Supply-Chain PO-vs-Invoice Bank & Amount Verification ───
    # For payment tools, cross-check extracted invoice fields against
    # TRUSTED_PO_DB to block spoofed IBANs, inflated amounts, and
    # unverified delivery receipts before execution is permitted.
    _PAYMENT_TOOLS_PO_CHECK = frozenset({
        "schedule_payment", "schedule_verified_payment",
        "initiate_payment", "transfer_funds",
        "process_invoice_payment", "pay_vendor", "wire_transfer",
    })
    norm_tool_name = req.tool_name.lower().strip()
    if eval_res.execution_permitted and norm_tool_name in _PAYMENT_TOOLS_PO_CHECK:
        # Check if any payment-relevant arguments exist in the tool call
        po_relevant_keys = {
            "po_id", "po_number", "po_ref", "amount_inr", "amount",
            "iban_account", "beneficiary_iban", "bank_account",
            "supplier_id", "vendor_id",
        }
        tool_args: dict = dict(req.tool_arguments or {})
        # If explicit po_id is missing, attempt to extract from contract prompt
        if not (tool_args.get("po_id") or tool_args.get("po_number") or tool_args.get("po_ref")):
            if contract_data:
                prompt_text = str(contract_data.get("user_prompt", ""))
                po_match = re.search(r"PO[ -#]*(\d+)", prompt_text, re.I)
                if po_match:
                    tool_args["po_id"] = f"PO-{po_match.group(1)}"
        has_po_args = bool(po_relevant_keys & set(tool_args.keys()))
        if has_po_args:
            po_res = purchase_order_verifier.verify_invoice_against_po(
                invoice_data=tool_args,
                provenance_map=None,
            )
            if not po_res.execution_permitted:
                card = interceptor_bridge.step_back_approval_engine.create_approval_card(
                    session_id=req.session_id,
                    tool_name=req.tool_name,
                    tool_arguments=req.tool_arguments,
                    reason=po_res.reason,
                    risk_category_ids=po_res.risk_category_ids,
                    intent_hmac_hash=req.intent_hmac_hash or eval_res.intent_hmac_hash,
                    po_verification_result=po_res,
                    pdf_page_number=tool_args.get("pdf_page_number") or tool_args.get("source_page_number") or (po_res.approval_card.source_page_number if po_res.approval_card else 1),
                    pdf_line_number=tool_args.get("source_line_number") or tool_args.get("pdf_line_number") or tool_args.get("line_number") or (po_res.approval_card.source_line_number if po_res.approval_card else 1),
                    exact_source_line_text=tool_args.get("exact_source_line_text"),
                    source_file=tool_args.get("source_file") or (po_res.approval_card.source_file if po_res.approval_card else "poisoned_invoice_INV402.pdf"),
                )
                po_card_id = card.card_id
                approval_dict = card.model_dump()
                po_event = _telemetry_event(
                    session_id=req.session_id,
                    hook_stage="HOOK_2_TOOL_CALL",
                    modality_or_tool=req.tool_name,
                    threat_detected=True,
                    action_taken=po_res.action_taken,
                    risk_category_ids=po_res.risk_category_ids,
                    summary=f"[PO-VERIFIER BLOCKED] {po_res.reason}",
                    details={
                        "intercept_id": intercept_id,
                        "tool": req.tool_name,
                        "execution_permitted": False,
                        "reason": po_res.reason,
                        "action_taken": po_res.action_taken,
                        "po_id": po_res.po_id,
                        "discrepancies": po_res.discrepancies,
                        "approval_card_id": po_card_id,
                        "approval_card": approval_dict,
                    },
                )
                await telemetry_manager.broadcast_event(po_event)
                logger.warning(
                    "Hook2 [%s] session=%s tool=%s BLOCKED by PO verifier: %s",
                    intercept_id, req.session_id, req.tool_name, po_res.reason,
                )
                return ToolCallInterceptResponse(
                    intercept_id=intercept_id,
                    session_id=req.session_id,
                    execution_permitted=False,
                    requires_human_approval_card=True,
                    approval_card_id=po_card_id,
                    approval_card=approval_dict,
                    action_taken=po_res.action_taken,
                    policy_reference="TASK17_PO_VERIFIER_RISK_10_16_18",
                    reason=po_res.reason,
                    execution_token_hmac=None,
                    risk_category_ids=po_res.risk_category_ids,
                    threat_detected=True,
                )

    if eval_res.requires_human_approval_card:
        card = interceptor_bridge.step_back_approval_engine.create_approval_card(
            session_id=req.session_id,
            tool_name=req.tool_name,
            tool_arguments=req.tool_arguments,
            reason=eval_res.reason,
            risk_category_ids=eval_res.risk_category_ids,
            intent_hmac_hash=req.intent_hmac_hash or eval_res.intent_hmac_hash,
            pdf_page_number=req.tool_arguments.get("pdf_page_number") or req.tool_arguments.get("source_page_number") or 1,
            pdf_line_number=req.tool_arguments.get("source_line_number") or req.tool_arguments.get("pdf_line_number") or req.tool_arguments.get("line_number") or 1,
            exact_source_line_text=req.tool_arguments.get("exact_source_line_text"),
            source_file=req.tool_arguments.get("source_file") or "poisoned_invoice_INV402.pdf",
        )
        card_id = card.card_id
        approval_card_dict = card.model_dump()
    else:
        card_id = None
        approval_card_dict = None

    # Task 29: Issue cryptographic ExecutionPermitToken for permitted execution
    issued_permit_token = None
    final_execution_token_hmac = eval_res.execution_token_hmac
    if eval_res.execution_permitted and not eval_res.requires_human_approval_card:
        issued_permit_token = anti_bypass_verifier.issue_permit_token(
            session_id=req.session_id,
            tool_name=req.tool_name,
            tool_arguments=req.tool_arguments,
            intent_hmac_hash=eval_res.intent_hmac_hash or req.intent_hmac_hash or ("0" * 64),
        )
        final_execution_token_hmac = issued_permit_token.signature_hmac

    response = ToolCallInterceptResponse(
        intercept_id=intercept_id,
        session_id=req.session_id,
        execution_permitted=eval_res.execution_permitted,
        requires_human_approval_card=eval_res.requires_human_approval_card,
        approval_card_id=card_id,
        approval_card=approval_card_dict,
        action_taken=eval_res.action_taken,
        policy_reference=eval_res.policy_reference,
        reason=eval_res.reason,
        execution_token_hmac=final_execution_token_hmac,
        risk_category_ids=eval_res.risk_category_ids,
        threat_detected=eval_res.threat_detected,
    )


    event = _telemetry_event(
        session_id=req.session_id,
        hook_stage="HOOK_2_TOOL_CALL",
        modality_or_tool=req.tool_name,
        threat_detected=eval_res.threat_detected,
        action_taken=eval_res.action_taken,
        risk_category_ids=eval_res.risk_category_ids,
        summary=(
            f"[THREAT] Tool '{req.tool_name}' blocked/flagged: {eval_res.reason}"
            if eval_res.threat_detected
            else f"Tool '{req.tool_name}' approved"
        ),
        details={
            "intercept_id": intercept_id,
            "tool": req.tool_name,
            "execution_permitted": eval_res.execution_permitted,
            "reason": eval_res.reason,
            "action_taken": eval_res.action_taken,
            "ifc_violations": [v.model_dump() for v in eval_res.ifc_violations],
            "approval_card_id": card_id,
            "intent_hmac_hash": eval_res.intent_hmac_hash,
        },
    )
    await telemetry_manager.broadcast_event(event)

    # Task 24: End-to-End Hook Wiring into Hyperledger Fabric Audit Event Pipeline
    try:
        dispatcher = getattr(interceptor_bridge, "audit_dispatcher", audit_dispatcher)
        await dispatcher.dispatch_audit_event(
            session_id=req.session_id,
            buyer_id=req.tool_arguments.get("buyer_id") or getattr(settings, "DEFAULT_BUYER_ID", "buyer-01"),
            supplier_id=req.tool_arguments.get("supplier_id") or getattr(settings, "DEFAULT_SUPPLIER_ID", "supplier-01"),
            input_modality="tool_call",
            action_taken=eval_res.action_taken,
            threat_detected=eval_res.threat_detected,
            intent_hmac_hash=eval_res.intent_hmac_hash or req.intent_hmac_hash,
            risk_category_ids=eval_res.risk_category_ids,
            policy_reference=eval_res.policy_reference,
            metadata={
                "tool_name": req.tool_name,
                "hook_stage": "HOOK_2_TOOL_CALL",
            },
            broadcast_telemetry=False,
        )
    except Exception as exc:
        logger.warning("Hook 2 audit dispatch failed: %s", exc)

    logger.info(
        "Hook2 [%s] session=%s tool=%s permitted=%s action=%s",
        intercept_id, req.session_id, req.tool_name, eval_res.execution_permitted, eval_res.action_taken,
    )
    return response


# ========================= HOOK 3: MEMORY WRITE =============================

@interceptor_router.post("/memory", response_model=MemoryWriteInterceptResponse)
async def intercept_memory_write(req: MemoryWriteInterceptRequest) -> MemoryWriteInterceptResponse:
    """
    Hook 3 — Memory Write Interceptor.
    Guards MEMORY.md against sleeper-rule injection and tainted session writes.
    Delegates safe evaluation and Redis TTL routing to MemoryQuarantineVault.
    """
    intercept_id = _new_id()

    # ── 1. Determine session taint ──────────────────────────────────────────
    is_tainted = (
        req.session_tainted_by_untrusted_ext
        or session_taint_registry.get(req.session_id, False)
    )

    # ── 2. Evaluate and route via MemoryQuarantineVault ─────────────────────
    response = await memory_quarantine_vault.evaluate_and_route_memory(
        session_id=req.session_id,
        proposed_content=req.proposed_memory_content,
        session_tainted=is_tainted,
        target_memory_file=req.target_memory_file,
        intercept_id=intercept_id,
    )

    # ── 3. Broadcast real-time X-Ray telemetry ──────────────────────────────
    event = _telemetry_event(
        session_id=req.session_id,
        hook_stage="HOOK_3_MEMORY_WRITE",
        modality_or_tool=req.target_memory_file,
        threat_detected=response.threat_detected,
        action_taken=response.action_taken,
        risk_category_ids=response.risk_category_ids,
        summary=(
            f"[QUARANTINED] Memory write blocked for session {req.session_id}"
            if not response.persistent_write_allowed
            else f"Memory write approved for session {req.session_id}"
        ),
        details={
            "intercept_id": intercept_id,
            "tainted": is_tainted,
            "quarantine_key": response.quarantine_key,
            "ttl": response.ttl_seconds,
            "reason": response.reason,
            "risk_category_ids": response.risk_category_ids,
        },
    )
    await telemetry_manager.broadcast_event(event)

    # Task 24: End-to-End Hook Wiring into Hyperledger Fabric Audit Event Pipeline
    try:
        dispatcher = getattr(interceptor_bridge, "audit_dispatcher", audit_dispatcher)
        await dispatcher.dispatch_audit_event(
            session_id=req.session_id,
            buyer_id=getattr(settings, "DEFAULT_BUYER_ID", "buyer-01"),
            supplier_id=getattr(settings, "DEFAULT_SUPPLIER_ID", "supplier-01"),
            input_modality="memory_write",
            action_taken=response.action_taken,
            threat_detected=response.threat_detected,
            risk_category_ids=response.risk_category_ids,
            policy_reference="HOOK3_MEMORY_QUARANTINE_POLICY",
            metadata={
                "target_memory_file": req.target_memory_file,
                "hook_stage": "HOOK_3_MEMORY_WRITE",
            },
            broadcast_telemetry=False,
        )
    except Exception as exc:
        logger.warning("Hook 3 audit dispatch failed: %s", exc)

    logger.info(
        "Hook3 [%s] session=%s allowed=%s action=%s",
        intercept_id, req.session_id, response.persistent_write_allowed, response.action_taken,
    )
    return response


# ========================= HOOK 4: OUTBOUND OUTPUT ==========================

@interceptor_router.post("/output", response_model=OutboundOutputInterceptResponse)
async def intercept_outbound_output(req: OutboundOutputInterceptRequest) -> OutboundOutputInterceptResponse:
    """
    Hook 4 — Outbound Output / Zero-Click Exfiltration Firewall.
    Scans agent responses for EchoLeak, SSRF, non-whitelisted URLs, confidential leaks,
    and forged tool output tags using ZeroClickOutboundFirewall.
    """
    intercept_id = _new_id()

    # ── 1. ZeroClickOutboundFirewall processing (Task 19) ───────────────────
    fw_res = outbound_firewall.inspect_and_sanitize_outbound_text(req.raw_agent_response)

    # ── 2. Check any URLs explicitly listed in req.outbound_urls ────────────
    for url in req.outbound_urls:
        finding = outbound_firewall.inspect_url(url, is_markdown_image=False)
        if finding.is_blocked or finding.sanitized_url != url:
            if url not in fw_res.exfiltration_links_removed:
                fw_res.exfiltration_links_removed.append(url)
            for rid in finding.risk_category_ids:
                if rid not in fw_res.risk_category_ids:
                    fw_res.risk_category_ids.append(rid)
            fw_res.threat_detected = True

    action_taken = "SURGICALLY_REDACTED" if fw_res.threat_detected else "SAFE_EXECUTED"

    response = OutboundOutputInterceptResponse(
        intercept_id=intercept_id,
        sanitized_agent_response=fw_res.sanitized_text,
        sanitized_output_text=fw_res.sanitized_text,
        blocked_urls=fw_res.exfiltration_links_removed,
        exfiltration_links_removed=fw_res.exfiltration_links_removed,
        stripped_forged_tags=fw_res.forged_tags_removed,
        action_taken=action_taken,
        threat_detected=fw_res.threat_detected,
        risk_category_ids=sorted(list(set(fw_res.risk_category_ids))),
    )

    event = _telemetry_event(
        session_id=req.session_id,
        hook_stage="HOOK_4_OUTBOUND",
        modality_or_tool="agent_response",
        threat_detected=fw_res.threat_detected,
        action_taken=action_taken,
        risk_category_ids=response.risk_category_ids,
        summary=(
            f"[EXFILTRATION BLOCKED] {len(fw_res.exfiltration_links_removed)} URL(s) stripped from output"
            if fw_res.threat_detected
            else "Outbound output is clean"
        ),
        details={
            "intercept_id": intercept_id,
            "blocked_urls": fw_res.exfiltration_links_removed,
            "exfiltration_links_removed": fw_res.exfiltration_links_removed,
            "forged_tags": fw_res.forged_tags_removed,
            "reason": fw_res.reason,
        },
    )
    await telemetry_manager.broadcast_event(event)

    # Task 24: End-to-End Hook Wiring into Hyperledger Fabric Audit Event Pipeline
    try:
        dispatcher = getattr(interceptor_bridge, "audit_dispatcher", audit_dispatcher)
        await dispatcher.dispatch_audit_event(
            session_id=req.session_id,
            buyer_id=getattr(settings, "DEFAULT_BUYER_ID", "buyer-01"),
            supplier_id=getattr(settings, "DEFAULT_SUPPLIER_ID", "supplier-01"),
            input_modality="outbound_output",
            action_taken=action_taken,
            threat_detected=fw_res.threat_detected,
            risk_category_ids=response.risk_category_ids,
            policy_reference="HOOK4_OUTBOUND_FIREWALL",
            metadata={
                "blocked_urls_count": len(fw_res.exfiltration_links_removed),
                "hook_stage": "HOOK_4_OUTBOUND",
            },
            broadcast_telemetry=False,
        )
    except Exception as exc:
        logger.warning("Hook 4 audit dispatch failed: %s", exc)

    logger.info(
        "Hook4 [%s] session=%s threat=%s action=%s blocked_urls=%d",
        intercept_id, req.session_id, fw_res.threat_detected, action_taken, len(fw_res.exfiltration_links_removed),
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
    session_intent_contracts.pop(session_id, None)
    return {
        "session_id": session_id,
        "status": "reset_successful",
        "message": f"Resource budget and intent contract for session '{session_id}' have been reset.",
    }


# ========================= STEP-0 INTENT CONTRACT ENDPOINTS ==================

@interceptor_router.post("/register-intent")
async def register_intent_endpoint(contract_data: Dict[str, Any]) -> dict:
    """
    Registers an active Step0IntentContract in the OpenClaw Interceptor Bridge session registry.
    """
    session_id = contract_data.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id is required")
    session_intent_contracts[session_id] = contract_data
    try:
        contract = Step0IntentContract(**contract_data)
        intent_contract_registry.force_register_contract(contract)
    except Exception as exc:
        logger.warning("Could not register Step0IntentContract in registry: %s", exc)
    return {"status": "registered", "session_id": session_id}


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
    session_intent_contracts[req.session_id] = contract.model_dump()

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
    raw_content_base64: Optional[str] = None
    raw_content_text: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


@interceptor_router.post("/decloak/document", response_model=DocumentDeCloakResult)
async def decloak_document_endpoint(req: DocumentDeCloakRequest) -> DocumentDeCloakResult:
    """
    Direct inspection endpoint for Forensic X-Ray UI and testing.
    Runs Pre-OCR De-Cloaker on base64-encoded PDF, DOCX, Image, Audio, Video, Web DOM, Email, or Chat file.
    """
    if req.modality in ("email", "chat") or req.filename.lower().endswith((".eml", ".msg")):
        raw_in: Union[bytes, str] = (
            base64.b64decode(req.raw_content_base64)
            if req.raw_content_base64
            else (req.raw_content_text or "")
        )
        return email_chat_scanner.scan_message_bytes(
            raw_input=raw_in,
            metadata=req.metadata,
            modality=req.modality or "email",
            filename=req.filename,
        )

    if req.modality in ("archive", "zip", "csv_xlsx", "xlsx", "csv") or req.filename.lower().endswith(
        (".zip", ".tar", ".gz", ".7z", ".rar", ".xlsx", ".xlsm", ".csv")
    ):
        file_bytes = (
            base64.b64decode(req.raw_content_base64)
            if req.raw_content_base64
            else (req.raw_content_text or "").encode("utf-8")
        )
        return archive_file_scanner.scan_file_bytes(
            file_bytes=file_bytes,
            filename=req.filename,
            modality=req.modality,
        )

    file_bytes = base64.b64decode(req.raw_content_base64) if req.raw_content_base64 else b""
    if req.modality in ("image", "screenshot", "receipt") or req.filename.lower().endswith(
        (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff")
    ):
        return image_decloaker.decloak_image_bytes(file_bytes=file_bytes, filename=req.filename)
    elif req.modality in ("audio", "video") or req.filename.lower().endswith(
        (".mp3", ".wav", ".ogg", ".mp4", ".mov", ".m4a", ".webm")
    ):
        mod_str = req.modality or ("video" if req.filename.lower().endswith((".mp4", ".mov", ".m4a", ".webm")) else "audio")
        return audio_video_decloaker.decloak_media_bytes(file_bytes=file_bytes, modality=mod_str, filename=req.filename)
    elif req.modality in ("web_dom", "html") or req.filename.lower().endswith((".html", ".htm")):
        return web_dom_decloaker.decloak_web_dom_bytes(html_input=file_bytes, filename=req.filename)
    return pdf_docx_decloaker.decloak_document(
        file_bytes=file_bytes,
        filename=req.filename,
        modality=req.modality,
    )


# ========================= TASK 29 PRE-EXECUTION GATE =======================

class CircuitBreakerStatusUpdate(BaseModel):
    service_name: Optional[str] = None
    status_code: Optional[int] = 200
    error_msg: Optional[str] = None
    reset: Optional[bool] = False


openclaw_sandbox_router = APIRouter(prefix="/openclaw", tags=["openclaw-sandbox"])


@openclaw_sandbox_router.post("/verify-execution-token", response_model=SandboxToolVerifyResponse)
@interceptor_router.post("/verify-execution-token", response_model=SandboxToolVerifyResponse)
async def verify_execution_token_endpoint(req: SandboxToolVerifyRequest) -> SandboxToolVerifyResponse:
    """
    Task 29 — Pre-Execution Sandbox Gate (Risk #30 & Risk #33).
    Verifies that the tool call has a valid, unexpired, un-replayed ExecutionPermitToken,
    and checks if the fail-closed circuit breaker is tripped for sensitive actions.
    """
    # 1. Fail-closed circuit breaker check
    fail_closed_res = fail_closed_breaker.enforce_fail_closed_before_action(req.tool_name)
    if fail_closed_res is not None:
        return fail_closed_res

    # 2. Anti-bypass token verification
    verify_res = anti_bypass_verifier.verify_permit_token(req)
    return verify_res


@openclaw_sandbox_router.get("/circuit-status")
@interceptor_router.get("/circuit-status")
async def get_circuit_status():
    """Returns the diagnostic snapshot of all tracked security dependencies."""
    return {
        "status": "active",
        "services": fail_closed_breaker.get_circuit_snapshot(),
    }


@openclaw_sandbox_router.post("/circuit-status")
@interceptor_router.post("/circuit-status")
async def update_circuit_status(payload: CircuitBreakerStatusUpdate):
    """Updates the status of a security dependency or trips/resets it."""
    if payload.reset:
        fail_closed_breaker.reset_circuit()
        return {
            "status": "reset",
            "message": "All security dependencies reset to healthy.",
            "circuit_snapshot": fail_closed_breaker.get_circuit_snapshot(),
        }

    if payload.service_name:
        fail_closed_breaker.record_service_status(
            service_name=payload.service_name,
            status_code=payload.status_code if payload.status_code is not None else 200,
            error_msg=payload.error_msg,
        )

    return {
        "status": "updated",
        "service_name": payload.service_name,
        "recorded_code": payload.status_code,
        "circuit_snapshot": fail_closed_breaker.get_circuit_snapshot(),
    }




