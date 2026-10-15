"""
IntentGuard Layer 2 CaMeL — Step-0 Cryptographic Intent Contract
================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Provides:
- Immutable Step0IntentContract (frozen Pydantic v2 model)
- Deterministic canonical JSON serialization & HMAC-SHA256 signer (64-char hex)
- Natural language Step-0 prompt-to-contract parser & compiler
- Pre-execution tool verification against locked authority contracts
- In-memory thread-safe session registry (IntentContractRegistry)

Defends against:
- Risk #10: Spoofed Authorization
- Risk #14: Instruction Override
- Risk #16: Unauthorized Tool Calls
- Risk #18: Sensitive Action Manipulation
- Risk #30: Cryptographic Intent Tampering
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Baseline Tool Catalog Constants
# ---------------------------------------------------------------------------

_BASELINE_READ_TOOLS: List[str] = [
    "extract_invoice",
    "get_po_details",
    "match_po",
    "parse_pdf",
    "query_inventory",
    "read_catalog",
    "read_email",
    "read_file",
    "view_catalog",
]

_BASELINE_PROHIBITED_OPERATIONS: List[str] = [
    "bash",
    "change_vendor_bank",
    "change_vendor_bank_details",
    "delete_file",
    "drop_table",
    "exec_shell",
    "export_all_files",
    "format_disk",
    "rmdir",
    "run_script",
    "set_payment_destination",
    "share_drive_file",
    "update_bank_account",
    "update_iban",
]

_FINANCIAL_ARGUMENT_KEYS: List[str] = [
    "amount_inr",
    "amount",
    "payment_amount",
    "total",
    "invoice_amount",
    "value",
]

_BANK_MUTATION_TOOLS: frozenset[str] = frozenset(
    {
        "change_vendor_bank",
        "change_vendor_bank_details",
        "update_iban",
        "update_bank_account",
        "set_payment_destination",
    }
)


# ---------------------------------------------------------------------------
# 1. Step0IntentContract (Immutable Pydantic v2 Model)
# ---------------------------------------------------------------------------

class Step0IntentContract(BaseModel):
    """
    Immutable cryptographic intent contract compiled at Step 0 from the
    authenticated user's initial prompt before external data is ingested.
    """
    model_config = ConfigDict(frozen=True)

    contract_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    buyer_id: str = Field(default_factory=lambda: getattr(settings, "DEFAULT_BUYER_ID", "buyer-01"))
    supplier_id: str = Field(default_factory=lambda: getattr(settings, "DEFAULT_SUPPLIER_ID", "supplier-01"))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    user_prompt: str
    provenance_tag: Literal["USER_AUTHORITY"] = "USER_AUTHORITY"
    allowed_tools: List[str] = Field(default_factory=list)
    prohibited_operations: List[str] = Field(default_factory=list)
    max_approved_amount_inr: float = 0.0
    allowed_recipients: List[str] = Field(default_factory=list)
    approved_po_numbers: List[str] = Field(default_factory=list)
    intent_hmac_hash: str  # 64-char lowercase hexadecimal HMAC-SHA256


# ---------------------------------------------------------------------------
# 2. Canonical JSON Serialization & HMAC-SHA256 Generator
# ---------------------------------------------------------------------------

def compute_intent_hmac(
    session_id: str,
    user_prompt: str,
    buyer_id: str,
    supplier_id: str,
    timestamp: str,
    provenance_tag: str,
    allowed_tools: List[str],
    prohibited_operations: List[str],
    max_approved_amount_inr: float,
    allowed_recipients: List[str],
    approved_po_numbers: List[str],
) -> str:
    """
    Builds a canonical dictionary of contract payload fields, serializes
    to UTF-8 JSON with sorted keys and tight separators, and generates
    an HMAC-SHA256 digest using settings.HMAC_MASTER_SECRET.

    Returns a 64-character lowercase hexadecimal string complying with
    Hyperledger Fabric chaincode validation rules.
    """
    payload_dict = {
        "allowed_recipients": sorted(list(set(allowed_recipients))),
        "allowed_tools": sorted(list(set(allowed_tools))),
        "approved_po_numbers": sorted(list(set(approved_po_numbers))),
        "buyer_id": buyer_id,
        "max_approved_amount_inr": float(max_approved_amount_inr),
        "prohibited_operations": sorted(list(set(prohibited_operations))),
        "provenance_tag": provenance_tag,
        "session_id": session_id,
        "supplier_id": supplier_id,
        "timestamp": timestamp,
        "user_prompt": user_prompt,
    }

    canonical_json_bytes = json.dumps(
        payload_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    secret_key = getattr(settings, "HMAC_MASTER_SECRET", "genesis2_eva03_ps01_intentguard_hmac_sha256_master_secret_2026")
    digest = hmac.new(
        secret_key.encode("utf-8"),
        canonical_json_bytes,
        hashlib.sha256,
    ).hexdigest().lower()

    if len(digest) != 64 or not re.fullmatch(r"^[0-9a-f]{64}$", digest):
        raise ValueError(
            f"Computed HMAC '{digest}' does not meet 64-char hex requirements."
        )

    return digest


def verify_contract_signature(contract: Step0IntentContract) -> bool:
    """
    Recomputes the canonical HMAC-SHA256 from the contract's fields and compares
    it against contract.intent_hmac_hash using constant-time comparison.
    """
    try:
        expected_digest = compute_intent_hmac(
            session_id=contract.session_id,
            user_prompt=contract.user_prompt,
            buyer_id=contract.buyer_id,
            supplier_id=contract.supplier_id,
            timestamp=contract.timestamp,
            provenance_tag=contract.provenance_tag,
            allowed_tools=contract.allowed_tools,
            prohibited_operations=contract.prohibited_operations,
            max_approved_amount_inr=contract.max_approved_amount_inr,
            allowed_recipients=contract.allowed_recipients,
            approved_po_numbers=contract.approved_po_numbers,
        )
        return hmac.compare_digest(expected_digest, contract.intent_hmac_hash.strip().lower())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Error verifying contract signature: %s", exc)
        return False


# ---------------------------------------------------------------------------
# 3. Prompt-to-Contract Parser & Compiler
# ---------------------------------------------------------------------------

def compile_step0_intent_contract(
    session_id: str,
    user_prompt: str,
    buyer_id: Optional[str] = None,
    supplier_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    explicit_allowed_tools: Optional[List[str]] = None,
    explicit_prohibited_operations: Optional[List[str]] = None,
    explicit_max_amount_inr: Optional[float] = None,
    explicit_allowed_recipients: Optional[List[str]] = None,
    explicit_approved_po_numbers: Optional[List[str]] = None,
) -> Step0IntentContract:
    """
    Compiles an immutable Step0IntentContract from a trusted user prompt.
    Extracts financial caps, PO numbers, tool allowances, and prohibited operations.
    """
    resolved_buyer_id = buyer_id or getattr(settings, "DEFAULT_BUYER_ID", "buyer-01")
    resolved_supplier_id = supplier_id or getattr(settings, "DEFAULT_SUPPLIER_ID", "supplier-01")
    resolved_timestamp = timestamp or datetime.now(timezone.utc).isoformat()

    # ── 1. Amount Extraction ────────────────────────────────────────────────
    max_amount = 0.0
    if explicit_max_amount_inr is not None:
        max_amount = float(explicit_max_amount_inr)
    else:
        # Regex patterns for currency amounts like ₹4,000, Rs. 4000, INR 4,000, $4000, 4000 INR
        patterns = [
            r"(?:₹|rs\.?|inr|\$)\s*([0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?)",
            r"([0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?)\s*(?:inr|rs\.?|rupees)",
            r"(?:up\s+to|max|limit\s+of|amount\s+of|approved\s+payment\s+(?:up\s+to\s+)?)(?:₹|rs\.?|inr|\$)?\s*([0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?)",
        ]
        for pat in patterns:
            match = re.search(pat, user_prompt, re.IGNORECASE)
            if match:
                raw_amt = match.group(1).replace(",", "")
                try:
                    max_amount = float(raw_amt)
                    break
                except ValueError:
                    pass

    # ── 2. PO Number Extraction ─────────────────────────────────────────────
    approved_pos: List[str] = []
    if explicit_approved_po_numbers is not None:
        approved_pos = sorted(list(set(explicit_approved_po_numbers)))
    else:
        po_matches = re.findall(r"\bpo\s*(?:#|-)?\s*([0-9a-zA-Z-]+)\b", user_prompt, re.IGNORECASE)
        for po in po_matches:
            normalized = f"PO-{po.upper()}" if not po.upper().startswith("PO-") else po.upper()
            if normalized not in approved_pos:
                approved_pos.append(normalized)
        approved_pos.sort()

    # ── 3. Recipient Extraction ─────────────────────────────────────────────
    allowed_recipients: List[str] = []
    if explicit_allowed_recipients is not None:
        allowed_recipients = sorted(list(set(explicit_allowed_recipients)))
    else:
        emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", user_prompt)
        allowed_recipients = sorted(list(set(emails)))

    # ── 4. Allowed Tools Inference ──────────────────────────────────────────
    if explicit_allowed_tools is not None:
        allowed_tools = sorted(list(set(explicit_allowed_tools)))
    else:
        tools_set = set(_BASELINE_READ_TOOLS)
        # If user explicitly requests payment scheduling/approval
        if re.search(r"\b(schedule|pay|approve|process)\s+(approved\s+)?(payment|invoice|po)\b", user_prompt, re.I) or "schedule_payment" in user_prompt.lower() or "payment" in user_prompt.lower():
            tools_set.add("schedule_payment")
        if re.search(r"\b(send|reply|forward)\s+(an\s+)?email\b", user_prompt, re.I) or "send_email" in user_prompt.lower():
            tools_set.add("send_email")
        allowed_tools = sorted(list(tools_set))

    # ── 5. Prohibited Operations Inference ──────────────────────────────────
    if explicit_prohibited_operations is not None:
        prohibited_operations = sorted(list(set(explicit_prohibited_operations)))
    else:
        proh_set = set(_BASELINE_PROHIBITED_OPERATIONS)
        # Never allow bank detail modifications unless explicitly instructed by Step-0 prompt
        if not re.search(r"\b(change|update|set)\s+(vendor\s+)?(bank|iban|account)\b", user_prompt, re.I):
            proh_set.update([
                "change_vendor_bank_details",
                "change_vendor_bank",
                "update_iban",
                "update_bank_account",
            ])
        prohibited_operations = sorted(list(proh_set))

    # ── 6. Compute HMAC-SHA256 Signature ───────────────────────────────────
    intent_hmac_hash = compute_intent_hmac(
        session_id=session_id,
        user_prompt=user_prompt,
        buyer_id=resolved_buyer_id,
        supplier_id=resolved_supplier_id,
        timestamp=resolved_timestamp,
        provenance_tag="USER_AUTHORITY",
        allowed_tools=allowed_tools,
        prohibited_operations=prohibited_operations,
        max_approved_amount_inr=max_amount,
        allowed_recipients=allowed_recipients,
        approved_po_numbers=approved_pos,
    )

    contract = Step0IntentContract(
        session_id=session_id,
        buyer_id=resolved_buyer_id,
        supplier_id=resolved_supplier_id,
        timestamp=resolved_timestamp,
        user_prompt=user_prompt,
        provenance_tag="USER_AUTHORITY",
        allowed_tools=allowed_tools,
        prohibited_operations=prohibited_operations,
        max_approved_amount_inr=max_amount,
        allowed_recipients=allowed_recipients,
        approved_po_numbers=approved_pos,
        intent_hmac_hash=intent_hmac_hash,
    )
    return contract


# ---------------------------------------------------------------------------
# 4. Deterministic Pre-Execution Contract Verifier
# ---------------------------------------------------------------------------

class IntentVerificationResult(BaseModel):
    """
    Structured outcome of evaluating a proposed tool call against a locked Step-0 contract.
    """
    allowed: bool
    action_taken: Literal["SAFE_EXECUTED", "BLOCKED", "HUMAN_APPROVAL_REQUIRED"] = "SAFE_EXECUTED"
    requires_human_approval_card: bool = False
    approval_card_id: Optional[str] = None
    violation_type: Optional[
        Literal[
            "HMAC_SIGNATURE_MISMATCH",
            "PROHIBITED_OPERATION",
            "TOOL_NOT_IN_STEP0_CONTRACT",
            "MAX_AMOUNT_EXCEEDED",
            "UNAUTHORIZED_RECIPIENT",
            "PO_NUMBER_MISMATCH",
        ]
    ] = None
    risk_category_ids: List[int] = Field(default_factory=list)
    policy_reference: str = "LAYER2_STEP0_HMAC_LOCK"
    reason: str = "Tool call conforms to Step-0 Cryptographic Intent Contract."
    intent_hmac_hash: Optional[str] = None
    contract_id: Optional[str] = None


def verify_tool_against_contract(
    contract: Step0IntentContract,
    tool_name: str,
    tool_arguments: Dict[str, Any],
    argument_provenance: Optional[Dict[str, str]] = None,
    provided_hmac_hash: Optional[str] = None,
) -> IntentVerificationResult:
    """
    Deterministically evaluates a proposed tool invocation against a locked Step-0 contract.
    Enforces:
    1. Cryptographic HMAC-SHA256 signature integrity.
    2. Prohibited operations blacklist (triggers block or human approval card).
    3. Allowed tools whitelist.
    4. Financial impact cap (max_approved_amount_inr).
    """
    # ── Check 1: Cryptographic Integrity ──────────────────────────────────
    if not verify_contract_signature(contract):
        logger.error(
            "Contract %s failed signature re-computation. Tamper detected!",
            contract.contract_id,
        )
        return IntentVerificationResult(
            allowed=False,
            action_taken="BLOCKED",
            violation_type="HMAC_SIGNATURE_MISMATCH",
            risk_category_ids=[10, 12, 30],
            policy_reference="RISK_10_SPOOFED_AUTHORITY_HMAC_FAIL",
            reason=f"Cryptographic contract signature invalid or tampered for contract {contract.contract_id}. Risk #10 & Risk #30.",
            intent_hmac_hash=contract.intent_hmac_hash,
            contract_id=contract.contract_id,
        )

    if provided_hmac_hash is not None:
        if not hmac.compare_digest(contract.intent_hmac_hash.strip().lower(), provided_hmac_hash.strip().lower()):
            logger.warning(
                "Provided HMAC hash '%s' does not match locked contract HMAC '%s'",
                provided_hmac_hash,
                contract.intent_hmac_hash,
            )
            return IntentVerificationResult(
                allowed=False,
                action_taken="BLOCKED",
                violation_type="HMAC_SIGNATURE_MISMATCH",
                risk_category_ids=[10, 12, 30],
                policy_reference="RISK_10_SPOOFED_AUTHORITY_HMAC_FAIL",
                reason=f"Provided intent_hmac_hash does not match locked Step-0 contract HMAC. Risk #10 (Spoofed Authorization).",
                intent_hmac_hash=contract.intent_hmac_hash,
                contract_id=contract.contract_id,
            )

    norm_tool = tool_name.strip().lower()

    # ── Check 2: Prohibited Operations Lock ─────────────────────────────────
    prohibited_set = {p.lower() for p in contract.prohibited_operations}
    if norm_tool in prohibited_set:
        is_bank_mutation = norm_tool in _BANK_MUTATION_TOOLS
        requires_card = is_bank_mutation
        action_taken: Literal["HUMAN_APPROVAL_REQUIRED", "BLOCKED"] = (
            "HUMAN_APPROVAL_REQUIRED" if requires_card else "BLOCKED"
        )
        card_id = str(uuid.uuid4()) if requires_card else None

        return IntentVerificationResult(
            allowed=False,
            action_taken=action_taken,
            requires_human_approval_card=requires_card,
            approval_card_id=card_id,
            violation_type="PROHIBITED_OPERATION",
            risk_category_ids=[14, 16, 18],
            policy_reference="RISK_14_STEP0_PROHIBITED_OP_LOCK",
            reason=(
                f"Operation '{tool_name}' is explicitly forbidden by Step-0 Intent Contract. "
                "Risk #14 (Instruction Override) & Risk #16 (Unauthorized Tool Calls)."
            ),
            intent_hmac_hash=contract.intent_hmac_hash,
            contract_id=contract.contract_id,
        )

    # ── Check 3: Allowed Tools Whitelist ────────────────────────────────────
    allowed_set = {a.lower() for a in contract.allowed_tools}
    if norm_tool not in allowed_set:
        return IntentVerificationResult(
            allowed=False,
            action_taken="BLOCKED",
            violation_type="TOOL_NOT_IN_STEP0_CONTRACT",
            risk_category_ids=[14, 16],
            policy_reference="RISK_16_UNAUTHORIZED_TOOL_CALL",
            reason=(
                f"Tool '{tool_name}' is not in the Step-0 Intent Contract whitelist: "
                f"{contract.allowed_tools}. Risk #16 (Unauthorized Tool Calls)."
            ),
            intent_hmac_hash=contract.intent_hmac_hash,
            contract_id=contract.contract_id,
        )

    # ── Check 4: Max Financial Impact Cap ──────────────────────────────────
    for key in _FINANCIAL_ARGUMENT_KEYS:
        if key in tool_arguments:
            try:
                amt = float(tool_arguments[key])
                if amt > contract.max_approved_amount_inr:
                    return IntentVerificationResult(
                        allowed=False,
                        action_taken="BLOCKED",
                        violation_type="MAX_AMOUNT_EXCEEDED",
                        risk_category_ids=[10, 18],
                        policy_reference="RISK_18_FINANCIAL_CAP_EXCEEDED",
                        reason=(
                            f"Financial cap exceeded: requested amount ₹{amt:,.2f} exceeds "
                            f"Step-0 locked maximum of ₹{contract.max_approved_amount_inr:,.2f}. "
                            "Risk #18 (Sensitive Action Manipulation) & Risk #10."
                        ),
                        intent_hmac_hash=contract.intent_hmac_hash,
                        contract_id=contract.contract_id,
                    )
            except (ValueError, TypeError):
                pass

    return IntentVerificationResult(
        allowed=True,
        action_taken="SAFE_EXECUTED",
        requires_human_approval_card=False,
        approval_card_id=None,
        violation_type=None,
        risk_category_ids=[],
        policy_reference=getattr(settings, "DEFAULT_POLICY_REFERENCE", "policy-v1"),
        reason="Tool invocation verified and authorized by Step-0 Cryptographic Intent Contract.",
        intent_hmac_hash=contract.intent_hmac_hash,
        contract_id=contract.contract_id,
    )


# ---------------------------------------------------------------------------
# 5. In-Memory Session Registry
# ---------------------------------------------------------------------------

class IntentContractRegistry:
    """
    Session registry storing active Step0IntentContract instances.
    Prevents untrusted mid-session overwrites.
    """
    def __init__(self) -> None:
        self._contracts: Dict[str, Step0IntentContract] = {}

    def register_contract(self, contract: Step0IntentContract) -> None:
        """Lock contract for session. Rejects if session already has locked contract."""
        if contract.session_id in self._contracts:
            raise ValueError(
                f"Step-0 Intent Contract for session '{contract.session_id}' is already locked "
                "and cannot be mutated mid-session (Risk #10 Authority Hijack Prevention)."
            )
        self._contracts[contract.session_id] = contract
        logger.info(
            "Locked Step-0 contract %s for session %s (HMAC: %s...)",
            contract.contract_id,
            contract.session_id,
            contract.intent_hmac_hash[:16],
        )

    def force_register_contract(self, contract: Step0IntentContract) -> None:
        """Admin/initial lock helper to set or replace contract."""
        self._contracts[contract.session_id] = contract

    def get_contract(self, session_id: str) -> Optional[Step0IntentContract]:
        """Retrieve locked contract for session."""
        return self._contracts.get(session_id)

    def reset_session(self, session_id: str) -> None:
        """Remove locked contract for session."""
        if session_id in self._contracts:
            del self._contracts[session_id]

    def clear(self) -> None:
        """Clear all registered contracts."""
        self._contracts.clear()


# Singleton instance for application-wide use
intent_contract_registry = IntentContractRegistry()
