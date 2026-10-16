"""
IntentGuard Layer 3 — Deterministic Policy & Taint Verifier (HMAC-SHA256 + Pydantic IFC)
========================================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01 — Separating Data from Authority

Enforces 100% deterministic, non-bypassable Python policies:
1. Gate 1: Cryptographic Step-0 HMAC-SHA256 contract verification (tamper resistance)
2. Gate 2: Step-0 Tool Allowlist and Prohibited Operations check
3. Gate 3: Credential & API Key Leakage Guard (Risk #25)
4. Gate 4: Strict Pydantic Information Flow Control (IFC) on Outbound Recipient Sinks (Risks #21, #27)
5. Gate 5: Strict Pydantic IFC on Financial Destination Sinks & Amount Caps (Risks #10, #18)
6. Gate 6: Deterministic execution token HMAC issuance on approval
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import uuid
from typing import Any, Dict, List, Literal, Optional, Set, Union

from pydantic import BaseModel, ConfigDict, Field

from app.config import settings
from app.layer2_camel.intent_contract import (
    Step0IntentContract,
    intent_contract_registry,
    verify_contract_signature,
)
from app.layer2_camel.provenance_wrapper import ProvenanceEnvelope, ProvenanceOrigin
from app.layer3_policy.micro_privilege import MicroPrivilegeSandbox, micro_privilege_sandbox
from app.layer3_policy.outbound_firewall import ZeroClickOutboundFirewall, outbound_firewall

logger = logging.getLogger(__name__)



# ---------------------------------------------------------------------------
# Constants & Risk Mappings
# ---------------------------------------------------------------------------

HIGH_IMPACT_TOOLS: Set[str] = {
    "schedule_payment",
    "schedule_verified_payment",
    "initiate_payment",
    "transfer_funds",
    "change_vendor_bank",
    "change_vendor_bank_details",
    "update_iban",
    "send_email",
    "share_file",
    "webhook_post",
    "export_database",
    "delete_file",
    "exec_shell",
    "bash",
    "write_file",
}

OUTBOUND_RECIPIENT_SINKS: Set[str] = {
    "email_to",
    "recipient",
    "to",
    "cc",
    "bcc",
    "webhook_url",
    "share_target",
    "destination_url",
    "callback_url",
}

FINANCIAL_DESTINATION_SINKS: Set[str] = {
    "beneficiary_iban",
    "iban_account",
    "bank_account",
    "stated_bank_iban",
    "payout_account",
    "routing_number",
}

AMOUNT_ARGUMENT_KEYS: Set[str] = {
    "amount",
    "amount_inr",
    "total_amount_inr",
    "payment_amount",
}

UNCONDITIONAL_PROHIBITED_TOOLS: Set[str] = {
    "exec_shell",
    "bash",
    "delete_file",
    "export_database",
    "drop_table",
    "format_disk",
    "rmdir",
    "run_script",
}

BANK_MUTATION_TOOLS: Set[str] = {
    "change_vendor_bank",
    "change_vendor_bank_details",
    "update_iban",
    "update_bank_account",
    "set_payment_destination",
}

PAYMENT_EXECUTION_TOOLS: Set[str] = {
    "schedule_payment",
    "schedule_verified_payment",
    "initiate_payment",
    "transfer_funds",
}

CREDENTIAL_LEAK_REGEXES: List[re.Pattern] = [
    re.compile(r"gsk_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{30,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]{20,}", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
]


# ---------------------------------------------------------------------------
# Pydantic Models for Taint Tracking & Policy Evaluation
# ---------------------------------------------------------------------------

class TaintedArgument(BaseModel):
    """Encapsulates an argument name, runtime value, and its provenance origin."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    arg_name: str
    value: Any
    origin: Literal["USER_AUTHORITY", "TRUSTED_PO_DB", "UNTRUSTED_EXT"] = "UNTRUSTED_EXT"
    source_reference: Optional[str] = None


class PolicyEvaluationRequest(BaseModel):
    """Incoming request to evaluate a proposed tool invocation against deterministic policy."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_id: str
    tool_name: str
    tool_arguments: Dict[str, Any] = Field(default_factory=dict)
    argument_provenance: Dict[str, str] = Field(default_factory=dict)
    intent_contract: Optional[Dict[str, Any]] = None
    provided_intent_hmac_hash: Optional[str] = None


class IFCViolationDetail(BaseModel):
    """Detailed record of an Information Flow Control policy violation."""
    arg_name: str
    sink_category: Literal[
        "OUTBOUND_RECIPIENT_SINK",
        "FINANCIAL_DESTINATION_SINK",
        "AMOUNT_LIMIT_SINK",
        "CREDENTIAL_LEAK_SINK",
        "PROHIBITED_TOOL",
        "HMAC_MISMATCH",
    ]
    actual_origin: str
    required_origins: List[str]
    risk_id: int
    description: str


class PolicyEvaluationResult(BaseModel):
    """Deterministic result of evaluating a proposed tool call."""
    session_id: str
    tool_name: str
    execution_permitted: bool
    requires_human_approval_card: bool = False
    action_taken: Literal["SAFE_EXECUTED", "BLOCKED", "HUMAN_APPROVAL_REQUIRED"]
    policy_reference: str
    reason: str
    ifc_violations: List[IFCViolationDetail] = Field(default_factory=list)
    risk_category_ids: List[int] = Field(default_factory=list)
    threat_detected: bool
    execution_token_hmac: Optional[str] = None
    intent_hmac_hash: str = ""


# ---------------------------------------------------------------------------
# Pydantic Information Flow Control (IFC) Rule Engine
# ---------------------------------------------------------------------------

class PydanticIFCRuleEngine:
    """
    Evaluates runtime arguments against Information Flow Control (IFC) taint sink rules.
    Guarantees untrusted data (UNTRUSTED_EXT) cannot flow into sensitive control/output sinks.
    """

    @staticmethod
    def normalize_arguments(
        tool_arguments: Dict[str, Any],
        argument_provenance: Dict[str, str],
        session_id: str,
        session_tainted: bool = False,
    ) -> Dict[str, TaintedArgument]:
        """
        Normalizes raw tool arguments and unwraps ProvenanceEnvelope objects if present.
        Assigns provenance origin based on envelope, explicit map, or session taint state.
        """
        normalized: Dict[str, TaintedArgument] = {}

        for arg_name, raw_val in tool_arguments.items():
            if isinstance(raw_val, ProvenanceEnvelope):
                clean_value = raw_val.value
                origin: Literal["USER_AUTHORITY", "TRUSTED_PO_DB", "UNTRUSTED_EXT"] = (
                    raw_val.origin if raw_val.origin in ("USER_AUTHORITY", "TRUSTED_PO_DB", "UNTRUSTED_EXT")
                    else "UNTRUSTED_EXT"
                )
                source_ref = raw_val.source_reference
            elif isinstance(raw_val, dict) and "origin" in raw_val and "value" in raw_val:
                clean_value = raw_val["value"]
                raw_origin = raw_val.get("origin")
                origin = raw_origin if raw_origin in ("USER_AUTHORITY", "TRUSTED_PO_DB", "UNTRUSTED_EXT") else "UNTRUSTED_EXT"
                source_ref = raw_val.get("source_reference")
            else:
                clean_value = raw_val
                explicit_prov = argument_provenance.get(arg_name)
                if explicit_prov in ("USER_AUTHORITY", "TRUSTED_PO_DB", "UNTRUSTED_EXT"):
                    origin = explicit_prov
                elif session_tainted:
                    origin = "UNTRUSTED_EXT"
                else:
                    origin = "USER_AUTHORITY"
                source_ref = None

            normalized[arg_name] = TaintedArgument(
                arg_name=arg_name,
                value=clean_value,
                origin=origin,
                source_reference=source_ref,
            )

        return normalized

    @staticmethod
    def scan_for_credentials(normalized_args: Dict[str, TaintedArgument]) -> List[IFCViolationDetail]:
        """
        Scans all argument values for leaked credentials, private keys, or API tokens.
        Defends against Risk #25 (Credential & Secret Leakage).
        """
        violations: List[IFCViolationDetail] = []

        def _recursive_search(val: Any) -> Optional[str]:
            if isinstance(val, str):
                for pat in CREDENTIAL_LEAK_REGEXES:
                    m = pat.search(val)
                    if m:
                        return m.group(0)
            elif isinstance(val, dict):
                for sub_v in val.values():
                    found = _recursive_search(sub_v)
                    if found:
                        return found
            elif isinstance(val, (list, tuple, set)):
                for item in val:
                    found = _recursive_search(item)
                    if found:
                        return found
            return None

        for arg_name, tainted in normalized_args.items():
            matched_secret = _recursive_search(tainted.value)
            if matched_secret:
                masked = matched_secret[:6] + "..." if len(matched_secret) > 6 else "***"
                violations.append(
                    IFCViolationDetail(
                        arg_name=arg_name,
                        sink_category="CREDENTIAL_LEAK_SINK",
                        actual_origin=tainted.origin,
                        required_origins=["NO_LEAKED_CREDENTIALS"],
                        risk_id=25,
                        description=(
                            f"Credential or API key leakage pattern detected in argument '{arg_name}': "
                            f"[{masked}]. Risk #25."
                        ),
                    )
                )

        return violations

    @staticmethod
    def check_outbound_recipient_sinks(
        tool_name: str,
        normalized_args: Dict[str, TaintedArgument],
    ) -> List[IFCViolationDetail]:
        """
        Enforces IFC sink rules on outbound recipients (email, webhooks, destinations).
        Requires origin in ["USER_AUTHORITY", "TRUSTED_PO_DB"].
        Blocks UNTRUSTED_EXT to prevent exfiltration (Risks #21, #27).
        """
        violations: List[IFCViolationDetail] = []

        for arg_name, tainted in normalized_args.items():
            norm_name = arg_name.lower()
            if norm_name in OUTBOUND_RECIPIENT_SINKS or (tool_name in ("send_email", "webhook_post") and norm_name in ("to", "recipient", "email_to", "destination_url", "url")):
                if tainted.origin == "UNTRUSTED_EXT":
                    violations.append(
                        IFCViolationDetail(
                            arg_name=arg_name,
                            sink_category="OUTBOUND_RECIPIENT_SINK",
                            actual_origin=tainted.origin,
                            required_origins=["USER_AUTHORITY", "TRUSTED_PO_DB"],
                            risk_id=21,
                            description=(
                                f"Pydantic IFC Sink Violation: Outbound recipient argument '{arg_name}' "
                                f"carries untrusted origin '{tainted.origin}'. Data exfiltration blocked. "
                                "Risks #21 & #27."
                            ),
                        )
                    )

        return violations

    @staticmethod
    def check_financial_destination_sinks(
        tool_name: str,
        normalized_args: Dict[str, TaintedArgument],
    ) -> List[IFCViolationDetail]:
        """
        Enforces IFC sink rules on financial destination sinks (IBAN, bank accounts).
        Requires origin in ["USER_AUTHORITY", "TRUSTED_PO_DB"].
        Flags UNTRUSTED_EXT to trigger Human Approval Card (Risks #10, #18).
        """
        violations: List[IFCViolationDetail] = []

        for arg_name, tainted in normalized_args.items():
            norm_name = arg_name.lower()
            if norm_name in FINANCIAL_DESTINATION_SINKS or (
                tool_name in PAYMENT_EXECUTION_TOOLS and "iban" in norm_name
            ):
                if tainted.origin == "UNTRUSTED_EXT":
                    violations.append(
                        IFCViolationDetail(
                            arg_name=arg_name,
                            sink_category="FINANCIAL_DESTINATION_SINK",
                            actual_origin=tainted.origin,
                            required_origins=["USER_AUTHORITY", "TRUSTED_PO_DB"],
                            risk_id=18,
                            description=(
                                f"Pydantic IFC Sink Violation: Financial destination argument '{arg_name}' "
                                f"carries untrusted origin '{tainted.origin}'. "
                                "Human approval required. Risks #10 & #18."
                            ),
                        )
                    )

        return violations

    @staticmethod
    def check_amount_limit_sinks(
        contract: Optional[Step0IntentContract],
        normalized_args: Dict[str, TaintedArgument],
    ) -> List[IFCViolationDetail]:
        """
        Checks financial amount arguments against the Step-0 contract max approved limit.
        Defends against Risk #18 (Sensitive Action Manipulation).
        """
        violations: List[IFCViolationDetail] = []
        if not contract or contract.max_approved_amount_inr <= 0:
            return violations

        for arg_name, tainted in normalized_args.items():
            norm_name = arg_name.lower()
            if norm_name in AMOUNT_ARGUMENT_KEYS:
                try:
                    val = float(tainted.value)
                    if val > contract.max_approved_amount_inr:
                        violations.append(
                            IFCViolationDetail(
                                arg_name=arg_name,
                                sink_category="AMOUNT_LIMIT_SINK",
                                actual_origin=tainted.origin,
                                required_origins=["USER_AUTHORITY", "TRUSTED_PO_DB"],
                                risk_id=18,
                                description=(
                                    f"Requested amount ₹{val:,.2f} exceeds Step-0 locked maximum "
                                    f"of ₹{contract.max_approved_amount_inr:,.2f}. Risk #18 & Risk #10."
                                ),
                            )
                        )
                except (ValueError, TypeError):
                    pass

        return violations


# ---------------------------------------------------------------------------
# Deterministic Policy Gateway
# ---------------------------------------------------------------------------

class DeterministicPolicyGateway:
    """
    Core Deterministic Policy Gateway executing 6 strict deterministic gates:
    Gate 1 — Step-0 intent_hmac_hash Cryptographic Verification
    Gate 2 — Step-0 Tool Allowlist & Prohibited Operations Check
    Gate 3 — Credential & Secret Leakage Guard (Risk #25)
    Gate 4 — Strict Pydantic IFC on Outbound Recipient Sinks (Risks #21, #27)
    Gate 5 — Strict Pydantic IFC on Financial Destination Sinks & Amount Limits (Risks #10, #18)
    Gate 6 — Issue Deterministic execution_token_hmac on Approval
    """

    def __init__(self) -> None:
        self.ifc_engine = PydanticIFCRuleEngine()
        self.micro_privilege_sandbox: MicroPrivilegeSandbox = micro_privilege_sandbox
        self.outbound_firewall: ZeroClickOutboundFirewall = outbound_firewall



    def evaluate_tool_call(self, request: PolicyEvaluationRequest) -> PolicyEvaluationResult:
        """
        Evaluates a tool call request through the 6 deterministic gates in strict sequence.
        Returns a complete PolicyEvaluationResult.
        """
        session_id = request.session_id
        tool_name = request.tool_name.strip()
        norm_tool = tool_name.lower()

        # ── Gate 1: Cryptographic Step-0 HMAC Verification ──────────────────
        contract: Optional[Step0IntentContract] = None
        if request.intent_contract:
            try:
                contract = Step0IntentContract(**request.intent_contract)
            except Exception as exc:
                logger.warning("Failed to deserialize intent_contract: %s", exc)
        if contract is None:
            contract = intent_contract_registry.get_contract(session_id)

        # 1a. If an intent_hmac_hash is provided, verify validity
        if request.provided_intent_hmac_hash is not None:
            provided_hash = request.provided_intent_hmac_hash.strip().lower()
            if len(provided_hash) != 64 or not re.fullmatch(r"^[0-9a-f]{64}$", provided_hash):
                violation = IFCViolationDetail(
                    arg_name="intent_hmac_hash",
                    sink_category="HMAC_MISMATCH",
                    actual_origin="UNTRUSTED_EXT",
                    required_origins=["USER_AUTHORITY"],
                    risk_id=30,
                    description=f"Provided intent_hmac_hash '{provided_hash}' is not a valid 64-char hex string.",
                )
                return PolicyEvaluationResult(
                    session_id=session_id,
                    tool_name=tool_name,
                    execution_permitted=False,
                    requires_human_approval_card=False,
                    action_taken="BLOCKED",
                    policy_reference="RISK_30_HMAC_FORMAT_INVALID",
                    reason="Step-0 HMAC Intent Contract signature verification failed or was tampered with.",
                    ifc_violations=[violation],
                    risk_category_ids=[10, 14, 16, 30],
                    threat_detected=True,
                    execution_token_hmac=None,
                    intent_hmac_hash=provided_hash,
                )

            if contract is None:
                violation = IFCViolationDetail(
                    arg_name="intent_hmac_hash",
                    sink_category="HMAC_MISMATCH",
                    actual_origin="UNTRUSTED_EXT",
                    required_origins=["USER_AUTHORITY"],
                    risk_id=30,
                    description="No active Step-0 Intent Contract registered for session.",
                )
                return PolicyEvaluationResult(
                    session_id=session_id,
                    tool_name=tool_name,
                    execution_permitted=False,
                    requires_human_approval_card=False,
                    action_taken="BLOCKED",
                    policy_reference="RISK_10_SPOOFED_AUTHORITY_HMAC_FAIL",
                    reason="Step-0 HMAC Intent Contract signature verification failed or was tampered with.",
                    ifc_violations=[violation],
                    risk_category_ids=[10, 14, 16, 30],
                    threat_detected=True,
                    execution_token_hmac=None,
                    intent_hmac_hash=provided_hash,
                )

            if not hmac.compare_digest(contract.intent_hmac_hash.strip().lower(), provided_hash):
                violation = IFCViolationDetail(
                    arg_name="intent_hmac_hash",
                    sink_category="HMAC_MISMATCH",
                    actual_origin="UNTRUSTED_EXT",
                    required_origins=["USER_AUTHORITY"],
                    risk_id=30,
                    description="Provided intent_hmac_hash does not match locked Step-0 contract HMAC.",
                )
                return PolicyEvaluationResult(
                    session_id=session_id,
                    tool_name=tool_name,
                    execution_permitted=False,
                    requires_human_approval_card=False,
                    action_taken="BLOCKED",
                    policy_reference="RISK_30_HMAC_SIGNATURE_MISMATCH",
                    reason="Step-0 HMAC Intent Contract signature verification failed or was tampered with.",
                    ifc_violations=[violation],
                    risk_category_ids=[10, 14, 16, 30],
                    threat_detected=True,
                    execution_token_hmac=None,
                    intent_hmac_hash=contract.intent_hmac_hash,
                )

        # 1b. If contract exists, verify its cryptographic integrity
        if contract is not None:
            if not verify_contract_signature(contract):
                violation = IFCViolationDetail(
                    arg_name="contract_signature",
                    sink_category="HMAC_MISMATCH",
                    actual_origin="UNTRUSTED_EXT",
                    required_origins=["USER_AUTHORITY"],
                    risk_id=30,
                    description="Cryptographic contract signature re-computation failed. Tamper detected!",
                )
                return PolicyEvaluationResult(
                    session_id=session_id,
                    tool_name=tool_name,
                    execution_permitted=False,
                    requires_human_approval_card=False,
                    action_taken="BLOCKED",
                    policy_reference="RISK_30_CONTRACT_TAMPER_DETECTED",
                    reason="Step-0 HMAC Intent Contract signature verification failed or was tampered with.",
                    ifc_violations=[violation],
                    risk_category_ids=[10, 14, 16, 30],
                    threat_detected=True,
                    execution_token_hmac=None,
                    intent_hmac_hash=contract.intent_hmac_hash,
                )

        locked_hmac_hash = contract.intent_hmac_hash if contract else ""

        # ── Gate 2: Step-0 Tool Allowlist & Prohibited Operations Check ─────
        # 2a. Unconditional prohibited destructive tools
        if norm_tool in UNCONDITIONAL_PROHIBITED_TOOLS:
            violation = IFCViolationDetail(
                arg_name=tool_name,
                sink_category="PROHIBITED_TOOL",
                actual_origin="SYSTEM",
                required_origins=["NEVER_ALLOWED"],
                risk_id=17,
                description=f"Destructive shell/exec tool '{tool_name}' is unconditionally prohibited.",
            )
            return PolicyEvaluationResult(
                session_id=session_id,
                tool_name=tool_name,
                execution_permitted=False,
                requires_human_approval_card=False,
                action_taken="BLOCKED",
                policy_reference="RISK_17_PROHIBITED_EXEC_TOOL",
                reason=f"BLOCKED: Shell/exec tool '{tool_name}' is not permitted inside the IntentGuard sandbox.",
                ifc_violations=[violation],
                risk_category_ids=[16, 17],
                threat_detected=True,
                execution_token_hmac=None,
                intent_hmac_hash=locked_hmac_hash,
            )

        # 2a-2. Task 18 Micro-Privilege Task Sandbox evaluation
        sandbox_res = self.micro_privilege_sandbox.evaluate_tool_call(session_id=session_id, tool_name=tool_name)
        if not sandbox_res.allowed and norm_tool not in BANK_MUTATION_TOOLS:
            violation = IFCViolationDetail(
                arg_name=tool_name,
                sink_category="MICRO_PRIVILEGE_STRIPPED",
                actual_origin="UNTRUSTED_EXT",
                required_origins=["FULL_TRUSTED_CONTEXT"],
                risk_id=17,
                description=sandbox_res.reason,
            )
            return PolicyEvaluationResult(
                session_id=session_id,
                tool_name=tool_name,
                execution_permitted=False,
                requires_human_approval_card=False,
                action_taken="BLOCKED",
                policy_reference=f"RISK_17_MICRO_PRIVILEGE_{sandbox_res.violated_category or 'SANDBOX'}",
                reason=sandbox_res.reason,
                ifc_violations=[violation],
                risk_category_ids=[16, 17],
                threat_detected=True,
                execution_token_hmac=None,
                intent_hmac_hash=locked_hmac_hash,
            )

        # 2a-3. Task 19 Zero-Click Outbound Exfiltration, URL/DNS & SSRF Firewall
        fw_tool_res = self.outbound_firewall.inspect_tool_call_urls(tool_name, request.tool_arguments)
        if not fw_tool_res.allowed:
            violation = IFCViolationDetail(
                arg_name="url",
                sink_category="OUTBOUND_FIREWALL_SSRF_OR_EXFIL",
                actual_origin="UNTRUSTED_EXT",
                required_origins=["WHITELISTED_DOMAIN"],
                risk_id=23 if 23 in fw_tool_res.risk_category_ids else 21,
                description=fw_tool_res.reason,
            )
            return PolicyEvaluationResult(
                session_id=session_id,
                tool_name=tool_name,
                execution_permitted=False,
                requires_human_approval_card=False,
                action_taken="BLOCKED",
                policy_reference="RISK_23_SSRF_OR_EXFIL_FIREWALL",
                reason=fw_tool_res.reason,
                ifc_violations=[violation],
                risk_category_ids=fw_tool_res.risk_category_ids,
                threat_detected=True,
                execution_token_hmac=None,
                intent_hmac_hash=locked_hmac_hash,
            )



        # 2b. Contract prohibited operations check
        if contract is not None:
            prohibited_set = {p.strip().lower() for p in contract.prohibited_operations}
            if norm_tool in prohibited_set:
                is_bank_mutation = norm_tool in BANK_MUTATION_TOOLS
                action = "HUMAN_APPROVAL_REQUIRED" if is_bank_mutation else "BLOCKED"
                requires_card = is_bank_mutation
                risk_ids = [16, 18] if is_bank_mutation else [14, 16]
                policy_ref = "RISK_18_BANK_MUTATION_HUMAN_APPROVAL" if is_bank_mutation else "RISK_14_STEP0_PROHIBITED_OP_LOCK"
                reason_msg = (
                    f"HIGH-RISK: Bank mutation tool '{tool_name}' requires human approval before execution."
                    if is_bank_mutation
                    else f"Operation '{tool_name}' is explicitly forbidden by Step-0 Intent Contract."
                )
                violation = IFCViolationDetail(
                    arg_name=tool_name,
                    sink_category="PROHIBITED_TOOL",
                    actual_origin="STEP0_PROHIBITED",
                    required_origins=["ALLOWED_IN_STEP0"],
                    risk_id=18 if is_bank_mutation else 16,
                    description=reason_msg,
                )
                return PolicyEvaluationResult(
                    session_id=session_id,
                    tool_name=tool_name,
                    execution_permitted=False,
                    requires_human_approval_card=requires_card,
                    action_taken=action,
                    policy_reference=policy_ref,
                    reason=reason_msg,
                    ifc_violations=[violation],
                    risk_category_ids=risk_ids,
                    threat_detected=True,
                    execution_token_hmac=None,
                    intent_hmac_hash=locked_hmac_hash,
                )

            # 2c. Contract allowed tools whitelist check
            if contract.allowed_tools:
                allowed_set = {a.strip().lower() for a in contract.allowed_tools}
                if norm_tool not in allowed_set:
                    violation = IFCViolationDetail(
                        arg_name=tool_name,
                        sink_category="PROHIBITED_TOOL",
                        actual_origin="OUT_OF_SCOPE",
                        required_origins=contract.allowed_tools,
                        risk_id=16,
                        description=f"Tool '{tool_name}' is not in allowed_tools list: {contract.allowed_tools}.",
                    )
                    return PolicyEvaluationResult(
                        session_id=session_id,
                        tool_name=tool_name,
                        execution_permitted=False,
                        requires_human_approval_card=False,
                        action_taken="BLOCKED",
                        policy_reference="RISK_16_UNAUTHORIZED_TOOL_CALL",
                        reason=(
                            f"Tool '{tool_name}' is not in the Step-0 Intent Contract whitelist: "
                            f"{contract.allowed_tools}. Risk #16 (Unauthorized Tool Calls)."
                        ),
                        ifc_violations=[violation],
                        risk_category_ids=[16, 17],
                        threat_detected=True,
                        execution_token_hmac=None,
                        intent_hmac_hash=locked_hmac_hash,
                    )

        # 2d. Inherent bank mutation check without contract
        if norm_tool in BANK_MUTATION_TOOLS and contract is None:
            # Check if any argument carries UNTRUSTED_EXT or if default applies
            has_untrusted = any(
                p == "UNTRUSTED_EXT" for p in request.argument_provenance.values()
            )
            # Bank mutation tools inherently require human approval
            violation = IFCViolationDetail(
                arg_name=tool_name,
                sink_category="PROHIBITED_TOOL",
                actual_origin="UNTRUSTED_EXT" if has_untrusted else "USER_AUTHORITY",
                required_origins=["HUMAN_APPROVAL_CARD"],
                risk_id=18,
                description=f"Bank details modification tool '{tool_name}' requires human approval card.",
            )
            return PolicyEvaluationResult(
                session_id=session_id,
                tool_name=tool_name,
                execution_permitted=False,
                requires_human_approval_card=True,
                action_taken="HUMAN_APPROVAL_REQUIRED",
                policy_reference="RISK_18_BANK_MUTATION_HUMAN_APPROVAL",
                reason=(
                    f"HIGH-RISK: Tool '{tool_name}' modifies vendor bank details. "
                    "Human approval required before execution."
                ),
                ifc_violations=[violation],
                risk_category_ids=[16, 18],
                threat_detected=True,
                execution_token_hmac=None,
                intent_hmac_hash=locked_hmac_hash,
            )

        # ── Normalize Arguments & Determine Provenance ─────────────────────
        normalized_args = self.ifc_engine.normalize_arguments(
            tool_arguments=request.tool_arguments,
            argument_provenance=request.argument_provenance,
            session_id=session_id,
        )

        # ── Gate 3: Credential & Secret Leakage Guard (Risk #25) ────────────
        cred_violations = self.ifc_engine.scan_for_credentials(normalized_args)
        if cred_violations:
            return PolicyEvaluationResult(
                session_id=session_id,
                tool_name=tool_name,
                execution_permitted=False,
                requires_human_approval_card=False,
                action_taken="BLOCKED",
                policy_reference="RISK_25_CREDENTIAL_LEAK_PREVENTION",
                reason=f"Credential or secret detected in tool arguments. Risk #25.",
                ifc_violations=cred_violations,
                risk_category_ids=[21, 25],
                threat_detected=True,
                execution_token_hmac=None,
                intent_hmac_hash=locked_hmac_hash,
            )

        # ── Gate 4: Strict Pydantic IFC on Outbound Recipient Sinks ────────
        recipient_violations = self.ifc_engine.check_outbound_recipient_sinks(
            tool_name=norm_tool,
            normalized_args=normalized_args,
        )
        if recipient_violations:
            return PolicyEvaluationResult(
                session_id=session_id,
                tool_name=tool_name,
                execution_permitted=False,
                requires_human_approval_card=False,
                action_taken="BLOCKED",
                policy_reference="RISK_21_UNTRUSTED_OUTBOUND_RECIPIENT",
                reason=(
                    f"Pydantic IFC violation: Outbound recipient sink '{recipient_violations[0].arg_name}' "
                    f"has untrusted origin '{recipient_violations[0].actual_origin}'. Risk #21 & Risk #27."
                ),
                ifc_violations=recipient_violations,
                risk_category_ids=[16, 21, 27],
                threat_detected=True,
                execution_token_hmac=None,
                intent_hmac_hash=locked_hmac_hash,
            )

        # ── Gate 5: Strict Pydantic IFC on Financial Sinks & Amount Limits ──
        # 5a. Financial destination sinks
        fin_dest_violations = self.ifc_engine.check_financial_destination_sinks(
            tool_name=norm_tool,
            normalized_args=normalized_args,
        )
        if fin_dest_violations:
            return PolicyEvaluationResult(
                session_id=session_id,
                tool_name=tool_name,
                execution_permitted=False,
                requires_human_approval_card=True,
                action_taken="HUMAN_APPROVAL_REQUIRED",
                policy_reference="RISK_18_UNTRUSTED_FINANCIAL_DESTINATION",
                reason=(
                    f"Pydantic IFC violation: Financial destination sink '{fin_dest_violations[0].arg_name}' "
                    f"carries UNTRUSTED_EXT origin. Human approval required. Risk #10 & Risk #18."
                ),
                ifc_violations=fin_dest_violations,
                risk_category_ids=[10, 16, 18],
                threat_detected=True,
                execution_token_hmac=None,
                intent_hmac_hash=locked_hmac_hash,
            )

        # 5b. Payment tool with untrusted arguments check
        if norm_tool in PAYMENT_EXECUTION_TOOLS:
            has_untrusted_arg = any(
                t.origin == "UNTRUSTED_EXT" for t in normalized_args.values()
            )
            if has_untrusted_arg:
                violation = IFCViolationDetail(
                    arg_name="payment_arguments",
                    sink_category="FINANCIAL_DESTINATION_SINK",
                    actual_origin="UNTRUSTED_EXT",
                    required_origins=["USER_AUTHORITY", "TRUSTED_PO_DB"],
                    risk_id=16,
                    description=f"Payment execution tool '{tool_name}' carries UNTRUSTED_EXT arguments.",
                )
                return PolicyEvaluationResult(
                    session_id=session_id,
                    tool_name=tool_name,
                    execution_permitted=False,
                    requires_human_approval_card=True,
                    action_taken="HUMAN_APPROVAL_REQUIRED",
                    policy_reference="RISK_16_PAYMENT_UNTRUSTED_ARGS",
                    reason=(
                        f"HIGH-RISK: Payment tool '{tool_name}' carries UNTRUSTED_EXT "
                        "arguments. Human approval required."
                    ),
                    ifc_violations=[violation],
                    risk_category_ids=[16],
                    threat_detected=True,
                    execution_token_hmac=None,
                    intent_hmac_hash=locked_hmac_hash,
                )

        # 5c. Amount cap verification against locked Step-0 contract
        amount_violations = self.ifc_engine.check_amount_limit_sinks(
            contract=contract,
            normalized_args=normalized_args,
        )
        if amount_violations:
            return PolicyEvaluationResult(
                session_id=session_id,
                tool_name=tool_name,
                execution_permitted=False,
                requires_human_approval_card=False,
                action_taken="BLOCKED",
                policy_reference="RISK_18_FINANCIAL_CAP_EXCEEDED",
                reason=(
                    f"Financial cap exceeded: {amount_violations[0].description}"
                ),
                ifc_violations=amount_violations,
                risk_category_ids=[10, 18],
                threat_detected=True,
                execution_token_hmac=None,
                intent_hmac_hash=locked_hmac_hash,
            )

        # ── Gate 6: Issue Deterministic execution_token_hmac on Approval ─────
        clean_args_dict = {k: v.value for k, v in normalized_args.items()}
        canonical_args_json = json.dumps(clean_args_dict, sort_keys=True, separators=(",", ":"), default=str)
        token_message = f"{session_id}:{tool_name}:{canonical_args_json}"
        secret_key = getattr(
            settings,
            "HMAC_MASTER_SECRET",
            "genesis2_eva03_ps01_intentguard_hmac_sha256_master_secret_2026",
        )
        execution_token = hmac.new(
            secret_key.encode("utf-8"),
            token_message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return PolicyEvaluationResult(
            session_id=session_id,
            tool_name=tool_name,
            execution_permitted=True,
            requires_human_approval_card=False,
            action_taken="SAFE_EXECUTED",
            policy_reference=getattr(settings, "DEFAULT_POLICY_REFERENCE", "policy-v1"),
            reason="Tool invocation verified and authorized by Step-0 Cryptographic Intent Contract and Pydantic IFC.",
            ifc_violations=[],
            risk_category_ids=[],
            threat_detected=False,
            execution_token_hmac=execution_token,
            intent_hmac_hash=locked_hmac_hash,
        )


# Singleton instance
deterministic_policy_gateway = DeterministicPolicyGateway()
