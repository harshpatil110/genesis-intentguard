"""
IntentGuard Layer 3 Deterministic Policy Gateway
=================================================
GENESIS 2.0 | Track: EVA 03 | PS 01

Provides Step-0 permissions, rate limits, micro-privilege loop caps,
resource budget enforcement, and strict Pydantic Information Flow Control (IFC).
"""

from app.layer3_policy.deterministic_gateway import (
    HIGH_IMPACT_TOOLS,
    OUTBOUND_RECIPIENT_SINKS,
    FINANCIAL_DESTINATION_SINKS,
    AMOUNT_ARGUMENT_KEYS,
    CREDENTIAL_LEAK_REGEXES,
    DeterministicPolicyGateway,
    IFCViolationDetail,
    PolicyEvaluationRequest,
    PolicyEvaluationResult,
    PydanticIFCRuleEngine,
    TaintedArgument,
    deterministic_policy_gateway,
)
from app.layer3_policy.resource_budget import (
    BudgetCheckResult,
    BudgetConfig,
    BudgetViolationError,
    ResourceBudgetEnforcer,
    SessionBudgetState,
    compute_tool_signature,
    resource_budget_enforcer,
)
from app.layer3_policy.po_verifier import (
    PurchaseOrderVerifier,
    POVerificationResult,
    StepBackApprovalCardPayload,
    TrustedPORecord,
    purchase_order_verifier,
)
from app.layer3_policy.micro_privilege import (
    ADMIN_TOOLS,
    BULK_EXPORT_TOOLS,
    FILESYSTEM_DELETION_TOOLS,
    HIGH_RISK_STRIPPED_TOOLS,
    SHELL_EXECUTION_TOOLS,
    MicroPrivilegeSandbox,
    PermissionMask,
    SandboxEvaluationResult,
    SessionPrivilegeState,
    micro_privilege_sandbox,
)
from app.layer3_policy.outbound_firewall import (
    DEFAULT_WHITELISTED_DOMAINS,
    OutboundFirewallResult,
    URLInspectionFinding,
    ZeroClickOutboundFirewall,
    calculate_shannon_entropy,
    outbound_firewall,
)

from app.layer3_policy.step_back_approval import (
    ApprovalResolutionRequest,
    ApprovalResolutionResponse,
    BlockchainAuditEventPayload,
    PendingApprovalCard,
    POBaselineComparison,
    StepBackApprovalEngine,
    step_back_approval_engine,
)

__all__ = [
    "BudgetCheckResult",
    "BudgetConfig",
    "BudgetViolationError",
    "ResourceBudgetEnforcer",
    "SessionBudgetState",
    "compute_tool_signature",
    "resource_budget_enforcer",
    "DeterministicPolicyGateway",
    "PydanticIFCRuleEngine",
    "PolicyEvaluationRequest",
    "PolicyEvaluationResult",
    "TaintedArgument",
    "IFCViolationDetail",
    "deterministic_policy_gateway",
    "HIGH_IMPACT_TOOLS",
    "OUTBOUND_RECIPIENT_SINKS",
    "FINANCIAL_DESTINATION_SINKS",
    "AMOUNT_ARGUMENT_KEYS",
    "CREDENTIAL_LEAK_REGEXES",
    # Task 17 — PO-vs-Invoice Verifier
    "PurchaseOrderVerifier",
    "POVerificationResult",
    "StepBackApprovalCardPayload",
    "TrustedPORecord",
    "purchase_order_verifier",
    # Task 18 — Micro-Privilege Task Sandboxing Engine
    "MicroPrivilegeSandbox",
    "SessionPrivilegeState",
    "SandboxEvaluationResult",
    "PermissionMask",
    "micro_privilege_sandbox",
    "ADMIN_TOOLS",
    "FILESYSTEM_DELETION_TOOLS",
    "SHELL_EXECUTION_TOOLS",
    "BULK_EXPORT_TOOLS",
    "HIGH_RISK_STRIPPED_TOOLS",
    # Task 19 — Zero-Click Outbound Exfiltration, URL/DNS, & SSRF Firewall
    "ZeroClickOutboundFirewall",
    "OutboundFirewallResult",
    "URLInspectionFinding",
    "outbound_firewall",
    "DEFAULT_WHITELISTED_DOMAINS",
    "calculate_shannon_entropy",
    # Task 20 — Step-Back Human-in-the-Loop Approval Card Engine
    "StepBackApprovalEngine",
    "step_back_approval_engine",
    "PendingApprovalCard",
    "POBaselineComparison",
    "ApprovalResolutionRequest",
    "ApprovalResolutionResponse",
    "BlockchainAuditEventPayload",
]


