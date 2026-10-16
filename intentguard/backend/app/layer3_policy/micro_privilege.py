"""
IntentGuard Layer 3 — Micro-Privilege Task Sandboxing Engine
============================================================
GENESIS 2.0 | Track: EVA 03 | PS 01 — Separating Data from Authority

Enforces dynamic Least Privilege and monotonic privilege downgrading:
- Sessions start in FULL_TRUSTED_CONTEXT with baseline capabilities.
- The instant Hook 1 ingests any untrusted external artifact (PDF, DOCX, email,
  chat, image, audio/video, web DOM, archive, spreadsheet, etc.), the session
  permission mask irreversibly downgrades to RESTRICTED_UNTRUSTED_CONTEXT.
- Administrative, filesystem deletion, shell execution, and bulk export capabilities
  are stripped from active tool bindings and deterministically blocked at Hook 2
  (Risk #17: Excessive Permissions / Agency, Risk #16: Unauthorized Tool Calls).
- Legitimate, contract-bound business tools (e.g., schedule_payment, match_purchase_order,
  read_invoice) remain permitted to ensure non-disruptive business operations.
"""

from __future__ import annotations

import logging
import threading
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# High-Risk Tool Sets & Categories
# ---------------------------------------------------------------------------

ADMIN_TOOLS: Set[str] = {
    "grant_admin_access",
    "modify_user_roles",
    "update_system_config",
    "disable_security_gateway",
    "rotate_api_keys",
    "change_permissions",
    "sudo_exec",
}

FILESYSTEM_DELETION_TOOLS: Set[str] = {
    "delete_file",
    "remove_directory",
    "rmdir",
    "unlink_path",
    "wipe_workspace",
    "format_disk",
    "shred_file",
    "truncate_log",
}

SHELL_EXECUTION_TOOLS: Set[str] = {
    "bash",
    "exec_shell",
    "run_script",
    "powershell",
    "cmd_exec",
    "spawn_process",
    "eval_code",
    "terminal_exec",
}

BULK_EXPORT_TOOLS: Set[str] = {
    "export_all_files",
    "dump_database",
    "bulk_download_contacts",
    "archive_workspace",
    "sync_external_drive",
    "share_drive_file",
    "exfiltrate_memory",
    "drop_table",
}

HIGH_RISK_STRIPPED_TOOLS: Set[str] = (
    ADMIN_TOOLS | FILESYSTEM_DELETION_TOOLS | SHELL_EXECUTION_TOOLS | BULK_EXPORT_TOOLS
)

DEFAULT_BUSINESS_TOOLS: List[str] = [
    "read_invoice",
    "match_purchase_order",
    "schedule_payment",
    "verify_po",
    "get_vendor_info",
    "send_notification",
    "query_inventory",
    "schedule_verified_payment",
    "get_po_details",
    "list_invoices",
    "view_document",
    "extract_invoice",
    "change_vendor_bank",
    "change_vendor_bank_details",
]

DEFAULT_ADMIN_TOOLS: List[str] = [
    "delete_file",
    "exec_shell",
    "bash",
    "export_all_files",
    "grant_admin_access",
    "rmdir",
]


def classify_high_risk_tool(tool_name: str) -> Optional[str]:
    """
    Classifies a tool into one of 4 high-risk categories, or returns None.
    Matches exact set memberships case-insensitively and prefixes/keywords:
    - ADMINISTRATIVE
    - FILESYSTEM_DELETION
    - SHELL_EXECUTION
    - BULK_EXPORT
    """
    tn = tool_name.strip().lower()

    # 1. Administrative tools
    if (
        tn in {t.lower() for t in ADMIN_TOOLS}
        or tn.startswith(("admin_", "sudo_", "rotate_api", "change_permission", "modify_user_role", "update_system_config", "disable_security"))
        or "grant_admin" in tn
    ):
        return "ADMINISTRATIVE"

    # 2. Filesystem deletion tools
    if (
        tn in {t.lower() for t in FILESYSTEM_DELETION_TOOLS}
        or tn.startswith(("delete_", "format_", "wipe_", "shred_", "rmdir", "remove_directory", "unlink_", "truncate_"))
        or "delete_file" in tn
        or tn == "rmdir"
    ):
        return "FILESYSTEM_DELETION"

    # 3. Shell execution tools
    if (
        tn in {t.lower() for t in SHELL_EXECUTION_TOOLS}
        or tn.startswith(("exec_", "shell_", "bash", "powershell", "cmd_", "spawn_", "eval_", "terminal_"))
        or "exec_shell" in tn
        or tn == "bash"
    ):
        return "SHELL_EXECUTION"

    # 4. Bulk export tools
    if (
        tn in {t.lower() for t in BULK_EXPORT_TOOLS}
        or tn.startswith(("bulk_export_", "export_", "dump_", "exfiltrate_", "archive_workspace", "drop_table"))
        or "export_all" in tn
        or "dump_db" in tn
        or "dump_database" in tn
    ):
        return "BULK_EXPORT"

    return None


# ---------------------------------------------------------------------------
# Enums & Pydantic Models
# ---------------------------------------------------------------------------

class PermissionMask(str, Enum):
    """Monotonic context permission mask for an agent session."""
    FULL_TRUSTED_CONTEXT = "FULL_TRUSTED_CONTEXT"
    RESTRICTED_UNTRUSTED_CONTEXT = "RESTRICTED_UNTRUSTED_CONTEXT"


class SessionPrivilegeState(BaseModel):
    """Tracks dynamic micro-privilege state for an individual session."""
    session_id: str
    permission_mask: PermissionMask = PermissionMask.FULL_TRUSTED_CONTEXT
    is_tainted_by_untrusted_data: bool = False
    taint_trigger_source: Optional[str] = None
    taint_trigger_modality: Optional[str] = None
    active_tool_bindings: List[str] = Field(default_factory=list)
    stripped_tools: List[str] = Field(default_factory=list)
    risk_category_ids: List[int] = Field(default_factory=list)


class SandboxEvaluationResult(BaseModel):
    """Result of evaluating a proposed tool call against Micro-Privilege Sandbox."""
    allowed: bool
    session_id: str
    tool_name: str
    permission_mask: PermissionMask
    action_taken: str  # "SAFE_EXECUTED" or "BLOCKED_BY_MICRO_PRIVILEGE_SANDBOX"
    violated_category: Optional[str] = None  # "ADMINISTRATIVE", "FILESYSTEM_DELETION", "SHELL_EXECUTION", "BULK_EXPORT", or "UNLISTED_IN_RESTRICTED_SANDBOX"
    active_tool_bindings: List[str] = Field(default_factory=list)
    stripped_tools: List[str] = Field(default_factory=list)
    risk_category_ids: List[int] = Field(default_factory=list)
    reason: str


# ---------------------------------------------------------------------------
# MicroPrivilegeSandbox Class
# ---------------------------------------------------------------------------

class MicroPrivilegeSandbox:
    """
    Micro-Privilege Task Sandboxing Engine.
    Enforces deterministic state transitions and monotonic privilege downgrade.
    """

    def __init__(self) -> None:
        self._sessions: Dict[str, SessionPrivilegeState] = {}
        self._lock = threading.Lock()

    def register_or_get_session(
        self,
        session_id: str,
        initial_tools: Optional[List[str]] = None,
    ) -> SessionPrivilegeState:
        """
        Returns existing session state or initializes a new FULL_TRUSTED_CONTEXT state.
        Monotonic property: If session is already RESTRICTED_UNTRUSTED_CONTEXT, it
        CANNOT be upgraded back to FULL_TRUSTED_CONTEXT.
        """
        with self._lock:
            if session_id in self._sessions:
                existing = self._sessions[session_id]
                if initial_tools:
                    for t in initial_tools:
                        if existing.permission_mask == PermissionMask.FULL_TRUSTED_CONTEXT:
                            if t not in existing.active_tool_bindings:
                                existing.active_tool_bindings.append(t)
                        else:
                            # In restricted untrusted context, only safe non-high-risk tools may be bound
                            if classify_high_risk_tool(t) is None and t not in existing.active_tool_bindings:
                                existing.active_tool_bindings.append(t)
                return existing

            # Initialize new session in FULL_TRUSTED_CONTEXT
            tools = list(initial_tools) if initial_tools else list(DEFAULT_BUSINESS_TOOLS + DEFAULT_ADMIN_TOOLS)
            for t in DEFAULT_BUSINESS_TOOLS + DEFAULT_ADMIN_TOOLS:
                if t not in tools:
                    tools.append(t)

            state = SessionPrivilegeState(
                session_id=session_id,
                permission_mask=PermissionMask.FULL_TRUSTED_CONTEXT,
                is_tainted_by_untrusted_data=False,
                taint_trigger_source=None,
                taint_trigger_modality=None,
                active_tool_bindings=tools,
                stripped_tools=[],
                risk_category_ids=[],
            )
            self._sessions[session_id] = state
            return state

    def taint_session_on_inbound(
        self,
        session_id: str,
        source_uri: str,
        modality: Any,
        allowed_contract_tools: Optional[List[str]] = None,
    ) -> SessionPrivilegeState:
        """
        Called automatically by Hook 1 whenever any external file, email, chat,
        image, audio/video, or web DOM payload is ingested.
        Transitions the session to RESTRICTED_UNTRUSTED_CONTEXT, strips all high-risk
        capabilities, and records Risk #17.
        """
        modality_str = modality.value if hasattr(modality, "value") else str(modality)
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                tools = list(allowed_contract_tools) if allowed_contract_tools else list(DEFAULT_BUSINESS_TOOLS + DEFAULT_ADMIN_TOOLS)
                for t in DEFAULT_BUSINESS_TOOLS + DEFAULT_ADMIN_TOOLS:
                    if t not in tools:
                        tools.append(t)
                state = SessionPrivilegeState(
                    session_id=session_id,
                    permission_mask=PermissionMask.FULL_TRUSTED_CONTEXT,
                    is_tainted_by_untrusted_data=False,
                    active_tool_bindings=tools,
                    stripped_tools=[],
                    risk_category_ids=[],
                )
                self._sessions[session_id] = state

            # Irreversible transition to RESTRICTED_UNTRUSTED_CONTEXT
            state.permission_mask = PermissionMask.RESTRICTED_UNTRUSTED_CONTEXT
            state.is_tainted_by_untrusted_data = True
            state.taint_trigger_source = source_uri
            state.taint_trigger_modality = modality_str

            if 17 not in state.risk_category_ids:
                state.risk_category_ids.append(17)

            # Collect all candidate high-risk tools from active bindings, defaults, and definitions
            all_candidate_tools = set(state.active_tool_bindings) | HIGH_RISK_STRIPPED_TOOLS | set(DEFAULT_ADMIN_TOOLS)
            for tool in all_candidate_tools:
                if classify_high_risk_tool(tool) is not None:
                    if tool not in state.stripped_tools:
                        state.stripped_tools.append(tool)

            # Strip high-risk tools from active bindings
            state.active_tool_bindings = [
                t for t in state.active_tool_bindings
                if classify_high_risk_tool(t) is None
            ]

            # Ensure business tools remain accessible in active bindings
            for bt in DEFAULT_BUSINESS_TOOLS:
                if bt not in state.active_tool_bindings and bt not in state.stripped_tools:
                    state.active_tool_bindings.append(bt)

            if allowed_contract_tools:
                for act in allowed_contract_tools:
                    if classify_high_risk_tool(act) is None and act not in state.active_tool_bindings:
                        state.active_tool_bindings.append(act)

            return state

    # Alias for hook compatibility
    transition_to_untrusted_context = taint_session_on_inbound

    def evaluate_tool_call(self, session_id: str, tool_name: str) -> SandboxEvaluationResult:
        """
        Inspects the session's privilege state and evaluates whether the tool call is permitted.
        If in RESTRICTED_UNTRUSTED_CONTEXT, blocks administrative, filesystem deletion,
        shell execution, and bulk export tools with exact category attribution.
        """
        tn = tool_name.strip()
        state = self.register_or_get_session(session_id)

        if state.permission_mask == PermissionMask.RESTRICTED_UNTRUSTED_CONTEXT:
            cat = classify_high_risk_tool(tn)
            is_stripped = tn.lower() in [s.lower() for s in state.stripped_tools] or (cat is not None)

            if is_stripped:
                violated_cat = cat or "ADMINISTRATIVE"
                reason = (
                    f"Micro-Privilege Sandbox Violation (Risk #17): Tool '{tool_name}' ({violated_cat}) "
                    f"was dynamically stripped from active tool bindings after ingesting untrusted "
                    f"{state.taint_trigger_modality or 'payload'} '{state.taint_trigger_source or 'external_source'}'. "
                    f"Session mask is locked to RESTRICTED_UNTRUSTED_CONTEXT."
                )
                return SandboxEvaluationResult(
                    allowed=False,
                    session_id=session_id,
                    tool_name=tool_name,
                    permission_mask=state.permission_mask,
                    action_taken="BLOCKED_BY_MICRO_PRIVILEGE_SANDBOX",
                    violated_category=violated_cat,
                    active_tool_bindings=list(state.active_tool_bindings),
                    stripped_tools=list(state.stripped_tools),
                    risk_category_ids=[16, 17],
                    reason=reason,
                )

            # If tool is permitted business tool or in active tool bindings
            if tn.lower() in [a.lower() for a in state.active_tool_bindings] or any(tn.lower() == bt.lower() for bt in DEFAULT_BUSINESS_TOOLS):
                return SandboxEvaluationResult(
                    allowed=True,
                    session_id=session_id,
                    tool_name=tool_name,
                    permission_mask=state.permission_mask,
                    action_taken="SAFE_EXECUTED",
                    violated_category=None,
                    active_tool_bindings=list(state.active_tool_bindings),
                    stripped_tools=list(state.stripped_tools),
                    risk_category_ids=list(state.risk_category_ids),
                    reason=f"Tool '{tool_name}' permitted in RESTRICTED_UNTRUSTED_CONTEXT.",
                )

            # Unlisted tool in restricted sandbox
            reason = (
                f"Micro-Privilege Sandbox Violation (Risk #17): Tool '{tool_name}' is not permitted "
                f"in active tool bindings for RESTRICTED_UNTRUSTED_CONTEXT."
            )
            return SandboxEvaluationResult(
                allowed=False,
                session_id=session_id,
                tool_name=tool_name,
                permission_mask=state.permission_mask,
                action_taken="BLOCKED_BY_MICRO_PRIVILEGE_SANDBOX",
                violated_category="UNLISTED_IN_RESTRICTED_SANDBOX",
                active_tool_bindings=list(state.active_tool_bindings),
                stripped_tools=list(state.stripped_tools),
                risk_category_ids=[16, 17],
                reason=reason,
            )

        # FULL_TRUSTED_CONTEXT permits standard tool execution
        return SandboxEvaluationResult(
            allowed=True,
            session_id=session_id,
            tool_name=tool_name,
            permission_mask=state.permission_mask,
            action_taken="SAFE_EXECUTED",
            violated_category=None,
            active_tool_bindings=list(state.active_tool_bindings),
            stripped_tools=list(state.stripped_tools),
            risk_category_ids=list(state.risk_category_ids),
            reason=f"Tool '{tool_name}' permitted in FULL_TRUSTED_CONTEXT.",
        )

    def get_active_tool_bindings(self, session_id: str) -> List[str]:
        """Returns the list of tools OpenClaw is permitted to see/bind for the session."""
        state = self.register_or_get_session(session_id)
        return list(state.active_tool_bindings)

    def reset_session(self, session_id: str) -> None:
        """Utility for test suites to reset session state."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def reset_all(self) -> None:
        """Utility for test suites to reset all sessions."""
        with self._lock:
            self._sessions.clear()


# Global singleton instance
micro_privilege_sandbox = MicroPrivilegeSandbox()
