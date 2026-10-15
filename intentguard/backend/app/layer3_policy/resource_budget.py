"""
IntentGuard Layer 3 Deterministic Policy Gateway — Resource Budget Engine
==========================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Defines Step-0 Permissions, Rate Limits, Micro-Privilege Task Loop Caps,
and strict Inbound Payload Resource Budgets.

Defends against:
- Risk #19: Looping or Resource Exhaustion (Infinite tool loops, excessive iterations, API flooding)
- Risk #17: Excessive Permissions (Dynamic downgrade to micro-privilege read-only mode)
- Risk #1 & #8: Archive Bombs / Oversized File Payloads (15 MB strict ceiling)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Literal, Optional, Set

from pydantic import BaseModel, Field

from app.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Destructive / Admin tools restricted under Step-0 Micro-Privilege (Risk #17)
# ---------------------------------------------------------------------------
_DESTRUCTIVE_TOOLS = frozenset(
    {
        "bash",
        "exec_shell",
        "delete_file",
        "drop_table",
        "rmdir",
        "format_disk",
        "run_script",
    }
)


# ---------------------------------------------------------------------------
# Pydantic & Dataclass Models
# ---------------------------------------------------------------------------

class BudgetConfig(BaseModel):
    """
    Configurable resource thresholds and caps per session/task.
    Enables custom constraints for unit testing and production hardening.
    """
    max_requests_per_minute: int = 30
    max_tool_iterations_per_task: int = 8
    max_identical_tool_calls: int = 3
    max_file_upload_bytes: int = 15 * 1024 * 1024  # 15 MB
    max_execution_timeout_sec: float = 45.0
    max_memory_mb: int = 512


@dataclass
class SessionBudgetState:
    """
    In-memory state tracker for a single session's consumption metrics,
    call history, and permission baseline.
    """
    session_id: str
    task_start_timestamp: float = field(default_factory=time.time)
    request_timestamps: Deque[float] = field(default_factory=deque)
    total_tool_iterations: int = 0
    tool_signature_counts: Dict[str, int] = field(default_factory=dict)
    tool_invocation_history: List[Dict[str, Any]] = field(default_factory=list)
    allowed_permissions: Set[str] = field(
        default_factory=lambda: {"READ", "EXECUTE_SAFE_TOOL", "WRITE_MEMORY"}
    )
    is_locked_or_aborted: bool = False
    abort_reason: Optional[str] = None
    abort_violation_type: Optional[str] = None


class BudgetCheckResult(BaseModel):
    """
    Structured policy gate decision returned by ResourceBudgetEnforcer.
    """
    allowed: bool
    action_taken: Literal["SAFE_EXECUTED", "BLOCKED"]
    violation_type: Optional[
        Literal[
            "RATE_LIMIT_EXCEEDED",
            "FILE_SIZE_EXCEEDED",
            "MAX_ITERATIONS_EXCEEDED",
            "INFINITE_TOOL_LOOP_DETECTED",
            "EXECUTION_TIMEOUT_EXCEEDED",
            "EXCESSIVE_PERMISSION_DENIED",
        ]
    ] = None
    risk_category_ids: List[int] = Field(default_factory=list)
    policy_reference: str = "LAYER3_BUDGET_POLICY"
    reason: str = "Authorized under active resource budget."
    current_metrics: Dict[str, Any] = Field(default_factory=dict)


class BudgetViolationError(Exception):
    """Raised when a budget or loop invariant is critically breached."""
    def __init__(self, result: BudgetCheckResult) -> None:
        self.result = result
        super().__init__(result.reason)


# ---------------------------------------------------------------------------
# Canonical Tool Invocation Signature
# ---------------------------------------------------------------------------

def compute_tool_signature(tool_name: str, tool_arguments: Dict[str, Any]) -> str:
    """
    Deterministically computes a normalized SHA-256 tool invocation signature:
    `tool_name:sha256(canonical_json(tool_arguments))`

    Ensures dictionary key ordering or whitespace differences do not allow
    an attacker to bypass the identical tool loop detector.
    """
    normalized_name = tool_name.strip().lower()
    canonical_json = json.dumps(
        tool_arguments,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    canonical_args_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return f"{normalized_name}:{canonical_args_hash}"


# ---------------------------------------------------------------------------
# ResourceBudgetEnforcer Core Engine
# ---------------------------------------------------------------------------

class ResourceBudgetEnforcer:
    """
    Step-0 Resource Budget and Deterministic Loop Guard.

    Enforces:
    1. Sliding window request rate limit (default: 30 RPM).
    2. Micro-privilege task iteration cap (default: max 8 tool calls per task).
    3. Infinite tool loop detector (default: aborts on 3rd identical tool invocation).
    4. Payload size ceiling (default: 15 MB).
    5. Task execution timeout (default: 45.0s).
    6. Micro-privilege permission downgrade on ingestion of untrusted data (Risk #17).
    """

    def __init__(
        self,
        config: Optional[BudgetConfig] = None,
        max_requests_per_minute: Optional[int] = None,
        max_tool_iterations_per_task: Optional[int] = None,
        max_identical_tool_calls: Optional[int] = None,
        max_file_upload_bytes: Optional[int] = None,
        max_execution_timeout_sec: Optional[float] = None,
        max_memory_mb: Optional[int] = None,
    ) -> None:
        cfg = config or BudgetConfig()

        self.max_requests_per_minute: int = (
            max_requests_per_minute
            if max_requests_per_minute is not None
            else getattr(settings, "MAX_REQUESTS_PER_MINUTE", cfg.max_requests_per_minute)
        )
        self.max_tool_iterations_per_task: int = (
            max_tool_iterations_per_task
            if max_tool_iterations_per_task is not None
            else getattr(settings, "MAX_TOOL_ITERATIONS_PER_TASK", cfg.max_tool_iterations_per_task)
        )
        self.max_identical_tool_calls: int = (
            max_identical_tool_calls
            if max_identical_tool_calls is not None
            else cfg.max_identical_tool_calls
        )
        self.max_file_upload_bytes: int = (
            max_file_upload_bytes
            if max_file_upload_bytes is not None
            else getattr(settings, "max_file_upload_bytes", cfg.max_file_upload_bytes)
        )
        self.max_execution_timeout_sec: float = (
            float(max_execution_timeout_sec)
            if max_execution_timeout_sec is not None
            else float(getattr(settings, "MAX_EXECUTION_TIMEOUT_SECONDS", cfg.max_execution_timeout_sec))
        )
        self.max_memory_mb: int = (
            max_memory_mb if max_memory_mb is not None else cfg.max_memory_mb
        )

        self.sessions: Dict[str, SessionBudgetState] = {}

    def get_or_create_session(
        self, session_id: str, now: Optional[float] = None
    ) -> SessionBudgetState:
        """Retrieve existing session state or initialize a fresh budget tracker."""
        if session_id not in self.sessions:
            t = now if now is not None else time.time()
            self.sessions[session_id] = SessionBudgetState(
                session_id=session_id,
                task_start_timestamp=t,
            )
        return self.sessions[session_id]

    def reset_session(self, session_id: str) -> None:
        """Reset budget tracking and unlock session state."""
        if session_id in self.sessions:
            del self.sessions[session_id]

    def get_session_metrics(
        self, session_id: str, now: Optional[float] = None
    ) -> Dict[str, Any]:
        """Return a snapshot of current budget metrics for the session."""
        state = self.get_or_create_session(session_id, now=now)
        current_time = now if now is not None else time.time()
        valid_reqs = [t for t in state.request_timestamps if current_time - t <= 60.0]
        elapsed = max(0.0, current_time - state.task_start_timestamp)
        return {
            "session_id": session_id,
            "rpm_count": len(valid_reqs),
            "max_requests_per_minute": self.max_requests_per_minute,
            "total_tool_iterations": state.total_tool_iterations,
            "max_tool_iterations_per_task": self.max_tool_iterations_per_task,
            "max_identical_tool_calls": self.max_identical_tool_calls,
            "max_file_upload_bytes": self.max_file_upload_bytes,
            "elapsed_seconds": round(elapsed, 3),
            "max_execution_timeout_sec": self.max_execution_timeout_sec,
            "is_locked_or_aborted": state.is_locked_or_aborted,
            "abort_reason": state.abort_reason,
            "abort_violation_type": state.abort_violation_type,
            "allowed_permissions": sorted(list(state.allowed_permissions)),
            "tool_signature_counts": dict(state.tool_signature_counts),
        }

    # ───────────────────────────────────────────────────────────────────────
    # Micro-Privilege Permissions (Risk #17)
    # ───────────────────────────────────────────────────────────────────────

    def downgrade_permissions_for_untrusted_data(self, session_id: str) -> None:
        """
        Step-0 Micro-Privilege downgrade:
        When untrusted external data (email, PDF, web DOM, archive) enters
        the session, downgrade permissions to READ_ONLY_UNTRUSTED.
        """
        state = self.get_or_create_session(session_id)
        state.allowed_permissions = {"READ_ONLY_UNTRUSTED"}
        logger.info(
            "Session %s permissions downgraded to READ_ONLY_UNTRUSTED (Risk #17 mitigation)",
            session_id,
        )

    def check_tool_permission(
        self, session_id: str, tool_name: str
    ) -> BudgetCheckResult:
        """
        Verifies if the proposed tool is permitted under current session privilege.
        """
        state = self.get_or_create_session(session_id)
        norm_name = tool_name.strip().lower()

        if "READ_ONLY_UNTRUSTED" in state.allowed_permissions:
            if norm_name in _DESTRUCTIVE_TOOLS:
                state.is_locked_or_aborted = True
                state.abort_violation_type = "EXCESSIVE_PERMISSION_DENIED"
                state.abort_reason = (
                    f"Step-0 Micro-Privilege Blocked: Destructive tool '{tool_name}' "
                    "is denied when session contains untrusted external data. "
                    "Risk #17 (Excessive Permissions)."
                )
                return BudgetCheckResult(
                    allowed=False,
                    action_taken="BLOCKED",
                    violation_type="EXCESSIVE_PERMISSION_DENIED",
                    risk_category_ids=[16, 17],
                    policy_reference="RISK_17_EXCESSIVE_PERMISSIONS",
                    reason=state.abort_reason,
                    current_metrics=self.get_session_metrics(session_id),
                )

        return BudgetCheckResult(
            allowed=True,
            action_taken="SAFE_EXECUTED",
            reason="Tool invocation permitted under current privilege level.",
            current_metrics=self.get_session_metrics(session_id),
        )

    # ───────────────────────────────────────────────────────────────────────
    # Rate Limiting & Timeouts
    # ───────────────────────────────────────────────────────────────────────

    def check_execution_timeout(
        self, session_id: str, now: Optional[float] = None
    ) -> BudgetCheckResult:
        """
        Checks if task execution time exceeds max_execution_timeout_sec (45s).
        """
        state = self.get_or_create_session(session_id, now=now)
        current_time = now if now is not None else time.time()

        if state.is_locked_or_aborted and state.abort_violation_type == "EXECUTION_TIMEOUT_EXCEEDED":
            return BudgetCheckResult(
                allowed=False,
                action_taken="BLOCKED",
                violation_type="EXECUTION_TIMEOUT_EXCEEDED",
                risk_category_ids=[19],
                policy_reference="LAYER3_BUDGET_RISK_19_TIMEOUT",
                reason=state.abort_reason or "Execution timeout previously exceeded.",
                current_metrics=self.get_session_metrics(session_id, now=current_time),
            )

        elapsed = current_time - state.task_start_timestamp
        if elapsed > self.max_execution_timeout_sec:
            state.is_locked_or_aborted = True
            state.abort_violation_type = "EXECUTION_TIMEOUT_EXCEEDED"
            state.abort_reason = (
                f"Task execution timeout exceeded: {elapsed:.2f}s elapsed "
                f"(limit: {self.max_execution_timeout_sec}s). "
                "Risk #19 (Looping / Resource Exhaustion)."
            )
            return BudgetCheckResult(
                allowed=False,
                action_taken="BLOCKED",
                violation_type="EXECUTION_TIMEOUT_EXCEEDED",
                risk_category_ids=[19],
                policy_reference="LAYER3_BUDGET_RISK_19_TIMEOUT",
                reason=state.abort_reason,
                current_metrics=self.get_session_metrics(session_id, now=current_time),
            )

        return BudgetCheckResult(
            allowed=True,
            action_taken="SAFE_EXECUTED",
            reason="Execution duration within timeout budget.",
            current_metrics=self.get_session_metrics(session_id, now=current_time),
        )

    def check_request_rate(
        self, session_id: str, now: Optional[float] = None
    ) -> BudgetCheckResult:
        """
        Sliding 60-second window rate limiter (default: 30 requests per minute).
        """
        state = self.get_or_create_session(session_id, now=now)
        current_time = now if now is not None else time.time()

        # Prune timestamps older than 60 seconds
        while state.request_timestamps and (current_time - state.request_timestamps[0] > 60.0):
            state.request_timestamps.popleft()

        # Append current request timestamp
        state.request_timestamps.append(current_time)

        if len(state.request_timestamps) > self.max_requests_per_minute:
            state.is_locked_or_aborted = True
            state.abort_violation_type = "RATE_LIMIT_EXCEEDED"
            state.abort_reason = (
                f"Rate limit exceeded: {len(state.request_timestamps)} requests/min "
                f"> max {self.max_requests_per_minute} RPM allowed. "
                "Risk #19 (Looping / Resource Exhaustion)."
            )
            return BudgetCheckResult(
                allowed=False,
                action_taken="BLOCKED",
                violation_type="RATE_LIMIT_EXCEEDED",
                risk_category_ids=[19],
                policy_reference="LAYER3_BUDGET_RISK_19_RATE_LIMIT",
                reason=state.abort_reason,
                current_metrics=self.get_session_metrics(session_id, now=current_time),
            )

        return BudgetCheckResult(
            allowed=True,
            action_taken="SAFE_EXECUTED",
            reason="Request rate within RPM budget.",
            current_metrics=self.get_session_metrics(session_id, now=current_time),
        )

    # ───────────────────────────────────────────────────────────────────────
    # Inbound Payload Budget (Hook 1)
    # ───────────────────────────────────────────────────────────────────────

    def check_inbound_payload_budget(
        self,
        session_id: str,
        raw_text: Optional[str] = None,
        raw_base64: Optional[str] = None,
        declared_size_bytes: Optional[int] = None,
        now: Optional[float] = None,
    ) -> BudgetCheckResult:
        """
        Evaluates inbound data size against the 15 MB file upload ceiling,
        along with task execution timeout and RPM rate limit.
        """
        state = self.get_or_create_session(session_id, now=now)

        if state.is_locked_or_aborted:
            return BudgetCheckResult(
                allowed=False,
                action_taken="BLOCKED",
                violation_type=state.abort_violation_type or "MAX_ITERATIONS_EXCEEDED",  # type: ignore[arg-type]
                risk_category_ids=[19],
                policy_reference="LAYER3_BUDGET_SESSION_ABORTED",
                reason=state.abort_reason or "Session is locked/aborted due to prior budget violation.",
                current_metrics=self.get_session_metrics(session_id, now=now),
            )

        timeout_check = self.check_execution_timeout(session_id, now=now)
        if not timeout_check.allowed:
            return timeout_check

        rate_check = self.check_request_rate(session_id, now=now)
        if not rate_check.allowed:
            return rate_check

        # Compute payload size
        text_bytes = len(raw_text.encode("utf-8")) if raw_text else 0
        b64_bytes = 0
        if raw_base64:
            try:
                b64_bytes = len(base64.b64decode(raw_base64))
            except Exception:
                b64_bytes = (len(raw_base64) * 3) // 4
        declared_bytes = declared_size_bytes or 0

        actual_size = max(text_bytes, b64_bytes, declared_bytes)

        if actual_size > self.max_file_upload_bytes:
            state.is_locked_or_aborted = True
            state.abort_violation_type = "FILE_SIZE_EXCEEDED"
            state.abort_reason = (
                f"Inbound payload size ({actual_size} bytes) exceeds maximum ceiling "
                f"of {self.max_file_upload_bytes} bytes (15 MB). "
                "Risk #19 (Looping / Resource Exhaustion) & Risk #1, #8 (Archive Bombs / Oversized Payloads)."
            )
            metrics = self.get_session_metrics(session_id, now=now)
            metrics["payload_bytes"] = actual_size
            return BudgetCheckResult(
                allowed=False,
                action_taken="BLOCKED",
                violation_type="FILE_SIZE_EXCEEDED",
                risk_category_ids=[1, 8, 19],
                policy_reference="LAYER3_BUDGET_PAYLOAD_LIMIT",
                reason=state.abort_reason,
                current_metrics=metrics,
            )

        metrics = self.get_session_metrics(session_id, now=now)
        metrics["payload_bytes"] = actual_size
        return BudgetCheckResult(
            allowed=True,
            action_taken="SAFE_EXECUTED",
            reason="Payload size within resource budget.",
            current_metrics=metrics,
        )

    # ───────────────────────────────────────────────────────────────────────
    # Tool Call Budget & Loop Cap (Hook 2)
    # ───────────────────────────────────────────────────────────────────────

    def check_tool_call_budget(
        self,
        session_id: str,
        tool_name: str,
        tool_arguments: Dict[str, Any],
        now: Optional[float] = None,
    ) -> BudgetCheckResult:
        """
        Hook 2 Step-0 Gatekeeper.
        Evaluates:
        1. Session abort status.
        2. Execution timeout.
        3. Rate limits.
        4. Step-0 micro-privilege permissions.
        5. Canonical tool loop detection (aborts if identical tool call repeats >= 3 times).
        6. Micro-privilege task iteration cap (aborts if total tool calls > 8).
        """
        state = self.get_or_create_session(session_id, now=now)

        if state.is_locked_or_aborted:
            return BudgetCheckResult(
                allowed=False,
                action_taken="BLOCKED",
                violation_type=state.abort_violation_type or "INFINITE_TOOL_LOOP_DETECTED",  # type: ignore[arg-type]
                risk_category_ids=[19],
                policy_reference="LAYER3_BUDGET_SESSION_ABORTED",
                reason=state.abort_reason or "Session is locked/aborted due to prior budget violation.",
                current_metrics=self.get_session_metrics(session_id, now=now),
            )

        timeout_check = self.check_execution_timeout(session_id, now=now)
        if not timeout_check.allowed:
            return timeout_check

        rate_check = self.check_request_rate(session_id, now=now)
        if not rate_check.allowed:
            return rate_check

        perm_check = self.check_tool_permission(session_id, tool_name)
        if not perm_check.allowed:
            return perm_check

        # Compute deterministic canonical signature
        sig = compute_tool_signature(tool_name, tool_arguments)
        state.tool_signature_counts[sig] = state.tool_signature_counts.get(sig, 0) + 1

        current_time = now if now is not None else time.time()
        state.tool_invocation_history.append(
            {
                "tool_name": tool_name,
                "signature": sig,
                "timestamp": current_time,
            }
        )

        # ── 1. Sliding Window Identical Tool Loop Detection ─────────────────
        repeat_count = state.tool_signature_counts[sig]
        if repeat_count >= self.max_identical_tool_calls:
            state.is_locked_or_aborted = True
            state.abort_violation_type = "INFINITE_TOOL_LOOP_DETECTED"
            state.abort_reason = (
                f"Infinite tool loop detected: tool '{tool_name}' invoked {repeat_count} "
                f"times with identical arguments. Aborting per Risk #19 "
                "(Looping / Resource Exhaustion)."
            )
            return BudgetCheckResult(
                allowed=False,
                action_taken="BLOCKED",
                violation_type="INFINITE_TOOL_LOOP_DETECTED",
                risk_category_ids=[19],
                policy_reference="RISK_19_IDENTICAL_TOOL_LOOP_CAP",
                reason=state.abort_reason,
                current_metrics=self.get_session_metrics(session_id, now=now),
            )

        # ── 2. Micro-Privilege Task Iteration Cap ───────────────────────────
        state.total_tool_iterations += 1
        if state.total_tool_iterations > self.max_tool_iterations_per_task:
            state.is_locked_or_aborted = True
            state.abort_violation_type = "MAX_ITERATIONS_EXCEEDED"
            state.abort_reason = (
                f"Micro-privilege task iteration cap exceeded: {state.total_tool_iterations} "
                f"iterations > maximum {self.max_tool_iterations_per_task} allowed per task. "
                "Risk #19 (Looping / Resource Exhaustion)."
            )
            return BudgetCheckResult(
                allowed=False,
                action_taken="BLOCKED",
                violation_type="MAX_ITERATIONS_EXCEEDED",
                risk_category_ids=[19],
                policy_reference="RISK_19_MICRO_PRIVILEGE_ITERATION_CAP",
                reason=state.abort_reason,
                current_metrics=self.get_session_metrics(session_id, now=now),
            )

        return BudgetCheckResult(
            allowed=True,
            action_taken="SAFE_EXECUTED",
            reason="Tool invocation within iteration budget and loop caps.",
            current_metrics=self.get_session_metrics(session_id, now=now),
        )


# Singleton instance for application-wide deterministic policy gating
resource_budget_enforcer = ResourceBudgetEnforcer()
