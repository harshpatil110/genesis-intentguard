"""
IntentGuard — Fail-Closed Security Circuit Breaker & Anti-Bypass Guard
======================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Mitigates:
  - Risk #30: Security-Control Bypass (Direct tool invocation without Layer 3 ExecutionPermitToken,
              token replay, TTL expiration, or parameter tampering after token issuance).
  - Risk #33: Fail-Open Behavior (Halts sensitive write/payment operations if Layer 1, Layer 3,
              Redis Quarantine Vault, or Hyperledger Fabric API suffers HTTP 500/503 outages).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Any, Callable, Dict, List, Literal, Optional, Set

from pydantic import BaseModel, Field

from app.config import settings

logger = logging.getLogger("intentguard.layer3.fail_closed_guard")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SENSITIVE_WRITE_AND_PAYMENT_TOOLS: Set[str] = {
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

DEFAULT_TOKEN_TTL_SECONDS: int = 15

CRITICAL_SERVICES = (
    "decloaker_service",
    "policy_engine",
    "redis_quarantine",
    "fabric_blockchain_api",
)


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class ExecutionPermitToken(BaseModel):
    """Short-lived, cryptographically signed token authorizing a specific sandbox tool call."""

    token_id: str = Field(default_factory=lambda: f"tok-{uuid.uuid4().hex[:12]}")
    session_id: str
    tool_name: str
    canonical_args_sha256: str
    intent_hmac_hash: str
    issued_at_epoch: float
    expires_at_epoch: float
    signature_hmac: str


class SandboxToolVerifyRequest(BaseModel):
    """Payload sent by the sandbox tool runner to verify execution permission."""

    session_id: str
    tool_name: str
    tool_arguments: Dict[str, Any] = Field(default_factory=dict)
    permit_token: Optional[ExecutionPermitToken] = None
    raw_execution_token_hmac: Optional[str] = None


class SandboxToolVerifyResponse(BaseModel):
    """Response returned to the sandbox tool runner authorizing or denying execution."""

    verified: bool
    allow_sandbox_execution: bool
    action_taken: Literal["SAFE_EXECUTED", "BLOCKED"]
    threat_detected: bool
    risk_category_ids: List[int] = Field(default_factory=list)
    bypass_attempt_detected: bool = False
    fail_closed_triggered: bool = False
    reason: str


class DependencyHealthState(BaseModel):
    """Tracks operational health of a critical downstream security dependency."""

    service_name: str
    healthy: bool = True
    last_status_code: int = 200
    failure_reason: Optional[str] = None
    consecutive_failures: int = 0


# ---------------------------------------------------------------------------
# Class 1: AntiBypassTokenVerifier (Prevents Risk #30 Security-Control Bypass)
# ---------------------------------------------------------------------------

class AntiBypassTokenVerifier:
    """Enforces cryptographic permit tokens on all sandbox tool executions."""

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key: str = secret_key or settings.HMAC_MASTER_SECRET
        self._consumed_token_ids: Set[str] = set()
        self._issued_tokens_by_hmac: Dict[str, ExecutionPermitToken] = {}
        self._issued_tokens_by_id: Dict[str, ExecutionPermitToken] = {}

    @staticmethod
    def compute_canonical_args_sha256(args: Dict[str, Any]) -> str:
        """Deterministically serialize tool arguments and compute 64-char hex SHA-256."""
        canonical_json = json.dumps(args, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def _sign_token(
        self,
        token_id: str,
        session_id: str,
        tool_name: str,
        canonical_args_sha256: str,
        intent_hmac_hash: str,
        issued_at_epoch: float,
        expires_at_epoch: float,
    ) -> str:
        """Compute 64-char hex HMAC-SHA256 signature binding token fields to the master secret."""
        payload = (
            f"{token_id}:{session_id}:{tool_name}:{canonical_args_sha256}:"
            f"{intent_hmac_hash}:{issued_at_epoch:.3f}:{expires_at_epoch:.3f}"
        )
        return hmac.new(
            self.secret_key.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def issue_permit_token(
        self,
        session_id: str,
        tool_name: str,
        tool_arguments: Dict[str, Any],
        intent_hmac_hash: str,
        ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
    ) -> ExecutionPermitToken:
        """Issue a short-lived, cryptographically signed ExecutionPermitToken."""
        token_id = f"tok-{uuid.uuid4().hex[:12]}"
        canonical_args_sha256 = self.compute_canonical_args_sha256(tool_arguments)
        issued_at = time.time()
        expires_at = issued_at + ttl_seconds

        signature = self._sign_token(
            token_id=token_id,
            session_id=session_id,
            tool_name=tool_name,
            canonical_args_sha256=canonical_args_sha256,
            intent_hmac_hash=intent_hmac_hash,
            issued_at_epoch=issued_at,
            expires_at_epoch=expires_at,
        )

        token = ExecutionPermitToken(
            token_id=token_id,
            session_id=session_id,
            tool_name=tool_name,
            canonical_args_sha256=canonical_args_sha256,
            intent_hmac_hash=intent_hmac_hash,
            issued_at_epoch=issued_at,
            expires_at_epoch=expires_at,
            signature_hmac=signature,
        )

        self._issued_tokens_by_hmac[signature] = token
        self._issued_tokens_by_id[token_id] = token
        return token

    def verify_and_consume_token(
        self, request: SandboxToolVerifyRequest
    ) -> SandboxToolVerifyResponse:
        """Verify an ExecutionPermitToken against all 5 anti-bypass invariants.

        Invariants checked:
          A. Token presence (detects direct sandbox bypass attempts)
          B. Single-use replay protection
          C. TTL expiration
          D. Tool name, session ID, and argument binding integrity
          E. HMAC-SHA256 cryptographic authenticity
        """
        token: Optional[ExecutionPermitToken] = request.permit_token
        if token is None and request.raw_execution_token_hmac:
            token = self._issued_tokens_by_hmac.get(request.raw_execution_token_hmac)

        # Check A: Missing or unregistered token (Direct Bypass Attempt)
        if token is None:
            return SandboxToolVerifyResponse(
                verified=False,
                allow_sandbox_execution=False,
                action_taken="BLOCKED",
                threat_detected=True,
                bypass_attempt_detected=True,
                risk_category_ids=[30],
                reason=(
                    "Risk #30 Security-Control Bypass blocked: Direct tool execution "
                    "attempted without a valid Layer 3 ExecutionPermitToken."
                ),
            )

        # Check B: Replay Attack Protection (Single-Use Nonce)
        if token.token_id in self._consumed_token_ids:
            return SandboxToolVerifyResponse(
                verified=False,
                allow_sandbox_execution=False,
                action_taken="BLOCKED",
                threat_detected=True,
                bypass_attempt_detected=True,
                risk_category_ids=[30],
                reason=(
                    f"Risk #30 Security-Control Bypass blocked: Replay of consumed "
                    f"ExecutionPermitToken '{token.token_id}'."
                ),
            )

        # Check C: TTL Expiration Check
        now = time.time()
        if now > token.expires_at_epoch:
            return SandboxToolVerifyResponse(
                verified=False,
                allow_sandbox_execution=False,
                action_taken="BLOCKED",
                threat_detected=True,
                bypass_attempt_detected=True,
                risk_category_ids=[30],
                reason=(
                    f"Risk #30 Security-Control Bypass blocked: Expired ExecutionPermitToken "
                    f"'{token.token_id}' (expired {now - token.expires_at_epoch:.2f}s ago)."
                ),
            )

        # Check D: Parameter and Tool Binding Integrity
        recomputed_args_sha = self.compute_canonical_args_sha256(request.tool_arguments)
        if (
            token.session_id != request.session_id
            or token.tool_name != request.tool_name
            or token.canonical_args_sha256 != recomputed_args_sha
        ):
            return SandboxToolVerifyResponse(
                verified=False,
                allow_sandbox_execution=False,
                action_taken="BLOCKED",
                threat_detected=True,
                bypass_attempt_detected=True,
                risk_category_ids=[18, 30],
                reason=(
                    f"Risk #30 Parameter Tampering blocked: Token bound to '{token.tool_name}' "
                    f"with args sha {token.canonical_args_sha256}, but received '{request.tool_name}' "
                    f"with sha {recomputed_args_sha}."
                ),
            )

        # Check E: Cryptographic HMAC Signature Verification
        expected_sig = self._sign_token(
            token_id=token.token_id,
            session_id=token.session_id,
            tool_name=token.tool_name,
            canonical_args_sha256=token.canonical_args_sha256,
            intent_hmac_hash=token.intent_hmac_hash,
            issued_at_epoch=token.issued_at_epoch,
            expires_at_epoch=token.expires_at_epoch,
        )
        if not hmac.compare_digest(token.signature_hmac, expected_sig):
            return SandboxToolVerifyResponse(
                verified=False,
                allow_sandbox_execution=False,
                action_taken="BLOCKED",
                threat_detected=True,
                bypass_attempt_detected=True,
                risk_category_ids=[30],
                reason=(
                    f"Risk #30 Security-Control Bypass blocked: Invalid cryptographic HMAC "
                    f"signature on ExecutionPermitToken '{token.token_id}'."
                ),
            )

        # All 5 invariants passed: Consume nonce and authorize execution
        self._consumed_token_ids.add(token.token_id)
        return SandboxToolVerifyResponse(
            verified=True,
            allow_sandbox_execution=True,
            action_taken="SAFE_EXECUTED",
            threat_detected=False,
            risk_category_ids=[],
            bypass_attempt_detected=False,
            fail_closed_triggered=False,
            reason=f"ExecutionPermitToken '{token.token_id}' verified and consumed successfully.",
        )

    def verify_permit_token(
        self, request: SandboxToolVerifyRequest
    ) -> SandboxToolVerifyResponse:
        """Alias for verify_and_consume_token."""
        return self.verify_and_consume_token(request)

    def reset(self) -> None:
        """Clear all consumed and issued tokens for test isolation."""
        self._consumed_token_ids.clear()
        self._issued_tokens_by_hmac.clear()
        self._issued_tokens_by_id.clear()


# ---------------------------------------------------------------------------
# Class 2: FailClosedCircuitBreaker (Prevents Risk #33 Fail-Open Behavior)
# ---------------------------------------------------------------------------

class FailClosedCircuitBreaker:
    """Monitors security dependencies and trips into lockdown on HTTP 500/503 outages."""

    def __init__(self):
        self._services: Dict[str, DependencyHealthState] = {
            svc: DependencyHealthState(service_name=svc) for svc in CRITICAL_SERVICES
        }

    def record_service_status(
        self, service_name: str, status_code: int, error_msg: Optional[str] = None
    ) -> None:
        """Record the health status of a critical security service."""
        if service_name not in self._services:
            self._services[service_name] = DependencyHealthState(service_name=service_name)

        state = self._services[service_name]
        state.last_status_code = status_code

        if status_code >= 500 or status_code == 0:
            state.healthy = False
            state.consecutive_failures += 1
            state.failure_reason = error_msg or f"Service returned status {status_code}"
            logger.warning(
                "Critical security dependency '%s' tripped into UNHEALTHY state (status=%d): %s",
                service_name,
                status_code,
                error_msg,
            )
        elif 200 <= status_code < 300:
            state.healthy = True
            state.consecutive_failures = 0
            state.failure_reason = None

    def enforce_fail_closed_before_action(
        self, tool_name: str, callable_check: Optional[Callable] = None
    ) -> Optional[SandboxToolVerifyResponse]:
        """Check if any critical security dependency is down before allowing a sensitive operation."""
        # 1. Run optional probe if provided
        if callable_check is not None:
            try:
                res = callable_check()
                if hasattr(res, "status_code") and res.status_code >= 500:
                    self.record_service_status("policy_engine", res.status_code, "Probe status failure")
            except Exception as exc:
                self.record_service_status("policy_engine", 503, str(exc))

        # 2. If sensitive tool, check for any unhealthy critical dependency
        if tool_name in SENSITIVE_WRITE_AND_PAYMENT_TOOLS:
            for svc_name, state in self._services.items():
                if not state.healthy:
                    logger.critical(
                        "Risk #33 Fail-Closed Lockdown engaged: Dependency '%s' is down (status=%d). "
                        "Sensitive tool '%s' blocked.",
                        svc_name,
                        state.last_status_code,
                        tool_name,
                    )
                    return SandboxToolVerifyResponse(
                        verified=False,
                        allow_sandbox_execution=False,
                        action_taken="BLOCKED",
                        threat_detected=True,
                        fail_closed_triggered=True,
                        bypass_attempt_detected=False,
                        risk_category_ids=[33],
                        reason=(
                            f"Risk #33 Fail-Closed Protection triggered: Critical security dependency "
                            f"'{svc_name}' is unreachable or returned status {state.last_status_code} "
                            f"({state.failure_reason or 'Service Outage'}). Halting sensitive tool '{tool_name}'."
                        ),
                    )

        return None

    def reset_circuit(self) -> None:
        """Reset all tracked services to healthy status."""
        for svc in CRITICAL_SERVICES:
            self._services[svc] = DependencyHealthState(service_name=svc)

    def get_circuit_snapshot(self) -> Dict[str, Any]:
        """Return diagnostic snapshot of all tracked services."""
        return {
            svc: {
                "healthy": state.healthy,
                "last_status_code": state.last_status_code,
                "consecutive_failures": state.consecutive_failures,
                "failure_reason": state.failure_reason,
            }
            for svc, state in self._services.items()
        }


# Singletons for application-wide wiring
anti_bypass_verifier: AntiBypassTokenVerifier = AntiBypassTokenVerifier()
fail_closed_breaker: FailClosedCircuitBreaker = FailClosedCircuitBreaker()
