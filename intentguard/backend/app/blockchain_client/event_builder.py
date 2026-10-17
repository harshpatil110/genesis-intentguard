"""
IntentGuard — Strict 12-Field Hyperledger Fabric Audit Event Builder & Validator
==================================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Implements the exact 12-field Audit Event Data Contract enforced by the deployed
Hyperledger Fabric `intentguard` chaincode (v1.0.1, sequence 2).

Every audit payload generated across Layers 1, 2, and 3 is validated on the
application side before being transmitted to the Fabric REST API.

Chaincode Invariant Rules:
  A. First 10 string fields must be non-empty.
  B. timestamp must be valid ISO 8601 UTC ending with Z.
  C. raw_evidence_sha256, redacted_diff_sha256, intent_hmac_hash must each be
     exactly 64 lowercase hex characters.
  D. risk_category_ids must be a JSON array (list).
  E. CRITICAL: action_taken CANNOT be "SAFE_EXECUTED" when threat_detected is True.
     When threat_detected=True, action_taken must be one of:
     {"BLOCKED", "SURGICALLY_REDACTED", "QUARANTINED_MEMORY", "HUMAN_REJECTED"}
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.config import settings


# ---------------------------------------------------------------------------
# Chaincode Constants
# ---------------------------------------------------------------------------

HEX_64_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
ISO_8601_UTC_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")

VALID_THREAT_ACTIONS: set[str] = {
    "BLOCKED",
    "SURGICALLY_REDACTED",
    "QUARANTINED_MEMORY",
    "HUMAN_REJECTED",
}

VALID_SAFE_ACTIONS: set[str] = {
    "SAFE_EXECUTED",
    "BLOCKED",
    "SURGICALLY_REDACTED",
    "QUARANTINED_MEMORY",
    "HUMAN_REJECTED",
    "HUMAN_APPROVED",
}

EMPTY_SHA256_HEX: str = hashlib.sha256(b"").hexdigest()  # e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855


# ---------------------------------------------------------------------------
# Internal non-empty string field validator helper
# ---------------------------------------------------------------------------

def _validate_nonempty(v: str, field_name: str) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"Chaincode Rule A Violation: '{field_name}' must be a non-empty string, got: {v!r}")
    return v


# ---------------------------------------------------------------------------
# FabricAuditEventPayload — Strict 12-Field Chaincode Data Contract
# ---------------------------------------------------------------------------

class FabricAuditEventPayload(BaseModel):
    """
    Pydantic model enforcing the exact 12-field Hyperledger Fabric audit event
    schema required by the `intentguard` chaincode (v1.0.1, sequence 2).

    Validated and rejected on the application side before any HTTP transmission
    to the Fabric Gateway REST API.
    """

    model_config = ConfigDict(extra="forbid")

    # ---- Field 1: Unique event identifier --------------------------------
    event_id: str = Field(
        default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}"
    )

    # ---- Field 2: ISO 8601 UTC timestamp of the security event -----------
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    # ---- Fields 3 & 4: Party identifiers ---------------------------------
    buyer_id: str = "buyer-01"
    supplier_id: str = "supplier-01"

    # ---- Field 5: Input modality that triggered the event ----------------
    input_modality: str = "text"

    # ---- Field 6: Deterministic policy action taken ----------------------
    action_taken: str

    # ---- Field 7: Canonical policy/risk reference string -----------------
    policy_reference: str = "policy-v1"

    # ---- Fields 8-10: 64-char hexadecimal cryptographic hashes ----------
    raw_evidence_sha256: str
    redacted_diff_sha256: str
    intent_hmac_hash: str

    # ---- Field 11: Risk category IDs triggered by this event ------------
    risk_category_ids: List[Union[int, str]] = Field(default_factory=list)

    # ---- Field 12: Whether a threat was detected ------------------------
    threat_detected: bool = True

    @property
    def event_type(self) -> str:
        return "PROMPT_INJECTION_DETECTED" if self.threat_detected else "SAFE_BUSINESS_INTENT"

    @property
    def source(self) -> str:
        return "intentguard_layer3"

    @model_validator(mode="before")
    @classmethod
    def populate_defaults_and_synonyms(cls, data: Any) -> Any:
        if isinstance(data, dict):
            threat = data.get("threat_detected")
            if "event_type" in data and threat is None:
                data["threat_detected"] = (data["event_type"] == "PROMPT_INJECTION_DETECTED")
            data.pop("event_type", None)
            data.pop("source", None)
        return data

    def model_dump(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Dumps the model dictionary, ensuring event_type and source are mapped
        from internal fields (threat_detected, input_modality) for remote API compatibility.
        """
        d = super().model_dump(*args, **kwargs)
        if "event_type" not in d:
            d["event_type"] = self.event_type
        if "source" not in d:
            d["source"] = getattr(self, "input_modality", None) or self.source
        return d

    def to_chaincode_json_dict(self) -> Dict[str, Any]:
        """
        Maps internal fields to the exact expected keys of the teammate's Node.js Fabric REST API / chaincode:
        {
            "event_id": self.event_id,
            "event_type": "PROMPT_INJECTION_DETECTED" if self.threat_detected else "SAFE_BUSINESS_INTENT",
            "source": "intentguard_layer3",
            "action_taken": self.action_taken,
            "raw_evidence_sha256": self.raw_evidence_sha256,
            "redacted_diff_sha256": self.redacted_diff_sha256,
            "intent_hmac_hash": self.intent_hmac_hash
        }
        """
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source": self.source,
            "action_taken": self.action_taken,
            "raw_evidence_sha256": self.raw_evidence_sha256,
            "redacted_diff_sha256": self.redacted_diff_sha256,
            "intent_hmac_hash": self.intent_hmac_hash,
        }

    # ======================================================================
    # Rule A: Non-empty string validators for the first 10 string fields
    # ======================================================================

    @field_validator("event_id", mode="before")
    @classmethod
    def validate_event_id(cls, v: Any) -> str:
        return _validate_nonempty(v if isinstance(v, str) else str(v or ""), "event_id")

    @field_validator("buyer_id", mode="before")
    @classmethod
    def validate_buyer_id(cls, v: Any) -> str:
        return _validate_nonempty(v if isinstance(v, str) else str(v or ""), "buyer_id")

    @field_validator("supplier_id", mode="before")
    @classmethod
    def validate_supplier_id(cls, v: Any) -> str:
        return _validate_nonempty(v if isinstance(v, str) else str(v or ""), "supplier_id")

    @field_validator("input_modality", mode="before")
    @classmethod
    def validate_input_modality(cls, v: Any) -> str:
        return _validate_nonempty(v if isinstance(v, str) else str(v or ""), "input_modality")

    @field_validator("action_taken", mode="before")
    @classmethod
    def validate_action_taken(cls, v: Any) -> str:
        return _validate_nonempty(v if isinstance(v, str) else str(v or ""), "action_taken")

    @field_validator("policy_reference", mode="before")
    @classmethod
    def validate_policy_reference(cls, v: Any) -> str:
        return _validate_nonempty(v if isinstance(v, str) else str(v or ""), "policy_reference")

    # ======================================================================
    # Rule B: ISO 8601 UTC timestamp validation
    # ======================================================================

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_timestamp(cls, v: Any) -> str:
        s = v if isinstance(v, str) else ""
        if not s.strip():
            raise ValueError("Chaincode Rule A Violation: 'timestamp' must be a non-empty string.")
        if not ISO_8601_UTC_REGEX.match(s):
            raise ValueError(
                f"Chaincode Rule B Violation: 'timestamp' must be valid ISO 8601 UTC ending with Z "
                f"(e.g. '2026-10-15T12:00:00Z'), got: {s!r}"
            )
        # Additionally validate that the date is parseable
        try:
            ts_str = s.split(".")[0].rstrip("Z") + "+00:00"
            datetime.fromisoformat(ts_str)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"Chaincode Rule B Violation: 'timestamp' is not a valid calendar datetime: {s!r}"
            ) from exc
        return s

    # ======================================================================
    # Rule C: 64-character hexadecimal hash validators
    # ======================================================================

    @field_validator("raw_evidence_sha256", mode="before")
    @classmethod
    def validate_raw_evidence_sha256(cls, v: Any) -> str:
        s = v if isinstance(v, str) else ""
        if not s.strip():
            raise ValueError("Chaincode Rule A Violation: 'raw_evidence_sha256' must be non-empty.")
        if not HEX_64_REGEX.match(s):
            raise ValueError(
                f"Chaincode Rule C Violation: 'raw_evidence_sha256' must be exactly 64 hexadecimal characters "
                f"(^[0-9a-fA-F]{{64}}$). Got {len(s)} chars: {s[:16]!r}..."
            )
        return s.lower()

    @field_validator("redacted_diff_sha256", mode="before")
    @classmethod
    def validate_redacted_diff_sha256(cls, v: Any) -> str:
        s = v if isinstance(v, str) else ""
        if not s.strip():
            raise ValueError("Chaincode Rule A Violation: 'redacted_diff_sha256' must be non-empty.")
        if not HEX_64_REGEX.match(s):
            raise ValueError(
                f"Chaincode Rule C Violation: 'redacted_diff_sha256' must be exactly 64 hexadecimal characters "
                f"(^[0-9a-fA-F]{{64}}$). Got {len(s)} chars: {s[:16]!r}..."
            )
        return s.lower()

    @field_validator("intent_hmac_hash", mode="before")
    @classmethod
    def validate_intent_hmac_hash(cls, v: Any) -> str:
        s = v if isinstance(v, str) else ""
        if not s.strip():
            raise ValueError("Chaincode Rule A Violation: 'intent_hmac_hash' must be non-empty.")
        if not HEX_64_REGEX.match(s):
            raise ValueError(
                f"Chaincode Rule C Violation: 'intent_hmac_hash' must be exactly 64 hexadecimal characters "
                f"(^[0-9a-fA-F]{{64}}$). Got {len(s)} chars: {s[:16]!r}..."
            )
        return s.lower()

    # ======================================================================
    # Rule D: risk_category_ids must be a JSON array
    # ======================================================================

    @field_validator("risk_category_ids", mode="before")
    @classmethod
    def validate_risk_category_ids(cls, v: Any) -> list:
        if not isinstance(v, list):
            raise ValueError(
                f"Chaincode Rule D Violation: 'risk_category_ids' must be a JSON array (list), got: {type(v).__name__!r}"
            )
        return v

    # ======================================================================
    # Rule E (CRITICAL CHAINCODE RULE): threat_detected vs action_taken
    # ======================================================================

    @model_validator(mode="after")
    def enforce_chaincode_threat_action_invariant(self) -> "FabricAuditEventPayload":
        if self.threat_detected:
            if self.action_taken == "SAFE_EXECUTED":
                raise ValueError(
                    "Chaincode Violation: action_taken cannot be 'SAFE_EXECUTED' when threat_detected is True. "
                    "Valid threat-mitigation actions: BLOCKED, SURGICALLY_REDACTED, QUARANTINED_MEMORY, HUMAN_REJECTED."
                )
            if self.action_taken not in VALID_THREAT_ACTIONS:
                raise ValueError(
                    f"Chaincode Rule E Violation: When threat_detected is True, action_taken must be one of "
                    f"{sorted(VALID_THREAT_ACTIONS)}, got: {self.action_taken!r}"
                )
        return self


# ---------------------------------------------------------------------------
# FabricAuditEventBuilder — Deterministic Helper for All 4 Hooks
# ---------------------------------------------------------------------------

class FabricAuditEventBuilder:
    """
    Convenience builder for constructing validated FabricAuditEventPayload instances.
    Used by Hook 1, Hook 2, Hook 3, Hook 4, and the StepBackApprovalEngine (Task 20)
    to reliably produce chaincode-compliant audit events.
    """

    # Internal mapping of internal gateway action strings to chaincode-compliant values
    _ACTION_NORMALIZATION_THREAT: Dict[str, str] = {
        # Redaction variants → SURGICALLY_REDACTED
        "redacted": "SURGICALLY_REDACTED",
        "decloaked": "SURGICALLY_REDACTED",
        "surgically_redacted": "SURGICALLY_REDACTED",
        "redacted_exfiltration_links": "SURGICALLY_REDACTED",
        "redacted_echoleak_image": "SURGICALLY_REDACTED",
        "safe_passed": "SURGICALLY_REDACTED",
        # Memory quarantine variants → QUARANTINED_MEMORY
        "quarantined": "QUARANTINED_MEMORY",
        "quarantined_memory": "QUARANTINED_MEMORY",
        # Human rejection variants → HUMAN_REJECTED
        "human_rejected": "HUMAN_REJECTED",
        "human_rejected_blocked": "HUMAN_REJECTED",
        "keep_action_blocked": "HUMAN_REJECTED",
        "human_approval_required": "BLOCKED",
        # Block variants → BLOCKED
        "blocked": "BLOCKED",
        "blocked_by_micro_privilege_sandbox": "BLOCKED",
        "blocked_ssrf_or_untrusted_url": "BLOCKED",
    }

    @staticmethod
    def generate_event_id() -> str:
        """Returns a globally unique event ID (e.g. 'evt-3f2a1b4c5d6e')."""
        return f"evt-{uuid.uuid4().hex[:12]}"

    @staticmethod
    def utc_timestamp_now() -> str:
        """Returns current UTC timestamp in ISO 8601 format with Z suffix."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def ensure_64_hex(value: Optional[str], fallback_seed: str = "") -> str:
        """
        If value is already a valid 64-char hex string, returns value.lower().
        Otherwise computes SHA-256 hash of fallback_seed and returns that.
        """
        if value and HEX_64_REGEX.match(value):
            return value.lower()
        return hashlib.sha256(fallback_seed.encode("utf-8")).hexdigest()

    @classmethod
    def normalize_action_for_chaincode(cls, action_taken: str, threat_detected: bool) -> str:
        """
        Maps internal IntentGuard gateway action strings to chaincode-compliant
        action_taken values. When threat_detected=True, the action must be one of
        the VALID_THREAT_ACTIONS set. Does NOT override the chaincode safety invariant
        (threat_detected=True + SAFE_EXECUTED will still be caught by the model_validator).
        """
        if not threat_detected:
            if action_taken.upper() == "SAFE_EXECUTED":
                return "SAFE_EXECUTED"
            return action_taken.upper() if action_taken.upper() in VALID_SAFE_ACTIONS else "BLOCKED"

        normalized = cls._ACTION_NORMALIZATION_THREAT.get(action_taken.lower().strip())
        if normalized:
            return normalized
        # Default fallback for threat actions
        return "BLOCKED"

    @classmethod
    def build_event(
        cls,
        buyer_id: str = "",
        supplier_id: str = "",
        input_modality: str = "text",
        action_taken: str = "BLOCKED",
        threat_detected: bool = True,
        risk_category_ids: Optional[List[Union[int, str]]] = None,
        raw_evidence_sha256: Optional[str] = None,
        redacted_diff_sha256: Optional[str] = None,
        intent_hmac_hash: Optional[str] = None,
        policy_reference: str = "policy-v1",
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> FabricAuditEventPayload:
        """
        Builds and validates a FabricAuditEventPayload with safe defaults.
        Auto-generates event_id and timestamp if not provided.
        Auto-ensures all 3 hash fields are valid 64-char hex.
        """
        resolved_buyer = buyer_id or getattr(settings, "DEFAULT_BUYER_ID", "buyer-01")
        resolved_supplier = supplier_id or getattr(settings, "DEFAULT_SUPPLIER_ID", "supplier-01")

        normalized_action = cls.normalize_action_for_chaincode(action_taken, threat_detected)

        return FabricAuditEventPayload(
            event_id=event_id or cls.generate_event_id(),
            timestamp=timestamp or cls.utc_timestamp_now(),
            buyer_id=resolved_buyer,
            supplier_id=resolved_supplier,
            input_modality=input_modality,
            action_taken=normalized_action,
            policy_reference=policy_reference,
            raw_evidence_sha256=cls.ensure_64_hex(raw_evidence_sha256, "raw_evidence"),
            redacted_diff_sha256=cls.ensure_64_hex(redacted_diff_sha256, "redacted_diff"),
            intent_hmac_hash=cls.ensure_64_hex(intent_hmac_hash, "intent_hmac"),
            risk_category_ids=risk_category_ids if risk_category_ids is not None else [],
            threat_detected=threat_detected,
        )

    @staticmethod
    def to_chaincode_json_dict(event: FabricAuditEventPayload) -> Dict[str, Any]:
        """
        Serializes the validated payload to the exact 7-field dictionary required by
        the teammate's remote Node.js Fabric REST API / chaincode.
        """
        return event.to_chaincode_json_dict()


# ---------------------------------------------------------------------------
# Module-level singleton builder instance
# ---------------------------------------------------------------------------

fabric_event_builder = FabricAuditEventBuilder()
