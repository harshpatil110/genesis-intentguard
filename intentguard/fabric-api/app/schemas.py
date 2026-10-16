"""Pydantic schemas for Hyperledger Fabric 2.5.16 REST API Gateway."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

HEX_64_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")


class AuditEventCreate(BaseModel):
    """Strict 12-field incoming audit event schema required by Hyperledger Fabric chaincode."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(description="Unique event identifier")
    timestamp: str = Field(description="ISO 8601 UTC timestamp")
    buyer_id: str = Field(description="Identifier of the buyer organization")
    supplier_id: str = Field(description="Identifier of the supplier organization")
    input_modality: str = Field(description="Input modality, e.g. text, pdf, image")
    action_taken: str = Field(description="Action taken by security interceptor")
    policy_reference: str = Field(description="Policy reference string or ID")
    raw_evidence_sha256: str = Field(description="64-char hex SHA-256 of raw input")
    redacted_diff_sha256: str = Field(description="64-char hex SHA-256 of surgical redaction diff")
    intent_hmac_hash: str = Field(description="64-char hex HMAC-SHA256 of Step-0 intent")
    risk_category_ids: List[Union[int, str]] = Field(default_factory=list, description="List of triggered risk IDs")
    threat_detected: bool = Field(description="Whether an injection threat was detected")

    @field_validator(
        "event_id",
        "timestamp",
        "buyer_id",
        "supplier_id",
        "input_modality",
        "action_taken",
        "policy_reference",
        "raw_evidence_sha256",
        "redacted_diff_sha256",
        "intent_hmac_hash",
        mode="before",
    )
    @classmethod
    def validate_non_empty_strings(cls, v: Any, info) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError(f"Field '{info.field_name}' must be a non-empty string.")
        return v.strip()

    @field_validator("raw_evidence_sha256", "redacted_diff_sha256", "intent_hmac_hash")
    @classmethod
    def validate_64_hex_hashes(cls, v: str, info) -> str:
        clean = v.strip().lower()
        if not HEX_64_REGEX.match(clean):
            raise ValueError(
                f"Field '{info.field_name}' must be exactly 64 hexadecimal characters, got {v!r} (length={len(v)})."
            )
        return clean

    @model_validator(mode="after")
    def validate_chaincode_threat_rule(self) -> AuditEventCreate:
        if self.threat_detected and self.action_taken.upper() == "SAFE_EXECUTED":
            raise ValueError(
                "Chaincode Invariant Violation: 'threat_detected' is True but 'action_taken' is 'SAFE_EXECUTED'. "
                "When a threat is detected, action_taken must be BLOCKED, SURGICALLY_REDACTED, QUARANTINED_MEMORY, or HUMAN_REJECTED."
            )
        return self

    def to_chaincode_dict(self) -> Dict[str, Any]:
        """Convert payload to canonical dictionary expected by chaincode."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "buyer_id": self.buyer_id,
            "supplier_id": self.supplier_id,
            "input_modality": self.input_modality,
            "action_taken": self.action_taken,
            "policy_reference": self.policy_reference,
            "raw_evidence_sha256": self.raw_evidence_sha256,
            "redacted_diff_sha256": self.redacted_diff_sha256,
            "intent_hmac_hash": self.intent_hmac_hash,
            "risk_category_ids": self.risk_category_ids,
            "threat_detected": self.threat_detected,
        }


class AuditRecordResponse(BaseModel):
    """Response returned upon successful submission of an audit event to the ledger."""

    event_id: str
    recorded: bool = True
    transaction_id: str
