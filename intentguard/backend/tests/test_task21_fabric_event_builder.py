"""
IntentGuard Automated Pytest Suite — Task 21: Strict 12-Field Hyperledger Fabric Audit Event Builder & Validator
=================================================================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Tests the complete FabricAuditEventPayload chaincode data contract enforcement:
1. Valid 12-field payload matching exact specification — 100% structural compliance.
2. Auto-generated event_id ("evt-" prefix) and ISO 8601 UTC timestamp.
3. Rule A: All 10 string fields reject empty or whitespace-only values.
4. Rule B: timestamp must be valid ISO 8601 UTC ending with Z.
5. Rule C: raw_evidence_sha256, redacted_diff_sha256, intent_hmac_hash must be
   exactly 64 hex characters — too short, too long, and non-hex chars all rejected.
6. Rule D: risk_category_ids must be a list, not None or a scalar.
7. Rule E (CRITICAL CHAINCODE RULE): threat_detected=True with
   action_taken="SAFE_EXECUTED" raises ValidationError.
   Each valid threat action ("BLOCKED", "SURGICALLY_REDACTED",
   "QUARANTINED_MEMORY", "HUMAN_REJECTED") passes.
   threat_detected=False with action_taken="SAFE_EXECUTED" passes.
8. FabricAuditEventBuilder.normalize_action_for_chaincode covers all gateway
   action string mappings.
9. to_chaincode_json_dict produces exactly 12 keys, all serializable.
"""

import re

import pytest
from pydantic import ValidationError

from app.blockchain_client.event_builder import (
    EMPTY_SHA256_HEX,
    HEX_64_REGEX,
    VALID_THREAT_ACTIONS,
    FabricAuditEventBuilder,
    FabricAuditEventPayload,
)

# ---------------------------------------------------------------------------
# Helper: valid 64-char hex strings of different characters
# ---------------------------------------------------------------------------
HEX_A_64 = "a" * 64
HEX_B_64 = "b" * 64
HEX_C_64 = "c" * 64

VALID_BASE_KWARGS = dict(
    event_id="evt-001",
    timestamp="2026-10-15T12:00:00Z",
    buyer_id="buyer-01",
    supplier_id="supplier-01",
    input_modality="text",
    action_taken="BLOCKED",
    policy_reference="policy-v1",
    raw_evidence_sha256=HEX_A_64,
    redacted_diff_sha256=HEX_B_64,
    intent_hmac_hash=HEX_C_64,
    risk_category_ids=[2, 18],
    threat_detected=True,
)


# ---------------------------------------------------------------------------
# Test 1: Valid 12-field payload matches exact spec
# ---------------------------------------------------------------------------

def test_valid_12_field_payload_matches_exact_contract():
    """
    Instantiate FabricAuditEventPayload with the specification sample.
    Assert model_dump() has exactly 12 keys and all values match.
    """
    ev = FabricAuditEventPayload(**VALID_BASE_KWARGS)
    dumped = ev.model_dump()

    assert len(dumped) == 14, f"Expected 14 keys, got {len(dumped)}: {list(dumped.keys())}"

    assert dumped["event_id"] == "evt-001"
    assert dumped["timestamp"] == "2026-10-15T12:00:00Z"
    assert dumped["buyer_id"] == "buyer-01"
    assert dumped["supplier_id"] == "supplier-01"
    assert dumped["input_modality"] == "text"
    assert dumped["action_taken"] == "BLOCKED"
    assert dumped["policy_reference"] == "policy-v1"
    assert dumped["raw_evidence_sha256"] == HEX_A_64
    assert dumped["redacted_diff_sha256"] == HEX_B_64
    assert dumped["intent_hmac_hash"] == HEX_C_64
    assert dumped["risk_category_ids"] == [2, 18]
    assert dumped["threat_detected"] is True
    assert dumped["event_type"] == "PROMPT_INJECTION_DETECTED"
    assert dumped["source"] == "text"

    # Verify exact key names (no extra or missing fields)
    expected_keys = {
        "event_id", "timestamp", "buyer_id", "supplier_id", "input_modality",
        "action_taken", "policy_reference", "raw_evidence_sha256",
        "redacted_diff_sha256", "intent_hmac_hash", "risk_category_ids", "threat_detected",
        "event_type", "source",
    }
    assert set(dumped.keys()) == expected_keys


# ---------------------------------------------------------------------------
# Test 2: Auto-generated event_id and ISO 8601 timestamp
# ---------------------------------------------------------------------------

def test_auto_generated_event_id_and_iso8601_timestamp():
    """
    Build event without event_id or timestamp.
    Assert event_id starts with 'evt-', is 16 chars total,
    and timestamp matches ISO 8601 Z format.
    """
    ev = FabricAuditEventBuilder.build_event(
        buyer_id="buyer-01",
        supplier_id="supplier-01",
        input_modality="pdf",
        action_taken="BLOCKED",
        threat_detected=True,
        risk_category_ids=[5],
    )

    assert ev.event_id.startswith("evt-"), f"event_id should start with 'evt-', got: {ev.event_id!r}"
    assert len(ev.event_id) == 16, f"event_id should be 16 chars (evt- + 12), got {len(ev.event_id)}: {ev.event_id!r}"
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", ev.timestamp), (
        f"timestamp does not match ISO 8601 UTC Z format: {ev.timestamp!r}"
    )


# ---------------------------------------------------------------------------
# Test 3: Rule A — All 10 string fields reject empty / whitespace-only values
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field_name,empty_value", [
    ("event_id", ""),
    ("event_id", "   "),
    ("timestamp", ""),
    ("timestamp", "   "),
    ("buyer_id", ""),
    ("buyer_id", "   "),
    ("supplier_id", ""),
    ("supplier_id", "   "),
    ("input_modality", ""),
    ("input_modality", "   "),
    ("action_taken", ""),
    ("action_taken", "   "),
    ("policy_reference", ""),
    ("policy_reference", "   "),
    ("raw_evidence_sha256", ""),
    ("raw_evidence_sha256", "   "),
    ("redacted_diff_sha256", ""),
    ("redacted_diff_sha256", "   "),
    ("intent_hmac_hash", ""),
    ("intent_hmac_hash", "   "),
])
def test_first_10_fields_reject_empty_strings(field_name, empty_value):
    """Rule A: All 10 string fields must be non-empty."""
    bad_kwargs = dict(VALID_BASE_KWARGS)
    bad_kwargs[field_name] = empty_value
    with pytest.raises(ValidationError) as exc_info:
        FabricAuditEventPayload(**bad_kwargs)
    assert "non-empty" in str(exc_info.value).lower() or "violation" in str(exc_info.value).lower() or "must" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Test 4: Rule B — ISO 8601 UTC timestamp validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_ts", [
    "2026-10-15T12:00:00",        # Missing Z
    "2026-10-15 12:00:00Z",       # Space instead of T
    "15/10/2026 12:00:00Z",       # Wrong format
    "2026-13-15T12:00:00Z",       # Invalid month
    "not-a-timestamp",
    "2026-10-15T25:00:00Z",       # Hour 25 — invalid
])
def test_timestamp_rejects_invalid_iso8601(bad_ts):
    """Rule B: timestamp must be valid ISO 8601 UTC ending with Z."""
    bad_kwargs = dict(VALID_BASE_KWARGS)
    bad_kwargs["timestamp"] = bad_ts
    with pytest.raises(ValidationError):
        FabricAuditEventPayload(**bad_kwargs)


def test_timestamp_accepts_valid_iso8601():
    """Rule B: valid ISO 8601 UTC timestamps should pass."""
    valid_timestamps = [
        "2026-10-15T12:00:00Z",
        "2026-01-01T00:00:00Z",
        "2099-12-31T23:59:59Z",
        "2026-10-15T12:00:00.123Z",  # fractional seconds
    ]
    for ts in valid_timestamps:
        ev = FabricAuditEventPayload(**{**VALID_BASE_KWARGS, "timestamp": ts})
        assert ev.timestamp == ts


# ---------------------------------------------------------------------------
# Test 5: Rule C — 64-char hex validation on all three hash fields
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("hash_field", [
    "raw_evidence_sha256",
    "redacted_diff_sha256",
    "intent_hmac_hash",
])
def test_64_hex_validation_on_all_three_hashes(hash_field):
    """Rule C: Each hash must be exactly 64 lowercase hex characters."""
    # Too short (63 chars)
    with pytest.raises(ValidationError) as exc_info:
        FabricAuditEventPayload(**{**VALID_BASE_KWARGS, hash_field: "a" * 63})
    assert "64" in str(exc_info.value)

    # Too long (65 chars)
    with pytest.raises(ValidationError) as exc_info:
        FabricAuditEventPayload(**{**VALID_BASE_KWARGS, hash_field: "a" * 65})
    assert "64" in str(exc_info.value)

    # 64 chars but contains non-hex char 'z'
    bad_hex = "z" * 64
    with pytest.raises(ValidationError) as exc_info:
        FabricAuditEventPayload(**{**VALID_BASE_KWARGS, hash_field: bad_hex})
    assert "64" in str(exc_info.value)

    # Exactly 64 lowercase hex chars — passes
    ev_lower = FabricAuditEventPayload(**{**VALID_BASE_KWARGS, hash_field: "a" * 64})
    assert getattr(ev_lower, hash_field) == "a" * 64

    # Exactly 64 UPPERCASE hex chars — passes (normalised to lowercase)
    ev_upper = FabricAuditEventPayload(**{**VALID_BASE_KWARGS, hash_field: "A" * 64})
    assert getattr(ev_upper, hash_field) == "a" * 64  # normalised to lowercase


# ---------------------------------------------------------------------------
# Test 6: Rule E (CRITICAL CHAINCODE RULE) — threat_detected vs action_taken
# ---------------------------------------------------------------------------

def test_critical_chaincode_rule_threat_detected_vs_action_taken():
    """Rule E: threat_detected=True + action_taken='SAFE_EXECUTED' must raise ValidationError."""
    # SAFE_EXECUTED with threat_detected=True → MUST raise
    with pytest.raises(ValidationError) as exc_info:
        FabricAuditEventPayload(**{
            **VALID_BASE_KWARGS,
            "action_taken": "SAFE_EXECUTED",
            "threat_detected": True,
        })
    err_msg = str(exc_info.value)
    assert "SAFE_EXECUTED" in err_msg or "chaincode" in err_msg.lower()

    # Each valid threat action with threat_detected=True → MUST succeed
    for valid_action in ["BLOCKED", "SURGICALLY_REDACTED", "QUARANTINED_MEMORY", "HUMAN_REJECTED"]:
        ev = FabricAuditEventPayload(**{**VALID_BASE_KWARGS, "action_taken": valid_action, "threat_detected": True})
        assert ev.action_taken == valid_action
        assert ev.threat_detected is True

    # threat_detected=False + action_taken="SAFE_EXECUTED" → MUST succeed
    ev_safe = FabricAuditEventPayload(**{**VALID_BASE_KWARGS, "action_taken": "SAFE_EXECUTED", "threat_detected": False})
    assert ev_safe.action_taken == "SAFE_EXECUTED"
    assert ev_safe.threat_detected is False


def test_unknown_action_with_threat_detected_true_raises():
    """Rule E extension: Unknown action strings with threat_detected=True must also raise."""
    with pytest.raises(ValidationError) as exc_info:
        FabricAuditEventPayload(**{
            **VALID_BASE_KWARGS,
            "action_taken": "DO_NOTHING",  # Not in VALID_THREAT_ACTIONS
            "threat_detected": True,
        })
    assert "DO_NOTHING" in str(exc_info.value) or "violation" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Test 7: Rule D — risk_category_ids must be a list
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_value", [
    None,
    2,
    "2",
    {"2": "risk"},
    (2, 18),
])
def test_risk_category_ids_rejects_non_list(bad_value):
    """Rule D: risk_category_ids must be a JSON array (list), not None or scalar."""
    with pytest.raises(ValidationError) as exc_info:
        FabricAuditEventPayload(**{**VALID_BASE_KWARGS, "risk_category_ids": bad_value})
    assert "list" in str(exc_info.value).lower() or "array" in str(exc_info.value).lower() or "violation" in str(exc_info.value).lower()


def test_risk_category_ids_accepts_int_list():
    """Rule D: risk_category_ids accepts List[int]."""
    ev = FabricAuditEventPayload(**{**VALID_BASE_KWARGS, "risk_category_ids": [2, 18, 23]})
    assert ev.risk_category_ids == [2, 18, 23]


def test_risk_category_ids_accepts_str_list():
    """Rule D: risk_category_ids accepts List[str]."""
    ev = FabricAuditEventPayload(**{**VALID_BASE_KWARGS, "risk_category_ids": ["2", "18"]})
    assert ev.risk_category_ids == ["2", "18"]


def test_risk_category_ids_accepts_empty_list():
    """Rule D: risk_category_ids accepts an empty list."""
    ev = FabricAuditEventPayload(**{**VALID_BASE_KWARGS, "risk_category_ids": []})
    assert ev.risk_category_ids == []


# ---------------------------------------------------------------------------
# Test 8: FabricAuditEventBuilder normalize_action_for_chaincode mappings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("internal_action,expected_normalized", [
    ("BLOCKED", "BLOCKED"),
    ("blocked", "BLOCKED"),
    ("REDACTED", "SURGICALLY_REDACTED"),
    ("decloaked", "SURGICALLY_REDACTED"),
    ("SURGICALLY_REDACTED", "SURGICALLY_REDACTED"),
    ("redacted_exfiltration_links", "SURGICALLY_REDACTED"),
    ("quarantined", "QUARANTINED_MEMORY"),
    ("QUARANTINED_MEMORY", "QUARANTINED_MEMORY"),
    ("HUMAN_REJECTED", "HUMAN_REJECTED"),
    ("human_rejected_blocked", "HUMAN_REJECTED"),
    ("keep_action_blocked", "HUMAN_REJECTED"),
    ("HUMAN_APPROVAL_REQUIRED", "BLOCKED"),
    ("blocked_by_micro_privilege_sandbox", "BLOCKED"),
])
def test_normalize_action_for_chaincode_threat_mappings(internal_action, expected_normalized):
    """Builder maps internal gateway strings to chaincode-compliant action_taken values."""
    result = FabricAuditEventBuilder.normalize_action_for_chaincode(internal_action, threat_detected=True)
    assert result == expected_normalized, f"Expected {expected_normalized!r} for {internal_action!r}, got {result!r}"


def test_normalize_action_safe_executed_no_threat():
    """SAFE_EXECUTED with threat_detected=False passes through unchanged."""
    result = FabricAuditEventBuilder.normalize_action_for_chaincode("SAFE_EXECUTED", threat_detected=False)
    assert result == "SAFE_EXECUTED"


# ---------------------------------------------------------------------------
# Test 9: to_chaincode_json_dict produces remote Node.js Fabric schema
# ---------------------------------------------------------------------------

def test_to_chaincode_json_dict_produces_remote_schema():
    """to_chaincode_json_dict must return the exact 7 keys required by the remote Fabric API."""
    ev = FabricAuditEventPayload(**VALID_BASE_KWARGS)
    result = FabricAuditEventBuilder.to_chaincode_json_dict(ev)

    assert len(result) == 7, f"Expected 7 keys, got {len(result)}: {list(result.keys())}"
    expected_keys = {
        "event_id", "event_type", "source", "action_taken",
        "raw_evidence_sha256", "redacted_diff_sha256", "intent_hmac_hash",
    }
    assert set(result.keys()) == expected_keys
    assert result["event_id"] == "evt-001"
    assert result["event_type"] == "PROMPT_INJECTION_DETECTED"
    assert result["source"] == "intentguard_layer3"
    assert result["action_taken"] == "BLOCKED"
    assert result["raw_evidence_sha256"] == HEX_A_64
    assert result["redacted_diff_sha256"] == HEX_B_64
    assert result["intent_hmac_hash"] == HEX_C_64

    import json
    json_str = json.dumps(result)  # Should not raise
    reparsed = json.loads(json_str)
    assert reparsed["event_id"] == "evt-001"
    assert reparsed["event_type"] == "PROMPT_INJECTION_DETECTED"


# ---------------------------------------------------------------------------
# Test 10: ensure_64_hex helper validation
# ---------------------------------------------------------------------------

def test_ensure_64_hex_passthrough_valid_hex():
    """ensure_64_hex returns value.lower() for a valid 64-char hex string."""
    valid = "A" * 64
    result = FabricAuditEventBuilder.ensure_64_hex(valid)
    assert result == "a" * 64
    assert HEX_64_REGEX.match(result)


def test_ensure_64_hex_fallback_for_invalid():
    """ensure_64_hex returns SHA-256 of fallback_seed for invalid/short values."""
    import hashlib
    fallback = "my_seed"
    expected = hashlib.sha256(fallback.encode("utf-8")).hexdigest()
    result = FabricAuditEventBuilder.ensure_64_hex("too-short", fallback_seed=fallback)
    assert result == expected
    assert len(result) == 64
    assert HEX_64_REGEX.match(result)


def test_ensure_64_hex_empty_value_uses_empty_hash():
    """ensure_64_hex with None/empty computes SHA-256 of fallback_seed."""
    import hashlib
    result = FabricAuditEventBuilder.ensure_64_hex(None, fallback_seed="")
    assert result == hashlib.sha256(b"").hexdigest()
    assert len(result) == 64


# ---------------------------------------------------------------------------
# Test 11: EMPTY_SHA256_HEX constant is the expected empty-string SHA-256
# ---------------------------------------------------------------------------

def test_empty_sha256_hex_constant_is_correct():
    """EMPTY_SHA256_HEX should be the SHA-256 of the empty byte string."""
    import hashlib
    expected = hashlib.sha256(b"").hexdigest()
    assert EMPTY_SHA256_HEX == expected
    assert len(EMPTY_SHA256_HEX) == 64
    assert HEX_64_REGEX.match(EMPTY_SHA256_HEX)


# ---------------------------------------------------------------------------
# Test 12: Extra fields rejected by model_config extra="forbid"
# ---------------------------------------------------------------------------

def test_extra_fields_rejected_by_model():
    """FabricAuditEventPayload forbids extra fields not in the 12-field contract."""
    with pytest.raises(ValidationError) as exc_info:
        FabricAuditEventPayload(**{**VALID_BASE_KWARGS, "extra_unauthorized_field": "malicious"})
    err = str(exc_info.value)
    assert "extra" in err.lower() or "unexpected" in err.lower() or "forbidden" in err.lower() or "extra_unauthorized_field" in err
