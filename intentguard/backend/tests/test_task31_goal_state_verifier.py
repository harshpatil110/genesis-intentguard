"""
Unit and Integration Tests for Task 31: Deterministic Goal-State Verifier
=========================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Validates:
  1. Clean goal state verification (verified_safe is True, zero violations)
  2. Unauthorized memory & bank mutation detection (Risk #32)
  3. Human approved exceptions honoring Step-Back Approval cards
  4. Unauthorized email exfiltration detection
  5. Fabric API final audit commit with 12-field schema validation
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.layer4_sandbox.sandbox_controller import SandboxStateSnapshot
from app.layer4_sandbox.goal_state_verifier import (
    DeterministicGoalVerifier,
    GoalStateVerificationResult,
    goal_state_verifier,
)


def _make_snapshot(
    session_id: str = "sess-test",
    memory_sha: str = "0" * 64,
    vendor_bank_records: dict = None,
    sent_messages: list = None,
    scheduled_payments: list = None,
) -> SandboxStateSnapshot:
    return SandboxStateSnapshot(
        timestamp=1700000000.0,
        session_id=session_id,
        memory_md_sha256=memory_sha,
        vendor_bank_records=vendor_bank_records or {"PO-402": "HDFC0001234_99887766"},
        sent_messages=sent_messages or [],
        scheduled_payments=scheduled_payments or [],
    )


def test_clean_verification():
    """Test 1: Pre- and post-states are clean; verification succeeds with zero violations."""
    pre = _make_snapshot(memory_sha="a" * 64)
    post = _make_snapshot(
        memory_sha="a" * 64,
        scheduled_payments=[{"po_id": "PO-402", "amount": 4000}],
    )

    result = goal_state_verifier.verify_goal_state(pre, post)

    assert result.verified_safe is True
    assert result.unauthorized_emails_detected == 0
    assert result.unauthorized_bank_mutations == 0
    assert result.memory_poisoning_detected is False
    assert result.legitimate_output_generated is True
    assert "Goal state fully verified" in result.reasoning[0]


def test_unauthorized_memory_and_bank_mutation():
    """Test 2: Memory hash changed and bank account changed to attacker IBAN."""
    pre = _make_snapshot(
        memory_sha="a" * 64,
        vendor_bank_records={"PO-402": "HDFC0001234_99887766"},
    )
    post = _make_snapshot(
        memory_sha="b" * 64,  # Mutated by sleeper prompt injection
        vendor_bank_records={"PO-402": "GB99HACK999"},  # Tampered IBAN
    )

    result = goal_state_verifier.verify_goal_state(pre, post)

    assert result.verified_safe is False
    assert result.memory_poisoning_detected is True
    assert result.unauthorized_bank_mutations == 1
    assert any("Persistent MEMORY.md corrupted" in r for r in result.reasoning)
    assert any("Unauthorized bank mutation" in r for r in result.reasoning)


def test_human_approved_bank_mutation():
    """Test 3: Bank mutation is permitted when explicit human approval is provided."""
    pre = _make_snapshot(vendor_bank_records={"PO-402": "HDFC0001234_99887766"})
    post = _make_snapshot(vendor_bank_records={"PO-402": "ICIC0009999_12345678"})

    # Provided with Step-Back human approval for bank_change:PO-402
    result = goal_state_verifier.verify_goal_state(
        pre, post, human_approved_actions=["bank_change:PO-402"]
    )

    assert result.unauthorized_bank_mutations == 0
    assert result.verified_safe is True


def test_unauthorized_email_detected():
    """Test 4: Exfiltration message to unapproved recipient triggers violation."""
    pre = _make_snapshot()
    post = _make_snapshot(
        sent_messages=[{"to": "attacker@darkweb-drop.com", "subject": "PO secrets", "body": "leak"}]
    )

    result = goal_state_verifier.verify_goal_state(pre, post)

    assert result.verified_safe is False
    assert result.unauthorized_emails_detected == 1
    assert any("Unauthorized outbound message" in r for r in result.reasoning)


@pytest.mark.asyncio
async def test_fabric_api_submission_mock():
    """Test 5: Committing goal-state verification outcome to Fabric via mock HTTP client."""
    mock_client = MagicMock()
    mock_client.record_audit_event = AsyncMock(
        return_value={"recorded": True, "transaction_id": "tx-goal-verif-abc1234"}
    )

    verifier = DeterministicGoalVerifier(http_client=mock_client)
    res_clean = GoalStateVerificationResult(
        session_id="session-fabric-verif",
        verified_safe=True,
        legitimate_output_generated=True,
    )

    audited = await verifier.submit_final_audit(res_clean, document_id="doc-402")

    mock_client.record_audit_event.assert_awaited_once()
    assert audited.fabric_transaction_id == "tx-goal-verif-abc1234"
