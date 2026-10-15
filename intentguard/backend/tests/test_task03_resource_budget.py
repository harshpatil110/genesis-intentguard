"""
Task 03 Verification Tests: Step-0 Permissions, Rate Limits, Loop Cap, & Resource Budget Engine
==============================================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01 — IntentGuard
Tests:
1. Canonical tool signature normalization
2. Sliding window 3x identical tool loop abortion (Risk #19)
3. Micro-privilege task iteration cap of 8 (Risk #19)
4. 15 MB payload size ceiling (Risk #1, #8, #19)
5. 30 requests/minute rate limit enforcement
6. 45.0s task execution timeout
7. Real-time WebSocket broadcasting on loop block
8. Step-0 permission downgrade on untrusted input ingestion (Risk #17)
9. Session budget inspection and reset endpoints

Run from intentguard/backend/:
    pytest tests/test_task03_resource_budget.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Ensure backend directory is in sys.path
# ---------------------------------------------------------------------------
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.layer3_policy.resource_budget import (
    ResourceBudgetEnforcer,
    compute_tool_signature,
    resource_budget_enforcer,
)
from app.main import app
from app.openclaw_bridge.interceptor import session_taint_registry


@pytest.fixture
def client():
    """Create a fresh FastAPI TestClient for each test."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def reset_enforcer_state():
    """Reset the session taint registry and budget enforcer sessions before each test."""
    session_taint_registry.clear()
    resource_budget_enforcer.sessions.clear()
    yield
    session_taint_registry.clear()
    resource_budget_enforcer.sessions.clear()


# ===========================================================================
# 1. Canonical Tool Invocation Signature
# ===========================================================================

def test_compute_tool_signature_canonicalization():
    """
    compute_tool_signature must yield identical hashes regardless of
    dictionary key ordering, capitalization of tool name, or whitespace.
    """
    sig1 = compute_tool_signature(
        "query_inventory",
        {"buyer_id": "buyer-01", "sku": "SKU-999", "limit": 10},
    )
    sig2 = compute_tool_signature(
        "  QUERY_INVENTORY  ",
        {"limit": 10, "sku": "SKU-999", "buyer_id": "buyer-01"},
    )
    assert sig1 == sig2
    assert sig1.startswith("query_inventory:")
    assert len(sig1.split(":")[1]) == 64  # 64-char SHA-256


# ===========================================================================
# 2. Sliding Window Loop Detection (3x Identical Tool Invocations)
# ===========================================================================

def test_identical_tool_loop_aborts_on_third_call(client: TestClient):
    """
    Invoke the exact same tool with identical arguments 3 times in a single session.
    Assert Call #1 and Call #2 succeed (execution_permitted is True).
    Assert Call #3 is immediately aborted (execution_permitted is False,
    action_taken == 'BLOCKED', 19 in risk_category_ids).
    """
    session_id = "sess-loop-3x-01"

    # Call #1: Succeeds
    res1 = client.post(
        "/internal/intercept/tool",
        json={
            "session_id": session_id,
            "tool_name": "query_invoice",
            "tool_arguments": {"invoice_id": "INV-402", "query": "status"},
        },
    )
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["execution_permitted"] is True
    assert data1["action_taken"] == "SAFE_EXECUTED"
    assert data1["threat_detected"] is False

    # Call #2: Succeeds (even with rearranged argument keys)
    res2 = client.post(
        "/internal/intercept/tool",
        json={
            "session_id": session_id,
            "tool_name": "query_invoice",
            "tool_arguments": {"query": "status", "invoice_id": "INV-402"},
        },
    )
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["execution_permitted"] is True
    assert data2["action_taken"] == "SAFE_EXECUTED"

    # Call #3: Identical tool call aborts immediately (Risk #19)
    res3 = client.post(
        "/internal/intercept/tool",
        json={
            "session_id": session_id,
            "tool_name": "query_invoice",
            "tool_arguments": {"invoice_id": "INV-402", "query": "status"},
        },
    )
    assert res3.status_code == 200
    data3 = res3.json()
    assert data3["execution_permitted"] is False
    assert data3["action_taken"] == "BLOCKED"
    assert data3["threat_detected"] is True
    assert 19 in data3["risk_category_ids"]
    assert "risk #19" in data3["reason"].lower() or "loop" in data3["reason"].lower()


# ===========================================================================
# 3. Micro-Privilege Task Iteration Cap (Max 8 Tool Invocations)
# ===========================================================================

def test_max_tool_iterations_cap_of_8(client: TestClient):
    """
    Invoke 8 distinct tool calls in one session. Assert all 8 pass.
    Invoke a 9th distinct tool call in the same session. Assert it is blocked
    with action_taken == 'BLOCKED' and 19 in risk_category_ids.
    """
    session_id = "sess-iterations-cap-01"

    # 8 distinct calls all succeed
    for i in range(8):
        res = client.post(
            "/internal/intercept/tool",
            json={
                "session_id": session_id,
                "tool_name": f"get_order_detail_{i}",
                "tool_arguments": {"order_id": f"ORD-{i}"},
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["execution_permitted"] is True
        assert data["action_taken"] == "SAFE_EXECUTED"

    # 9th distinct call exceeds task iteration cap
    res9 = client.post(
        "/internal/intercept/tool",
        json={
            "session_id": session_id,
            "tool_name": "get_order_detail_9",
            "tool_arguments": {"order_id": "ORD-9"},
        },
    )
    assert res9.status_code == 200
    data9 = res9.json()
    assert data9["execution_permitted"] is False
    assert data9["action_taken"] == "BLOCKED"
    assert data9["threat_detected"] is True
    assert 19 in data9["risk_category_ids"]
    assert "iteration" in data9["reason"].lower() or "risk #19" in data9["reason"].lower()


# ===========================================================================
# 4. Inbound Payload 15 MB Ceiling (Risk #1, #8, #19)
# ===========================================================================

def test_max_file_upload_bytes_15mb_cap(client: TestClient):
    """
    Send a normal payload (1 KB) -> allowed_to_proceed is True.
    Send an oversized payload (> 15 MB) -> allowed_to_proceed is False,
    action_taken == 'BLOCKED', and 19 in risk_category_ids.
    """
    # 1. Normal payload passes
    session_ok = "sess-payload-ok-01"
    res_ok = client.post(
        "/internal/intercept/input",
        json={
            "session_id": session_ok,
            "modality": "text",
            "source_uri_or_filename": "clean_input.txt",
            "raw_content_text": "Hello world from legit supplier.",
        },
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["allowed_to_proceed"] is True
    assert res_ok.json()["action_taken"] == "SAFE_EXECUTED"

    # 2. Oversized payload (16 MB via declared metadata) blocked
    session_over = "sess-payload-over-01"
    res_over = client.post(
        "/internal/intercept/input",
        json={
            "session_id": session_over,
            "modality": "pdf",
            "source_uri_or_filename": "massive_archive_bomb.pdf",
            "raw_content_text": "Normal header preview",
            "metadata": {"file_size_bytes": 16 * 1024 * 1024},
        },
    )
    assert res_over.status_code == 200
    data_over = res_over.json()
    assert data_over["allowed_to_proceed"] is False
    assert data_over["action_taken"] == "BLOCKED"
    assert data_over["threat_detected"] is True
    assert 19 in data_over["risk_category_ids"]
    assert "RESOURCE BUDGET" in data_over["sanitized_text"]


# ===========================================================================
# 5. Sliding Window Request Rate Limiter (30 Requests / Minute)
# ===========================================================================

def test_rate_limit_30_requests_per_minute():
    """
    Fire 30 requests within the same 60-second window -> all 30 pass.
    Fire the 31st request -> allowed is False, violation_type == 'RATE_LIMIT_EXCEEDED',
    and 19 in risk_category_ids.
    """
    enforcer = ResourceBudgetEnforcer(max_requests_per_minute=30)
    session_id = "sess-rate-limit-test-01"
    base_time = 1000.0

    # 30 requests within 60s
    for i in range(30):
        res = enforcer.check_request_rate(session_id, now=base_time + (i * 0.5))
        assert res.allowed is True
        assert res.action_taken == "SAFE_EXECUTED"

    # 31st request exceeds RPM
    res_31 = enforcer.check_request_rate(session_id, now=base_time + 20.0)
    assert res_31.allowed is False
    assert res_31.action_taken == "BLOCKED"
    assert res_31.violation_type == "RATE_LIMIT_EXCEEDED"
    assert 19 in res_31.risk_category_ids


# ===========================================================================
# 6. Task Execution Timeout (45.0 Seconds)
# ===========================================================================

def test_execution_timeout_45_seconds():
    """
    Simulate a session where now - task_start_timestamp > 45.0 seconds.
    Assert check_tool_call_budget blocks immediately with
    violation_type == 'EXECUTION_TIMEOUT_EXCEEDED' and 19 in risk_category_ids.
    """
    enforcer = ResourceBudgetEnforcer(max_execution_timeout_sec=45.0)
    session_id = "sess-timeout-test-01"
    start_time = 5000.0
    enforcer.get_or_create_session(session_id, now=start_time)

    # Within 45.0s -> permitted
    res_ok = enforcer.check_execution_timeout(session_id, now=start_time + 40.0)
    assert res_ok.allowed is True
    assert res_ok.action_taken == "SAFE_EXECUTED"

    # Beyond 45.0s -> blocked
    res_blocked = enforcer.check_tool_call_budget(
        session_id=session_id,
        tool_name="read_catalog",
        tool_arguments={"catalog_id": "CAT-1"},
        now=start_time + 46.0,
    )
    assert res_blocked.allowed is False
    assert res_blocked.action_taken == "BLOCKED"
    assert res_blocked.violation_type == "EXECUTION_TIMEOUT_EXCEEDED"
    assert 19 in res_blocked.risk_category_ids
    assert "timeout" in res_blocked.reason.lower()


# ===========================================================================
# 7. WebSocket Live Telemetry Broadcasts Loop Block Event
# ===========================================================================

def test_xray_websocket_broadcasts_loop_block_event(client: TestClient):
    """
    Connect to /ws/xray-stream, trigger a 3x identical tool loop on
    /internal/intercept/tool, and verify the WebSocket receives the
    BLOCKED event with risk_category_ids: [19].
    """
    session_id = "sess-ws-loop-block-01"
    with client.websocket_connect("/ws/xray-stream") as ws:
        # 1st call
        client.post(
            "/internal/intercept/tool",
            json={
                "session_id": session_id,
                "tool_name": "query_inventory",
                "tool_arguments": {"buyer_id": "buyer-01"},
            },
        )
        event1 = ws.receive_json()
        assert event1["action_taken"] == "SAFE_EXECUTED"

        # 2nd call
        client.post(
            "/internal/intercept/tool",
            json={
                "session_id": session_id,
                "tool_name": "query_inventory",
                "tool_arguments": {"buyer_id": "buyer-01"},
            },
        )
        event2 = ws.receive_json()
        assert event2["action_taken"] == "SAFE_EXECUTED"

        # 3rd identical call triggers loop abort
        client.post(
            "/internal/intercept/tool",
            json={
                "session_id": session_id,
                "tool_name": "query_inventory",
                "tool_arguments": {"buyer_id": "buyer-01"},
            },
        )
        event3 = ws.receive_json()
        assert event3["session_id"] == session_id
        assert event3["hook_stage"] == "HOOK_2_TOOL_CALL"
        assert event3["action_taken"] == "BLOCKED"
        assert event3["threat_detected"] is True
        assert 19 in event3["risk_category_ids"]


# ===========================================================================
# 8. Step-0 Micro-Privilege Permission Downgrade (Risk #17)
# ===========================================================================

def test_untrusted_data_permission_downgrade(client: TestClient):
    """
    When untrusted external data is ingested in Hook 1, Step-0 micro-privilege
    downgrades permissions to READ_ONLY_UNTRUSTED, blocking destructive tools
    like delete_file or bash.
    """
    session_id = "sess-priv-downgrade-01"

    # Ingest external PDF
    client.post(
        "/internal/intercept/input",
        json={
            "session_id": session_id,
            "modality": "pdf",
            "source_uri_or_filename": "invoice.pdf",
            "raw_content_text": "Invoice for buyer-01",
        },
    )

    # Attempt destructive tool call
    res_destructive = client.post(
        "/internal/intercept/tool",
        json={
            "session_id": session_id,
            "tool_name": "delete_file",
            "tool_arguments": {"path": "/var/log/audit.log"},
        },
    )
    assert res_destructive.status_code == 200
    data = res_destructive.json()
    assert data["execution_permitted"] is False
    assert data["action_taken"] == "BLOCKED"
    assert data["threat_detected"] is True
    assert 16 in data["risk_category_ids"] or 17 in data["risk_category_ids"]


# ===========================================================================
# 9. Resource Budget Observability & Reset Endpoints
# ===========================================================================

def test_budget_observability_and_reset_endpoints(client: TestClient):
    """
    Test GET /internal/policy/budget/{session_id} and
    POST /internal/policy/budget/{session_id}/reset.
    """
    session_id = "sess-metrics-01"

    # Perform a tool call to record activity
    client.post(
        "/internal/intercept/tool",
        json={
            "session_id": session_id,
            "tool_name": "view_catalog",
            "tool_arguments": {"category": "electronics"},
        },
    )

    # Query metrics via policy route
    res_metrics = client.get(f"/internal/policy/budget/{session_id}")
    assert res_metrics.status_code == 200
    metrics = res_metrics.json()
    assert metrics["session_id"] == session_id
    assert metrics["total_tool_iterations"] == 1
    assert metrics["max_tool_iterations_per_task"] == 8
    assert metrics["max_identical_tool_calls"] == 3

    # Reset session budget
    res_reset = client.post(f"/internal/policy/budget/{session_id}/reset")
    assert res_reset.status_code == 200
    assert res_reset.json()["status"] == "reset_successful"

    # Query metrics again -> should be fresh
    res_metrics_after = client.get(f"/internal/policy/budget/{session_id}")
    assert res_metrics_after.status_code == 200
    metrics_after = res_metrics_after.json()
    assert metrics_after["total_tool_iterations"] == 0
