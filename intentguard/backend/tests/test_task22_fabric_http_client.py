"""
IntentGuard Automated Pytest Suite — Task 22: Configurable Blockchain HTTP API Client
with Transaction Confirmation & Retry Logic
=======================================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Tests the complete FabricGatewayHttpClient using respx to mock httpx.AsyncClient
without needing a real Hyperledger Fabric server:

1.  test_record_audit_event_success_201                  — 201 with recorded+tx_id returns dict
2.  test_record_audit_event_201_missing_recorded         — 201 without recorded=True raises BlockchainAPIError
3.  test_record_audit_event_201_missing_transaction_id   — 201 without transaction_id raises BlockchainAPIError
4.  test_record_audit_event_400_raises_schema_error      — 400 raises BlockchainSchemaValidationError
5.  test_record_audit_event_401_raises_auth_error        — 401 raises BlockchainAuthError
6.  test_record_audit_event_403_raises_auth_error        — 403 raises BlockchainAuthError
7.  test_record_audit_event_409_raises_conflict_error    — 409 raises BlockchainConflictError
8.  test_record_audit_event_503_buffers_and_circuit_breaks — 503 + threat_detected=True → buffer + circuit breaker
9.  test_record_audit_event_500_buffers_and_circuit_breaks — 500 + high-risk action → buffer + circuit breaker
10. test_record_audit_event_503_safe_event_buffers_no_circuit_break — 503 + safe event → buffer only, no circuit breaker
11. test_get_audit_event_200_returns_dict                — GET 200 returns event dict with recorded_at
12. test_get_audit_event_404_returns_none                — GET 404 returns None
13. test_get_audit_event_401_raises_auth_error           — GET 401 raises BlockchainAuthError
14. test_list_audit_events_passes_rbac_headers           — GET list verifies X-Fabric-Role & X-Fabric-Party-Id headers
15. test_list_audit_events_returns_events_list           — GET list extracts ["events"] from response
16. test_flush_retry_buffer_empty                        — flush on empty buffer returns 0
17. test_flush_retry_buffer_retries_and_removes_success  — flush retries buffered events and removes committed ones
18. test_network_error_buffers_and_circuit_breaks        — httpx.ConnectError → buffer + circuit breaker for threat event
19. test_context_manager_closes_client                   — async context manager closes underlying httpx client
20. test_client_repr                                     — repr contains api_base_url and retry_buffer_size
"""

import asyncio
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from app.blockchain_client.event_builder import FabricAuditEventBuilder, FabricAuditEventPayload
from app.blockchain_client.http_client import (
    BlockchainAPIError,
    BlockchainAuthError,
    BlockchainCircuitBreakerException,
    BlockchainConflictError,
    BlockchainSchemaValidationError,
    FabricGatewayHttpClient,
    _AUDIT_EVENTS_PATH,
)

# ---------------------------------------------------------------------------
# Helpers — valid 64-char hex hashes
# ---------------------------------------------------------------------------
HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64

MOCK_BASE_URL = "http://mock-fabric:8200"
MOCK_API_KEY = "test_key_abc"

FULL_EVENTS_URL = f"{MOCK_BASE_URL}{_AUDIT_EVENTS_PATH}"


def make_payload(threat_detected: bool = True, action_taken: str = "BLOCKED") -> FabricAuditEventPayload:
    """Helper to build a valid FabricAuditEventPayload for testing."""
    return FabricAuditEventPayload(
        event_id="evt-test001234",
        timestamp="2026-10-15T12:00:00Z",
        buyer_id="buyer-test-01",
        supplier_id="supplier-test-01",
        input_modality="text",
        action_taken=action_taken,
        policy_reference="policy-v1",
        raw_evidence_sha256=HEX_A,
        redacted_diff_sha256=HEX_B,
        intent_hmac_hash=HEX_C,
        risk_category_ids=[2, 18],
        threat_detected=threat_detected,
    )


# ---------------------------------------------------------------------------
# Test 1: 201 success — returns recorded + transaction_id
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_record_audit_event_success_201():
    """201 response with recorded=True and transaction_id returns the dict."""
    event = make_payload()
    mock_response = {"recorded": True, "transaction_id": "tx_abc123", "ledger_height": 42}

    respx.post(FULL_EVENTS_URL).mock(
        return_value=httpx.Response(201, json=mock_response)
    )

    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        result = await client.record_audit_event(event)

    assert result["recorded"] is True
    assert result["transaction_id"] == "tx_abc123"
    assert result["ledger_height"] == 42


# ---------------------------------------------------------------------------
# Test 2: 201 missing recorded=True raises BlockchainAPIError
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_record_audit_event_201_missing_recorded():
    """201 with recorded=False or missing must raise BlockchainAPIError."""
    event = make_payload()

    respx.post(FULL_EVENTS_URL).mock(
        return_value=httpx.Response(201, json={"transaction_id": "tx_xyz"})
    )

    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        with pytest.raises(BlockchainAPIError) as exc_info:
            await client.record_audit_event(event)
    assert "recorded" in str(exc_info.value).lower() or "missing" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Test 3: 201 missing transaction_id raises BlockchainAPIError
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_record_audit_event_201_missing_transaction_id():
    """201 with recorded=True but no transaction_id must raise BlockchainAPIError."""
    event = make_payload()

    respx.post(FULL_EVENTS_URL).mock(
        return_value=httpx.Response(201, json={"recorded": True})
    )

    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        with pytest.raises(BlockchainAPIError) as exc_info:
            await client.record_audit_event(event)
    assert "transaction_id" in str(exc_info.value).lower() or "missing" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Test 4: 400 raises BlockchainSchemaValidationError
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_record_audit_event_400_raises_schema_error():
    """Mock a 400 response — assert BlockchainSchemaValidationError is raised."""
    event = make_payload()

    respx.post(FULL_EVENTS_URL).mock(
        return_value=httpx.Response(400, json={"error": "invalid_schema", "detail": "missing buyer_id"})
    )

    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        with pytest.raises(BlockchainSchemaValidationError) as exc_info:
            await client.record_audit_event(event)

    assert exc_info.value.status_code == 400
    assert isinstance(exc_info.value, BlockchainAPIError)


# ---------------------------------------------------------------------------
# Test 5 & 6: 401 / 403 raise BlockchainAuthError
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_record_audit_event_401_raises_auth_error():
    """HTTP 401 must raise BlockchainAuthError."""
    event = make_payload()
    respx.post(FULL_EVENTS_URL).mock(return_value=httpx.Response(401, json={"error": "unauthorized"}))

    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        with pytest.raises(BlockchainAuthError) as exc_info:
            await client.record_audit_event(event)

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
@respx.mock
async def test_record_audit_event_403_raises_auth_error():
    """HTTP 403 must raise BlockchainAuthError."""
    event = make_payload()
    respx.post(FULL_EVENTS_URL).mock(return_value=httpx.Response(403, json={"error": "forbidden"}))

    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        with pytest.raises(BlockchainAuthError) as exc_info:
            await client.record_audit_event(event)

    assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# Test 7: 409 raises BlockchainConflictError
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_record_audit_event_409_raises_conflict_error():
    """HTTP 409 must raise BlockchainConflictError with the duplicate event_id context."""
    event = make_payload()
    respx.post(FULL_EVENTS_URL).mock(return_value=httpx.Response(409, json={"error": "conflict", "event_id": event.event_id}))

    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        with pytest.raises(BlockchainConflictError) as exc_info:
            await client.record_audit_event(event)

    assert exc_info.value.status_code == 409
    assert event.event_id in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 8: 503 + threat_detected=True → buffer event + circuit breaker
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_record_audit_event_503_buffers_and_circuit_breaks():
    """
    Mock a 503 response. Pass an event with threat_detected=True.
    Assert the event is appended to client._retry_buffer and
    BlockchainCircuitBreakerException is raised.
    """
    event = make_payload(threat_detected=True, action_taken="BLOCKED")

    respx.post(FULL_EVENTS_URL).mock(
        return_value=httpx.Response(503, text="Service Unavailable")
    )

    client = FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY)
    try:
        with pytest.raises(BlockchainCircuitBreakerException) as exc_info:
            await client.record_audit_event(event)

        # Event must be in the retry buffer
        assert len(client._retry_buffer) == 1
        assert client._retry_buffer[0].event_id == event.event_id

        # Exception must carry correct status code
        assert exc_info.value.status_code == 503
        assert isinstance(exc_info.value, BlockchainAPIError)
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# Test 9: 500 + high-risk action → buffer + circuit breaker
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_record_audit_event_500_buffers_and_circuit_breaks():
    """HTTP 500 with SURGICALLY_REDACTED action_taken must also trigger circuit breaker."""
    event = make_payload(threat_detected=True, action_taken="SURGICALLY_REDACTED")

    respx.post(FULL_EVENTS_URL).mock(
        return_value=httpx.Response(500, text="Internal Server Error")
    )

    client = FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY)
    try:
        with pytest.raises(BlockchainCircuitBreakerException):
            await client.record_audit_event(event)

        assert len(client._retry_buffer) == 1
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# Test 10: 503 + safe event (no threat) → buffer only, no circuit breaker
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_record_audit_event_503_safe_event_buffers_no_circuit_break():
    """
    503 for a safe event (threat_detected=False, action_taken=SAFE_EXECUTED)
    must buffer the event but NOT raise BlockchainCircuitBreakerException.
    Instead it raises the generic BlockchainAPIError.
    """
    event = make_payload(threat_detected=False, action_taken="SAFE_EXECUTED")

    respx.post(FULL_EVENTS_URL).mock(
        return_value=httpx.Response(503, text="Service Unavailable")
    )

    client = FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY)
    try:
        with pytest.raises(BlockchainAPIError) as exc_info:
            await client.record_audit_event(event)

        # Must NOT be a circuit breaker — safe events don't fail-closed
        assert not isinstance(exc_info.value, BlockchainCircuitBreakerException)
        # Must be buffered
        assert len(client._retry_buffer) == 1
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# Test 11: GET 200 returns event dict
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_get_audit_event_200_returns_dict():
    """GET /audit-events/{event_id} 200 returns the event dict with recorded_at."""
    event_id = "evt-test001234"
    expected = {
        "event_id": event_id,
        "recorded_at": "2026-10-15T12:00:05Z",
        "buyer_id": "buyer-test-01",
        "threat_detected": True,
    }

    respx.get(f"{FULL_EVENTS_URL}/{event_id}").mock(
        return_value=httpx.Response(200, json=expected)
    )

    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        result = await client.get_audit_event(event_id)

    assert result is not None
    assert result["event_id"] == event_id
    assert result["recorded_at"] == "2026-10-15T12:00:05Z"


# ---------------------------------------------------------------------------
# Test 12: GET 404 returns None
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_get_audit_event_404_returns_none():
    """GET 404 from audit-events/{event_id} must return None."""
    event_id = "evt-notexist"

    respx.get(f"{FULL_EVENTS_URL}/{event_id}").mock(
        return_value=httpx.Response(404, json={"error": "not_found"})
    )

    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        result = await client.get_audit_event(event_id)

    assert result is None


# ---------------------------------------------------------------------------
# Test 13: GET 401 raises BlockchainAuthError
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_get_audit_event_401_raises_auth_error():
    """GET 401 on audit-events/{event_id} must raise BlockchainAuthError."""
    event_id = "evt-test001234"

    respx.get(f"{FULL_EVENTS_URL}/{event_id}").mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )

    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        with pytest.raises(BlockchainAuthError) as exc_info:
            await client.get_audit_event(event_id)

    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# Test 14: list_audit_events passes RBAC headers
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_list_audit_events_passes_rbac_headers():
    """
    GET /api/v1/audit-events must include X-Fabric-Role and X-Fabric-Party-Id
    headers in the request.
    """
    role = "BUYER"
    party_id = "buyer-test-01"

    captured_headers: Dict[str, str] = {}

    def capture_and_respond(request: httpx.Request) -> httpx.Response:
        nonlocal captured_headers
        captured_headers = dict(request.headers)
        return httpx.Response(200, json={"events": []})

    respx.get(FULL_EVENTS_URL).mock(side_effect=capture_and_respond)

    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        await client.list_audit_events(role=role, party_id=party_id)

    # Verify RBAC headers were sent (headers are lowercased by httpx)
    assert "x-fabric-role" in captured_headers, "X-Fabric-Role header missing"
    assert "x-fabric-party-id" in captured_headers, "X-Fabric-Party-Id header missing"
    assert captured_headers["x-fabric-role"] == role
    assert captured_headers["x-fabric-party-id"] == party_id
    assert "authorization" in captured_headers
    assert captured_headers["authorization"] == f"Bearer {MOCK_API_KEY}"


# ---------------------------------------------------------------------------
# Test 15: list_audit_events returns events list
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_list_audit_events_returns_events_list():
    """GET list must extract and return the ['events'] list from the response."""
    sample_events = [
        {"event_id": "evt-001", "threat_detected": True},
        {"event_id": "evt-002", "threat_detected": False},
    ]

    respx.get(FULL_EVENTS_URL).mock(
        return_value=httpx.Response(200, json={"events": sample_events, "total": 2})
    )

    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        result = await client.list_audit_events(role="AUDITOR", party_id="audit-firm-01")

    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["event_id"] == "evt-001"
    assert result[1]["event_id"] == "evt-002"


# ---------------------------------------------------------------------------
# Test 16: flush_retry_buffer on empty buffer returns 0
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_flush_retry_buffer_empty():
    """flush_retry_buffer on an empty buffer must return 0 immediately."""
    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        result = await client.flush_retry_buffer()

    assert result == 0


# ---------------------------------------------------------------------------
# Test 17: flush_retry_buffer retries and removes successfully committed events
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_flush_retry_buffer_retries_and_removes_success():
    """
    Pre-populate the retry buffer with two events.
    Mock 201 responses for both.
    flush_retry_buffer must return 2 and clear the buffer.
    """
    event1 = make_payload(threat_detected=True, action_taken="BLOCKED")
    event2 = FabricAuditEventPayload(
        event_id="evt-buffered002",
        timestamp="2026-10-15T13:00:00Z",
        buyer_id="buyer-02",
        supplier_id="supplier-02",
        input_modality="pdf",
        action_taken="SURGICALLY_REDACTED",
        policy_reference="policy-v1",
        raw_evidence_sha256=HEX_A,
        redacted_diff_sha256=HEX_B,
        intent_hmac_hash=HEX_C,
        risk_category_ids=[5],
        threat_detected=True,
    )

    respx.post(FULL_EVENTS_URL).mock(
        return_value=httpx.Response(201, json={"recorded": True, "transaction_id": "tx_flush_01"})
    )

    client = FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY)
    # Manually inject events into the retry buffer
    client._retry_buffer = [event1, event2]

    try:
        flushed = await client.flush_retry_buffer()
    finally:
        await client.close()

    assert flushed == 2
    assert len(client._retry_buffer) == 0


# ---------------------------------------------------------------------------
# Test 18: Network error (ConnectError) for threat event → buffer + circuit breaker
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_network_error_buffers_and_circuit_breaks():
    """
    httpx.ConnectError during record_audit_event for threat_detected=True
    must buffer the event and raise BlockchainCircuitBreakerException.
    """
    event = make_payload(threat_detected=True, action_taken="BLOCKED")

    respx.post(FULL_EVENTS_URL).mock(side_effect=httpx.ConnectError("Connection refused"))

    client = FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY)
    try:
        with pytest.raises(BlockchainCircuitBreakerException):
            await client.record_audit_event(event)

        assert len(client._retry_buffer) == 1
        assert client._retry_buffer[0].event_id == event.event_id
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# Test 19: Async context manager closes the underlying httpx client
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_context_manager_closes_client():
    """async with FabricGatewayHttpClient() as client: must call client.close()."""
    close_called = False

    async def mock_close():
        nonlocal close_called
        close_called = True

    async with FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY) as client:
        # Monkey-patch close to detect it's called
        client._client.aclose = mock_close

    assert close_called, "FabricGatewayHttpClient.__aexit__ must call client.close()"


# ---------------------------------------------------------------------------
# Test 20: __repr__ contains api_base_url and retry_buffer_size
# ---------------------------------------------------------------------------

def test_client_repr():
    """__repr__ must include api_base_url and current retry_buffer_size."""
    client = FabricGatewayHttpClient(MOCK_BASE_URL, MOCK_API_KEY)
    r = repr(client)
    assert MOCK_BASE_URL in r
    assert "retry_buffer_size" in r
    assert "0" in r  # buffer starts empty
