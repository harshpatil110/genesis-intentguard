"""
IntentGuard — Configurable Blockchain HTTP API Client
======================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Task 22: Async `httpx`-based client for the Hyperledger Fabric Gateway REST API.

Responsibilities:
  - POST validated FabricAuditEventPayload to /api/v1/audit-events.
  - Handle all HTTP status codes gracefully (201, 400, 401, 403, 404, 409,
    500, 502, 503, 504) with structured exceptions.
  - Maintain a local fail-safe retry buffer for transient server errors.
  - Trigger BlockchainCircuitBreakerException when critical (threat_detected=True)
    audit events cannot be committed — fail-closed for security events.
  - Support GET /api/v1/audit-events/{event_id} retrieval.
  - Support GET /api/v1/audit-events with RBAC role/party headers.
  - flush_retry_buffer() to drain queued failed events on reconnect.

Never executes Fabric CLI commands directly; communicates exclusively via HTTP.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

import httpx

from app.blockchain_client.event_builder import FabricAuditEventPayload

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safe settings import (fallback to sensible defaults if settings unavailable)
# ---------------------------------------------------------------------------
try:
    from app.config import settings
    _DEFAULT_API_BASE_URL: str = getattr(settings, "BLOCKCHAIN_API_BASE_URL", "http://localhost:8200")
    _DEFAULT_API_KEY: str = getattr(settings, "BLOCKCHAIN_API_KEY", "intentguard_local_dev_key")
except Exception:
    _DEFAULT_API_BASE_URL = "http://localhost:8200"
    _DEFAULT_API_KEY = "intentguard_local_dev_key"

# ---------------------------------------------------------------------------
# HTTP endpoint constants
# ---------------------------------------------------------------------------
_AUDIT_EVENTS_PATH = "/audit-events"

# Actions that indicate a high-risk security block requiring fail-closed behavior
_HIGH_RISK_ACTIONS: frozenset[str] = frozenset({
    "BLOCKED",
    "SURGICALLY_REDACTED",
    "QUARANTINED_MEMORY",
    "HUMAN_REJECTED",
})


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------

class BlockchainAPIError(Exception):
    """Base exception for all Hyperledger Fabric HTTP API errors."""

    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={str(self)!r}, "
            f"status_code={self.status_code!r})"
        )


class BlockchainSchemaValidationError(BlockchainAPIError):
    """
    Raised when the Fabric REST API returns HTTP 400 Bad Request,
    indicating the submitted payload does not satisfy the chaincode schema.
    """


class BlockchainAuthError(BlockchainAPIError):
    """
    Raised when the Fabric REST API returns HTTP 401 Unauthorized or
    403 Forbidden, indicating missing/expired API key or RBAC denial.
    """


class BlockchainConflictError(BlockchainAPIError):
    """
    Raised when the Fabric REST API returns HTTP 409 Conflict,
    indicating a duplicate event_id already exists on the ledger.
    """


class BlockchainCircuitBreakerException(BlockchainAPIError):
    """
    Raised when the Fabric REST API returns HTTP 500/502/503/504 or a
    network RequestError for an event where threat_detected=True or the
    action_taken indicates a high-risk security enforcement action.

    This exception triggers fail-closed behavior: the calling code must
    block or quarantine the agent workflow until the ledger is reachable.
    """


# ---------------------------------------------------------------------------
# FabricGatewayHttpClient
# ---------------------------------------------------------------------------

class FabricGatewayHttpClient:
    """
    Async HTTP client for the Hyperledger Fabric Gateway REST API.

    Usage:
        client = FabricGatewayHttpClient()
        result = await client.record_audit_event(fabric_payload)
        await client.close()

    Supports async context manager protocol:
        async with FabricGatewayHttpClient() as client:
            result = await client.record_audit_event(payload)
    """

    def __init__(
        self,
        api_base_url: str = _DEFAULT_API_BASE_URL,
        api_key: str = _DEFAULT_API_KEY,
        timeout: float = 5.0,
    ) -> None:
        self.api_base_url = api_base_url.rstrip("/")
        self.api_key = api_key
        self._client = httpx.AsyncClient(base_url=self.api_base_url, timeout=timeout)
        self._retry_buffer: List[FabricAuditEventPayload] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _auth_headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
        }

    @staticmethod
    def _is_high_risk(event: FabricAuditEventPayload) -> bool:
        """Return True if event represents a high-risk security enforcement action."""
        return event.threat_detected or event.action_taken.upper() in _HIGH_RISK_ACTIONS

    def _buffer_and_maybe_circuit_break(self, event: FabricAuditEventPayload, status_code: int, detail: str) -> None:
        """
        Appends the event to the local retry buffer.
        For high-risk (threat_detected=True) events, raises BlockchainCircuitBreakerException
        to enforce fail-closed behavior.
        """
        self._retry_buffer.append(event)
        logger.error(
            "[IntentGuard Fabric] AUDIT LEDGER UNREACHABLE — event_id=%s status=%d buffered. Retry buffer size: %d. Detail: %s",
            event.event_id, status_code, len(self._retry_buffer), detail,
        )
        if self._is_high_risk(event):
            logger.critical(
                "[IntentGuard Fabric] CIRCUIT BREAKER TRIGGERED — High-risk event (threat_detected=%s, action=%s) "
                "could not be committed to ledger. Failing closed.",
                event.threat_detected, event.action_taken,
            )
            raise BlockchainCircuitBreakerException(
                f"Circuit breaker: high-risk audit event {event.event_id!r} (action={event.action_taken!r}, "
                f"threat_detected={event.threat_detected}) could not be committed to Hyperledger Fabric. "
                f"HTTP {status_code}: {detail}",
                status_code=status_code,
            )

    # ------------------------------------------------------------------
    # Public API Methods
    # ------------------------------------------------------------------

    async def record_audit_event(self, event: FabricAuditEventPayload) -> Dict[str, Any]:
        """
        POST the validated FabricAuditEventPayload to the ledger.

        Returns the confirmed response dict containing at minimum:
            {"recorded": True, "transaction_id": "<tx_id>"}

        Raises:
            BlockchainSchemaValidationError  — HTTP 400
            BlockchainAuthError              — HTTP 401 / 403
            BlockchainConflictError          — HTTP 409
            BlockchainCircuitBreakerException — HTTP 5xx (high-risk events)
            BlockchainAPIError               — all other unexpected errors
        """
        url = f"{self.api_base_url}/audit-events"
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
        }
        payload_dict = event.model_dump()

        print("\n" + "=" * 50)
        print(f"🚀 [BLOCKCHAIN DISPATCH] Sending to {url}")
        print(f"🔑 [HEADERS] {headers}")
        print(f"📦 [PAYLOAD] {json.dumps(payload_dict, indent=2)}")

        try:
            response = await self._client.post(
                url,
                json=payload_dict,
                headers=headers,
            )
            print(f"📥 [RESPONSE CODE]: {response.status_code}")
            print(f"📜 [RESPONSE BODY]: {response.text}")
            print("=" * 50 + "\n")
        except httpx.RequestError as exc:
            print(f"❌ [BLOCKCHAIN ERROR]: {str(exc)}")
            print("=" * 50 + "\n")
            logger.error("[IntentGuard Fabric] Network error posting event %s: %s", event.event_id, exc)
            self._buffer_and_maybe_circuit_break(event, status_code=503, detail=str(exc))
            # If _is_high_risk() above did not raise (safe events), still surface the error
            raise BlockchainAPIError(
                f"Network error contacting Fabric API: {exc}",
                status_code=503,
            ) from exc
        except Exception as e:
            print(f"❌ [BLOCKCHAIN ERROR]: {str(e)}")
            print("=" * 50 + "\n")
            raise

        status = response.status_code

        if status in (200, 201):
            try:
                data: Dict[str, Any] = response.json()
            except Exception as parse_exc:
                raise BlockchainAPIError(
                    f"HTTP {status} but response body is not valid JSON: {parse_exc}",
                    status_code=status,
                    response_body=response.text,
                ) from parse_exc

            if "transaction_id" not in data and "tx_id" in data:
                data["transaction_id"] = str(data["tx_id"])

            if not data.get("recorded"):
                raise BlockchainAPIError(
                    f"HTTP 201 received but 'recorded' field is missing or False in response: {data!r}",
                    status_code=201,
                    response_body=response.text,
                )
            if "transaction_id" not in data:
                raise BlockchainAPIError(
                    f"HTTP 201 received but 'transaction_id' field is missing in response: {data!r}",
                    status_code=201,
                    response_body=response.text,
                )
            logger.info(
                "[IntentGuard Fabric] Audit event %s committed — tx_id=%s",
                event.event_id, data["transaction_id"],
            )
            return data

        elif status == 400:
            logger.error(
                "[IntentGuard Fabric] Schema validation error for event %s — HTTP 400: %s",
                event.event_id, response.text,
            )
            raise BlockchainSchemaValidationError(
                f"Fabric chaincode rejected payload for event {event.event_id!r}: {response.text}",
                status_code=400,
                response_body=response.text,
            )

        elif status in (401, 403):
            logger.error(
                "[IntentGuard Fabric] Auth failure for event %s — HTTP %d: %s",
                event.event_id, status, response.text,
            )
            raise BlockchainAuthError(
                f"Fabric API authentication failed (HTTP {status}) for event {event.event_id!r}: {response.text}",
                status_code=status,
                response_body=response.text,
            )

        elif status == 409:
            logger.warning(
                "[IntentGuard Fabric] Duplicate event_id=%s — HTTP 409. Caller should regenerate event_id for idempotency.",
                event.event_id,
            )
            raise BlockchainConflictError(
                f"Duplicate event_id {event.event_id!r} already exists on Hyperledger Fabric ledger. "
                f"Regenerate event_id and retry.",
                status_code=409,
                response_body=response.text,
            )

        elif status in (500, 502, 503, 504):
            detail = response.text
            self._buffer_and_maybe_circuit_break(event, status_code=status, detail=detail)
            # Safe (non-threat) events: still surface a generic API error
            raise BlockchainAPIError(
                f"Fabric API server error (HTTP {status}) for event {event.event_id!r}: {detail}",
                status_code=status,
                response_body=detail,
            )

        else:
            # Unexpected status codes
            logger.error(
                "[IntentGuard Fabric] Unexpected status %d for event %s: %s",
                status, event.event_id, response.text,
            )
            raise BlockchainAPIError(
                f"Unexpected HTTP {status} from Fabric API for event {event.event_id!r}: {response.text}",
                status_code=status,
                response_body=response.text,
            )

    async def get_audit_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """
        GET /api/v1/audit-events/{event_id}

        Returns the event dict on 200, None on 404.

        Raises:
            BlockchainAuthError — HTTP 401 / 403
            BlockchainAPIError  — HTTP 500 / 503
        """
        url = f"{_AUDIT_EVENTS_PATH}/{event_id}"
        headers = self._auth_headers()

        try:
            response = await self._client.get(url, headers=headers)
        except httpx.RequestError as exc:
            raise BlockchainAPIError(
                f"Network error fetching event {event_id!r}: {exc}",
                status_code=503,
            ) from exc

        status = response.status_code

        if status == 200:
            return response.json()
        elif status == 404:
            logger.info("[IntentGuard Fabric] Event %s not found on ledger (404).", event_id)
            return None
        elif status in (401, 403):
            raise BlockchainAuthError(
                f"Fabric API auth error (HTTP {status}) fetching event {event_id!r}.",
                status_code=status,
                response_body=response.text,
            )
        else:
            raise BlockchainAPIError(
                f"Fabric API error (HTTP {status}) fetching event {event_id!r}: {response.text}",
                status_code=status,
                response_body=response.text,
            )

    async def list_audit_events(self, role: str, party_id: str) -> List[Dict[str, Any]]:
        """
        GET /api/v1/audit-events with RBAC role and party ID headers.

        Returns the list of audit event dicts from the Fabric ledger.

        Raises:
            BlockchainAuthError — HTTP 401 / 403
            BlockchainAPIError  — HTTP 4xx / 5xx
        """
        headers = {
            **self._auth_headers(),
            "X-Fabric-Role": role,
            "X-Fabric-Party-Id": party_id,
        }

        try:
            response = await self._client.get(_AUDIT_EVENTS_PATH, headers=headers)
        except httpx.RequestError as exc:
            raise BlockchainAPIError(
                f"Network error listing audit events: {exc}",
                status_code=503,
            ) from exc

        status = response.status_code

        if status == 200:
            data = response.json()
            return data.get("events", [])
        elif status in (401, 403):
            raise BlockchainAuthError(
                f"Fabric API auth error (HTTP {status}) listing audit events for role={role!r}.",
                status_code=status,
                response_body=response.text,
            )
        else:
            raise BlockchainAPIError(
                f"Fabric API error (HTTP {status}) listing audit events: {response.text}",
                status_code=status,
                response_body=response.text,
            )

    async def flush_retry_buffer(self) -> int:
        """
        Attempt to re-POST all events in the local fail-safe retry buffer.

        Returns the count of successfully flushed (committed) events.
        Successfully committed events are removed from the buffer.
        Failed events remain in the buffer for the next flush attempt.
        """
        if not self._retry_buffer:
            return 0

        logger.info(
            "[IntentGuard Fabric] Flushing retry buffer — %d events pending.",
            len(self._retry_buffer),
        )

        still_failing: List[FabricAuditEventPayload] = []
        flushed_count = 0

        for event in self._retry_buffer:
            try:
                await self.record_audit_event(event)
                flushed_count += 1
                logger.info("[IntentGuard Fabric] Retry success — event %s committed.", event.event_id)
            except (BlockchainAPIError, BlockchainCircuitBreakerException):
                still_failing.append(event)
                logger.warning("[IntentGuard Fabric] Retry failed — event %s still pending.", event.event_id)

        self._retry_buffer = still_failing
        logger.info(
            "[IntentGuard Fabric] Flush complete — %d committed, %d still pending.",
            flushed_count, len(self._retry_buffer),
        )
        return flushed_count

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying httpx.AsyncClient connection pool."""
        await self._client.aclose()
        logger.debug("[IntentGuard Fabric] HTTP client closed.")

    async def __aenter__(self) -> "FabricGatewayHttpClient":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    def __repr__(self) -> str:
        return (
            f"FabricGatewayHttpClient("
            f"api_base_url={self.api_base_url!r}, "
            f"retry_buffer_size={len(self._retry_buffer)})"
        )
