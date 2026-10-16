"""
IntentGuard Blockchain Client Package
======================================
GENESIS 2.0 | Track: EVA 03 | PS 01

Application-side Hyperledger Fabric client, audit event builder,
mock server, and HTTP gateway client.

Phase 5 tasks are implemented in this package:
  - Task 21: Strict 12-Field Audit Event Builder & Validator (event_builder.py)
  - Task 22: Configurable Blockchain HTTP API Client (http_client.py)
  - Task 23: Built-In Mock Fabric HTTP Server (mock_fabric_server.py)
  - Task 24: Fabric Chaincode Audit Event Retrieval & RBAC Filtering (rbac_client.py)
"""

from app.blockchain_client.event_builder import (
    EMPTY_SHA256_HEX,
    HEX_64_REGEX,
    ISO_8601_UTC_REGEX,
    VALID_SAFE_ACTIONS,
    VALID_THREAT_ACTIONS,
    FabricAuditEventBuilder,
    FabricAuditEventPayload,
    fabric_event_builder,
)

__all__ = [
    # Task 21 — Strict 12-Field Fabric Audit Event Builder & Validator
    "FabricAuditEventPayload",
    "FabricAuditEventBuilder",
    "fabric_event_builder",
    "VALID_THREAT_ACTIONS",
    "VALID_SAFE_ACTIONS",
    "HEX_64_REGEX",
    "ISO_8601_UTC_REGEX",
    "EMPTY_SHA256_HEX",
]
