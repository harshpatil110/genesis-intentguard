"""
IntentGuard Layer 2 CaMeL Dual-LLM & Authority Plane
=====================================================
GENESIS 2.0 | Track: EVA 03 | PS 01

Provides Step-0 Cryptographic Intent Contracts (HMAC-SHA256 Authority Lock),
dual-LLM causal mediation, and verifiable policy enforcement.
"""

from app.layer2_camel.intent_contract import (
    IntentContractRegistry,
    IntentVerificationResult,
    Step0IntentContract,
    compile_step0_intent_contract,
    compute_intent_hmac,
    intent_contract_registry,
    verify_contract_signature,
    verify_tool_against_contract,
)

__all__ = [
    "IntentContractRegistry",
    "IntentVerificationResult",
    "Step0IntentContract",
    "compile_step0_intent_contract",
    "compute_intent_hmac",
    "intent_contract_registry",
    "verify_contract_signature",
    "verify_tool_against_contract",
]
