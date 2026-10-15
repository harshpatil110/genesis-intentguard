"""
IntentGuard Layer 2 CaMeL Dual-LLM & Authority Plane
=====================================================
GENESIS 2.0 | Track: EVA 03 | PS 01

Provides Step-0 Cryptographic Intent Contracts (HMAC-SHA256 Authority Lock),
Context-Aware Business Language Disambiguation, Surgical Redaction, deterministic
Hyperledger Fabric diff hashing, and the CaMeL Data Plane Quarantined Reader (Q-LLM).
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
from app.layer2_camel.business_disambiguator import (
    BusinessCommandDisambiguator,
    DirectiveClassification,
    DisambiguationResult,
    EvaluatedSpan,
    business_disambiguator,
)
from app.layer2_camel.surgical_redactor import (
    RedactionDiffRecord,
    RemovedMaliciousSpan,
    SurgicalRedactionResult,
    SurgicalRedactor,
    XRayDiffSegment,
    compute_canonical_diff_sha256,
    surgical_redactor,
)
from app.layer2_camel.schemas import (
    EmailExtractionSchema,
    InvoiceExtractionSchema,
    InvoiceLineItem,
    WebExtractionSchema,
)
from app.layer2_camel.quarantined_reader import (
    SPOTLIGHT_END,
    SPOTLIGHT_START,
    QuarantinedReaderLLM,
    quarantined_reader,
)

__all__ = [
    # Intent Contract
    "IntentContractRegistry",
    "IntentVerificationResult",
    "Step0IntentContract",
    "compile_step0_intent_contract",
    "compute_intent_hmac",
    "intent_contract_registry",
    "verify_contract_signature",
    "verify_tool_against_contract",
    # Business Disambiguator
    "BusinessCommandDisambiguator",
    "DirectiveClassification",
    "DisambiguationResult",
    "EvaluatedSpan",
    "business_disambiguator",
    # Surgical Redactor
    "RedactionDiffRecord",
    "RemovedMaliciousSpan",
    "SurgicalRedactionResult",
    "SurgicalRedactor",
    "XRayDiffSegment",
    "compute_canonical_diff_sha256",
    "surgical_redactor",
    # CaMeL Data Plane Schemas
    "InvoiceLineItem",
    "InvoiceExtractionSchema",
    "EmailExtractionSchema",
    "WebExtractionSchema",
    # Quarantined Reader
    "QuarantinedReaderLLM",
    "quarantined_reader",
    "SPOTLIGHT_START",
    "SPOTLIGHT_END",
]
