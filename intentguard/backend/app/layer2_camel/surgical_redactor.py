"""
IntentGuard Surgical Redactor & Deterministic Diff Hasher
==========================================================
GENESIS 2.0 | Track: EVA 03 | Problem Statement ID: PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Phase 3 — Layer 2: Surgical Redactor & redacted_diff_sha256
------------------------------------------------------------
Acts as the "Eraser, Not the Hammer": Slices out identified prompt injections,
authority overrides, and cloaked artifacts while preserving 100% of legitimate
business tables, PO data, and operational instructions.

Produces:
1. clean_business_text for Quarantined Reader (Q-LLM) / OpenClaw
2. Canonical RedactionDiffRecord hashed with SHA-256 into a 64-character
   lowercase hex string (redacted_diff_sha256), strictly satisfying the
   Hyperledger Fabric 2.5.16 intentguard chaincode data contract.
3. Visual XRayDiffSegment list for the Next.js UI.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

from pydantic import BaseModel, Field

from app.layer2_camel.business_disambiguator import (
    BusinessCommandDisambiguator,
    DisambiguationResult,
    EvaluatedSpan,
    business_disambiguator,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic v2 Models
# ---------------------------------------------------------------------------

class RemovedMaliciousSpan(BaseModel):
    """
    Metadata for a single sliced-out attack span.
    """
    span_id: str
    source_layer: Literal["LAYER1_DECLOAKER", "LAYER2_DISAMBIGUATOR", "HYBRID_PATTERN"]
    exact_removed_text: str
    page_number: int = 1
    line_number: int = 1
    start_char: int = 0
    end_char: int = 0
    risk_category_ids: List[int] = Field(default_factory=list)
    threat_reason: str


class XRayDiffSegment(BaseModel):
    """
    Visual diff segment consumed by the Next.js Forensic UI.
    """
    segment_index: int
    status: Literal["KEPT_SAFE", "REDACTED_MALICIOUS", "CLOAKED_STRIPPED"]
    text: str
    page_number: int = 1
    line_number: int = 1
    risk_category_ids: List[int] = Field(default_factory=list)
    annotation: Optional[str] = None


class RedactionDiffRecord(BaseModel):
    """
    Canonical record representing the difference between original and sanitized input.
    Serialized and hashed to generate redacted_diff_sha256 for Hyperledger Fabric.
    """
    document_id: str
    kept_business_text: str
    removed_malicious_spans: List[RemovedMaliciousSpan] = Field(default_factory=list)
    redaction_count: int = 0


class SurgicalRedactionResult(BaseModel):
    """
    Full result of surgical redaction and cryptographic diff hashing.
    """
    document_id: str
    clean_business_text: str
    diff_record: RedactionDiffRecord
    redacted_diff_sha256: str
    xray_diff_segments: List[XRayDiffSegment] = Field(default_factory=list)
    threat_detected: bool = False
    action_taken: Literal["SAFE_EXECUTED", "SURGICALLY_REDACTED"] = "SAFE_EXECUTED"
    risk_category_ids: List[int] = Field(default_factory=list)
    task_continuity_preserved: bool = True


# ---------------------------------------------------------------------------
# Canonical Diff Hasher (Hyperledger Fabric Compliance)
# ---------------------------------------------------------------------------

def compute_canonical_diff_sha256(diff_record: RedactionDiffRecord) -> str:
    """
    Computes a deterministic 64-character lowercase hexadecimal SHA-256 hash
    over the canonical JSON representation of RedactionDiffRecord.
    Strictly adheres to Hyperledger Fabric chaincode deterministic data contracts.
    """
    payload = diff_record.model_dump()
    canonical_bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    h = hashlib.sha256(canonical_bytes).hexdigest().lower()
    assert len(h) == 64 and bool(re.match(r"^[0-9a-f]{64}$", h)), (
        f"Invalid diff SHA-256: {h}"
    )
    return h


# ---------------------------------------------------------------------------
# Core SurgicalRedactor Engine
# ---------------------------------------------------------------------------

class SurgicalRedactor:
    """
    Slices out identified prompt injections, authority overrides, and cloaked artifacts
    while preserving 100% of legitimate business tables, PO data, and operational instructions.
    """

    def __init__(self, disambiguator: Optional[BusinessCommandDisambiguator] = None):
        self.disambiguator = disambiguator or business_disambiguator

    def compute_canonical_diff_sha256(self, diff_record: RedactionDiffRecord) -> str:
        """Instance helper routing to module-level canonical hasher."""
        return compute_canonical_diff_sha256(diff_record)

    def redact(
        self,
        document_id: str,
        raw_or_decloaked_text: str,
        layer1_cloaked_spans: Optional[List[Dict[str, Any]]] = None,
        disambiguation_result: Optional[DisambiguationResult] = None,
        po_hint: Optional[str] = None,
    ) -> SurgicalRedactionResult:
        """
        Executes surgical redaction:
        1. Identifies malicious spans via Layer 1 cloaked spans and Layer 2 disambiguator.
        2. Preserves legitimate business text, tables, and instructions.
        3. Formats visual X-Ray Diff segments for the Next.js UI.
        4. Hashes the canonical RedactionDiffRecord into a 64-char lowercase hex SHA-256.
        """
        doc_id = document_id or f"doc-{os.urandom(4).hex()}"

        # 1. Run disambiguator if not already provided
        if disambiguation_result is None:
            disambig_res = self.disambiguator.disambiguate_document(
                text=raw_or_decloaked_text,
                document_id=doc_id,
                po_hint=po_hint,
            )
        else:
            disambig_res = disambiguation_result

        removed_spans: List[RemovedMaliciousSpan] = []
        xray_segments: List[XRayDiffSegment] = []
        all_risk_ids: List[int] = []
        segment_idx = 0

        # 2. Ingest Layer 1 cloaked spans (font-size 0.1, white-on-white, hidden CSS/DOM, etc.)
        if layer1_cloaked_spans:
            for item in layer1_cloaked_spans:
                text_item = (
                    item.get("exact_removed_text")
                    or item.get("match")
                    or item.get("text")
                    or item.get("content")
                    or ""
                )
                page_no = int(item.get("page_number") or item.get("page") or 1)
                line_no = int(item.get("line_number") or item.get("line") or 1)
                risks = list(item.get("risk_category_ids") or item.get("risk_ids") or [2])
                reason = (
                    item.get("threat_reason")
                    or item.get("cloak_reason")
                    or item.get("reason")
                    or "Cloaked artifact stripped by Layer 1 de-cloaker"
                )
                start_c = int(item.get("start_char") or item.get("position") or 0)
                end_c = int(item.get("end_char") or (start_c + len(text_item)))

                removed_spans.append(
                    RemovedMaliciousSpan(
                        span_id=f"redacted-span-{len(removed_spans) + 1:03d}",
                        source_layer="LAYER1_DECLOAKER",
                        exact_removed_text=text_item,
                        page_number=page_no,
                        line_number=line_no,
                        start_char=start_c,
                        end_char=end_c,
                        risk_category_ids=risks,
                        threat_reason=reason,
                    )
                )
                for r in risks:
                    if r not in all_risk_ids:
                        all_risk_ids.append(r)

                xray_segments.append(
                    XRayDiffSegment(
                        segment_index=segment_idx,
                        status="CLOAKED_STRIPPED",
                        text=text_item,
                        page_number=page_no,
                        line_number=line_no,
                        risk_category_ids=risks,
                        annotation=reason,
                    )
                )
                segment_idx += 1

        # 3. Ingest Layer 2 flagged malicious authority overrides
        for flagged in disambig_res.malicious_overrides_flagged:
            removed_spans.append(
                RemovedMaliciousSpan(
                    span_id=f"redacted-span-{len(removed_spans) + 1:03d}",
                    source_layer="LAYER2_DISAMBIGUATOR",
                    exact_removed_text=flagged.text,
                    page_number=flagged.page_number,
                    line_number=flagged.line_number,
                    start_char=flagged.start_char,
                    end_char=flagged.end_char,
                    risk_category_ids=flagged.triggered_risk_ids,
                    threat_reason=flagged.reason,
                )
            )
            for r in flagged.triggered_risk_ids:
                if r not in all_risk_ids:
                    all_risk_ids.append(r)

        # 4. Ingest and sort document spans for visual X-Ray Diff
        doc_spans = (
            disambig_res.safe_business_directives_kept
            + disambig_res.factual_spans_kept
            + disambig_res.malicious_overrides_flagged
        )
        doc_spans.sort(key=lambda s: s.span_index)

        for span in doc_spans:
            if (
                span.marked_for_surgical_redaction
                or span.classification == "MALICIOUS_AUTHORITY_OVERRIDE"
            ):
                xray_segments.append(
                    XRayDiffSegment(
                        segment_index=segment_idx,
                        status="REDACTED_MALICIOUS",
                        text=span.text,
                        page_number=span.page_number,
                        line_number=span.line_number,
                        risk_category_ids=span.triggered_risk_ids,
                        annotation=span.reason,
                    )
                )
            else:
                xray_segments.append(
                    XRayDiffSegment(
                        segment_index=segment_idx,
                        status="KEPT_SAFE",
                        text=span.text,
                        page_number=span.page_number,
                        line_number=span.line_number,
                        risk_category_ids=[],
                        annotation="Safe commercial data",
                    )
                )
            segment_idx += 1

        # If document had no spans but raw text exists
        if not doc_spans and raw_or_decloaked_text.strip():
            xray_segments.append(
                XRayDiffSegment(
                    segment_index=segment_idx,
                    status="KEPT_SAFE",
                    text=raw_or_decloaked_text.strip(),
                    page_number=1,
                    line_number=1,
                    risk_category_ids=[],
                    annotation="Safe business text",
                )
            )
            segment_idx += 1

        # 5. Build clean_business_text (slicing out malicious spans and Layer 1 residues)
        text_buffer = raw_or_decloaked_text

        # Slice out flagged Layer 2 malicious spans
        for flagged in disambig_res.malicious_overrides_flagged:
            if flagged.text and flagged.text in text_buffer:
                text_buffer = text_buffer.replace(flagged.text, "")

        # Slice out any Layer 1 text if present
        for r in removed_spans:
            if r.source_layer == "LAYER1_DECLOAKER" and r.exact_removed_text and r.exact_removed_text in text_buffer:
                text_buffer = text_buffer.replace(r.exact_removed_text, "")

        # Normalize whitespace cleanly line-by-line while preserving invoice table formatting
        cleaned_lines: List[str] = []
        for line in text_buffer.splitlines():
            clean_l = re.sub(r"[ \t]+", " ", line).strip()
            if clean_l:
                cleaned_lines.append(clean_l)

        clean_business_text = "\n".join(cleaned_lines).strip()

        # 6. Construct canonical RedactionDiffRecord
        redaction_count = len(removed_spans)
        diff_record = RedactionDiffRecord(
            document_id=doc_id,
            kept_business_text=clean_business_text,
            removed_malicious_spans=removed_spans,
            redaction_count=redaction_count,
        )

        # 7. Compute deterministic 64-char lowercase hexadecimal SHA-256
        redacted_diff_sha256 = compute_canonical_diff_sha256(diff_record)

        # 8. Threat & Action evaluation (Hyperledger Fabric Invariant)
        threat_detected = (redaction_count > 0)
        action_taken: Literal["SAFE_EXECUTED", "SURGICALLY_REDACTED"] = (
            "SURGICALLY_REDACTED" if threat_detected else "SAFE_EXECUTED"
        )
        task_continuity_preserved = bool(clean_business_text.strip())

        # Fabric Invariant Guard: threat_detected: True can NEVER use action_taken: "SAFE_EXECUTED"
        if threat_detected:
            assert action_taken != "SAFE_EXECUTED", "Hyperledger Fabric invariant violation"

        return SurgicalRedactionResult(
            document_id=doc_id,
            clean_business_text=clean_business_text,
            diff_record=diff_record,
            redacted_diff_sha256=redacted_diff_sha256,
            xray_diff_segments=xray_segments,
            threat_detected=threat_detected,
            action_taken=action_taken,
            risk_category_ids=all_risk_ids,
            task_continuity_preserved=task_continuity_preserved,
        )


# Global singleton instance
surgical_redactor = SurgicalRedactor()
