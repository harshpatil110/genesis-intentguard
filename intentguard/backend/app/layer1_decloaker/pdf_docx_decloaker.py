"""
IntentGuard Layer 1 Multi-Modal Pre-OCR De-Cloaker (PDF & DOCX)
================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Mechanically compares visual rendering properties against raw extracted text to
neutralize:
- Risk #1: Malicious Attachments / Embedded Scripts (Embedded PDF /JavaScript)
- Risk #2: Hidden Prompt Injections (0.1pt Micro-Fonts, White-on-White, Off-Page Cropbox)
- Risk #7: Poisoned Documents & Metadata (Hidden DOCX runs, suspicious metadata)

Preserves 100% of visible, legitimate business text for Task Continuity.
"""

from __future__ import annotations

import hashlib
import io
import logging
import uuid
from typing import Any, Dict, List, Literal, Optional, Tuple

import docx
import fitz  # PyMuPDF
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Suspicious keywords in document metadata
_SUSPICIOUS_METADATA_MARKERS = frozenset(
    {
        "ignore",
        "system",
        "override",
        "instruction",
        "instructions",
        "bank",
        "transfer",
        "forward",
        "email",
        "disregard",
        "you are now",
        "http://",
        "https://",
    }
)


# ---------------------------------------------------------------------------
# Pydantic v2 Models for Findings & Results
# ---------------------------------------------------------------------------

class CloakedSpanFinding(BaseModel):
    """
    Detailed telemetry finding for every stripped cloaked span or metadata trap.
    Supplies coordinates and color metrics for the Forensic X-Ray Diff UI.
    """
    finding_id: str = Field(default_factory=lambda: f"span-{uuid.uuid4().hex[:8]}")
    modality: Literal["pdf", "docx", "image", "screenshot", "receipt", "audio", "video", "web_dom", "email", "chat"]
    page_or_paragraph: int = 1  # 1-indexed page number (PDF) or paragraph/element index
    cloak_reason: Literal[
        "MICRO_FONT_SIZE",
        "WHITE_ON_WHITE_OR_LOW_CONTRAST",
        "OUTSIDE_CROPBOX",
        "OCCLUDED_BY_VECTOR_RECT",
        "SUSPICIOUS_METADATA",
        "EMBEDDED_PDF_JAVASCRIPT",
        "DOCX_HIDDEN_RUN",
        "STEGANOGRAPHIC_OR_FAINT_TEXT",
        "MALICIOUS_QR_CODE",
        "FORGED_SYSTEM_UI",
        "SUBLIMINAL_VIDEO_TEXT",
        "MALICIOUS_SUBTITLES",
        "SPOKEN_PROMPT_INJECTION",
        "INVISIBLE_MARKDOWN_COMMENT",
        "HIDDEN_CSS_TRAP",
        "POISONED_ARIA_ATTRIBUTE",
        "TRACKING_PIXEL_OR_HIDDEN_IFRAME",
        "EXECUTIVE_IMPERSONATION",
        "REPLY_TO_MISMATCH",
        "SPOOFED_AUTHORIZATION_CLAIM",
        "FORGED_SYSTEM_OUTPUT",
    ]
    hidden_text: str
    font_size_pt: Optional[float] = None
    text_rgb: Optional[Tuple[int, int, int]] = None
    bg_rgb: Optional[Tuple[int, int, int]] = None
    contrast_ratio: Optional[float] = None
    bbox: Optional[Tuple[float, float, float, float]] = None  # (x0, y0, x1, y1)
    metadata_key: Optional[str] = None
    risk_category_ids: List[int] = Field(default_factory=list)


class DocumentDeCloakResult(BaseModel):
    """
    Outcome of the Pre-OCR De-Cloaker engine for a single PDF, DOCX, Image, Audio, Video, Web DOM, Email, or Chat file/payload.
    """
    raw_evidence_sha256: str  # 64-char lowercase hex
    redacted_diff_sha256: str  # 64-char lowercase hex
    modality: Literal["pdf", "docx", "image", "screenshot", "receipt", "audio", "video", "web_dom", "email", "chat"]
    visible_clean_text: str
    raw_unfiltered_text: str
    cloaked_findings: List[CloakedSpanFinding] = Field(default_factory=list)
    metadata_sanitized: Dict[str, str] = Field(default_factory=dict)
    threat_detected: bool = False
    risk_category_ids: List[int] = Field(default_factory=list)
    summary: str = ""


# ---------------------------------------------------------------------------
# Color & WCAG Contrast Helpers
# ---------------------------------------------------------------------------

def int_color_to_rgb(color: Any) -> Tuple[int, int, int]:
    """
    Converts PyMuPDF 24-bit sRGB integer (or float/int sequence) into (r, g, b) 0-255.
    """
    if isinstance(color, int):
        r = (color >> 16) & 255
        g = (color >> 8) & 255
        b = color & 255
        return (r, g, b)
    if isinstance(color, (list, tuple)) and len(color) >= 3:
        if all(isinstance(c, (float, int)) and c <= 1.0 for c in color[:3]):
            return (
                int(round(float(color[0]) * 255)),
                int(round(float(color[1]) * 255)),
                int(round(float(color[2]) * 255)),
            )
        return (int(color[0]), int(color[1]), int(color[2]))
    return (0, 0, 0)


def relative_luminance(rgb: Tuple[int, int, int]) -> float:
    """
    Computes WCAG 2.1 relative luminance:
    L = 0.2126 * R' + 0.7152 * G' + 0.0722 * B'
    """
    def channel_lum(val: int) -> float:
        c = max(0, min(255, val)) / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = rgb
    return 0.2126 * channel_lum(r) + 0.7152 * channel_lum(g) + 0.0722 * channel_lum(b)


def compute_contrast_ratio(
    rgb1: Tuple[int, int, int], rgb2: Tuple[int, int, int]
) -> float:
    """
    Computes WCAG contrast ratio: (L1 + 0.05) / (L2 + 0.05)
    """
    l1 = relative_luminance(rgb1)
    l2 = relative_luminance(rgb2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return round((lighter + 0.05) / (darker + 0.05), 3)


def sample_background_rgb_from_pixmap(
    pixmap: fitz.Pixmap,
    bbox: Tuple[float, float, float, float],
    page_rect: fitz.Rect,
) -> Tuple[int, int, int]:
    """
    Samples background pixel color near bounding box corners on the rendered page pixmap.
    Falls back to standard white (255, 255, 255).
    """
    try:
        x0, y0, x1, y1 = bbox
        sx = max(0, min(pixmap.width - 1, int(x0 - 2)))
        sy = max(0, min(pixmap.height - 1, int(y0 - 2)))
        pixel = pixmap.pixel(sx, sy)
        if len(pixel) >= 3:
            return (int(pixel[0]), int(pixel[1]), int(pixel[2]))
    except Exception:
        pass
    return (255, 255, 255)


# ---------------------------------------------------------------------------
# PDF De-Cloaking Engine
# ---------------------------------------------------------------------------

def decloak_pdf_bytes(
    file_bytes: bytes, filename: str = "document.pdf"
) -> DocumentDeCloakResult:
    """
    Scans a raw PDF byte stream, stripping 0.1pt fonts, white-on-white text,
    off-page cropbox injections, opaque vector covers, malicious metadata,
    and embedded /JavaScript streams.
    """
    raw_evidence_sha256 = hashlib.sha256(file_bytes).hexdigest().lower()

    findings: List[CloakedSpanFinding] = []
    metadata_sanitized: Dict[str, str] = {}
    raw_spans: List[str] = []
    visible_spans: List[str] = []
    risk_category_ids: List[int] = []

    doc = fitz.open(stream=file_bytes, filetype="pdf")

    # ── Step 1: Scan Metadata for Injections ─────────────────────────────────
    if doc.metadata:
        for k, v in doc.metadata.items():
            if not v or not isinstance(v, str):
                continue
            v_lower = v.lower()
            is_suspicious = any(m in v_lower for m in _SUSPICIOUS_METADATA_MARKERS) or (
                len(v) > 120 and any(w in v_lower for w in ["pay", "wire", "iban", "transfer"])
            )
            if is_suspicious:
                findings.append(
                    CloakedSpanFinding(
                        finding_id=f"meta-{uuid.uuid4().hex[:8]}",
                        modality="pdf",
                        page_or_paragraph=1,
                        cloak_reason="SUSPICIOUS_METADATA",
                        hidden_text=f"Metadata [{k}]: {v}",
                        metadata_key=k,
                        risk_category_ids=[2, 7],
                    )
                )
                if 2 not in risk_category_ids:
                    risk_category_ids.append(2)
                if 7 not in risk_category_ids:
                    risk_category_ids.append(7)
            else:
                metadata_sanitized[k] = v

    # ── Step 2: Scan for Embedded PDF JavaScript / Launch Actions ───────────
    has_embedded_js = False
    js_sample = ""
    if b"/JavaScript" in file_bytes or b"/JS" in file_bytes or b"/Launch" in file_bytes:
        has_embedded_js = True
        js_sample = "Embedded /JavaScript or /Launch action present in raw PDF stream."

    try:
        for xref in range(1, doc.xref_length()):
            obj_str = doc.xref_object(xref)
            if "/JavaScript" in obj_str or "/JS" in obj_str or "/Launch" in obj_str:
                has_embedded_js = True
                js_sample = f"Embedded PDF /JavaScript action found in xref #{xref}: {obj_str[:100]}"
                break
    except Exception:
        pass

    if has_embedded_js:
        findings.append(
            CloakedSpanFinding(
                finding_id=f"js-{uuid.uuid4().hex[:8]}",
                modality="pdf",
                page_or_paragraph=1,
                cloak_reason="EMBEDDED_PDF_JAVASCRIPT",
                hidden_text=js_sample,
                metadata_key="/JavaScript",
                risk_category_ids=[1, 2],
            )
        )
        if 1 not in risk_category_ids:
            risk_category_ids.append(1)
        if 2 not in risk_category_ids:
            risk_category_ids.append(2)

    # ── Step 3: Iterate Pages, Text Spans & Visual Properties ────────────────
    for page_idx, page in enumerate(doc):
        page_num = page_idx + 1
        cropbox = page.cropbox or page.rect

        # Collect opaque vector rectangles that could occlude text
        opaque_rects: List[fitz.Rect] = []
        try:
            drawings = page.get_drawings()
            for d in drawings:
                fill_color = d.get("fill")
                fill_opacity = d.get("fill_opacity", 1.0)
                if fill_color is not None and (fill_opacity is None or fill_opacity >= 0.9):
                    rect = d.get("rect")
                    if rect is not None:
                        opaque_rects.append(fitz.Rect(rect))
        except Exception:
            pass

        # Render a low-DPI reference pixmap for background color sampling
        pixmap = None
        try:
            pixmap = page.get_pixmap(dpi=72, alpha=False)
        except Exception:
            pass

        # Use an extended clip beyond standard cropbox to detect off-page injected text
        extended_clip = fitz.Rect(
            cropbox.x0 - 2000,
            cropbox.y0 - 2000,
            cropbox.x1 + 2000,
            cropbox.y1 + 2000,
        )
        try:
            text_dict = page.get_text("dict", clip=extended_clip)
        except Exception:
            text_dict = page.get_text("dict")

        blocks = text_dict.get("blocks", [])

        for block in blocks:
            if block.get("type") == 0:  # Text block
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        span_text = span.get("text", "")
                        if not span_text.strip():
                            continue

                        raw_spans.append(span_text)

                        font_size = float(span.get("size", 12.0))
                        color_raw = span.get("color", 0)
                        text_rgb = int_color_to_rgb(color_raw)
                        bbox = tuple(float(c) for c in span.get("bbox", (0, 0, 0, 0)))
                        span_rect = fitz.Rect(bbox)

                        # Sample background color
                        bg_rgb = (255, 255, 255)
                        if pixmap:
                            bg_rgb = sample_background_rgb_from_pixmap(pixmap, bbox, page.rect)

                        contrast_ratio = compute_contrast_ratio(text_rgb, bg_rgb)

                        is_cloaked = False
                        cloak_reason: Optional[str] = None

                        # Check 1: Micro-Font Size (< 3.0 pt)
                        if font_size < 3.0:
                            is_cloaked = True
                            cloak_reason = "MICRO_FONT_SIZE"

                        # Check 2: Outside Cropbox / Off-Page
                        elif (
                            not cropbox.intersects(span_rect)
                            or bbox[0] < cropbox.x0 - 5
                            or bbox[1] < cropbox.y0 - 5
                            or bbox[0] > cropbox.x1 + 5
                            or bbox[1] > cropbox.y1 + 5
                        ):
                            is_cloaked = True
                            cloak_reason = "OUTSIDE_CROPBOX"

                        # Check 3: White-on-White or Low Contrast
                        elif (
                            (
                                text_rgb[0] > 238
                                and text_rgb[1] > 238
                                and text_rgb[2] > 238
                                and sum(bg_rgb) / 3.0 > 220
                            )
                            or contrast_ratio < 1.35
                        ):
                            is_cloaked = True
                            cloak_reason = "WHITE_ON_WHITE_OR_LOW_CONTRAST"

                        # Check 4: Occluded by Opaque Vector Rect
                        elif any(
                            r.contains(span_rect)
                            for r in opaque_rects
                            if r is not None and not r.is_empty
                        ):
                            is_cloaked = True
                            cloak_reason = "OCCLUDED_BY_VECTOR_RECT"

                        if is_cloaked and cloak_reason:
                            finding = CloakedSpanFinding(
                                finding_id=f"span-{uuid.uuid4().hex[:8]}",
                                modality="pdf",
                                page_or_paragraph=page_num,
                                cloak_reason=cloak_reason,  # type: ignore[arg-type]
                                hidden_text=span_text,
                                font_size_pt=round(font_size, 2),
                                text_rgb=text_rgb,
                                bg_rgb=bg_rgb,
                                contrast_ratio=contrast_ratio,
                                bbox=bbox,
                                risk_category_ids=[2, 7],
                            )
                            findings.append(finding)
                            if 2 not in risk_category_ids:
                                risk_category_ids.append(2)
                            if 7 not in risk_category_ids:
                                risk_category_ids.append(7)
                        else:
                            visible_spans.append(span_text)

    visible_clean_text = " ".join(visible_spans).strip()
    raw_unfiltered_text = " ".join(raw_spans).strip()

    threat_detected = len(findings) > 0
    diff_payload = (
        f"RAW:{raw_evidence_sha256}|CLEAN:{visible_clean_text}|FINDINGS:{len(findings)}"
    )
    redacted_diff_sha256 = hashlib.sha256(diff_payload.encode("utf-8")).hexdigest().lower()

    summary = (
        f"PDF De-Cloaker neutralized {len(findings)} cloaked threat(s) across "
        f"{doc.page_count} page(s)."
        if threat_detected
        else "PDF document is clean with no cloaked spans."
    )

    return DocumentDeCloakResult(
        raw_evidence_sha256=raw_evidence_sha256,
        redacted_diff_sha256=redacted_diff_sha256,
        modality="pdf",
        visible_clean_text=visible_clean_text,
        raw_unfiltered_text=raw_unfiltered_text,
        cloaked_findings=findings,
        metadata_sanitized=metadata_sanitized,
        threat_detected=threat_detected,
        risk_category_ids=sorted(list(set(risk_category_ids))),
        summary=summary,
    )


# ---------------------------------------------------------------------------
# DOCX De-Cloaking Engine
# ---------------------------------------------------------------------------

def decloak_docx_bytes(
    file_bytes: bytes, filename: str = "document.docx"
) -> DocumentDeCloakResult:
    """
    Scans a raw DOCX byte stream, stripping hidden runs (run.font.hidden),
    micro-font runs (< 3.0pt), white-on-white text, and metadata traps.
    """
    raw_evidence_sha256 = hashlib.sha256(file_bytes).hexdigest().lower()

    findings: List[CloakedSpanFinding] = []
    metadata_sanitized: Dict[str, str] = {}
    raw_spans: List[str] = []
    visible_spans: List[str] = []
    risk_category_ids: List[int] = []

    doc = docx.Document(io.BytesIO(file_bytes))

    # ── Step 1: Scan Core Properties Metadata ────────────────────────────────
    cp = doc.core_properties
    for prop in ["author", "subject", "comments", "keywords", "title"]:
        val = getattr(cp, prop, None)
        if val and isinstance(val, str):
            val_lower = val.lower()
            is_suspicious = any(m in val_lower for m in _SUSPICIOUS_METADATA_MARKERS) or (
                len(val) > 120 and any(w in val_lower for w in ["pay", "wire", "iban"])
            )
            if is_suspicious:
                findings.append(
                    CloakedSpanFinding(
                        finding_id=f"docx-meta-{uuid.uuid4().hex[:8]}",
                        modality="docx",
                        page_or_paragraph=1,
                        cloak_reason="SUSPICIOUS_METADATA",
                        hidden_text=f"DOCX metadata [{prop}]: {val}",
                        metadata_key=prop,
                        risk_category_ids=[2, 7],
                    )
                )
                if 2 not in risk_category_ids:
                    risk_category_ids.append(2)
                if 7 not in risk_category_ids:
                    risk_category_ids.append(7)
            else:
                metadata_sanitized[prop] = val

    # ── Step 2: Iterate Paragraphs and Runs ──────────────────────────────────
    def _scan_paragraph(paragraph: Any, p_idx: int) -> None:
        for run in paragraph.runs:
            r_text = run.text
            if not r_text:
                continue

            raw_spans.append(r_text)

            is_cloaked = False
            cloak_reason: Optional[str] = None
            font_size: Optional[float] = None
            if run.font.size is not None and hasattr(run.font.size, "pt"):
                font_size = float(run.font.size.pt)

            text_rgb = (0, 0, 0)
            if run.font.color and run.font.color.rgb:
                try:
                    rgb_val = run.font.color.rgb
                    text_rgb = (int(rgb_val[0]), int(rgb_val[1]), int(rgb_val[2]))
                except Exception:
                    pass

            # Check 1: Hidden Run (run.font.hidden == True)
            if getattr(run.font, "hidden", False) is True:
                is_cloaked = True
                cloak_reason = "DOCX_HIDDEN_RUN"

            # Check 2: Micro-Font (< 3.0 pt)
            elif font_size is not None and font_size < 3.0:
                is_cloaked = True
                cloak_reason = "MICRO_FONT_SIZE"

            # Check 3: White / Near-White Text
            elif text_rgb[0] > 238 and text_rgb[1] > 238 and text_rgb[2] > 238:
                is_cloaked = True
                cloak_reason = "WHITE_ON_WHITE_OR_LOW_CONTRAST"

            if is_cloaked and cloak_reason:
                findings.append(
                    CloakedSpanFinding(
                        finding_id=f"docx-{uuid.uuid4().hex[:8]}",
                        modality="docx",
                        page_or_paragraph=p_idx + 1,
                        cloak_reason=cloak_reason,  # type: ignore[arg-type]
                        hidden_text=r_text,
                        font_size_pt=font_size,
                        text_rgb=text_rgb,
                        bg_rgb=(255, 255, 255),
                        contrast_ratio=compute_contrast_ratio(text_rgb, (255, 255, 255)),
                        risk_category_ids=[2, 7],
                    )
                )
                if 2 not in risk_category_ids:
                    risk_category_ids.append(2)
                if 7 not in risk_category_ids:
                    risk_category_ids.append(7)
            else:
                visible_spans.append(r_text)

    for p_idx, p in enumerate(doc.paragraphs):
        _scan_paragraph(p, p_idx)

    # Also inspect all table cells
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    _scan_paragraph(p, 0)

    visible_clean_text = " ".join(visible_spans).strip()
    raw_unfiltered_text = " ".join(raw_spans).strip()

    threat_detected = len(findings) > 0
    diff_payload = (
        f"RAW:{raw_evidence_sha256}|CLEAN:{visible_clean_text}|FINDINGS:{len(findings)}"
    )
    redacted_diff_sha256 = hashlib.sha256(diff_payload.encode("utf-8")).hexdigest().lower()

    summary = (
        f"DOCX De-Cloaker neutralized {len(findings)} cloaked threat(s)."
        if threat_detected
        else "DOCX document is clean with no cloaked runs."
    )

    return DocumentDeCloakResult(
        raw_evidence_sha256=raw_evidence_sha256,
        redacted_diff_sha256=redacted_diff_sha256,
        modality="docx",
        visible_clean_text=visible_clean_text,
        raw_unfiltered_text=raw_unfiltered_text,
        cloaked_findings=findings,
        metadata_sanitized=metadata_sanitized,
        threat_detected=threat_detected,
        risk_category_ids=sorted(list(set(risk_category_ids))),
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Unified Multi-Modal Dispatcher
# ---------------------------------------------------------------------------

class PDFDocxDeCloaker:
    """
    Unified entry point for PDF and DOCX document de-cloaking.
    """
    def decloak_pdf_bytes(
        self, file_bytes: bytes, filename: str = "document.pdf"
    ) -> DocumentDeCloakResult:
        """De-cloak raw PDF bytes."""
        return decloak_pdf_bytes(file_bytes, filename=filename)

    def decloak_docx_bytes(
        self, file_bytes: bytes, filename: str = "document.docx"
    ) -> DocumentDeCloakResult:
        """De-cloak raw DOCX bytes."""
        return decloak_docx_bytes(file_bytes, filename=filename)

    def decloak_document(
        self,
        file_bytes: bytes,
        filename: str = "",
        modality: Optional[str] = None,
    ) -> DocumentDeCloakResult:

        """
        Routes the file to the appropriate de-cloaker based on magic bytes,
        extension, or explicit modality.
        """
        is_pdf = (
            (modality and modality.lower() == "pdf")
            or filename.lower().endswith(".pdf")
            or file_bytes.startswith(b"%PDF")
        )
        is_docx = (
            (modality and modality.lower() == "docx")
            or filename.lower().endswith(".docx")
            or (file_bytes.startswith(b"PK\x03\x04") and ".docx" in filename.lower())
        )

        if is_pdf:
            return decloak_pdf_bytes(file_bytes, filename=filename or "document.pdf")
        if is_docx:
            return decloak_docx_bytes(file_bytes, filename=filename or "document.docx")

        # Fallback for unrecognized raw text
        raw_evidence_sha256 = hashlib.sha256(file_bytes).hexdigest().lower()
        decoded_text = file_bytes.decode("utf-8", errors="replace")
        return DocumentDeCloakResult(
            raw_evidence_sha256=raw_evidence_sha256,
            redacted_diff_sha256=hashlib.sha256(f"CLEAN:{decoded_text}".encode("utf-8")).hexdigest().lower(),
            modality="pdf" if "pdf" in filename.lower() else "docx",
            visible_clean_text=decoded_text,
            raw_unfiltered_text=decoded_text,
            cloaked_findings=[],
            metadata_sanitized={},
            threat_detected=False,
            risk_category_ids=[],
            summary="Clean document: no cloaked elements detected.",
        )


# Singleton instance for application-wide use
pdf_docx_decloaker = PDFDocxDeCloaker()
