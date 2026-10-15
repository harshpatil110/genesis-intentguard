"""
IntentGuard Layer 1 Multi-Modal Pre-OCR De-Cloaker (Image, Screenshot, Receipt & QR)
=====================================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Neutralizes multimodal attacks hidden inside images, receipts, screenshots, and QR codes:
- Risk #4: Multimodal Prompt Injections (Faint steganographic text, hidden EXIF)
- Risk #5: Malicious QR Links (SSRF internal IPs, unauthorized domains)
- Risk #7: Poisoned Documents & Metadata (EXIF metadata command injection)
- Risk #12: Forged System Output (Fake UI alerts, [SYSTEM TOOL OUTPUT] tags)
"""

from __future__ import annotations

import hashlib
import io
import logging
import re
import os
import shutil
import uuid
from typing import Any, Dict, List, Optional, Tuple

import cv2
import numpy as np
from PIL import ExifTags, Image
import pytesseract
import pyzbar.pyzbar as pyzbar

# Ensure Tesseract executable path is resolved on Windows environments
_DEFAULT_WIN_TESSERACT_PATHS = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
]
if shutil.which("tesseract") is None:
    for candidate in _DEFAULT_WIN_TESSERACT_PATHS:
        if os.path.isfile(candidate):
            pytesseract.pytesseract.tesseract_cmd = candidate
            break

from app.config import settings
from app.layer1_decloaker.pdf_docx_decloaker import (
    CloakedSpanFinding,
    DocumentDeCloakResult,
)

logger = logging.getLogger(__name__)

# Markers indicating malicious command injection in image EXIF tags
_EXIF_INJECTION_MARKERS = frozenset(
    {
        "ignore",
        "system",
        "override",
        "instruction",
        "instructions",
        "http://",
        "https://",
        "transfer",
        "wire",
        "iban",
        "forward",
        "disregard",
        "you are now",
        "evil",
    }
)

# Forged system UI patterns in image OCR
_FORGED_SYSTEM_PATTERNS = [
    "[SYSTEM TOOL OUTPUT]",
    "Action Required: Approve Transfer",
    "Authentication Error: Send API Key",
    "[SYSTEM",
    "ADMIN OVERRIDE",
]


class ImageDeCloaker:
    """
    Layer 1 Pre-OCR Image De-Cloaker Engine.
    Performs:
    1. EXIF metadata scanning & sanitization.
    2. Dual-Pass OCR (Standard Otsu vs High-Gain CLAHE faint text detection).
    3. QR code & barcode decoding for SSRF / command traps.
    4. Forged system UI detection and neutralization.
    """

    # ───────────────────────────────────────────────────────────────────────
    # 1. EXIF Inspection & Stripping
    # ───────────────────────────────────────────────────────────────────────

    def strip_exif_metadata(
        self, file_bytes: bytes
    ) -> Tuple[bytes, List[CloakedSpanFinding], Dict[str, str]]:
        """
        Inspects EXIF metadata for prompt injection directives.
        Returns sanitized image bytes stripped of EXIF, any findings, and sanitized tags.
        """
        findings: List[CloakedSpanFinding] = []
        metadata_sanitized: Dict[str, str] = {}

        try:
            img = Image.open(io.BytesIO(file_bytes))
        except Exception as exc:
            logger.warning("Could not open image for EXIF inspection: %s", exc)
            return file_bytes, findings, metadata_sanitized

        exif_dict: Dict[int, Any] = {}
        try:
            get_exif = getattr(img, "getexif", None)
            if callable(get_exif):
                raw_exif = get_exif()
                if raw_exif:
                    exif_dict.update(dict(raw_exif))
            # Also check _getexif if available (JPEG)
            _getexif = getattr(img, "_getexif", None)
            if callable(_getexif):
                raw__exif = _getexif()
                if raw__exif:
                    exif_dict.update(dict(raw__exif))
        except Exception:
            pass

        for tag_id, val in exif_dict.items():
            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
            if isinstance(val, (bytes, bytearray)):
                try:
                    val_str = val.decode("utf-8", errors="ignore")
                except Exception:
                    val_str = str(val)
            else:
                val_str = str(val)

            val_str = val_str.strip()
            if not val_str:
                continue

            val_lower = val_str.lower()
            is_suspicious = any(m in val_lower for m in _EXIF_INJECTION_MARKERS) or (
                len(val_str) > 120 and any(w in val_lower for w in ["pay", "wire", "iban"])
            )

            if is_suspicious:
                findings.append(
                    CloakedSpanFinding(
                        finding_id=f"exif-{uuid.uuid4().hex[:8]}",
                        modality="image",
                        page_or_paragraph=1,
                        cloak_reason="SUSPICIOUS_METADATA",
                        hidden_text=f"EXIF [{tag_name}]: {val_str}",
                        metadata_key=tag_name,
                        risk_category_ids=[4, 7],
                    )
                )
            else:
                metadata_sanitized[tag_name] = val_str

        # Re-save image without EXIF metadata
        clean_io = io.BytesIO()
        try:
            img_format = img.format or "PNG"
            clean_img = Image.new(img.mode, img.size)
            clean_img.putdata(list(img.getdata()))
            if clean_img.mode in ("RGBA", "LA") and img_format.upper() in ("JPEG", "JPG"):
                clean_img = clean_img.convert("RGB")
            clean_img.save(clean_io, format=img_format)
            clean_bytes = clean_io.getvalue()
        except Exception:
            clean_bytes = file_bytes

        return clean_bytes, findings, metadata_sanitized

    # ───────────────────────────────────────────────────────────────────────
    # 2. Dual-Pass OCR Engine
    # ───────────────────────────────────────────────────────────────────────

    def dual_pass_ocr(
        self, cv2_img: np.ndarray
    ) -> Tuple[str, List[CloakedSpanFinding]]:
        """
        Executes Dual-Pass OCR:
        - Pass 1 (Human-Visibility): Standard Otsu thresholding.
        - Pass 2 (High-Gain): CLAHE adaptive histogram equalization to expose faint text.
        Diffs outputs to uncover steganographic text injections.
        """
        pass1_text = ""
        pass2_text = ""
        findings: List[CloakedSpanFinding] = []

        try:
            # Convert to grayscale
            if len(cv2_img.shape) == 3 and cv2_img.shape[2] == 3:
                gray = cv2.cvtColor(cv2_img, cv2.COLOR_BGR2GRAY)
            elif len(cv2_img.shape) == 3 and cv2_img.shape[2] == 4:
                gray = cv2.cvtColor(cv2_img, cv2.COLOR_BGRA2GRAY)
            else:
                gray = cv2_img

            # Pass 1: Otsu's thresholding
            _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            pass1_text = pytesseract.image_to_string(otsu)

            # Pass 2: High-Gain CLAHE + Adaptive thresholding
            clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
            clahe_img = clahe.apply(gray)
            adaptive = cv2.adaptiveThreshold(
                clahe_img, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
            )
            pass2_text = pytesseract.image_to_string(adaptive)
        except Exception as exc:
            logger.warning("pytesseract dual-pass OCR error: %s", exc)

        pass1_lower = pass1_text.lower()
        pass2_lower = pass2_text.lower()

        # Check for injection keywords revealed in Pass 2 that were absent in Pass 1
        keywords = [
            "ignore previous",
            "ignore all",
            "system update",
            "system override",
            "transfer",
            "forward",
            "disregard",
            "override",
            "system prompt",
            "iban",
            "wire",
            "attacker@evil.com",
        ]

        faint_hits = [
            kw for kw in keywords if kw in pass2_lower and kw not in pass1_lower
        ]
        if not faint_hits:
            if ("ignore" in pass2_lower and "ignore" not in pass1_lower) or (
                "system" in pass2_lower and "system" not in pass1_lower
            ):
                faint_hits.append("ignore/system")

        if faint_hits:
            # Extract malicious lines from Pass 2
            malicious_lines = [
                line
                for line in pass2_text.splitlines()
                if any(
                    kw in line.lower()
                    for kw in [
                        "ignore",
                        "system",
                        "transfer",
                        "override",
                        "forward",
                        "iban",
                        "wire",
                    ]
                )
            ]
            hidden_content = (
                " | ".join(malicious_lines) if malicious_lines else pass2_text.strip()
            )
            findings.append(
                CloakedSpanFinding(
                    finding_id=f"faint-{uuid.uuid4().hex[:8]}",
                    modality="image",
                    page_or_paragraph=1,
                    cloak_reason="STEGANOGRAPHIC_OR_FAINT_TEXT",
                    hidden_text=f"Faint text revealed by high-gain CLAHE pass: {hidden_content}",
                    risk_category_ids=[4],
                )
            )

        # Clean visible text derived from Pass 1 (strip any injection phrases)
        clean_lines = [
            line
            for line in pass1_text.splitlines()
            if not any(kw in line.lower() for kw in keywords)
        ]
        visible_clean_text = "\n".join(clean_lines).strip()

        return visible_clean_text, findings

    # ───────────────────────────────────────────────────────────────────────
    # 3. QR Code & Barcode Scanner
    # ───────────────────────────────────────────────────────────────────────

    def scan_qr_codes(self, cv2_img: np.ndarray) -> List[CloakedSpanFinding]:
        """
        Decodes QR codes and barcodes using pyzbar.
        Flags SSRF targets (169.254.169.254, 127.0.0.1), unauthorized external domains,
        and embedded prompt commands.
        """
        findings: List[CloakedSpanFinding] = []

        try:
            barcodes = pyzbar.decode(cv2_img)
            for b in barcodes:
                raw_data = b.data.decode("utf-8", errors="ignore").strip()
                data_lower = raw_data.lower()

                # Check for SSRF internal IPs
                is_ssrf = any(
                    ip in data_lower
                    for ip in [
                        "169.254.169.254",
                        "127.0.0.1",
                        "0.0.0.0",
                        "localhost",
                        "::1",
                    ]
                )
                # Check for prompt commands
                is_command = any(
                    cmd in data_lower
                    for cmd in [
                        "system:",
                        "ignore previous",
                        "override",
                        "transfer funds",
                        "wire",
                    ]
                )
                # Check for unauthorized domains
                is_unauthorized_domain = False
                if "http://" in data_lower or "https://" in data_lower:
                    allowed = getattr(
                        settings,
                        "allowed_domains_list",
                        ["localhost", "127.0.0.1", "api.groq.com"],
                    )
                    safe_domains = [d for d in allowed if d not in ["localhost", "127.0.0.1"]]
                    if not any(d in data_lower for d in safe_domains):
                        is_unauthorized_domain = True

                if is_ssrf or is_command or is_unauthorized_domain:
                    risk_ids = [4, 5]
                    if is_ssrf:
                        risk_ids.append(23)
                    findings.append(
                        CloakedSpanFinding(
                            finding_id=f"qr-{uuid.uuid4().hex[:8]}",
                            modality="image",
                            page_or_paragraph=1,
                            cloak_reason="MALICIOUS_QR_CODE",
                            hidden_text=f"Malicious QR Code Content: {raw_data}",
                            risk_category_ids=sorted(list(set(risk_ids))),
                        )
                    )
        except Exception as exc:
            logger.warning("pyzbar QR scanning error: %s", exc)

        return findings

    # ───────────────────────────────────────────────────────────────────────
    # 4. Fake System UI Detection
    # ───────────────────────────────────────────────────────────────────────

    def detect_forged_system_ui(self, text: str) -> List[CloakedSpanFinding]:
        """
        Scans OCR output for fake system UI elements or forged system output tags.
        """
        findings: List[CloakedSpanFinding] = []
        text_lower = text.lower()

        for pattern in _FORGED_SYSTEM_PATTERNS:
            if pattern.lower() in text_lower:
                findings.append(
                    CloakedSpanFinding(
                        finding_id=f"ui-{uuid.uuid4().hex[:8]}",
                        modality="image",
                        page_or_paragraph=1,
                        cloak_reason="FORGED_SYSTEM_UI",
                        hidden_text=f"Forged system UI element in image: '{pattern}'",
                        risk_category_ids=[4, 12],
                    )
                )

        return findings

    # ───────────────────────────────────────────────────────────────────────
    # 5. Main Image De-Cloaking Method
    # ───────────────────────────────────────────────────────────────────────

    def decloak_image_bytes(
        self, file_bytes: bytes, filename: str = "image.png"
    ) -> DocumentDeCloakResult:
        """
        Full de-cloaking pipeline for images:
        1. Strips EXIF metadata traps.
        2. Scans for malicious QR codes.
        3. Executes Dual-Pass OCR for faint text.
        4. Detects forged system UI prompts.
        Returns a structured DocumentDeCloakResult.
        """
        raw_evidence_sha256 = hashlib.sha256(file_bytes).hexdigest().lower()
        findings: List[CloakedSpanFinding] = []
        risk_category_ids: List[int] = []

        # 1. EXIF Scanning & Stripping
        clean_bytes, exif_findings, metadata_sanitized = self.strip_exif_metadata(
            file_bytes
        )
        for f in exif_findings:
            findings.append(f)
            for r_id in f.risk_category_ids:
                if r_id not in risk_category_ids:
                    risk_category_ids.append(r_id)

        # 2. Decode OpenCV image
        np_arr = np.frombuffer(clean_bytes, np.uint8)
        cv2_img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if cv2_img is None:
            # Fallback if cv2 cannot decode (e.g. invalid format)
            return DocumentDeCloakResult(
                raw_evidence_sha256=raw_evidence_sha256,
                redacted_diff_sha256=hashlib.sha256(b"CLEAN:").hexdigest().lower(),
                modality="image",
                visible_clean_text="",
                raw_unfiltered_text="",
                cloaked_findings=findings,
                metadata_sanitized=metadata_sanitized,
                threat_detected=len(findings) > 0,
                risk_category_ids=sorted(list(set(risk_category_ids))),
                summary="Image could not be decoded by OpenCV.",
            )

        # 3. QR Code Scanning
        qr_findings = self.scan_qr_codes(cv2_img)
        for f in qr_findings:
            findings.append(f)
            for r_id in f.risk_category_ids:
                if r_id not in risk_category_ids:
                    risk_category_ids.append(r_id)

        # 4. Dual-Pass OCR Engine
        visible_clean_text, ocr_findings = self.dual_pass_ocr(cv2_img)
        for f in ocr_findings:
            findings.append(f)
            for r_id in f.risk_category_ids:
                if r_id not in risk_category_ids:
                    risk_category_ids.append(r_id)

        # 5. Fake System UI Detection
        ui_findings = self.detect_forged_system_ui(visible_clean_text)
        for f in ui_findings:
            findings.append(f)
            for r_id in f.risk_category_ids:
                if r_id not in risk_category_ids:
                    risk_category_ids.append(r_id)

        # Redact forged UI tags from clean visible text
        for pattern in _FORGED_SYSTEM_PATTERNS:
            visible_clean_text = re.sub(
                re.escape(pattern), "[REDACTED_FORGED_UI]", visible_clean_text, flags=re.I
            )

        threat_detected = len(findings) > 0
        diff_payload = (
            f"RAW:{raw_evidence_sha256}|CLEAN:{visible_clean_text}|FINDINGS:{len(findings)}"
        )
        redacted_diff_sha256 = hashlib.sha256(diff_payload.encode("utf-8")).hexdigest().lower()

        summary = (
            f"Image De-Cloaker intercepted {len(findings)} threat(s) across EXIF, QR, and Dual-Pass OCR."
            if threat_detected
            else "Image is clean: no steganographic text, QR traps, or metadata threats detected."
        )

        return DocumentDeCloakResult(
            raw_evidence_sha256=raw_evidence_sha256,
            redacted_diff_sha256=redacted_diff_sha256,
            modality="image",
            visible_clean_text=visible_clean_text.strip(),
            raw_unfiltered_text=visible_clean_text.strip(),
            cloaked_findings=findings,
            metadata_sanitized=metadata_sanitized,
            threat_detected=threat_detected,
            risk_category_ids=sorted(list(set(risk_category_ids))),
            summary=summary,
        )


# Singleton instance for application-wide use
image_decloaker = ImageDeCloaker()
