"""
IntentGuard Layer 1 Multi-Modal Pre-OCR De-Cloaker (Web DOM & HTML)
====================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Neutralizes HTML/DOM prompt injections and tracking exfiltration vectors:
- Risk #2: Hidden Prompt Injection (CSS display:none, opacity:0, font-size:0px)
- Risk #6: Malicious Web Pages (Poisoned ARIA labels, hidden comments, sr-only traps)
- Risk #21: EchoLeak Outbound Data Exfiltration (0x0 / 1x1 tracking pixels & hidden iframes)
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union

from bs4 import BeautifulSoup, Comment, Tag

from app.layer1_decloaker.pdf_docx_decloaker import (
    CloakedSpanFinding,
    DocumentDeCloakResult,
)

logger = logging.getLogger(__name__)

# Imperative words that indicate injection directives in comments and ARIA labels
_DOM_IMPERATIVE_WORDS = frozenset(
    {
        "ignore",
        "system",
        "override",
        "transfer",
        "wire",
        "forward",
        "leak",
        "admin",
        "authenticate",
        "delete",
        "disregard",
        "password",
        "api key",
        "secret",
        "prompt",
    }
)

_DOM_INJECTION_KEYWORDS = [
    "ignore previous",
    "ignore all",
    "ignore rules",
    "system override",
    "system prompt",
    "system update",
    "override",
    "transfer funds",
    "forward all",
    "leak",
    "send api key",
    "authenticate",
    "admin override",
    "admin access",
    "delete all",
    "disregard",
]

_DOM_INJECTION_RE = re.compile(
    r"(?i)\b(?:ignore\s+(?:previous|all|instructions?|rules?|restrictions?|prompt)|"
    r"system\s+(?:override|prompt|update|tool)|"
    r"override\s+(?:all\s+)?(?:previous\s+)?(?:instructions?|rules?)|"
    r"transfer\s+(?:all\s+)?(?:funds?|money|balance)|"
    r"wire\s+(?:all\s+)?(?:funds?|money)|"
    r"forward\s+all\s+(?:files?|emails?|data)|"
    r"leak|send\s+api\s+key|admin\s+override|admin\s+access|delete\s+all|disregard)\b",
    re.I,
)

# Inline CSS patterns that physically obscure or hide content from human eyes
_HIDDEN_CSS_PATTERNS = [
    re.compile(r"display\s*:\s*none", re.I),
    re.compile(r"visibility\s*:\s*hidden", re.I),
    re.compile(r"opacity\s*:\s*0(?:\.0*)?(?:;|$|\s)", re.I),
    re.compile(r"font-size\s*:\s*0(?:px|pt|em|rem)?", re.I),
    re.compile(r"height\s*:\s*0(?:px|pt)?", re.I),
    re.compile(r"width\s*:\s*0(?:px|pt)?", re.I),
    re.compile(r"text-indent\s*:\s*-[0-9]{2,}px", re.I),
    re.compile(r"position\s*:\s*absolute\b.*?(?:left|top)\s*:\s*-[0-9]{2,}px", re.I | re.DOTALL),
    re.compile(r"transform\s*:\s*scale\(0\)", re.I),
    re.compile(r"clip\s*:\s*rect\(0", re.I),
    re.compile(r"clip-path\s*:\s*inset\(100%\)", re.I),
]

# CSS classes commonly used to hide content off-screen
_HIDDEN_CLASSES = frozenset(
    {
        "sr-only",
        "visually-hidden",
        "hidden",
        "d-none",
        "invisible",
        "hide",
        "offscreen",
        "is-hidden",
    }
)


class WebDOMDeCloaker:
    """
    Layer 1 Pre-OCR Web DOM & HTML De-Cloaker Engine.
    Performs:
    1. Removal of invisible HTML comments (`<!-- ... -->`) and scripts/styles.
    2. Stripping of hidden CSS elements (display:none, opacity:0, font-size:0px).
    3. Neutralization of poisoned ARIA labels (aria-label, aria-valuetext, alt, title).
    4. Removal of tracking pixels & EchoLeak iframes (0x0, 1x1 dimensions).
    """

    # ───────────────────────────────────────────────────────────────────────
    # 1. HTML Comments and Script / Style Stripping
    # ───────────────────────────────────────────────────────────────────────

    def strip_comments_and_scripts(
        self, soup: BeautifulSoup
    ) -> List[CloakedSpanFinding]:
        """
        Removes all HTML comments and decomposes <script>, <style>, <noscript> tags.
        Flags comments containing imperative prompt injection directives.
        """
        findings: List[CloakedSpanFinding] = []

        # Find and process all HTML comments
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for c in comments:
            c_str = str(c).strip()
            c_lower = c_str.lower()

            is_suspicious = (
                any(kw in c_lower for kw in _DOM_INJECTION_KEYWORDS)
                or any(w in c_lower for w in _DOM_IMPERATIVE_WORDS)
                or bool(_DOM_INJECTION_RE.search(c_lower))
            )

            if is_suspicious:
                findings.append(
                    CloakedSpanFinding(
                        finding_id=f"comment-{uuid.uuid4().hex[:8]}",
                        modality="web_dom",
                        page_or_paragraph=1,
                        cloak_reason="INVISIBLE_MARKDOWN_COMMENT",
                        hidden_text=f"HTML comment injection: '{c_str}'",
                        risk_category_ids=[2, 6],
                    )
                )
            c.extract()

        # Decompose executable scripts and stylesheet blocks
        for element in soup.find_all(["script", "style", "noscript", "meta"]):
            element.decompose()

        return findings

    # ───────────────────────────────────────────────────────────────────────
    # 2. Hidden CSS Element Stripper
    # ───────────────────────────────────────────────────────────────────────

    def strip_hidden_css_traps(self, soup: BeautifulSoup) -> List[CloakedSpanFinding]:
        """
        Scans for inline styles and classes that hide text from human view
        (e.g., display:none, opacity:0, font-size:0, text-indent:-9999px).
        Decomposes tags and flags findings.
        """
        findings: List[CloakedSpanFinding] = []
        tags_to_decompose: List[Tuple[Tag, str]] = []

        for tag in soup.find_all(True):
            if not isinstance(tag, Tag) or tag.name in ["html", "head", "body"]:
                continue

            # Check inline style attribute
            style = tag.get("style", "")
            is_hidden = False
            if style:
                for pat in _HIDDEN_CSS_PATTERNS:
                    if pat.search(style):
                        is_hidden = True
                        break

            # Check class names
            classes = tag.get("class", [])
            if isinstance(classes, str):
                classes = classes.split()
            if any(cls.lower() in _HIDDEN_CLASSES for cls in classes):
                inner_text = tag.get_text(separator=" ", strip=True)
                if inner_text and (
                    any(kw in inner_text.lower() for kw in _DOM_INJECTION_KEYWORDS)
                    or bool(_DOM_INJECTION_RE.search(inner_text))
                ):
                    is_hidden = True

            if is_hidden:
                hidden_content = tag.get_text(separator=" ", strip=True)
                tags_to_decompose.append((tag, hidden_content))

        for tag, hidden_content in tags_to_decompose:
            if hidden_content:
                findings.append(
                    CloakedSpanFinding(
                        finding_id=f"css-{uuid.uuid4().hex[:8]}",
                        modality="web_dom",
                        page_or_paragraph=1,
                        cloak_reason="HIDDEN_CSS_TRAP",
                        hidden_text=f"Hidden CSS trap stripped: '{hidden_content}'",
                        risk_category_ids=[2, 6],
                    )
                )
            tag.decompose()

        return findings

    # ───────────────────────────────────────────────────────────────────────
    # 3. Poisoned ARIA & Alt Tag Sanitizer
    # ───────────────────────────────────────────────────────────────────────

    def scan_and_sanitize_aria_attributes(
        self, soup: BeautifulSoup
    ) -> List[CloakedSpanFinding]:
        """
        Inspects accessibility attributes (aria-label, aria-valuetext, alt, title)
        for prompt injection directives. Redacts malicious attributes in-place.
        """
        findings: List[CloakedSpanFinding] = []
        target_attrs = ["aria-label", "aria-valuetext", "aria-description", "alt", "title"]

        for tag in soup.find_all(True):
            if not isinstance(tag, Tag):
                continue

            for attr in target_attrs:
                val = tag.get(attr)
                if isinstance(val, list):
                    val = " ".join(val)
                if not val or not isinstance(val, str):
                    continue

                val_clean = val.strip()
                val_lower = val_clean.lower()

                if (
                    any(kw in val_lower for kw in _DOM_INJECTION_KEYWORDS)
                    or any(w in val_lower for w in _DOM_IMPERATIVE_WORDS)
                    or bool(_DOM_INJECTION_RE.search(val_clean))
                ):
                    findings.append(
                        CloakedSpanFinding(
                            finding_id=f"aria-{uuid.uuid4().hex[:8]}",
                            modality="web_dom",
                            page_or_paragraph=1,
                            cloak_reason="POISONED_ARIA_ATTRIBUTE",
                            hidden_text=f"Poisoned {attr} attribute: '{val_clean}'",
                            metadata_key=attr,
                            risk_category_ids=[2, 6],
                        )
                    )
                    del tag[attr]

        return findings

    # ───────────────────────────────────────────────────────────────────────
    # 4. Tracking Pixel & EchoLeak Iframe Remover
    # ───────────────────────────────────────────────────────────────────────

    def strip_tracking_pixels_and_iframes(
        self, soup: BeautifulSoup
    ) -> List[CloakedSpanFinding]:
        """
        Finds and deletes 0x0 or 1x1 <img> and <iframe> tags used for zero-click
        outbound data exfiltration (EchoLeak).
        """
        findings: List[CloakedSpanFinding] = []
        tags_to_decompose: List[Tuple[Tag, str]] = []

        for tag in soup.find_all(["img", "iframe"]):
            if not isinstance(tag, Tag):
                continue

            src = tag.get("src", "")
            width = tag.get("width", "")
            height = tag.get("height", "")
            style = tag.get("style", "").replace(" ", "").lower()

            is_pixel = False
            # Check attribute dimensions
            if width in ("0", "1", "0px", "1px") or height in ("0", "1", "0px", "1px"):
                is_pixel = True
            # Check style dimensions
            elif ("width:0" in style or "width:1px" in style) and (
                "height:0" in style or "height:1px" in style
            ):
                is_pixel = True
            # Check hidden img
            elif "display:none" in style or "visibility:hidden" in style:
                is_pixel = True

            if is_pixel:
                tags_to_decompose.append((tag, src))

        for tag, src in tags_to_decompose:
            findings.append(
                CloakedSpanFinding(
                    finding_id=f"pixel-{uuid.uuid4().hex[:8]}",
                    modality="web_dom",
                    page_or_paragraph=1,
                    cloak_reason="TRACKING_PIXEL_OR_HIDDEN_IFRAME",
                    hidden_text=f"Tracking pixel / EchoLeak iframe removed: src='{src}'",
                    risk_category_ids=[6, 21],
                )
            )
            tag.decompose()

        return findings

    # ───────────────────────────────────────────────────────────────────────
    # 5. Main Web DOM De-Cloaking Method
    # ───────────────────────────────────────────────────────────────────────

    def decloak_web_dom_bytes(
        self,
        html_input: Union[bytes, str],
        filename: str = "page.html",
    ) -> DocumentDeCloakResult:
        """
        Full de-cloaking pipeline for Web DOM & HTML inputs:
        1. Strips HTML comments and scripts/styles.
        2. Removes hidden CSS traps.
        3. Neutralizes poisoned ARIA/alt attributes.
        4. Removes tracking pixels and EchoLeak iframes.
        Returns a structured DocumentDeCloakResult.
        """
        if isinstance(html_input, str):
            raw_bytes = html_input.encode("utf-8")
            html_text = html_input
        else:
            raw_bytes = html_input
            try:
                html_text = html_input.decode("utf-8", errors="replace")
            except Exception:
                html_text = str(html_input)

        raw_evidence_sha256 = hashlib.sha256(raw_bytes).hexdigest().lower()
        findings: List[CloakedSpanFinding] = []
        risk_category_ids: List[int] = []

        try:
            soup = BeautifulSoup(html_text, "lxml")
        except Exception:
            soup = BeautifulSoup(html_text, "html.parser")

        # Step 1: Comments and Scripts
        comment_findings = self.strip_comments_and_scripts(soup)
        for f in comment_findings:
            findings.append(f)
            for r in f.risk_category_ids:
                if r not in risk_category_ids:
                    risk_category_ids.append(r)

        # Step 2: Hidden CSS Traps
        css_findings = self.strip_hidden_css_traps(soup)
        for f in css_findings:
            findings.append(f)
            for r in f.risk_category_ids:
                if r not in risk_category_ids:
                    risk_category_ids.append(r)

        # Step 3: Poisoned ARIA / Alt Attributes
        aria_findings = self.scan_and_sanitize_aria_attributes(soup)
        for f in aria_findings:
            findings.append(f)
            for r in f.risk_category_ids:
                if r not in risk_category_ids:
                    risk_category_ids.append(r)

        # Step 4: Tracking Pixels & Iframes
        pixel_findings = self.strip_tracking_pixels_and_iframes(soup)
        for f in pixel_findings:
            findings.append(f)
            for r in f.risk_category_ids:
                if r not in risk_category_ids:
                    risk_category_ids.append(r)

        visible_clean_text = soup.get_text(separator=" ", strip=True)
        sanitized_html = str(soup)
        threat_detected = len(findings) > 0

        diff_payload = (
            f"RAW:{raw_evidence_sha256}|CLEAN:{visible_clean_text}|FINDINGS:{len(findings)}"
        )
        redacted_diff_sha256 = (
            hashlib.sha256(diff_payload.encode("utf-8")).hexdigest().lower()
        )

        summary = (
            f"Web DOM De-Cloaker neutralized {len(findings)} threat(s) across HTML structure."
            if threat_detected
            else "Web DOM is clean: no hidden CSS, poisoned ARIA, or tracking pixels found."
        )

        return DocumentDeCloakResult(
            raw_evidence_sha256=raw_evidence_sha256,
            redacted_diff_sha256=redacted_diff_sha256,
            modality="web_dom",
            visible_clean_text=visible_clean_text,
            raw_unfiltered_text=visible_clean_text,
            cloaked_findings=findings,
            metadata_sanitized={"sanitized_html": sanitized_html},
            threat_detected=threat_detected,
            risk_category_ids=sorted(list(set(risk_category_ids))),
            summary=summary,
        )


# Singleton instance for application-wide use
web_dom_decloaker = WebDOMDeCloaker()
