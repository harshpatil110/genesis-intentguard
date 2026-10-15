"""
IntentGuard Layer 1 Email & Chat Impersonation / Spoofed Authority Scanner
============================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

Mechanically inspects sender metadata, reply-to headers, and message bodies
from enterprise communication channels (Gmail/SMTP, Slack, Teams) to neutralize:
- Risk #9:  Impersonation (Executive/Admin display name spoofing, Reply-To mismatches)
- Risk #10: Spoofed Authorization (Fake human-in-the-loop approvals / buyer claims)
- Risk #11: Compromised Account (Freemail sender pretending to be internal authority)
- Risk #12: Forged System Output (Pseudo-tool outputs e.g. [SYSTEM TOOL OUTPUT: ...])
- Risk #14: Instruction Override
- Risk #18: Financial Mutation

Preserves 100% of legitimate conversational text for Task Continuity while
surgically neutralizing spoofed authority and forged system tags.
"""

from __future__ import annotations

import email.utils
import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from app.config import settings
from app.layer1_decloaker.pdf_docx_decloaker import CloakedSpanFinding, DocumentDeCloakResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detection Regex Patterns
# ---------------------------------------------------------------------------

# High-authority keywords in display names (Executive, IT Admin, Security, Finance)
_EXECUTIVE_NAME_PATTERN = re.compile(
    r"\b(ceo|cfo|cto|coo|cio|ciso|president|founder|director|manager|admin|administrator|"
    r"it\s+support|helpdesk|security\s+team|finance\s+team|executive)\b",
    re.IGNORECASE,
)

# Common public freemail domains used in spoofing/phishing
_DEFAULT_FREEMAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "protonmail.com",
        "proton.me",
        "icloud.com",
        "mail.com",
        "aol.com",
        "zoho.com",
        "yandex.com",
        "gmx.com",
    }
)

# Forged system output and pseudo-tool execution tags
_FORGED_SYSTEM_TAG_PATTERN = re.compile(
    r"\[\s*(?:system|tool output|admin warning|security alert|verified|user authorized|"
    r"admin notice|security warning|prompt injection|system tool output)[^\]]*\]",
    re.IGNORECASE,
)

# Spoofed human-in-the-loop authorization claims
_AUTH_CLAIM_REGEX = re.compile(
    r"(?:the\s+)?(?:buyer|management|finance|user|admin)\s+(?:has\s+)?(?:already\s+)?approved(?:\s+this\s+payment)?|"
    r"management\s+authorized|"
    r"cleared\s+by\s+finance|"
    r"user\s+has\s+approved(?:\s+this\s+payment)?|"
    r"override\s+authorization|"
    r"pre-approved\s+by|"
    r"approved\s+by\s+(?:buyer|management|finance|admin)",
    re.IGNORECASE,
)


def _extract_bare_email(raw_addr: str) -> str:
    """Extract bare email address from formats like 'Name <user@domain.com>' or 'user@domain.com'."""
    if not raw_addr:
        return ""
    parsed_name, parsed_email = email.utils.parseaddr(raw_addr.strip())
    if parsed_email:
        return parsed_email.strip().lower()
    # Fallback regex if parseaddr didn't catch bare email
    match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", raw_addr)
    return match.group(0).lower() if match else raw_addr.strip().lower()


def _extract_domain(addr: str) -> str:
    """Return lowercase domain of email address, or empty string."""
    bare = _extract_bare_email(addr)
    if "@" in bare:
        return bare.split("@")[-1].strip().lower()
    return ""


# ---------------------------------------------------------------------------
# Email & Chat Scanner Engine
# ---------------------------------------------------------------------------

class EmailChatScanner:
    """
    Core inspection engine for Inbound Email and Chat messages.
    Inspects sender metadata, reply-to headers, and content text to detect
    impersonation, spoofed authority claims, and forged system tags.
    """

    def __init__(self, internal_domain: Optional[str] = None):
        self.internal_domain = (
            internal_domain
            or getattr(settings, "INTERNAL_DOMAIN", "enterprise.internal")
        ).lower()

    @property
    def freemail_domains(self) -> frozenset[str]:
        cfg_domains = getattr(settings, "freemail_domains_list", [])
        return _DEFAULT_FREEMAIL_DOMAINS | set(cfg_domains)

    def scan_sender_metadata(
        self,
        metadata: Optional[Dict[str, Any]] = None,
        modality: str = "email",
    ) -> List[CloakedSpanFinding]:
        """
        Inspect sender name, sender email, and reply-to email headers for:
        1. Executive / Admin display name spoofing from external/freemail accounts.
        2. Reply-to address mismatches (phishing / bounce manipulation).
        """
        findings: List[CloakedSpanFinding] = []
        if not metadata:
            return findings

        # Extract fields flexibly
        sender_name = (
            metadata.get("sender_name")
            or metadata.get("display_name")
            or metadata.get("from_name")
            or ""
        )
        sender_email = (
            metadata.get("sender_email")
            or metadata.get("from_email")
            or metadata.get("sender")
            or metadata.get("from")
            or ""
        )
        reply_to_email = (
            metadata.get("reply_to_email")
            or metadata.get("reply_to")
            or metadata.get("reply-to")
            or ""
        )

        # If sender_name not provided but sender_email contains "Display Name <email>", extract
        if not sender_name and sender_email:
            parsed_name, _ = email.utils.parseaddr(sender_email)
            if parsed_name:
                sender_name = parsed_name

        bare_sender_email = _extract_bare_email(sender_email)
        sender_domain = _extract_domain(bare_sender_email)

        # ── Rule 1: Executive / Admin Display Name Spoofing ──────────────────
        if sender_name and _EXECUTIVE_NAME_PATTERN.search(sender_name):
            # Sender has high-authority title; verify if email domain is trusted internal
            is_internal = bool(
                sender_domain
                and (
                    sender_domain == self.internal_domain
                    or sender_domain.endswith("." + self.internal_domain)
                )
            )
            # If not internal (e.g. freemail like @gmail.com or unknown external domain like evil.com)
            if not is_internal:
                findings.append(
                    CloakedSpanFinding(
                        modality=modality if modality in ("email", "chat") else "email",  # type: ignore[arg-type]
                        page_or_paragraph=1,
                        cloak_reason="EXECUTIVE_IMPERSONATION",
                        hidden_text=(
                            f"Executive/Admin impersonation detected: Display name '{sender_name}' "
                            f"paired with untrusted non-internal sender '{sender_email or 'EMPTY'}'"
                        ),
                        metadata_key="sender_metadata",
                        risk_category_ids=[9, 11],
                    )
                )

        # ── Rule 2: Reply-To Address Mismatch ────────────────────────────────
        if reply_to_email and bare_sender_email:
            bare_reply_to = _extract_bare_email(reply_to_email)
            if bare_reply_to and bare_reply_to != bare_sender_email:
                findings.append(
                    CloakedSpanFinding(
                        modality=modality if modality in ("email", "chat") else "email",  # type: ignore[arg-type]
                        page_or_paragraph=1,
                        cloak_reason="REPLY_TO_MISMATCH",
                        hidden_text=(
                            f"Reply-To mismatch: Inbound sender is '{bare_sender_email}' "
                            f"but Reply-To points to '{bare_reply_to}'"
                        ),
                        metadata_key="reply_to_email",
                        risk_category_ids=[9],
                    )
                )

        return findings

    def scan_forged_system_tags(
        self,
        raw_text: str,
        modality: str = "email",
    ) -> Tuple[str, List[CloakedSpanFinding]]:
        """
        Detect pseudo-tool tags such as [SYSTEM TOOL OUTPUT: ...] and redact them.
        """
        findings: List[CloakedSpanFinding] = []
        if not raw_text:
            return raw_text, findings

        matches = list(_FORGED_SYSTEM_TAG_PATTERN.finditer(raw_text))
        for m in matches:
            tag_text = m.group(0)
            findings.append(
                CloakedSpanFinding(
                    modality=modality if modality in ("email", "chat") else "email",  # type: ignore[arg-type]
                    page_or_paragraph=1,
                    cloak_reason="FORGED_SYSTEM_OUTPUT",
                    hidden_text=tag_text,
                    risk_category_ids=[12, 14],
                )
            )

        if matches:
            clean_text = _FORGED_SYSTEM_TAG_PATTERN.sub("[REDACTED_FORGED_SYSTEM_TAG]", raw_text)
        else:
            clean_text = raw_text

        return clean_text, findings

    def scan_authorization_claims(
        self,
        raw_text: str,
        modality: str = "email",
    ) -> Tuple[str, List[CloakedSpanFinding]]:
        """
        Detect spoofed human-in-the-loop authorization claims and redact them
        sentence-by-sentence to prevent indirect prompt injection.
        """
        findings: List[CloakedSpanFinding] = []
        if not raw_text or not _AUTH_CLAIM_REGEX.search(raw_text):
            return raw_text, findings

        # Split sentences preserving punctuation and whitespace delimiters
        parts = re.split(r"((?<=[.!?\n])\s+)", raw_text)
        cleaned_parts: List[str] = []

        for part in parts:
            if part and _AUTH_CLAIM_REGEX.search(part):
                findings.append(
                    CloakedSpanFinding(
                        modality=modality if modality in ("email", "chat") else "email",  # type: ignore[arg-type]
                        page_or_paragraph=1,
                        cloak_reason="SPOOFED_AUTHORIZATION_CLAIM",
                        hidden_text=part.strip(),
                        risk_category_ids=[10, 18],
                    )
                )
                cleaned_parts.append("[REDACTED_SPOOFED_AUTHORIZATION]")
            else:
                cleaned_parts.append(part)

        clean_text = "".join(cleaned_parts)

        # Fallback in case a claim spans across punctuation or inside un-delimited text
        if _AUTH_CLAIM_REGEX.search(clean_text):
            clean_text = _AUTH_CLAIM_REGEX.sub("[REDACTED_SPOOFED_AUTHORIZATION]", clean_text)

        return clean_text, findings

    def scan_message_bytes(
        self,
        raw_input: Union[bytes, str],
        metadata: Optional[Dict[str, Any]] = None,
        modality: str = "email",
        filename: str = "message.eml",
    ) -> DocumentDeCloakResult:
        """
        Complete mechanical scanning pipeline for an email or chat payload:
        1. Decodes raw input to text and computes evidence SHA-256.
        2. Scans sender & reply-to metadata for impersonation.
        3. Scans and strips forged system tags.
        4. Scans and redacts spoofed authorization claims.
        5. Computes redacted diff SHA-256 and returns structured DocumentDeCloakResult.
        """
        if isinstance(raw_input, bytes):
            raw_text = raw_input.decode("utf-8", errors="replace")
            raw_evidence_sha256 = hashlib.sha256(raw_input).hexdigest()
        else:
            raw_text = str(raw_input)
            raw_evidence_sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        mod_val = modality if modality in ("email", "chat") else "email"
        meta = metadata or {}
        findings: List[CloakedSpanFinding] = []

        # 1. Scan sender metadata
        sender_findings = self.scan_sender_metadata(meta, modality=mod_val)
        findings.extend(sender_findings)

        # 2. Scan forged system tags
        text_after_tags, tag_findings = self.scan_forged_system_tags(raw_text, modality=mod_val)
        findings.extend(tag_findings)

        # 3. Scan spoofed authorization claims
        clean_text, auth_findings = self.scan_authorization_claims(text_after_tags, modality=mod_val)
        findings.extend(auth_findings)

        # Aggregate unique risk category IDs
        all_risk_ids: List[int] = []
        for f in findings:
            for rid in f.risk_category_ids:
                if rid not in all_risk_ids:
                    all_risk_ids.append(rid)

        threat_detected = len(findings) > 0
        diff_record = f"ORIGINAL:{raw_evidence_sha256}|SANITIZED:{clean_text}"
        redacted_diff_sha256 = hashlib.sha256(diff_record.encode("utf-8")).hexdigest()

        # Sanitize metadata record
        sanitized_meta: Dict[str, str] = {str(k): str(v) for k, v in meta.items()}
        if any(f.cloak_reason == "EXECUTIVE_IMPERSONATION" for f in findings):
            sanitized_meta["impersonation_flagged"] = "true"
        if any(f.cloak_reason == "REPLY_TO_MISMATCH" for f in findings):
            sanitized_meta["reply_to_mismatch_flagged"] = "true"

        reasons = [f.cloak_reason for f in findings]
        summary = (
            f"Email/Chat scan found {len(findings)} threats: {reasons}"
            if threat_detected
            else "Email/Chat message clean: no impersonation, spoofed approvals, or forged tags detected."
        )

        return DocumentDeCloakResult(
            raw_evidence_sha256=raw_evidence_sha256,
            redacted_diff_sha256=redacted_diff_sha256,
            modality=mod_val,  # type: ignore[arg-type]
            visible_clean_text=clean_text,
            raw_unfiltered_text=raw_text,
            cloaked_findings=findings,
            metadata_sanitized=sanitized_meta,
            threat_detected=threat_detected,
            risk_category_ids=all_risk_ids,
            summary=summary,
        )


# Global singleton instance
email_chat_scanner = EmailChatScanner()
