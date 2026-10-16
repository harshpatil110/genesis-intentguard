"""
IntentGuard Layer 3 — Zero-Click Outbound Exfiltration, URL/DNS, & SSRF Firewall
================================================================================
GENESIS 2.0 | Track: EVA 03 | PS 01 — Separating Data from Authority

Protects against:
- Risk #5: Malicious Links & Tracking Pixels
- Risk #21: Silent Data Exfiltration
- Risk #22: Markdown / Image / Link Leak (EchoLeak)
- Risk #23: Server-Side Request Forgery / SSRF
- Risk #25: Credential & Secret Exposure
- Risk #27: Cross-Channel / Unauthorized External Communication
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
import urllib.parse
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from app.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Whitelisted Domains & Constants
# ---------------------------------------------------------------------------

DEFAULT_WHITELISTED_DOMAINS: Set[str] = {
    "acme-industrial.example.com",
    "portal.buyer-enterprise.internal",
    "api.intentguard.local",
    "trusted-bank-verify.in",
    "docs.company.com",
}

# SSRF Restricted IP Networks
LOOPBACK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("0.0.0.0/32"),
]

CLOUD_METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]

PRIVATE_RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]

METADATA_HOSTNAMES: Set[str] = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.internal",
    "instance-data",
}

LOOPBACK_HOSTNAMES: Set[str] = {
    "localhost",
    "0.0.0.0",
    "ip6-localhost",
    "ip6-loopback",
}

# ---------------------------------------------------------------------------
# Secret / Exfiltration Detection Regexes
# ---------------------------------------------------------------------------

SECRET_TOKEN_RE = re.compile(
    r"(?i)(gsk_[a-zA-Z0-9]{10,}|AIza[a-zA-Z0-9_\-]{15,}|sk-[a-zA-Z0-9]{15,}|xox[baprs]-[a-zA-Z0-9\-]+|eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}|bearer\s+[a-zA-Z0-9_\-\.]+)"
)

SENSITIVE_PARAM_NAME_RE = re.compile(
    r"(?i)^(token|api_key|apikey|secret|password|passwd|auth|jwt|access_token|session_key|hmac|iban|bank_account|po_number|invoice_data|exfil|leak|data|dump)$"
)

CONFIDENTIAL_DATA_RE = re.compile(
    r"(?i)(PO-?\d{3,}|INV-?\d{3,}|HDFC0\d+_[0-9]+|ICIC0\d+_[0-9]+|ACME-SUPPLIER-\d+|BUYER-ENTERPRISE-\d+)"
)

# Forged System / Tool Output Tags
FORGED_TAG_RE = re.compile(
    r"(?i)\[\s*(?:TOOL OUTPUT|SYSTEM|SYSTEM WARNING|ADMIN OVERRIDE|VERIFIED TOOL|SECURITY BYPASS|SYSTEM TOOL OUTPUT)\s*:?[^\]]*\]"
)

# Markdown Image pattern: ![alt](url)
MARKDOWN_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\((https?://[^)\s]+)\)")

# Markdown Link pattern: [label](url)
MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[([^\]]+)\]\((https?://[^)\s]+)\)")

# Standalone URL pattern
STANDALONE_URL_RE = re.compile(r"(https?://[^\s\)\]>\"']+)")


# ---------------------------------------------------------------------------
# Shannon Entropy Helper
# ---------------------------------------------------------------------------

def calculate_shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class URLInspectionFinding(BaseModel):
    """Detailed inspection result for a single URL."""
    original_url: str
    sanitized_url: Optional[str] = None
    domain: str = ""
    is_blocked: bool = False
    violation_reasons: List[str] = Field(default_factory=list)
    risk_category_ids: List[int] = Field(default_factory=list)


class OutboundFirewallResult(BaseModel):
    """Evaluation result for an outbound text payload or tool call parameter."""
    allowed: bool
    threat_detected: bool
    action_taken: str  # "SAFE_PASSED", "REDACTED_EXFILTRATION_LINKS", "BLOCKED_SSRF_OR_UNTRUSTED_URL"
    original_text: str
    sanitized_text: str
    urls_inspected: List[URLInspectionFinding] = Field(default_factory=list)
    forged_tags_removed: List[str] = Field(default_factory=list)
    exfiltration_links_removed: List[str] = Field(default_factory=list)
    risk_category_ids: List[int] = Field(default_factory=list)
    reason: str


# ---------------------------------------------------------------------------
# ZeroClickOutboundFirewall Class
# ---------------------------------------------------------------------------

class ZeroClickOutboundFirewall:
    """
    Zero-Click Outbound Exfiltration, URL/DNS, & SSRF Firewall (Layer 3 Policy).
    Evaluates Hook 4 outbound text streams and Hook 2 URL-bearing tool parameters.
    """

    def __init__(self, whitelisted_domains: Optional[Set[str]] = None) -> None:
        self.whitelisted_domains: Set[str] = set(DEFAULT_WHITELISTED_DOMAINS)
        if whitelisted_domains:
            self.whitelisted_domains.update(whitelisted_domains)

        # Merge domains from application settings if available
        if hasattr(settings, "allowed_domains_list") and settings.allowed_domains_list:
            for d in settings.allowed_domains_list:
                if d and d.strip():
                    self.whitelisted_domains.add(d.strip().lower())

    def is_domain_whitelisted(self, domain: str) -> bool:
        """Checks if domain or any parent domain is in whitelisted domains."""
        d = domain.lower().strip()
        if not d:
            return False
        for wd in self.whitelisted_domains:
            wd_norm = wd.lower().strip()
            if d == wd_norm or d.endswith("." + wd_norm):
                return True
        return False

    def _parse_ip_literal(self, host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Parses standard, integer, or hex representation of IP literal."""
        clean_host = host.strip("[]")
        try:
            return ipaddress.ip_address(clean_host)
        except ValueError:
            pass

        try:
            if clean_host.isdigit():
                val = int(clean_host)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            elif clean_host.startswith(("0x", "0X")):
                val = int(clean_host, 16)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass

        return None

    def check_ssrf_target(self, url: str) -> Tuple[bool, Optional[str], List[int]]:
        """
        Determines whether the given URL targets loopback, cloud metadata,
        or internal private subnets (RFC-1918 / IPv6 ULA).
        Returns: (is_ssrf, violation_type, risk_ids)
        """
        try:
            parsed = urllib.parse.urlparse(url)
            host = (parsed.hostname or "").lower().strip()
        except Exception:
            return True, "SSRF_MALFORMED_URL", [23]

        if not host:
            return True, "SSRF_MISSING_HOST", [23]

        # 1. Hostname checks
        if host in METADATA_HOSTNAMES:
            return True, "SSRF_CLOUD_METADATA_TARGET", [22, 23]

        if host in LOOPBACK_HOSTNAMES:
            return True, "SSRF_PRIVATE_OR_LOOPBACK_TARGET", [22, 23]

        # 2. IP literal checks
        ip_obj = self._parse_ip_literal(host)
        if ip_obj is not None:
            # Cloud metadata
            for net in CLOUD_METADATA_NETWORKS:
                if ip_obj in net:
                    return True, "SSRF_CLOUD_METADATA_TARGET", [22, 23]

            # Loopback
            for net in LOOPBACK_NETWORKS:
                if ip_obj in net:
                    return True, "SSRF_PRIVATE_OR_LOOPBACK_TARGET", [22, 23]

            # Private RFC-1918
            for net in PRIVATE_RFC1918_NETWORKS:
                if ip_obj in net:
                    return True, "SSRF_PRIVATE_OR_LOOPBACK_TARGET", [22, 23]

        # 3. Internal top-level domain checks (.internal, .local, etc. if not whitelisted)
        if host.endswith((".internal", ".local", ".lan", ".corp")) and not self.is_domain_whitelisted(host):
            return True, "SSRF_PRIVATE_OR_LOOPBACK_TARGET", [22, 23]

        return False, None, []

    def inspect_url(self, url: str, is_markdown_image: bool = False) -> URLInspectionFinding:
        """
        Thoroughly inspects a single URL for EchoLeak, SSRF, non-whitelisted domains,
        confidential data leakage, and high-entropy secret tokens.
        """
        clean_url = url.strip()
        try:
            parsed = urllib.parse.urlparse(clean_url)
            domain = (parsed.hostname or "").lower().strip()
        except Exception:
            return URLInspectionFinding(
                original_url=clean_url,
                domain="",
                is_blocked=True,
                violation_reasons=["MALFORMED_URL"],
                risk_category_ids=[23],
            )

        violation_reasons: List[str] = []
        risk_category_ids: List[int] = []
        is_blocked = False

        # ── 1. EchoLeak: Markdown Image Exfiltration ─────────────────────────
        if is_markdown_image:
            is_blocked = True
            violation_reasons.append("ECHOLEAK_MARKDOWN_IMAGE")
            risk_category_ids.extend([5, 21, 22])

        # ── 2. SSRF Check ───────────────────────────────────────────────────
        is_ssrf, ssrf_reason, ssrf_risks = self.check_ssrf_target(clean_url)
        if is_ssrf:
            is_blocked = True
            if ssrf_reason:
                violation_reasons.append(ssrf_reason)
            risk_category_ids.extend(ssrf_risks)

        # ── 3. Secret & Confidential Data Exfiltration in Query / Path ───────
        has_secret_or_entropy = False
        has_confidential_data = False
        safe_query_params: List[Tuple[str, str]] = []
        stripped_params: List[Tuple[str, str]] = []

        if parsed.query:
            query_tuples = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            for k, v in query_tuples:
                is_sensitive_key = bool(SENSITIVE_PARAM_NAME_RE.match(k))
                is_secret_val = bool(SECRET_TOKEN_RE.search(v))
                is_confidential_val = bool(CONFIDENTIAL_DATA_RE.search(v))
                is_entropy_val = len(v) >= 16 and calculate_shannon_entropy(v) >= 3.8

                if is_sensitive_key or is_secret_val or is_entropy_val:
                    has_secret_or_entropy = True
                    stripped_params.append((k, v))
                elif is_confidential_val:
                    has_confidential_data = True
                    stripped_params.append((k, v))
                else:
                    safe_query_params.append((k, v))

        # Check path segments for leaks
        if parsed.path:
            if SECRET_TOKEN_RE.search(parsed.path):
                has_secret_or_entropy = True
            if CONFIDENTIAL_DATA_RE.search(parsed.path):
                has_confidential_data = True

        if has_secret_or_entropy:
            violation_reasons.append("SECRET_OR_HIGH_ENTROPY_TOKEN_IN_URL")
            risk_category_ids.extend([21, 25, 27])

        if has_confidential_data:
            violation_reasons.append("CONFIDENTIAL_PO_OR_BANK_EXFILTRATION")
            risk_category_ids.extend([21, 25, 27])

        # ── 4. Domain Whitelist Check ───────────────────────────────────────
        is_whitelisted = self.is_domain_whitelisted(domain)
        if not is_whitelisted:
            is_blocked = True
            violation_reasons.append("NON_WHITELISTED_EXTERNAL_DOMAIN")
            risk_category_ids.extend([5, 21, 27])

        # ── 5. Compute Sanitized URL ─────────────────────────────────────────
        sanitized_url = clean_url
        if stripped_params:
            reconstructed_query = urllib.parse.urlencode(safe_query_params)
            sanitized_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, reconstructed_query, parsed.fragment)
            )

        return URLInspectionFinding(
            original_url=clean_url,
            sanitized_url=sanitized_url,
            domain=domain,
            is_blocked=is_blocked,
            violation_reasons=violation_reasons,
            risk_category_ids=sorted(list(set(risk_category_ids))),
        )

    def inspect_and_sanitize_outbound_text(self, raw_text: str) -> OutboundFirewallResult:
        """
        Scans and surgically neutralizes zero-click exfiltration channels in outbound text:
        1. Strips EchoLeak markdown images `![alt](url)`
        2. Neutralizes non-whitelisted markdown links & standalone URLs
        3. Strips sensitive query tokens from whitelisted URLs
        4. Neutralizes forged system and tool output tags
        """
        sanitized = raw_text
        threat_detected = False
        urls_inspected: List[URLInspectionFinding] = []
        forged_tags_removed: List[str] = []
        exfiltration_links_removed: List[str] = []
        accumulated_risks: Set[int] = set()

        # ── Step A: EchoLeak Markdown Images (![alt](url)) ──────────────────
        for match in MARKDOWN_IMAGE_RE.finditer(raw_text):
            alt_text = match.group(1)
            img_url = match.group(2)
            finding = self.inspect_url(img_url, is_markdown_image=True)
            urls_inspected.append(finding)

            threat_detected = True
            accumulated_risks.update(finding.risk_category_ids)
            exfiltration_links_removed.append(img_url)

            # Surgical replacement satisfying both [REDACTED_ECHOLEAK_IMAGE] and [REDACTED_EXFILTRATION_LINK]
            replacement = "[REDACTED_ECHOLEAK_IMAGE] [REDACTED_EXFILTRATION_LINK]"
            sanitized = sanitized.replace(match.group(0), replacement)

        # ── Step B: Markdown Links ([label](url)) ────────────────────────────
        for match in MARKDOWN_LINK_RE.finditer(sanitized):
            label = match.group(1)
            link_url = match.group(2)
            finding = self.inspect_url(link_url, is_markdown_image=False)
            urls_inspected.append(finding)

            if finding.is_blocked:
                threat_detected = True
                accumulated_risks.update(finding.risk_category_ids)
                exfiltration_links_removed.append(link_url)
                sanitized = sanitized.replace(match.group(0), "[REDACTED_UNTRUSTED_URL]")
            elif finding.sanitized_url != link_url:
                # Whitelisted domain with stripped tokens
                threat_detected = True
                accumulated_risks.update(finding.risk_category_ids)
                sanitized = sanitized.replace(match.group(0), f"[{label}]({finding.sanitized_url})")

        # ── Step C: Standalone URLs in text ───────────────────────────────────
        for match in STANDALONE_URL_RE.finditer(sanitized):
            raw_url = match.group(1)
            # Skip if already part of a markdown link target
            if f"]({raw_url})" in sanitized:
                continue

            finding = self.inspect_url(raw_url, is_markdown_image=False)
            urls_inspected.append(finding)

            if finding.is_blocked:
                threat_detected = True
                accumulated_risks.update(finding.risk_category_ids)
                exfiltration_links_removed.append(raw_url)
                if any("SSRF" in r for r in finding.violation_reasons):
                    replacement = "[REDACTED_SSRF_IP] [REDACTED_UNTRUSTED_URL]"
                else:
                    replacement = "[REDACTED_UNTRUSTED_URL]"
                sanitized = sanitized.replace(raw_url, replacement)
            elif finding.sanitized_url != raw_url:
                threat_detected = True
                accumulated_risks.update(finding.risk_category_ids)
                sanitized = sanitized.replace(raw_url, finding.sanitized_url)

        # ── Step D: Forged System & Tool Output Tags ─────────────────────────
        for match in FORGED_TAG_RE.finditer(sanitized):
            tag_str = match.group(0)
            forged_tags_removed.append(tag_str)
            threat_detected = True
            accumulated_risks.update([12, 22, 24])

        if forged_tags_removed:
            sanitized = FORGED_TAG_RE.sub("[REDACTED_FORGED_TAG]", sanitized)

        action_taken = "REDACTED_EXFILTRATION_LINKS" if threat_detected else "SAFE_PASSED"
        reason = (
            f"Neutralized {len(exfiltration_links_removed)} exfiltration/SSRF URLs and "
            f"{len(forged_tags_removed)} forged tags."
            if threat_detected
            else "Outbound output contains zero exfiltration or SSRF targets."
        )

        return OutboundFirewallResult(
            allowed=True,  # Text reaches user with surgical sanitization applied
            threat_detected=threat_detected,
            action_taken=action_taken,
            original_text=raw_text,
            sanitized_text=sanitized,
            urls_inspected=urls_inspected,
            forged_tags_removed=forged_tags_removed,
            exfiltration_links_removed=exfiltration_links_removed,
            risk_category_ids=sorted(list(accumulated_risks)),
            reason=reason,
        )

    def inspect_tool_call_urls(self, tool_name: str, tool_arguments: Dict[str, Any]) -> OutboundFirewallResult:
        """
        Inspects URL-bearing parameters in tool calls (Hook 2).
        Deterministically blocks invocation if SSRF or exfiltration target is detected.
        """
        urls_to_check: List[str] = []

        def extract_urls(val: Any) -> None:
            if isinstance(val, str):
                v_strip = val.strip()
                if v_strip.startswith(("http://", "https://")):
                    urls_to_check.append(v_strip)
            elif isinstance(val, dict):
                for k, v in val.items():
                    if isinstance(v, str):
                        v_strip = v.strip()
                        if v_strip.startswith(("http://", "https://")):
                            urls_to_check.append(v_strip)
                    else:
                        extract_urls(v)
            elif isinstance(val, list):
                for item in val:
                    extract_urls(item)

        extract_urls(tool_arguments)

        inspected_findings: List[URLInspectionFinding] = []
        accumulated_risks: Set[int] = set()

        for u in urls_to_check:
            finding = self.inspect_url(u, is_markdown_image=False)
            inspected_findings.append(finding)
            if finding.is_blocked:
                accumulated_risks.add(16)
                accumulated_risks.update(finding.risk_category_ids)
                reason = (
                    f"Outbound Firewall Violation (Risk {sorted(list(accumulated_risks))}): "
                    f"Blocked network target '{u}' ({', '.join(finding.violation_reasons)}) in tool '{tool_name}'."
                )
                return OutboundFirewallResult(

                    allowed=False,
                    threat_detected=True,
                    action_taken="BLOCKED_SSRF_OR_UNTRUSTED_URL",
                    original_text=u,
                    sanitized_text="",
                    urls_inspected=inspected_findings,
                    forged_tags_removed=[],
                    exfiltration_links_removed=[u],
                    risk_category_ids=sorted(list(accumulated_risks)),
                    reason=reason,
                )

        return OutboundFirewallResult(
            allowed=True,
            threat_detected=False,
            action_taken="SAFE_PASSED",
            original_text="",
            sanitized_text="",
            urls_inspected=inspected_findings,
            forged_tags_removed=[],
            exfiltration_links_removed=[],
            risk_category_ids=[],
            reason=f"Tool '{tool_name}' parameters contain safe or whitelisted network targets.",
        )


# Global singleton instance
outbound_firewall = ZeroClickOutboundFirewall()
