"""
IntentGuard Memory Quarantine Vault & Sleeper Attack Scanner
============================================================
GENESIS 2.0 | Track: EVA 03 | PS 01 | Separating Data from Authority

Phase 3 — Layer 2: Memory Quarantine Vault
------------------------------------------
Guards ./openclaw/workspace/MEMORY.md against persistent poisoning and sleeper attacks:
1. Blocks persistent file writes if the current session has ingested UNTRUSTED_EXT data.
2. Diverts tainted memory writes to a temporary Redis TTL cache (default 300 seconds).
3. Scans memory text for sleeper injection patterns ("always", "whenever", "in future",
   "change bank", "bcc", "override") to prevent delayed sleeper agent hijacks (Risks #15, #20).
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from app.config import Settings, settings as global_settings
from app.openclaw_bridge.models import MemoryWriteInterceptResponse

logger = logging.getLogger(__name__)

# Sleeper-rule injection patterns (Risks #15, #20)
_SLEEPER_PATTERNS = [
    re.compile(r"\balways\b", re.I),
    re.compile(r"\bwhenever\b", re.I),
    re.compile(r"\bin\s+future(?:\s+tasks?)?\b", re.I),
    re.compile(r"\bnext\s+time\b", re.I),
    re.compile(r"\bforward\s+to\b", re.I),
    re.compile(r"\bbcc\b", re.I),
    re.compile(r"\bchange\s+bank\b", re.I),
    re.compile(r"\bupdate\s+account\b", re.I),
    re.compile(r"\boverride\b", re.I),
    re.compile(r"\bfrom\s+now\s+on\b", re.I),
]


class MemoryQuarantineVault:
    """
    Guards OpenClaw long-term memory (MEMORY.md) from sleeper attacks and untrusted contamination.
    Routes tainted memory into Redis TTL quarantine.
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        redis_client: Optional[Any] = None,
    ):
        self.settings = settings or global_settings
        self.ttl_seconds = int(getattr(self.settings, "MEMORY_QUARANTINE_TTL_SECONDS", 300))
        self._custom_redis = redis_client
        self._redis = None
        self._fallback_memory: Dict[str, str] = {}

    def get_redis_client(self) -> Optional[Any]:
        """Returns the configured or lazily connected async Redis client."""
        if self._custom_redis is not None:
            return self._custom_redis
        if self._redis is None:
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(
                    self.settings.REDIS_URL,
                    decode_responses=True,
                )
            except Exception as exc:
                logger.warning("Failed to initialize async Redis connection (%s)", exc)
                self._redis = None
        return self._redis

    def _scan_for_sleeper_patterns(self, text: str) -> Tuple[bool, List[int], List[str]]:
        """
        Scans proposed memory text for delayed sleeper rules or persistent overrides.
        Returns: (has_sleeper, risk_category_ids, matched_patterns)
        """
        matched: List[str] = []
        for pat in _SLEEPER_PATTERNS:
            if pat.search(text):
                matched.append(pat.pattern)

        if matched:
            return True, [15, 20], matched
        return False, [], []

    async def evaluate_and_route_memory(
        self,
        session_id: str,
        proposed_content: str,
        session_tainted: bool,
        target_memory_file: str = "MEMORY.md",
        intercept_id: Optional[str] = None,
    ) -> MemoryWriteInterceptResponse:
        """
        Evaluates memory write safety and routes to Redis TTL if tainted or poisoned.
        """
        inc_id = intercept_id or f"mem-{os.urandom(4).hex()}"
        has_sleeper, sleeper_risks, sleeper_hits = self._scan_for_sleeper_patterns(proposed_content)

        threat_detected = has_sleeper
        risk_category_ids: List[int] = []

        if has_sleeper:
            risk_category_ids = [15, 20]
        elif session_tainted:
            risk_category_ids = [14]

        # Block persistent write if session ingested untrusted external data OR sleeper rules detected
        if session_tainted or has_sleeper:
            persistent_write_allowed = False
            routed_to_quarantine = True
            quarantine_key = f"intentguard:quarantine:{session_id}"
            session_mem_key = f"intentguard:session_mem:{session_id}"
            ttl = self.ttl_seconds
            action_taken = "QUARANTINED_MEMORY"

            reasons: List[str] = []
            if has_sleeper:
                reasons.append(f"Sleeper attack patterns detected: {sleeper_hits}")
            if session_tainted:
                reasons.append("Session is tainted by untrusted external data (UNTRUSTED_EXT)")
            reason = " | ".join(reasons)

            # Store in Redis TTL cache
            client = self.get_redis_client()
            if client is not None:
                try:
                    await client.setex(session_mem_key, ttl, proposed_content)
                    await client.setex(quarantine_key, ttl, proposed_content)
                except Exception as exc:
                    logger.warning("Redis setex failed (%s); storing in local fallback memory", exc)
                    self._fallback_memory[session_mem_key] = proposed_content
                    self._fallback_memory[quarantine_key] = proposed_content
            else:
                self._fallback_memory[session_mem_key] = proposed_content
                self._fallback_memory[quarantine_key] = proposed_content
        else:
            persistent_write_allowed = True
            routed_to_quarantine = False
            quarantine_key = None
            ttl = 0
            action_taken = "SAFE_EXECUTED"
            reason = "Memory write is from an untainted USER_AUTHORITY session without sleeper rules."

        return MemoryWriteInterceptResponse(
            intercept_id=inc_id,
            persistent_write_allowed=persistent_write_allowed,
            routed_to_redis_quarantine=routed_to_quarantine,
            quarantine_key=quarantine_key,
            ttl_seconds=ttl,
            action_taken=action_taken,
            threat_detected=threat_detected,
            risk_category_ids=risk_category_ids,
            reason=reason,
        )


# Global singleton instance
memory_quarantine_vault = MemoryQuarantineVault()
