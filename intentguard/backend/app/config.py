"""
IntentGuard Configuration Module
=================================
GENESIS 2.0 | Track: EVA 03 | PS 01
Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection

All runtime configuration is loaded from environment variables (intentguard/backend/.env
or root .env.example). Zero machine-specific addresses are hardcoded here.

Usage:
    from app.config import settings          # singleton — preferred
    from app.config import get_settings      # callable — use inside FastAPI Depends
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# Attempt to import pydantic-settings (preferred); fall back to plain Pydantic
# + os.getenv so the module still works in minimal environments.
# ---------------------------------------------------------------------------
try:
    from pydantic_settings import BaseSettings, SettingsConfigDict

    _USE_PYDANTIC_SETTINGS = True
except ImportError:  # pragma: no cover
    from pydantic import BaseModel as BaseSettings  # type: ignore[assignment]

    SettingsConfigDict = None  # type: ignore[assignment,misc]
    _USE_PYDANTIC_SETTINGS = False


# ---------------------------------------------------------------------------
# Resolve the project root (two levels up from this file: app/ -> backend/ -> intentguard/)
# We also accept an explicit PROJECT_ROOT env var for CI / Docker overrides.
# ---------------------------------------------------------------------------
_THIS_FILE = Path(__file__).resolve()
_APP_DIR = _THIS_FILE.parent           # intentguard/backend/app/
_BACKEND_DIR = _APP_DIR.parent         # intentguard/backend/
_INTENTGUARD_DIR = _BACKEND_DIR.parent # intentguard/
_PROJECT_ROOT = _INTENTGUARD_DIR.parent  # genesis-intentguard/  (monorepo root)


class Settings(BaseSettings):
    """
    Strongly-typed, environment-backed configuration for all 4 IntentGuard layers.

    Loading priority (pydantic-settings):
      1. Environment variables (highest priority)
      2. .env file at BACKEND_DIR/.env
      3. Field default values (lowest priority)
    """

    # ------------------------------------------------------------------
    # Application identity
    # ------------------------------------------------------------------
    APP_NAME: str = "IntentGuard-Hidden-Security-Agent"
    APP_ENV: str = "development"
    INTENTGUARD_HOST: str = "0.0.0.0"
    INTENTGUARD_PORT: int = 8000

    # Comma-separated list; use cors_origins_list property for List[str]
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    # ------------------------------------------------------------------
    # OpenClaw Base Agent connection (Subfolder 1)
    # ------------------------------------------------------------------
    OPENCLAW_GATEWAY_WS_URL: str = "ws://127.0.0.1:18789"
    OPENCLAW_GATEWAY_HTTP_URL: str = "http://127.0.0.1:18789"
    OPENCLAW_WORKSPACE_DIR: str = "openclaw/workspace"
    OPENCLAW_MEMORY_FILE: str = "openclaw/workspace/MEMORY.md"

    # ------------------------------------------------------------------
    # Layer 2: CaMeL Dual-LLM Engine
    # P-LLM = Control Plane (Privileged Planner) — groq, zero raw-data access
    # Q-LLM = Data Plane  (Quarantined Reader)  — ollama/qwen, zero tool access
    # ------------------------------------------------------------------
    # P-LLM (Control Plane)
    P_LLM_PROVIDER: str = "groq"
    P_LLM_BASE_URL: str = "https://api.groq.com/openai/v1"
    P_LLM_MODEL: str = "llama-3.3-70b-versatile"
    OPENCLAW_PRIMARY_MODEL: str = "groq/llama-3.3-70b-versatile"
    GROQ_API_KEY: str = ""

    # Q-LLM (Data Plane)
    Q_LLM_PROVIDER: str = "ollama"
    Q_LLM_BASE_URL: str = "http://localhost:11434/v1"
    Q_LLM_API_KEY: str = "ollama-local"
    Q_LLM_MODEL: str = "qwen:3b"
    Q_LLM_FALLBACK_MODEL: str = "llama-3.1-8b-instant"

    # ------------------------------------------------------------------
    # Layer 2: Memory Quarantine Vault (Redis TTL)
    # ------------------------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"
    MEMORY_QUARANTINE_TTL_SECONDS: int = 300

    # ------------------------------------------------------------------
    # Layer 3: Step-0 HMAC Intent Lock & Resource Budgets
    # ------------------------------------------------------------------
    HMAC_MASTER_SECRET: str = "genesis2_eva03_ps01_intentguard_hmac_sha256_master_secret_2026"
    MAX_REQUESTS_PER_MINUTE: int = 30
    MAX_TOOL_ITERATIONS_PER_TASK: int = 8
    MAX_FILE_UPLOAD_MB: int = 15
    MAX_EXECUTION_TIMEOUT_SECONDS: int = 45

    # Comma-separated; use allowed_domains_list property for List[str]
    ALLOWED_OUTBOUND_DOMAINS: str = "localhost,127.0.0.1,api.groq.com"

    # ------------------------------------------------------------------
    # Supply-Chain default party identifiers
    # ------------------------------------------------------------------
    DEFAULT_BUYER_ID: str = "buyer-01"
    DEFAULT_SUPPLIER_ID: str = "supplier-01"
    DEFAULT_AUDITOR_ID: str = "auditor-01"
    DEFAULT_POLICY_REFERENCE: str = "policy-v1"

    # ------------------------------------------------------------------
    # Layer 4: Hyperledger Fabric 2.5.16 HTTP Gateway
    # BLOCKCHAIN_USE_MOCK=true  → mock responses (Tasks 01-24, standalone dev)
    # BLOCKCHAIN_USE_MOCK=false → live WSL2 Fabric Gateway API
    # ------------------------------------------------------------------
    BLOCKCHAIN_API_BASE_URL: str = "http://localhost:8200"
    BLOCKCHAIN_API_KEY: str = "intentguard-fabric-gateway-dev-key-2026"
    BLOCKCHAIN_USE_MOCK: bool = True
    BLOCKCHAIN_TIMEOUT_SECONDS: float = 10.0
    FABRIC_CHANNEL_NAME: str = "intentguard"
    FABRIC_CHAINCODE_NAME: str = "intentguard"

    # ------------------------------------------------------------------
    # pydantic-settings model config
    # ------------------------------------------------------------------
    if _USE_PYDANTIC_SETTINGS:
        model_config = SettingsConfigDict(
            # Look for .env in the backend directory first, then fall back
            # to the monorepo root .env.example
            env_file=[
                str(_BACKEND_DIR / ".env"),
                str(_PROJECT_ROOT / ".env.example"),
            ],
            env_file_encoding="utf-8",
            case_sensitive=True,
            extra="ignore",  # silently ignore extra env vars
        )

    # ==================================================================
    # Helper properties
    # ==================================================================

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse comma-separated CORS_ORIGINS into a clean list of strings."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def allowed_domains_list(self) -> List[str]:
        """Parse comma-separated ALLOWED_OUTBOUND_DOMAINS into a list."""
        return [d.strip() for d in self.ALLOWED_OUTBOUND_DOMAINS.split(",") if d.strip()]

    @property
    def blockchain_audit_events_url(self) -> str:
        """Full URL to the Fabric Gateway audit-events endpoint."""
        return f"{self.BLOCKCHAIN_API_BASE_URL.rstrip('/')}/audit-events"

    @property
    def resolved_openclaw_memory_path(self) -> Path:
        """
        Safely resolve the absolute path to ./openclaw/workspace/MEMORY.md.

        Resolution strategy:
          1. If OPENCLAW_MEMORY_FILE is an absolute path, use it directly.
          2. If it starts with ../ segments, resolve relative to _BACKEND_DIR
             (backward-compatible with legacy env values like ../../openclaw/...).
          3. Otherwise treat as relative to the monorepo project root (_PROJECT_ROOT).

        Creates the parent directory and an empty MEMORY.md stub if they
        do not yet exist, so the Memory Quarantine Vault always has a
        valid target file on first boot.
        """
        mem_file_str = self.OPENCLAW_MEMORY_FILE.strip()
        mem_file = Path(mem_file_str)

        if mem_file.is_absolute():
            resolved = mem_file.resolve()
        elif mem_file_str.startswith(".."):
            # Legacy relative path (e.g. ../../openclaw/workspace/MEMORY.md)
            # was designed to be resolved from backend/; honour that.
            resolved = (_BACKEND_DIR / mem_file).resolve()
        else:
            # Modern project-root-relative path (e.g. openclaw/workspace/MEMORY.md)
            resolved = (_PROJECT_ROOT / mem_file).resolve()

        # Ensure the directory and stub file exist
        resolved.parent.mkdir(parents=True, exist_ok=True)
        if not resolved.exists():
            resolved.write_text(
                "# OpenClaw Agent Memory\n"
                "# Managed by IntentGuard Memory Quarantine Vault (Layer 2)\n"
                "# Auto-generated stub — populated at runtime.\n",
                encoding="utf-8",
            )
        return resolved

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    @property
    def project_root(self) -> Path:
        """Absolute path to the monorepo root."""
        return _PROJECT_ROOT

    @property
    def backend_dir(self) -> Path:
        """Absolute path to intentguard/backend/."""
        return _BACKEND_DIR

    @property
    def is_development(self) -> bool:
        return self.APP_ENV.lower() == "development"

    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower() == "production"

    @property
    def max_file_upload_bytes(self) -> int:
        """MAX_FILE_UPLOAD_MB converted to bytes."""
        return self.MAX_FILE_UPLOAD_MB * 1024 * 1024


# ---------------------------------------------------------------------------
# Fallback: if pydantic-settings is not installed, load from os.environ
# manually so the module still imports cleanly.
# ---------------------------------------------------------------------------
if not _USE_PYDANTIC_SETTINGS:  # pragma: no cover

    def _load_dotenv_manually(env_path: Path) -> None:
        """Minimal dotenv loader for environments without python-dotenv."""
        if not env_path.exists():
            return
        with open(env_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value

    _load_dotenv_manually(_BACKEND_DIR / ".env")
    _load_dotenv_manually(_PROJECT_ROOT / ".env.example")


# ---------------------------------------------------------------------------
# Cached singleton factory — use inside FastAPI Depends() or import directly.
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the cached Settings singleton.

    Example (FastAPI dependency injection)::

        from fastapi import Depends
        from app.config import get_settings, Settings

        @router.get("/status")
        def status(cfg: Settings = Depends(get_settings)):
            return {"app": cfg.APP_NAME}
    """
    return Settings()


# ---------------------------------------------------------------------------
# Module-level singleton — import directly for non-DI usage.
# ---------------------------------------------------------------------------
settings: Settings = get_settings()
