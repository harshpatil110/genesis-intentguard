"""
Task 01 Verification Tests
===========================
GENESIS 2.0 | Track: EVA 03 | PS 01 — IntentGuard
Tests: Monorepo structure, environment configuration, and Settings singleton.

Run from intentguard/backend/:
    pytest tests/test_task01_config.py -v
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Make sure the backend is importable regardless of how pytest is invoked.
# ---------------------------------------------------------------------------
_BACKEND_DIR = Path(__file__).resolve().parent.parent  # intentguard/backend/
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))


# ===========================================================================
# Fixture
# ===========================================================================

@pytest.fixture(scope="module")
def cfg():
    """Import and return the Settings singleton exactly once per test module."""
    from app.config import settings as _settings
    return _settings


# ===========================================================================
# 1. Import & Basic Smoke Test
# ===========================================================================

def test_settings_import():
    """Settings singleton can be imported without raising."""
    from app.config import settings
    assert settings is not None, "settings singleton must not be None"


def test_get_settings_factory():
    """get_settings() returns the same cached object as the module-level singleton."""
    from app.config import get_settings, settings
    assert get_settings() is settings, "get_settings() must return the cached singleton"


# ===========================================================================
# 2. OpenClaw Connection URLs
# ===========================================================================

def test_openclaw_ws_url(cfg):
    """OPENCLAW_GATEWAY_WS_URL must match the default ws://127.0.0.1:18789."""
    assert cfg.OPENCLAW_GATEWAY_WS_URL == "ws://127.0.0.1:18789", (
        f"Expected 'ws://127.0.0.1:18789', got '{cfg.OPENCLAW_GATEWAY_WS_URL}'"
    )


def test_openclaw_http_url(cfg):
    """OPENCLAW_GATEWAY_HTTP_URL must be the correct HTTP endpoint."""
    assert cfg.OPENCLAW_GATEWAY_HTTP_URL == "http://127.0.0.1:18789"


# ===========================================================================
# 3. Blockchain / Fabric Configuration
# ===========================================================================

def test_blockchain_api_base_url_is_configurable(cfg):
    """BLOCKCHAIN_API_BASE_URL must be set and non-empty."""
    assert cfg.BLOCKCHAIN_API_BASE_URL, "BLOCKCHAIN_API_BASE_URL must not be empty"
    assert cfg.BLOCKCHAIN_API_BASE_URL.startswith("http"), (
        "BLOCKCHAIN_API_BASE_URL must start with http(s)"
    )


def test_blockchain_audit_events_url(cfg):
    """blockchain_audit_events_url property must end with /audit-events."""
    url = cfg.blockchain_audit_events_url
    assert url.endswith("/audit-events"), (
        f"blockchain_audit_events_url must end with '/audit-events', got: '{url}'"
    )
    # Must not have double slashes before /audit-events
    assert "//audit-events" not in url


def test_blockchain_use_mock_is_true(cfg):
    """BLOCKCHAIN_USE_MOCK must be True for standalone development (Tasks 01-24)."""
    assert cfg.BLOCKCHAIN_USE_MOCK is True, (
        "BLOCKCHAIN_USE_MOCK must be True during standalone development"
    )


def test_fabric_channel_and_chaincode(cfg):
    """Fabric channel and chaincode names must match spec."""
    assert cfg.FABRIC_CHANNEL_NAME == "intentguard"
    assert cfg.FABRIC_CHAINCODE_NAME == "intentguard"


# ===========================================================================
# 4. LLM Configuration
# ===========================================================================

def test_p_llm_model(cfg):
    """P-LLM model must be llama-3.3-70b-versatile."""
    assert cfg.P_LLM_MODEL == "llama-3.3-70b-versatile", (
        f"Expected 'llama-3.3-70b-versatile', got '{cfg.P_LLM_MODEL}'"
    )


def test_openclaw_primary_model(cfg):
    """OPENCLAW_PRIMARY_MODEL must be groq/llama-3.3-70b-versatile."""
    assert cfg.OPENCLAW_PRIMARY_MODEL == "groq/llama-3.3-70b-versatile", (
        f"Expected 'groq/llama-3.3-70b-versatile', got '{cfg.OPENCLAW_PRIMARY_MODEL}'"
    )


def test_q_llm_defaults(cfg):
    """Q-LLM defaults must point to local Ollama with qwen:3b."""
    assert cfg.Q_LLM_PROVIDER == "ollama"
    assert "11434" in cfg.Q_LLM_BASE_URL, "Q_LLM_BASE_URL must reference Ollama port 11434"
    assert cfg.Q_LLM_MODEL == "qwen:3b"
    assert cfg.Q_LLM_FALLBACK_MODEL == "llama-3.1-8b-instant"


# ===========================================================================
# 5. Security & Memory Configuration
# ===========================================================================

def test_hmac_master_secret_is_non_empty(cfg):
    """HMAC_MASTER_SECRET must be set and non-empty."""
    assert cfg.HMAC_MASTER_SECRET, "HMAC_MASTER_SECRET must not be empty"
    assert len(cfg.HMAC_MASTER_SECRET) >= 16, (
        "HMAC_MASTER_SECRET is suspiciously short — must be at least 16 chars"
    )


def test_redis_url(cfg):
    """REDIS_URL must match the expected default."""
    assert cfg.REDIS_URL == "redis://localhost:6379/0", (
        f"Expected 'redis://localhost:6379/0', got '{cfg.REDIS_URL}'"
    )


def test_memory_quarantine_ttl(cfg):
    """MEMORY_QUARANTINE_TTL_SECONDS must be a positive integer."""
    assert isinstance(cfg.MEMORY_QUARANTINE_TTL_SECONDS, int)
    assert cfg.MEMORY_QUARANTINE_TTL_SECONDS > 0


# ===========================================================================
# 6. Helper Properties
# ===========================================================================

def test_cors_origins_list(cfg):
    """cors_origins_list must return a list of non-empty strings."""
    origins = cfg.cors_origins_list
    assert isinstance(origins, list)
    assert len(origins) >= 1
    assert all(o.startswith("http") for o in origins)


def test_allowed_domains_list(cfg):
    """allowed_domains_list must include localhost and api.groq.com."""
    domains = cfg.allowed_domains_list
    assert isinstance(domains, list)
    assert "localhost" in domains
    assert "api.groq.com" in domains


def test_max_file_upload_bytes(cfg):
    """max_file_upload_bytes must equal MAX_FILE_UPLOAD_MB * 1024 * 1024."""
    expected = cfg.MAX_FILE_UPLOAD_MB * 1024 * 1024
    assert cfg.max_file_upload_bytes == expected


# ===========================================================================
# 7. Disk Structure Verification
# ===========================================================================

def _backend_app_dir() -> Path:
    """Return the intentguard/backend/app/ directory."""
    return Path(__file__).resolve().parent.parent / "app"


def test_openclaw_directory_exists():
    """./openclaw/ must exist in the monorepo root."""
    from app.config import settings
    openclaw_dir = settings.project_root / "openclaw"
    assert openclaw_dir.exists(), (
        f"openclaw directory not found at: {openclaw_dir}\n"
        "Run: git clone https://github.com/openclaw/openclaw.git openclaw"
    )
    assert openclaw_dir.is_dir()


@pytest.mark.parametrize("subpackage", [
    "openclaw_bridge",
    "layer1_decloaker",
    "layer2_camel",
    "layer3_policy",
    "layer4_sandbox",
    "blockchain_client",
])
def test_intentguard_subpackage_exists(subpackage: str):
    """All required sub-packages must exist as directories with __init__.py."""
    app_dir = _backend_app_dir()
    pkg_dir = app_dir / subpackage
    assert pkg_dir.exists(), f"Sub-package directory missing: {pkg_dir}"
    assert pkg_dir.is_dir(), f"Expected a directory at: {pkg_dir}"
    init_file = pkg_dir / "__init__.py"
    assert init_file.exists(), f"Missing __init__.py in: {pkg_dir}"


def test_env_file_exists():
    """intentguard/backend/.env must exist and be non-empty."""
    from app.config import settings
    env_path = settings.backend_dir / ".env"
    assert env_path.exists(), f".env not found at: {env_path}"
    assert env_path.stat().st_size > 0, ".env file is empty"


def test_env_example_exists():
    """Root .env.example must exist and be non-empty."""
    from app.config import settings
    env_example = settings.project_root / ".env.example"
    assert env_example.exists(), f".env.example not found at: {env_example}"
    assert env_example.stat().st_size > 0, ".env.example is empty"


def test_requirements_txt_exists():
    """intentguard/backend/requirements.txt must exist and be non-empty."""
    from app.config import settings
    req_file = settings.backend_dir / "requirements.txt"
    assert req_file.exists(), f"requirements.txt not found at: {req_file}"
    assert req_file.stat().st_size > 0, "requirements.txt is empty"


def test_config_py_exists():
    """intentguard/backend/app/config.py must exist and be non-empty."""
    config_path = _backend_app_dir() / "config.py"
    assert config_path.exists(), f"config.py not found at: {config_path}"
    assert config_path.stat().st_size > 0, "config.py is empty"


# ===========================================================================
# 8. resolved_openclaw_memory_path
# ===========================================================================

def test_resolved_openclaw_memory_path_creates_stub(cfg):
    """resolved_openclaw_memory_path must return a Path and create the stub file."""
    mem_path = cfg.resolved_openclaw_memory_path
    assert isinstance(mem_path, Path), "resolved_openclaw_memory_path must return a Path"
    assert mem_path.exists(), f"MEMORY.md stub was not created at: {mem_path}"
    assert mem_path.name == "MEMORY.md"
    assert mem_path.parent.is_dir()


# ===========================================================================
# 9. Resource Budget Sanity Checks
# ===========================================================================

def test_resource_budgets_are_positive(cfg):
    """All resource budget settings must be positive integers/floats."""
    assert cfg.MAX_REQUESTS_PER_MINUTE > 0
    assert cfg.MAX_TOOL_ITERATIONS_PER_TASK > 0
    assert cfg.MAX_FILE_UPLOAD_MB > 0
    assert cfg.MAX_EXECUTION_TIMEOUT_SECONDS > 0
    assert cfg.BLOCKCHAIN_TIMEOUT_SECONDS > 0


def test_supply_chain_party_ids(cfg):
    """Default supply-chain party IDs must be non-empty strings."""
    assert cfg.DEFAULT_BUYER_ID
    assert cfg.DEFAULT_SUPPLIER_ID
    assert cfg.DEFAULT_AUDITOR_ID
    assert cfg.DEFAULT_POLICY_REFERENCE
