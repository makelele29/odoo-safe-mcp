"""Configuration loaded from environment variables (set in the MCP client config or a .env file)."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_GUARD_URL = "https://odoosafemcp.stream"


def _guard_base_url(raw: str) -> str:
    """Accept both the base URL and the legacy '.../v1/guard' endpoint."""
    url = (raw or DEFAULT_GUARD_URL).strip().rstrip("/")
    for suffix in ("/v1/guard", "/v1", "/v2"):
        if url.endswith(suffix):
            url = url[: -len(suffix)]
    return url


@dataclass(frozen=True)
class Config:
    url: str
    db: str
    username: str
    api_key: str
    guard_key: str
    guard_url: str
    timeout: float
    dry_run: bool
    approval_wait: float
    state_dir: Path

    @property
    def has_credentials(self) -> bool:
        return bool(self.url and self.db and self.username and self.api_key)

    @property
    def has_pro(self) -> bool:
        return bool(self.guard_key)

    def get(self, key: str, default=None):
        """dict-style access kept for backward compatibility with 2.x helpers."""
        return getattr(self, key, default)

    def __getitem__(self, key: str):
        return getattr(self, key)


def localhost_warning(url: str) -> str | None:
    """On Windows 'localhost' resolves to IPv6 first: measured ~21 s per call vs ~1 s with 127.0.0.1."""
    host = (urlparse(url).hostname or "").lower()
    if host == "localhost" and sys.platform == "win32":
        return (
            "ODOO_URL uses 'localhost': on Windows each call can take ~20 s (IPv6 fallback). "
            "Use http://127.0.0.1:<port> instead."
        )
    return None


def get_config() -> Config:
    try:
        timeout = float(os.getenv("ODOO_TIMEOUT", "30") or 30)
    except ValueError:
        timeout = 30.0
    try:
        approval_wait = float(os.getenv("ODOO_APPROVAL_WAIT_SECONDS", "25") or 0)
    except ValueError:
        approval_wait = 25.0
    state_dir = Path(os.getenv("ODOO_SAFE_STATE_DIR") or Path.home() / ".odoo-safe-mcp")
    return Config(
        url=os.getenv("ODOO_URL", "").strip().rstrip("/"),
        db=os.getenv("ODOO_DB", "").strip(),
        username=os.getenv("ODOO_USERNAME", "").strip(),
        api_key=os.getenv("ODOO_API_KEY", "") or os.getenv("ODOO_PASSWORD", ""),
        guard_key=os.getenv("ODOO_SAFE_GUARD_KEY", "").strip(),
        guard_url=_guard_base_url(os.getenv("ODOO_GUARD_PROXY_URL") or os.getenv("ODOO_GUARD_URL") or ""),
        timeout=timeout,
        dry_run=os.getenv("ODOO_DRY_RUN", "").strip().lower() in ("1", "true", "yes"),
        approval_wait=max(0.0, min(approval_wait, 120.0)),
        state_dir=state_dir,
    )


def sanitize_error(msg: str, cfg: Config) -> str:
    """Scrub API keys or licence tokens from error strings before they reach the LLM."""
    sanitized = str(msg)
    for secret in (cfg.api_key, cfg.guard_key):
        secret = (secret or "").strip()
        if secret and len(secret) >= 4:
            sanitized = sanitized.replace(secret, "[REDACTED_SECRET]")
    return sanitized
