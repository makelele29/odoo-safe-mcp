"""
Client for the Guard API v2 (zero-credential approvals).

What leaves this machine: licence key (as bearer), database name, the exact operation JSON and its
SHA-256, a human-readable preview and the agent's justification. Never the Odoo URL, user or API key.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

import httpx

from odoo_safe_mcp import __version__
from odoo_safe_mcp.config import Config
from odoo_safe_mcp.trust import sha256_hex


class GuardError(Exception):
    """A Guard answer the agent must be told about (licence, kill-switch, outdated client...)."""


def canonical_op_json(cfg: Config, model: str, method: str, args: Any, kwargs: Any) -> str:
    return json.dumps(
        {"db": cfg.db, "model": model, "method": method, "args": args, "kwargs": kwargs},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


_ERRORS = {
    401: "Pro Guard licence missing or invalid. Check ODOO_SAFE_GUARD_KEY or get one at https://odoosafemcp.stream/#pricing.",
    403: "Pro Guard refused the request: {error}",
    409: "Pro Guard policy mismatch: {error}",
    413: "Operation too large for an approval request. Split it into smaller batches.",
    423: "⏸️ Kill-switch active: all AI writes are paused for this licence. A human must resume them from the Guard portal.",
    426: "odoo-safe-mcp is outdated for this Guard: run `uvx --refresh odoo-safe-mcp` (or pip install --upgrade odoo-safe-mcp).",
    429: "Pro Guard rate limit reached. Wait a minute and try again.",
}


class GuardClient:
    def __init__(self, cfg: Config, client: httpx.AsyncClient):
        self.cfg = cfg
        self.client = client
        self.headers = {
            "Authorization": f"Bearer {cfg.guard_key}",
            "Content-Type": "application/json",
            "User-Agent": f"odoo-safe-mcp/{__version__}",
            "X-MCP-Version": __version__,
        }

    async def _request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        resp = await self.client.request(method, f"{self.cfg.guard_url}{path}", json=payload, headers=self.headers)
        try:
            data = resp.json()
        except ValueError:
            data = {"error": resp.text[:300]}
        if resp.status_code >= 400:
            template = _ERRORS.get(resp.status_code, "Pro Guard error (HTTP {status}): {error}")
            raise GuardError(template.format(status=resp.status_code, error=data.get("error") or data))
        return data

    async def create_intent(self, op_json: str, preview: Dict[str, Any], justification: str) -> Dict[str, Any]:
        return await self._request(
            "POST",
            "/v2/intents",
            {
                "odoo_db": self.cfg.db,
                "op_json": op_json,
                "op_sha256": sha256_hex(op_json),
                "preview": preview,
                "agent_justification": justification,
            },
        )

    async def get_intent(self, intent_id: str) -> Dict[str, Any]:
        return await self._request("GET", f"/v2/intents/{intent_id}")

    async def report_result(self, intent_id: str, outcome: str, result_sha256: str = "", detail: str = "") -> None:
        try:
            await self._request(
                "POST",
                f"/v2/intents/{intent_id}/result",
                {"outcome": outcome, "result_sha256": result_sha256, "detail": detail[:200]},
            )
        except (GuardError, httpx.HTTPError):
            pass  # execution already happened locally; the audit gap is visible as APPROVED-not-EXECUTED

    async def license(self) -> Dict[str, Any]:
        return await self._request("GET", "/v2/license")

    async def keys(self) -> Dict[str, Any]:
        return await self._request("GET", "/v2/keys")
