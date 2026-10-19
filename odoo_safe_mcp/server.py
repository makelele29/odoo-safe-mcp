"""
Odoo Safe MCP Server.
Provides a deterministic security firewall between AI Agents and Odoo ERP.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional, Union

import httpx
from dotenv import load_dotenv

from odoo_safe_mcp.rules import (
    RiskLevel,
    RuleEvaluationResult,
    evaluate_rule,
)

# Support both mcp 2.x (MCPServer) and mcp 1.x (FastMCP)
try:
    from mcp.server.mcpserver import MCPServer
    mcp_server = MCPServer(
        name="odoo-safe-mcp",
        version="2.0.0",
        instructions="Deterministic security firewall & MCP server for Odoo ERP with Human-in-the-Loop protection.",
    )
except ImportError:
    from mcp.server.fastmcp import FastMCP
    mcp_server = FastMCP(
        "odoo-safe-mcp",
        instructions="Deterministic security firewall & MCP server for Odoo ERP with Human-in-the-Loop protection.",
    )

# Cached UIDs keyed by (url, db, username) to prevent cross-tenant UID collisions
_UID_CACHE: Dict[ tuple[str, str, str], int ] = {}


def get_config() -> Dict[str, str]:
    """Load configuration from environment variables."""
    raw_guard_url = (
        os.getenv("ODOO_GUARD_PROXY_URL")
        or os.getenv("ODOO_GUARD_URL")
        or "https://api.tudominio.com/v1/guard"
    ).strip()
    if raw_guard_url and not raw_guard_url.endswith("/v1/guard"):
        guard_url = f"{raw_guard_url.rstrip('/')}/v1/guard"
    else:
        guard_url = raw_guard_url

    return {
        "url": os.getenv("ODOO_URL", "").rstrip("/"),
        "db": os.getenv("ODOO_DB", ""),
        "username": os.getenv("ODOO_USERNAME", ""),
        "api_key": os.getenv("ODOO_API_KEY", "") or os.getenv("ODOO_PASSWORD", ""),
        "guard_key": os.getenv("ODOO_SAFE_GUARD_KEY", "").strip(),
        "guard_url": guard_url,
        "timeout": os.getenv("ODOO_TIMEOUT", "30.0"),
    }


def _normalize_list(val: Any) -> List[Any]:
    if val is None:
        return []
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        val = val.strip()
        if not val:
            return []
        try:
            parsed = json.loads(val)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            return [val]
    return [val]


def _normalize_dict(val: Any) -> Dict[str, Any]:
    if val is None:
        return {}
    if isinstance(val, dict):
        return val
    if isinstance(val, str):
        val = val.strip()
        if not val:
            return {}
        try:
            parsed = json.loads(val)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


async def _odoo_jsonrpc_call(
    client: httpx.AsyncClient,
    url: str,
    service: str,
    method: str,
    args: List[Any],
) -> Dict[str, Any]:
    """Execute a low-level JSON-RPC call against Odoo's /jsonrpc endpoint."""
    endpoint = f"{url}/jsonrpc"
    payload = {
        "jsonrpc": "2.0",
        "method": "call",
        "params": {
            "service": service,
            "method": method,
            "args": args,
        },
        "id": 1,
    }
    response = await client.post(
        endpoint,
        json=payload,
        headers={"Content-Type": "application/json"},
    )
    response.raise_for_status()
    data = response.json()
    if "error" in data:
        err = data["error"]
        msg = err.get("data", {}).get("message") or err.get("message") or str(err)
        raise RuntimeError(f"Odoo RPC Error: {msg}")
    return data


async def _get_authenticated_uid(
    client: httpx.AsyncClient,
    cfg: Dict[str, str],
) -> int:
    """Authenticate with Odoo and return user ID (UID) scoped to (url, db, username)."""
    cache_key = (cfg["url"], cfg["db"], cfg["username"])
    if cache_key in _UID_CACHE:
        return _UID_CACHE[cache_key]

    auth_response = await _odoo_jsonrpc_call(
        client=client,
        url=cfg["url"],
        service="common",
        method="authenticate",
        args=[cfg["db"], cfg["username"], cfg["api_key"], {}],
    )
    uid = auth_response.get("result")
    if not uid:
        raise PermissionError(
            f"Authentication failed for user '{cfg['username']}' on database '{cfg['db']}'."
        )
    _UID_CACHE[cache_key] = int(uid)
    return _UID_CACHE[cache_key]


async def _execute_local_odoo(
    cfg: Dict[str, str],
    model: str,
    method: str,
    args: List[Any],
    kwargs: Dict[str, Any],
) -> Any:
    """Execute permitted read call directly against Odoo JSON-RPC."""
    timeout_sec = float(cfg.get("timeout", 30.0))
    async with httpx.AsyncClient(timeout=timeout_sec) as client:
        uid = await _get_authenticated_uid(client, cfg)
        exec_response = await _odoo_jsonrpc_call(
            client=client,
            url=cfg["url"],
            service="object",
            method="execute_kw",
            args=[
                cfg["db"],
                uid,
                cfg["api_key"],
                model,
                method,
                args,
                kwargs,
            ],
        )
        return exec_response.get("result")


async def _forward_to_guard_proxy(
    cfg: Dict[str, str],
    model: str,
    method: str,
    eval_res: RuleEvaluationResult,
) -> Any:
    """Forward write/critical request to Cloudflare Worker Guard Proxy."""
    timeout_sec = float(cfg.get("timeout", 45.0))
    payload = {
        "odoo_url": cfg["url"],
        "odoo_db": cfg["db"],
        "odoo_username": cfg["username"],
        "odoo_api_key": cfg["api_key"],
        "model": model,
        "method": method,
        "args": eval_res.sanitized_args,
        "kwargs": eval_res.sanitized_kwargs,
        "risk_level": eval_res.level.value,
        "inject_chatter_note": bool(eval_res.audit_note),
        "agent_justification": eval_res.audit_note or "Operación ejecutada por Agente IA",
        "audit_note": eval_res.audit_note,
    }
    headers = {
        "Authorization": f"Bearer {cfg['guard_key']}",
        "Content-Type": "application/json",
        "User-Agent": "odoo-safe-mcp/2.0.0",
        "X-MCP-Version": "2.0.0",
    }
    async with httpx.AsyncClient(timeout=timeout_sec) as client:
        resp = await client.post(cfg["guard_url"], json=payload, headers=headers)
        if resp.status_code == 426:
            return (
                "⚠️ Version Deprecated: Your odoo-safe-mcp client version is outdated. "
                "Please run: uvx --refresh odoo-safe-mcp (or pip install --upgrade odoo-safe-mcp)."
            )
        if resp.status_code in (401, 403):
            return (
                "❌ Pro Guard License Error: Your ODOO_SAFE_GUARD_KEY is invalid, expired, "
                "or not authorized. Visit https://tudominio.com/pricing to renew or get a license."
            )
        resp.raise_for_status()
        try:
            return resp.json()
        except Exception:
            return resp.text


@mcp_server.tool()
async def odoo_execute_kw(
    model: str,
    method: str,
    args: Optional[Union[List[Any], str]] = None,
    kwargs: Optional[Union[Dict[str, Any], str]] = None,
) -> str:
    """
    Safely execute an Odoo ORM method (execute_kw) via deterministic firewall rules.

    Args:
        model: Odoo technical model name (e.g. 'sale.order', 'res.partner', 'account.move').
        method: ORM method name (e.g. 'search_read', 'read', 'create', 'unlink', 'action_post').
        args: Positional arguments (e.g. search domains, list of record IDs, or record dictionaries).
        kwargs: Keyword arguments (e.g. {'fields': ['name', 'amount_total'], 'limit': 10}).

    Returns:
        JSON string or formatted message with query results or human approval status.
    """
    cfg = get_config()

    # Normalize parameters from LLM agents
    norm_args = _normalize_list(args)
    norm_kwargs = _normalize_dict(kwargs)
    has_pro = bool(cfg.get("guard_key"))

    # 1. Evaluate safety rules & traffic light status
    eval_res = evaluate_rule(
        model=model,
        method=method,
        args=norm_args,
        kwargs=norm_kwargs,
        has_pro_license=has_pro,
    )

    # 2. Blocked or Disallowed
    if not eval_res.allowed:
        return eval_res.reason

    # 3. Safe Read (GREEN) -> Direct Local JSON-RPC Execution
    if eval_res.level == RiskLevel.GREEN:
        if not (cfg["url"] and cfg["db"] and cfg["username"] and cfg["api_key"]):
            return (
                "⚠️ Configuration Error: Missing required Odoo credentials. "
                "Please configure ODOO_URL, ODOO_DB, ODOO_USERNAME, and ODOO_API_KEY."
            )
        try:
            result = await _execute_local_odoo(
                cfg=cfg,
                model=model,
                method=method,
                args=eval_res.sanitized_args,
                kwargs=eval_res.sanitized_kwargs,
            )
            return json.dumps(result, indent=2, default=str)
        except Exception as exc:
            return f"❌ Error querying Odoo: {str(exc)}"

    # 4. Guarded Draft (YELLOW) or Critical / Destructive (RED)
    if eval_res.requires_guard_proxy:
        if not (cfg["url"] and cfg["db"] and cfg["username"] and cfg["api_key"]):
            return (
                "⚠️ Configuration Error: Missing required Odoo credentials. "
                "Please configure ODOO_URL, ODOO_DB, ODOO_USERNAME, and ODOO_API_KEY."
            )
        try:
            guard_result = await _forward_to_guard_proxy(
                cfg=cfg,
                model=model,
                method=method,
                eval_res=eval_res,
            )
            if isinstance(guard_result, (dict, list)):
                return json.dumps(guard_result, indent=2, default=str)
            return str(guard_result)
        except Exception as exc:
            return f"❌ Guard Proxy Communication Error: {str(exc)}"

    return "⚠️ Unexpected evaluation state."


def main():
    """Main entrypoint for CLI execution."""
    load_dotenv()
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ("--version", "-v"):
            from odoo_safe_mcp import __version__
            print(f"odoo-safe-mcp v{__version__}")
            return
        elif arg in ("--help", "-h"):
            print("Usage: odoo-safe-mcp")
            print("Deterministic AI Firewall and Model Context Protocol (MCP) Server for Odoo ERP.")
            print("\nEnvironment Variables:")
            print("  ODOO_URL              Odoo instance URL (e.g. https://my-company.odoo.com)")
            print("  ODOO_DB               Odoo database name")
            print("  ODOO_USERNAME         Odoo user email or login")
            print("  ODOO_API_KEY          Odoo user API key or password")
            print("  ODOO_SAFE_GUARD_KEY   Optional Pro license key for write access")
            print("  ODOO_GUARD_URL        Optional Cloudflare Worker Proxy URL")
            print("\nRun directly with Claude Desktop, Cursor, n8n, or MCP Inspector.")
            return
    mcp_server.run(transport="stdio")


if __name__ == "__main__":
    main()
