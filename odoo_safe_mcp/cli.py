"""
Command line entry point.

  odoo-safe-mcp            run the MCP server over stdio (what Claude Desktop / Cursor launch)
  odoo-safe-mcp doctor     check configuration, connectivity, permissions and Pro Guard status
  odoo-safe-mcp init       interactive setup that writes the Claude Desktop / Cursor config
  odoo-safe-mcp --version
"""

from __future__ import annotations

import asyncio
import getpass
import json
import os
import shutil
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

from dotenv import load_dotenv

from odoo_safe_mcp import __version__
from odoo_safe_mcp.config import Config, get_config, localhost_warning, sanitize_error
from odoo_safe_mcp.guard import GuardClient
from odoo_safe_mcp.odoo import OdooClient, open_client
from odoo_safe_mcp.trust import trusted_keys

OK, WARN, FAIL = "✅", "⚠️ ", "❌"
SERVER_NAME = "odoo"

USAGE = f"""odoo-safe-mcp v{__version__} — AI firewall & MCP server for Odoo ERP

Usage:
  odoo-safe-mcp           Run the MCP server (stdio)
  odoo-safe-mcp doctor    Diagnose configuration, Odoo access and Pro Guard
  odoo-safe-mcp init      Guided setup for Claude Desktop / Cursor
  odoo-safe-mcp --version

Environment:
  ODOO_URL, ODOO_DB, ODOO_USERNAME, ODOO_API_KEY   Odoo access (use a least-privilege bot user)
  ODOO_DRY_RUN=true                                Simulate writes, never touch Odoo
  ODOO_SAFE_GUARD_KEY                              Pro Guard licence (approvals, audit, kill-switch)
  ODOO_APPROVAL_WAIT_SECONDS                       Wait inline for an approval (default 25)
  ODOO_GUARD_URL, ODOO_GUARD_PUBLIC_KEYS           Self-hosted Guard only
"""


def _print(line: str = "") -> None:
    try:
        print(line)
    except UnicodeEncodeError:  # legacy Windows consoles
        print(line.encode("ascii", "replace").decode("ascii"))


# --- doctor -----------------------------------------------------------------------------------------

async def run_doctor(cfg: Config) -> int:
    failures = 0

    def report(status: str, text: str) -> None:
        nonlocal failures
        if status == FAIL:
            failures += 1
        _print(f"{status} {text}")

    _print(f"odoo-safe-mcp v{__version__} — doctor\n")
    missing = [name for name, value in (("ODOO_URL", cfg.url), ("ODOO_DB", cfg.db), ("ODOO_USERNAME", cfg.username), ("ODOO_API_KEY", cfg.api_key)) if not value]
    if missing:
        report(FAIL, f"Missing configuration: {', '.join(missing)}")
        return 1
    report(OK, f"Config: {cfg.url} · db '{cfg.db}' · user '{cfg.username}'")
    warning = localhost_warning(cfg.url)
    if warning:
        report(WARN, warning)

    async with open_client(cfg) as client:
        odoo = OdooClient(cfg, client)
        try:
            start = time.perf_counter()
            info = await odoo.version()
            report(OK, f"Odoo {info.get('server_version')} reachable ({(time.perf_counter() - start) * 1000:.0f} ms)")
        except Exception as exc:
            report(FAIL, f"Cannot reach Odoo at {cfg.url}: {sanitize_error(str(exc), cfg)}")
            return failures
        try:
            uid = await odoo.uid()
            report(OK, f"Authenticated as uid {uid}")
        except Exception as exc:
            report(FAIL, f"Authentication failed: {sanitize_error(str(exc), cfg)}")
            major = (info.get("server_version_info") or [0])[0]
            if isinstance(major, int) and major >= 20:
                report(WARN, "Odoo 20+ only accepts API keys with the RPC scope over RPC: create the key with scope 'RPC' (an MCP-scoped key will not work).")
            return failures
        try:
            me = await odoo.execute("res.users", "read", [[uid]], {"fields": ["email"]})
            if me and me[0].get("email"):
                report(OK, "AI user has an email (needed for Chatter audit notes)")
            else:
                report(WARN, "AI user has no email: Odoo will refuse the Chatter audit notes. Set one in Settings → Users.")
        except Exception:
            pass
        try:
            await odoo.execute("ir.config_parameter", "search_count", [[]], {})
            report(WARN, "This user can read system parameters (administrator rights). Create a dedicated bot user with only the business rights the agent needs.")
        except Exception:
            report(OK, "Least privilege: the user cannot read system parameters")

        if cfg.dry_run:
            report(OK, "Dry-run active: writes are simulated, Odoo is never modified")
        if not cfg.has_pro:
            report(OK, "Community tier: read-only (set ODOO_SAFE_GUARD_KEY for approvals and audit)")
        else:
            guard = GuardClient(cfg, client)
            try:
                lic = await guard.license()
                report(OK, f"Pro Guard: plan {lic.get('plan')} · {len(lic.get('databases') or [])}/{lic.get('max_databases')} databases")
                channels = [name for name, on in (lic.get("approval_channels") or {}).items() if on]
                report(OK if channels else FAIL, f"Approval channels: {', '.join(channels) or 'none — connect Slack or Teams in the portal'}")
                if lic.get("writes_paused"):
                    report(WARN, "Kill-switch is ON: all AI writes are paused")
            except Exception as exc:
                report(FAIL, f"Pro Guard: {sanitize_error(str(exc), cfg)}")
            pinned = trusted_keys()
            try:
                published = {k["kid"]: k["public_key"] for k in (await guard.keys()).get("keys", [])}
                matching = [kid for kid, key in published.items() if pinned.get(kid) == key]
                report(OK if matching else FAIL, "Guard signing key verified" if matching else "Guard signing key does not match the keys pinned in this client: approvals will be refused")
            except Exception as exc:
                report(FAIL, f"Could not fetch Guard signing keys: {sanitize_error(str(exc), cfg)}")

    try:
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        probe = cfg.state_dir / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        report(OK, f"State directory writable: {cfg.state_dir}")
    except OSError as exc:
        report(FAIL, f"State directory not writable ({cfg.state_dir}): {exc}")

    _print("\nAll checks passed." if not failures else f"\n{failures} check(s) failed.")
    return 1 if failures else 0


# --- init -------------------------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """Strip trailing slashes and replace localhost by 127.0.0.1 (20x faster on Windows)."""
    parsed = urlparse(url.strip().rstrip("/"))
    if (parsed.hostname or "").lower() == "localhost":
        netloc = "127.0.0.1" + (f":{parsed.port}" if parsed.port else "")
        parsed = parsed._replace(netloc=netloc)
    return urlunparse(parsed)


def client_config_paths() -> Dict[str, Path]:
    home = Path.home()
    if sys.platform == "win32":
        claude = Path(os.getenv("APPDATA", home / "AppData" / "Roaming")) / "Claude" / "claude_desktop_config.json"
    elif sys.platform == "darwin":
        claude = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    else:
        claude = home / ".config" / "Claude" / "claude_desktop_config.json"
    return {"Claude Desktop": claude, "Cursor": home / ".cursor" / "mcp.json"}


def server_entry(env: Dict[str, str]) -> Dict[str, Any]:
    return {"command": "uvx", "args": [f"odoo-safe-mcp@{__version__}"], "env": {k: v for k, v in env.items() if v}}


def merge_mcp_config(existing: Dict[str, Any], name: str, entry: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(existing or {})
    servers = dict(merged.get("mcpServers") or {})
    servers[name] = entry
    merged["mcpServers"] = servers
    return merged


def write_client_config(path: Path, name: str, entry: Dict[str, Any]) -> Optional[Path]:
    """Merge our server into an MCP client config, keeping a timestamped backup. Returns the backup path."""
    existing: Dict[str, Any] = {}
    backup = None
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8") or "{}")
        backup = path.with_name(f"{path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(path, backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(merge_mcp_config(existing, name, entry), indent=2, ensure_ascii=False), encoding="utf-8")
    return backup


def run_init(ask: Callable[[str], str] = input, ask_secret: Callable[[str], str] = getpass.getpass) -> int:
    _print(f"odoo-safe-mcp v{__version__} — setup\n")
    _print("Tip: create a dedicated Odoo user for the AI (e.g. 'ai-bot') with only the rights it needs,")
    _print("then generate an API key for it in Preferences → Account Security.\n")
    env = {
        "ODOO_URL": normalize_url(ask("Odoo URL (e.g. https://mycompany.odoo.com): ")),
        "ODOO_DB": ask("Database name: ").strip(),
        "ODOO_USERNAME": ask("Login of the AI user: ").strip(),
        "ODOO_API_KEY": ask_secret("API key (hidden): ").strip(),
        "ODOO_SAFE_GUARD_KEY": ask_secret("Pro Guard licence (optional, Enter to skip): ").strip(),
    }
    cfg = replace(get_config(), url=env["ODOO_URL"], db=env["ODOO_DB"], username=env["ODOO_USERNAME"], api_key=env["ODOO_API_KEY"], guard_key=env["ODOO_SAFE_GUARD_KEY"])
    _print("")
    if asyncio.run(run_doctor(cfg)) and ask("\nSome checks failed. Save the configuration anyway? [y/N] ").strip().lower() != "y":
        return 1

    entry = server_entry(env)
    _print("")
    for client, path in client_config_paths().items():
        if ask(f"Add to {client} ({path})? [Y/n] ").strip().lower() in ("", "y", "yes", "s", "si", "sí"):
            backup = write_client_config(path, SERVER_NAME, entry)
            _print(f"{OK} {client} configured" + (f" (backup: {backup.name})" if backup else ""))
    _print("\nRestart your AI client and ask: \"How many customers do we have in Odoo?\"")
    return 0


# --- main -------------------------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> None:
    load_dotenv()
    argv = sys.argv[1:] if argv is None else argv
    command = argv[0].lower() if argv else ""
    if command in ("--version", "-v", "version"):
        _print(f"odoo-safe-mcp v{__version__}")
        return
    if command in ("--help", "-h", "help"):
        _print(USAGE)
        return
    if command == "doctor":
        sys.exit(asyncio.run(run_doctor(get_config())))
    if command == "init":
        sys.exit(run_init())
    if command:
        _print(USAGE)
        sys.exit(2)

    from odoo_safe_mcp.server import mcp_server

    mcp_server.run(transport="stdio")


if __name__ == "__main__":  # pragma: no cover
    main()
