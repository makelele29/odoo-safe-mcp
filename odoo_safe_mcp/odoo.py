"""Thin async JSON-RPC client for Odoo 14 → 20, with cross-version compatibility shims."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import httpx

from odoo_safe_mcp.config import Config

# Cached UIDs keyed by (url, db, username) to prevent cross-tenant UID collisions
_UID_CACHE: Dict[Tuple[str, str, str], int] = {}


class OdooRPCError(RuntimeError):
    pass


async def jsonrpc(client: httpx.AsyncClient, url: str, service: str, method: str, args: List[Any]) -> Any:
    response = await client.post(
        f"{url}/jsonrpc",
        json={"jsonrpc": "2.0", "method": "call", "params": {"service": service, "method": method, "args": args}, "id": 1},
        headers={"Content-Type": "application/json"},
    )
    response.raise_for_status()
    data = response.json()
    if "error" in data:
        err = data["error"]
        msg = (err.get("data") or {}).get("message") or err.get("message") or str(err)
        raise OdooRPCError(f"Odoo RPC Error: {msg}")
    return data.get("result")


def legacy_read_group_kwargs(args: List[Any], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Map the Odoo ≤19 read_group signature onto Odoo 20's formatted_read_group."""
    domain = kwargs.get("domain", args[0] if args else [])
    fields = kwargs.get("fields", args[1] if len(args) > 1 else [])
    groupby = kwargs.get("groupby", args[2] if len(args) > 2 else [])
    groupby = [groupby] if isinstance(groupby, str) else list(groupby or [])
    # Odoo 20 only accepts explicit 'field:aggregator' specs; plain names were implicit sums before.
    aggregates = [f for f in fields or [] if isinstance(f, str) and ":" in f]
    if "__count" not in aggregates:
        aggregates.append("__count")
    new_kwargs: Dict[str, Any] = {"domain": domain, "groupby": groupby, "aggregates": aggregates}
    for old, new in (("offset", "offset"), ("limit", "limit"), ("orderby", "order"), ("order", "order")):
        if kwargs.get(old):
            new_kwargs[new] = kwargs[old]
    return new_kwargs


class OdooClient:
    """Executes ORM calls with the user's own credentials. Never used for anything the firewall rejected."""

    def __init__(self, cfg: Config, client: httpx.AsyncClient):
        self.cfg = cfg
        self.client = client

    async def uid(self) -> int:
        key = (self.cfg.url, self.cfg.db, self.cfg.username)
        if key not in _UID_CACHE:
            uid = await jsonrpc(self.client, self.cfg.url, "common", "authenticate", [self.cfg.db, self.cfg.username, self.cfg.api_key, {}])
            if not uid:
                raise PermissionError(f"Authentication failed for user '{self.cfg.username}' on database '{self.cfg.db}'.")
            _UID_CACHE[key] = int(uid)
        return _UID_CACHE[key]

    async def version(self) -> Dict[str, Any]:
        return await jsonrpc(self.client, self.cfg.url, "common", "version", [])

    async def execute(self, model: str, method: str, args: List[Any], kwargs: Dict[str, Any]) -> Any:
        uid = await self.uid()
        call = [self.cfg.db, uid, self.cfg.api_key, model, method, args, kwargs]
        try:
            return await jsonrpc(self.client, self.cfg.url, "object", "execute_kw", call)
        except OdooRPCError as exc:
            # name_get was removed in Odoo 17: emulate it with display_name so agents keep working.
            if method == "name_get" and "does not exist" in str(exc) and args:
                rows = await self.execute(model, "read", [args[0]], {"fields": ["display_name"]})
                return [[row["id"], row.get("display_name")] for row in rows or []]
            # Odoo 20 replaced read_group(domain, fields, groupby, ...) by read_group(domain, groupby, aggregates)
            # returning tuples (verified on 20.0): translate to formatted_read_group, which still returns dicts.
            if method == "read_group" and "unexpected keyword argument" in str(exc):
                return await self.execute(model, "formatted_read_group", [], legacy_read_group_kwargs(args, kwargs))
            raise

    async def post_note(self, model: str, record_id: int, html: str) -> bool:
        """Chatter note. Odoo 17+ escapes HTML sent over RPC unless body_is_html=True (verified on 18)."""
        base = {"body": html, "message_type": "comment", "subtype_xmlid": "mail.mt_note"}
        for extra in ({"body_is_html": True}, {}):
            try:
                await self.execute(model, "message_post", [[record_id]], {**base, **extra})
                return True
            except Exception:
                continue
        return False


def open_client(cfg: Config) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=cfg.timeout)
