"""
Protocol-level tests: drive the server through a real in-memory MCP client, as Claude/Cursor would.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest

Client = pytest.importorskip("mcp.client.client").Client

from odoo_safe_mcp.server import mcp_server


def _input_schema(tool):
    return getattr(tool, "input_schema", None) or getattr(tool, "inputSchema")


def _text(result) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


@pytest.mark.asyncio
async def test_lists_execute_kw_tool_with_expected_schema():
    async with Client(mcp_server) as client:
        tools = (await client.list_tools()).tools
    names = [tool.name for tool in tools]
    assert "odoo_execute_kw" in names
    schema = _input_schema(next(t for t in tools if t.name == "odoo_execute_kw"))
    assert {"model", "method", "args", "kwargs"} <= set(schema["properties"])
    assert set(schema.get("required", [])) == {"model", "method"}


@pytest.mark.asyncio
async def test_curated_tools_are_listed_with_annotations():
    async with Client(mcp_server) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    for name in ("odoo_search", "odoo_read", "odoo_count", "odoo_aggregate", "odoo_describe_model", "odoo_list_models"):
        hints = tools[name].annotations
        assert hints and (getattr(hints, "read_only_hint", None) or getattr(hints, "readOnlyHint", None)), name
    for name in ("odoo_execute_kw", "odoo_approval_status"):
        hints = tools[name].annotations
        assert hints and (getattr(hints, "destructive_hint", None) or getattr(hints, "destructiveHint", None)), name


@pytest.mark.asyncio
async def test_forbidden_model_is_blocked_end_to_end(monkeypatch):
    monkeypatch.setenv("ODOO_SAFE_GUARD_KEY", "pro_key")
    async with Client(mcp_server) as client:
        result = await client.call_tool("odoo_execute_kw", {"model": "res.users.apikeys", "method": "search_read"})
    assert "SECURITY ALERT" in _text(result)
    assert getattr(result, "is_error", None) or getattr(result, "isError", None)


@pytest.mark.asyncio
async def test_llm_stringified_arguments_are_accepted(monkeypatch):
    monkeypatch.setenv("ODOO_URL", "https://example.odoo.com")
    monkeypatch.setenv("ODOO_DB", "demo")
    monkeypatch.setenv("ODOO_USERNAME", "bot")
    monkeypatch.setenv("ODOO_API_KEY", "secret")
    monkeypatch.delenv("ODOO_DRY_RUN", raising=False)
    with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = [{"id": 1, "name": "Azure Interior"}]
        async with Client(mcp_server) as client:
            result = await client.call_tool(
                "odoo_execute_kw",
                {
                    "model": "res.partner",
                    "method": "search_read",
                    "args": '[[["is_company", "=", true]]]',
                    "kwargs": '{"fields": ["name", "access_token"], "limit": 1}',
                },
            )
    assert json.loads(_text(result)) == [{"id": 1, "name": "Azure Interior"}]
    sent_kwargs = mock_exec.call_args.args[4]
    assert sent_kwargs == {"fields": ["name"], "limit": 1}


@pytest.mark.asyncio
async def test_dry_run_never_touches_odoo(monkeypatch):
    monkeypatch.setenv("ODOO_DRY_RUN", "true")
    with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock) as mock_exec, patch(
        "odoo_safe_mcp.server._guarded_write", new_callable=AsyncMock
    ) as mock_guard:
        async with Client(mcp_server) as client:
            result = await client.call_tool(
                "odoo_execute_kw", {"model": "account.move", "method": "action_post", "args": [[7]]}
            )
    data = json.loads(_text(result))
    assert data["status"] == "DRY_RUN_SIMULATION" and data["risk_level"] == "RED"
    mock_exec.assert_not_called()
    mock_guard.assert_not_called()
