"""
Tests for odoo_safe_mcp/server.py and MCP tool execution.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest

from odoo_safe_mcp.server import (
    OdooSafeError,
    _normalize_dict,
    _normalize_list,
    odoo_count,
    odoo_describe_model,
    odoo_execute_kw,
    odoo_search,
)

from .conftest import call_text


class TestParameterNormalization:
    def test_normalize_list_formats(self):
        assert _normalize_list(None) == []
        assert _normalize_list([1, 2, 3]) == [1, 2, 3]
        assert _normalize_list("[1, 2, 3]") == [1, 2, 3]
        assert _normalize_list("single_string") == ["single_string"]

    def test_normalize_dict_formats(self):
        assert _normalize_dict(None) == {}
        assert _normalize_dict({"key": "val"}) == {"key": "val"}
        assert _normalize_dict('{"key": "val"}') == {"key": "val"}
        assert _normalize_dict("invalid") == {}


@pytest.fixture
def free_env(monkeypatch):
    monkeypatch.setenv("ODOO_URL", "https://example.odoo.com")
    monkeypatch.setenv("ODOO_DB", "demo")
    monkeypatch.setenv("ODOO_USERNAME", "admin")
    monkeypatch.setenv("ODOO_API_KEY", "secret")
    monkeypatch.delenv("ODOO_SAFE_GUARD_KEY", raising=False)
    monkeypatch.delenv("ODOO_DRY_RUN", raising=False)


@pytest.mark.asyncio
class TestServerExecutionKW:
    async def test_free_tier_blocks_mutation(self, free_env):
        with pytest.raises(OdooSafeError) as err:
            await odoo_execute_kw(model="sale.order", method="create", args=[{"partner_id": 1}])
        assert "Strict Read-Only Mode" in str(err.value)
        assert "odoosafemcp.stream/#pricing" in str(err.value)

    async def test_blacklisted_model_always_blocked(self, monkeypatch):
        monkeypatch.setenv("ODOO_SAFE_GUARD_KEY", "pro_guard_license_key")
        res = await call_text(odoo_execute_kw(model="res.users", method="unlink", args=[[1]]))
        assert "SECURITY ALERT" in res

    async def test_missing_credentials_detected(self, monkeypatch):
        for name in ("ODOO_URL", "ODOO_DB", "ODOO_USERNAME", "ODOO_API_KEY", "ODOO_SAFE_GUARD_KEY", "ODOO_DRY_RUN"):
            monkeypatch.delenv(name, raising=False)
        res = await call_text(odoo_execute_kw(model="res.partner", method="search_read", args=[[]]))
        assert "Configuration Error" in res

    async def test_green_read_executes_jsonrpc(self, free_env):
        with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = [{"id": 1, "name": "Test Partner"}]
            res = await odoo_execute_kw(model="res.partner", method="search_read", args=[[]], kwargs={"fields": ["name"]})
        assert json.loads(res) == [{"id": 1, "name": "Test Partner"}]
        mock_exec.assert_called_once()

    async def test_dry_run_mode_simulates_mutations(self, monkeypatch):
        monkeypatch.setenv("ODOO_DRY_RUN", "true")
        monkeypatch.delenv("ODOO_SAFE_GUARD_KEY", raising=False)
        data = json.loads(await odoo_execute_kw(model="sale.order", method="create", args=[{"partner_id": 1, "state": "sale"}]))
        assert data["status"] == "DRY_RUN_SIMULATION"
        assert data["executed_in_odoo"] is False
        assert data["risk_level"] == "YELLOW"
        assert data["sanitized_args"][0]["state"] == "draft"

    async def test_error_message_scrubs_secrets(self, monkeypatch, free_env):
        monkeypatch.setenv("ODOO_API_KEY", "super_secret_odoo_key_999")
        with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = RuntimeError("Failed with token super_secret_odoo_key_999")
            res = await call_text(odoo_execute_kw(model="res.partner", method="search_read", args=[[]]))
        assert "super_secret_odoo_key_999" not in res
        assert "[REDACTED_SECRET]" in res


@pytest.mark.asyncio
class TestCuratedTools:
    async def test_search_caps_limit_and_trims_long_text(self, free_env):
        with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = [{"id": 1, "description": "x" * 5000}]
            res = json.loads(await odoo_search("res.partner", domain='[["is_company","=",true]]', limit=10_000))
        model, method, args, kwargs = mock_exec.call_args.args[1:]
        assert (model, method) == ("res.partner", "search_read")
        assert args == [[["is_company", "=", True]]]
        assert kwargs["limit"] == 200
        assert len(res[0]["description"]) < 1100 and "truncated" in res[0]["description"]

    async def test_count_goes_through_the_firewall(self, monkeypatch):
        monkeypatch.setenv("ODOO_SAFE_GUARD_KEY", "pro")
        assert "SECURITY ALERT" in await call_text(odoo_count("res.users.apikeys"))

    async def test_describe_model_hides_credential_fields(self, free_env):
        with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = {
                "name": {"string": "Name", "type": "char", "required": True, "readonly": False},
                "access_token": {"string": "Security Token", "type": "char"},
            }
            schema = json.loads(await odoo_describe_model("sale.order"))
        assert schema == {"name": {"string": "Name", "type": "char", "required": True}}
