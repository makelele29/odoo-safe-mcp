"""
Tests for odoo_safe_mcp/server.py and MCP tool execution.
"""

import json
from unittest.mock import AsyncMock, patch
import pytest
from odoo_safe_mcp.server import odoo_execute_kw, _normalize_list, _normalize_dict


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


@pytest.mark.asyncio
class TestServerExecutionKW:
    async def test_free_tier_blocks_mutation(self, monkeypatch):
        monkeypatch.setenv("ODOO_URL", "https://example.odoo.com")
        monkeypatch.setenv("ODOO_DB", "demo")
        monkeypatch.setenv("ODOO_USERNAME", "admin")
        monkeypatch.setenv("ODOO_API_KEY", "secret")
        monkeypatch.delenv("ODOO_SAFE_GUARD_KEY", raising=False)

        res = await odoo_execute_kw(
            model="sale.order",
            method="create",
            args=[{"partner_id": 1}],
        )
        assert "Strict Read-Only Mode" in res
        assert "odoosafemcp.stream/#pricing" in res

    async def test_blacklisted_model_always_blocked(self, monkeypatch):
        monkeypatch.setenv("ODOO_SAFE_GUARD_KEY", "pro_guard_license_key")
        res = await odoo_execute_kw(
            model="res.users",
            method="unlink",
            args=[[1]],
        )
        assert "SECURITY ALERT" in res

    async def test_missing_credentials_detected(self, monkeypatch):
        monkeypatch.delenv("ODOO_URL", raising=False)
        monkeypatch.delenv("ODOO_DB", raising=False)
        monkeypatch.delenv("ODOO_USERNAME", raising=False)
        monkeypatch.delenv("ODOO_API_KEY", raising=False)
        monkeypatch.delenv("ODOO_SAFE_GUARD_KEY", raising=False)

        res = await odoo_execute_kw(
            model="res.partner",
            method="search_read",
            args=[[]],
        )
        assert "Configuration Error" in res

    async def test_green_read_executes_jsonrpc(self, monkeypatch):
        monkeypatch.setenv("ODOO_URL", "https://example.odoo.com")
        monkeypatch.setenv("ODOO_DB", "demo")
        monkeypatch.setenv("ODOO_USERNAME", "admin")
        monkeypatch.setenv("ODOO_API_KEY", "secret")
        monkeypatch.delenv("ODOO_SAFE_GUARD_KEY", raising=False)

        mock_result = [{"id": 1, "name": "Test Partner"}]

        with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_result
            res = await odoo_execute_kw(
                model="res.partner",
                method="search_read",
                args=[[]],
                kwargs={"fields": ["name"]},
            )
            data = json.loads(res)
            assert data == mock_result
            mock_exec.assert_called_once()

    async def test_guard_proxy_forwarding_yellow(self, monkeypatch):
        monkeypatch.setenv("ODOO_URL", "https://example.odoo.com")
        monkeypatch.setenv("ODOO_DB", "demo")
        monkeypatch.setenv("ODOO_USERNAME", "admin")
        monkeypatch.setenv("ODOO_API_KEY", "secret")
        monkeypatch.setenv("ODOO_SAFE_GUARD_KEY", "pro_guard_test_key")

        mock_proxy_res = {"status": "success", "id": 105, "state": "draft"}

        with patch("odoo_safe_mcp.server._forward_to_guard_proxy", new_callable=AsyncMock) as mock_guard:
            mock_guard.return_value = mock_proxy_res
            res = await odoo_execute_kw(
                model="sale.order",
                method="create",
                args=[{"partner_id": 1}],
            )
            data = json.loads(res)
            assert data["status"] == "success"
            assert data["id"] == 105
            mock_guard.assert_called_once()

    async def test_dry_run_mode_simulates_mutations(self, monkeypatch):
        monkeypatch.setenv("ODOO_DRY_RUN", "true")
        monkeypatch.delenv("ODOO_SAFE_GUARD_KEY", raising=False)

        res = await odoo_execute_kw(
            model="sale.order",
            method="create",
            args=[{"partner_id": 1, "state": "sale"}],
        )
        data = json.loads(res)
        assert data["status"] == "DRY_RUN_SIMULATION"
        assert data["executed_in_odoo"] is False
        assert data["risk_level"] == "YELLOW"
        assert data["sanitized_args"][0]["state"] == "draft"

    async def test_error_message_scrubs_secrets(self, monkeypatch):
        monkeypatch.setenv("ODOO_URL", "https://example.odoo.com")
        monkeypatch.setenv("ODOO_DB", "demo")
        monkeypatch.setenv("ODOO_USERNAME", "admin")
        monkeypatch.setenv("ODOO_API_KEY", "super_secret_odoo_key_999")
        monkeypatch.delenv("ODOO_DRY_RUN", raising=False)

        with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = RuntimeError("Failed with token super_secret_odoo_key_999")
            res = await odoo_execute_kw(
                model="res.partner",
                method="search_read",
                args=[[]],
            )
            assert "super_secret_odoo_key_999" not in res
            assert "[REDACTED_SECRET]" in res

