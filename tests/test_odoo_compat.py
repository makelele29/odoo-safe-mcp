"""Cross-version ORM shims, pinned by what the testbed found on real Odoo releases."""

from dataclasses import replace
from unittest.mock import patch

import pytest

from odoo_safe_mcp.config import get_config
from odoo_safe_mcp.odoo import _UID_CACHE, OdooClient, OdooRPCError, legacy_read_group_kwargs


def test_legacy_read_group_kwargs_map_to_odoo_20():
    new = legacy_read_group_kwargs(
        [], {"domain": [["state", "=", "sale"]], "fields": ["amount_total:sum", "name"], "groupby": "state", "lazy": False, "orderby": "state", "limit": 5}
    )
    assert new == {
        "domain": [["state", "=", "sale"]],
        "groupby": ["state"],
        "aggregates": ["amount_total:sum", "__count"],
        "limit": 5,
        "order": "state",
    }


def test_legacy_read_group_positional_args():
    assert legacy_read_group_kwargs([[], ["x:max"], ["partner_id"]], {}) == {
        "domain": [],
        "groupby": ["partner_id"],
        "aggregates": ["x:max", "__count"],
    }


@pytest.mark.asyncio
async def test_read_group_falls_back_to_formatted_read_group_on_odoo_20():
    calls = []

    async def fake_rpc(client, url, service, method, args):
        if method == "authenticate":
            return 2
        calls.append((args[4], args[6]))
        if args[4] == "read_group":
            raise OdooRPCError("Odoo RPC Error: BaseModel.read_group() got an unexpected keyword argument 'fields'")
        return [{"state": "sale", "amount_total:sum": 99.0, "__count": 3}]

    cfg = replace(get_config(), url="http://odoo", db="db", username="bot", api_key="k")
    _UID_CACHE.clear()
    with patch("odoo_safe_mcp.odoo.jsonrpc", new=fake_rpc):
        result = await OdooClient(cfg, client=None).execute(
            "sale.order", "read_group", [], {"domain": [], "fields": ["amount_total:sum"], "groupby": ["state"], "lazy": False}
        )
    assert result == [{"state": "sale", "amount_total:sum": 99.0, "__count": 3}]
    assert [c[0] for c in calls] == ["read_group", "formatted_read_group"]
    assert calls[1][1] == {"domain": [], "groupby": ["state"], "aggregates": ["amount_total:sum", "__count"]}


@pytest.mark.asyncio
async def test_other_rpc_errors_are_not_masked():
    async def fake_rpc(client, url, service, method, args):
        if method == "authenticate":
            return 2
        raise OdooRPCError("Odoo RPC Error: Access Denied")

    cfg = replace(get_config(), url="http://odoo", db="db", username="bot", api_key="k")
    _UID_CACHE.clear()
    with patch("odoo_safe_mcp.odoo.jsonrpc", new=fake_rpc), pytest.raises(OdooRPCError, match="Access Denied"):
        await OdooClient(cfg, client=None).execute("sale.order", "read_group", [], {"fields": []})
