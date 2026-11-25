"""Tests for v3.1 governance, privacy, context efficiency, and UX features."""

from __future__ import annotations

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from odoo_safe_mcp.config import get_config
from odoo_safe_mcp.odoo import _UID_CACHE, OdooClient
from odoo_safe_mcp.pending import PendingStore
from odoo_safe_mcp.preview import build_preview
from odoo_safe_mcp.rules import (
    PII_MASKED_VALUE,
    PII_REDACTED_VALUE,
    RiskLevel,
    evaluate_odoo_call,
    redact_pii_output,
)
from odoo_safe_mcp.server import (
    DEFAULT_FIELD_PROFILES,
    MAX_OUTPUT_BYTES,
    _SCHEMA_CACHE,
    odoo_describe_model,
    odoo_execute_kw,
    odoo_pending_approvals,
    odoo_read,
    odoo_search,
)

from .conftest import call_text


class TestGdprPiiShield:
    SAMPLE = {
        "id": 10,
        "name": "Acme Corp",
        "vat": "ESB12345678",
        "email": "finance@acme.example",
        "phone": "+34600112233",
        "acc_number": "ES9121000418450200051332",
        "wage": 4500.0,
        "country_id": [68, "Spain"],
    }

    def test_off_mode_leaves_data_untouched(self):
        assert redact_pii_output(self.SAMPLE, "off") == self.SAMPLE

    def test_strict_mode_redacts_all_pii(self):
        out = redact_pii_output(self.SAMPLE, "strict")
        assert out["name"] == "Acme Corp"
        assert out["country_id"] == [68, "Spain"]
        for field in ("vat", "email", "phone", "acc_number", "wage"):
            assert out[field] == PII_REDACTED_VALUE

    def test_mask_mode_preserves_shape_without_leaking(self):
        out = redact_pii_output(self.SAMPLE, "mask")
        assert out["email"] == "f***@acme.example"
        assert out["vat"].startswith("ES") and out["vat"].endswith("78") and "123456" not in out["vat"]
        assert out["acc_number"].startswith("ES") and out["acc_number"].endswith("32") and "2100041845" not in out["acc_number"]
        assert out["wage"] == PII_MASKED_VALUE

    @pytest.mark.asyncio
    async def test_server_applies_pii_mode_on_reads(self, monkeypatch):
        monkeypatch.setenv("ODOO_URL", "https://example.odoo.com")
        monkeypatch.setenv("ODOO_DB", "demo")
        monkeypatch.setenv("ODOO_USERNAME", "bot")
        monkeypatch.setenv("ODOO_API_KEY", "secret")
        monkeypatch.setenv("ODOO_PII_MODE", "strict")
        monkeypatch.delenv("ODOO_DRY_RUN", raising=False)
        with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = [dict(self.SAMPLE)]
            res = json.loads(await odoo_search("res.partner"))
        assert res[0]["vat"] == PII_REDACTED_VALUE
        assert res[0]["email"] == PII_REDACTED_VALUE
        assert res[0]["name"] == "Acme Corp"


class TestDomainOracleHardeningSec07:
    @pytest.mark.parametrize(
        "args,kwargs",
        [
            ([[["user_ids.oauth_access_token", "!=", False]]], {}),
            ([["&", ["active", "=", True], ["signup_token", "ilike", "abc%"]]], {}),
            ([[]], {"domain": [["password", "!=", ""]]}),
            ([[]], {"groupby": ["user_ids.totp_secret"]}),
            ([[]], {"order": "access_token desc"}),
        ],
    )
    def test_sensitive_domain_groupby_order_oracles_are_forbidden(self, args, kwargs):
        res = evaluate_odoo_call("res.partner", "search_read", args, kwargs)
        assert res.level == RiskLevel.FORBIDDEN
        assert res.allowed is False


class TestMultiCompanyIsolation:
    @pytest.mark.asyncio
    async def test_injects_and_clamps_allowed_company_ids(self, monkeypatch):
        monkeypatch.setenv("ODOO_ALLOWED_COMPANY_IDS", "2, 5")
        cfg = replace(get_config(), url="http://127.0.0.1:8069", db="db", username="bot", api_key="k")
        _UID_CACHE.clear()
        seen = []

        async def fake_rpc(client, url, service, method, args):
            if method == "authenticate":
                return 2
            seen.append(args[6])  # kwargs
            return []

        with patch("odoo_safe_mcp.odoo.jsonrpc", new=fake_rpc):
            cli = OdooClient(cfg, client=None)
            await cli.execute("sale.order", "search_read", [[]], {"limit": 5})
            await cli.execute("sale.order", "search_read", [[]], {"context": {"allowed_company_ids": [1, 5, 99], "lang": "es_ES"}})
            await cli.execute("sale.order", "search_read", [[]], {"context": {"allowed_company_ids": [99]}})

        assert seen[0]["context"]["allowed_company_ids"] == [2, 5]
        assert seen[1]["context"]["allowed_company_ids"] == [5]
        assert seen[1]["context"]["lang"] == "es_ES"
        assert seen[2]["context"]["allowed_company_ids"] == [2, 5]


@pytest.mark.asyncio
class TestContextEfficiencyAndTools:
    async def test_search_uses_lightweight_profile_and_bin_size(self, monkeypatch):
        monkeypatch.setenv("ODOO_URL", "https://example.odoo.com")
        monkeypatch.setenv("ODOO_DB", "demo")
        monkeypatch.setenv("ODOO_USERNAME", "bot")
        monkeypatch.setenv("ODOO_API_KEY", "secret")
        monkeypatch.delenv("ODOO_DRY_RUN", raising=False)

        with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = [{"id": 1, "name": "Order 1"}]
            await odoo_search("sale.order")
            kwargs_profiled = mock_exec.call_args.args[4]
            assert kwargs_profiled["fields"] == DEFAULT_FIELD_PROFILES["sale.order"]

            await odoo_search("sale.order", all_fields=True)
            kwargs_full = mock_exec.call_args.args[4]
            assert "fields" not in kwargs_full and kwargs_full["context"] == {"bin_size": True}

            await odoo_read("res.partner", [1])
            kwargs_read = mock_exec.call_args.args[4]
            assert kwargs_read["context"] == {"bin_size": True}

    async def test_output_exceeding_60kb_is_truncated_with_envelope(self, monkeypatch):
        monkeypatch.setenv("ODOO_URL", "https://example.odoo.com")
        monkeypatch.setenv("ODOO_DB", "demo")
        monkeypatch.setenv("ODOO_USERNAME", "bot")
        monkeypatch.setenv("ODOO_API_KEY", "secret")
        monkeypatch.delenv("ODOO_DRY_RUN", raising=False)

        huge_rows = [{"id": i, "name": f"Row {i}", "note": "A" * 950} for i in range(120)]
        with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = huge_rows
            raw = await odoo_search("x_custom.model", limit=120)
        assert len(raw.encode("utf-8")) <= MAX_OUTPUT_BYTES
        parsed = json.loads(raw)
        assert parsed["_truncated"] is True
        assert parsed["_total_in_page"] == 120
        assert 0 < parsed["_returned"] < 120

    async def test_describe_model_supports_fuzzy_search_and_writable_filter(self, monkeypatch):
        monkeypatch.setenv("ODOO_URL", "https://example.odoo.com")
        monkeypatch.setenv("ODOO_DB", "demo")
        monkeypatch.setenv("ODOO_USERNAME", "bot")
        monkeypatch.setenv("ODOO_API_KEY", "secret")
        _SCHEMA_CACHE.clear()
        with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = {
                "name": {"string": "Order Reference", "type": "char", "readonly": False},
                "amount_total": {"string": "Total", "type": "monetary", "readonly": True},
                "x_studio_iban": {"string": "Custom IBAN", "type": "char", "readonly": False},
            }
            filtered = json.loads(await odoo_describe_model("sale.order", search="x_studio", include_readonly=False))
            assert list(filtered.keys()) == ["x_studio_iban"]
            writable = json.loads(await odoo_describe_model("sale.order", include_readonly=False))
            assert "amount_total" not in writable and "name" in writable


@pytest.mark.asyncio
class TestDraftThresholdsAndPendingApprovals:
    async def test_preview_estimates_sale_order_create_amount_total(self, world):
        _, guard = world
        await odoo_execute_kw(
            "sale.order",
            "create",
            [
                {
                    "partner_id": 1,
                    "order_line": [
                        [0, 0, {"product_id": 5, "product_uom_qty": 2, "price_unit": 300.0}],
                        [0, 0, {"product_id": 6, "product_uom_qty": 1, "price_unit": 100.0, "discount": 10.0}],
                    ],
                }
            ],
        )
        preview = guard.requests[0]["body"]["preview"]
        assert preview["amount_total"] == 690.0

    async def test_local_draft_max_amount_sends_escalation_reason(self, world, monkeypatch):
        _, guard = world
        monkeypatch.setenv("ODOO_DRAFT_MAX_AMOUNT", "500")
        await odoo_execute_kw(
            "sale.order",
            "create",
            [{"partner_id": 1, "order_line": [[0, 0, {"product_id": 5, "product_uom_qty": 2, "price_unit": 400.0}]]}],
        )
        req_body = guard.requests[0]["body"]
        assert "ODOO_DRAFT_MAX_AMOUNT" in req_body["require_approval_reason"]

    async def test_odoo_pending_approvals_lists_only_unclaimed_intents(self, world):
        _, guard = world
        first = json.loads(await odoo_execute_kw("sale.order", "write", [[16], {"note": "one"}]))
        second = json.loads(await odoo_execute_kw("sale.order", "write", [[17], {"note": "two"}]))
        pending = json.loads(await odoo_pending_approvals())
        ids = {item["intent_id"] for item in pending["pending"]}
        assert first["intent_id"] in ids and second["intent_id"] in ids
        # Claim first intent
        store = PendingStore(get_config().state_dir)
        store.claim(first["intent_id"])
        pending_after = json.loads(await odoo_pending_approvals())
        ids_after = {item["intent_id"] for item in pending_after["pending"]}
        assert first["intent_id"] not in ids_after and second["intent_id"] in ids_after
