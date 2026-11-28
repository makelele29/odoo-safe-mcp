"""Security hardening and cross-version regression tests for v3.1.1."""

from __future__ import annotations

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from odoo_safe_mcp.config import get_config, sanitize_error
from odoo_safe_mcp.odoo import _UID_CACHE, OdooClient
from odoo_safe_mcp.preview import _estimate_create_amount_details, build_preview
from odoo_safe_mcp.rules import (
    PII_REDACTED_VALUE,
    RiskLevel,
    evaluate_odoo_call,
    find_pii_read_oracle,
    redact_pii_output,
)
from odoo_safe_mcp.server import (
    _SCHEMA_CACHE,
    MAX_OUTPUT_BYTES,
    OdooSafeError,
    _dumps_bounded,
    odoo_describe_model,
    odoo_execute_kw,
    odoo_search,
)

from .conftest import call_text


class TestDraftAmountAntiBypass:
    def test_ignores_client_amount_total_spoof_and_opposing_lines(self):
        payload = [
            {
                "partner_id": 7,
                "amount_total": 0.0,
                "order_line": [
                    [0, 0, {"product_id": 5, "product_uom_qty": 100, "price_unit": 500.0}],
                    [0, 0, {"product_id": 6, "product_uom_qty": -100, "price_unit": 500.0}],
                ],
            }
        ]
        amt, uncertain = _estimate_create_amount_details("sale.order", payload)
        assert amt == 100_000.0
        assert uncertain is False

    def test_discount_over_100_cannot_cancel_amount(self):
        payload = [
            {
                "partner_id": 7,
                "order_line": [[0, 0, {"product_id": 5, "product_uom_qty": 10, "price_unit": 100.0, "discount": 200}]],
            }
        ]
        amt, _ = _estimate_create_amount_details("sale.order", payload)
        assert amt == 0.0

    def test_missing_price_unit_without_catalog_marks_uncertain(self):
        payload = [{"partner_id": 7, "order_line": [[0, 0, {"product_id": 5, "product_uom_qty": 100}]]}]
        amt, uncertain = _estimate_create_amount_details("sale.order", payload)
        assert amt is None and uncertain is True

    @pytest.mark.asyncio
    async def test_missing_price_unit_escalates_fail_closed_or_uses_product_list_price(self, world, monkeypatch):
        odoo, guard = world
        monkeypatch.setenv("ODOO_DRAFT_MAX_AMOUNT", "500")
        await odoo_execute_kw(
            "sale.order",
            "create",
            [{"partner_id": 7, "amount_total": 1.0, "order_line": [[0, 0, {"product_id": 5, "product_uom_qty": 100}]]}],
        )
        req_body = guard.requests[0]["body"]
        assert req_body["require_approval_reason"] is not None

    @pytest.mark.asyncio
    async def test_zero_draft_max_amount_escalates_all_drafts(self, world, monkeypatch):
        _, guard = world
        monkeypatch.setenv("ODOO_DRAFT_MAX_AMOUNT", "0")
        await odoo_execute_kw(
            "sale.order",
            "create",
            [{"partner_id": 7, "order_line": [[0, 0, {"product_id": 5, "product_uom_qty": 1, "price_unit": 5.0}]]}],
        )
        assert "ODOO_DRAFT_MAX_AMOUNT" in guard.requests[0]["body"]["require_approval_reason"]

    @pytest.mark.asyncio
    async def test_account_payment_uses_amount_field_in_preview(self, world):
        odoo, guard = world
        odoo.fields["amount"] = {"string": "Amount", "type": "monetary"}
        odoo.fields["partner_id"] = {"string": "Partner", "type": "many2one"}
        odoo.records[("account.payment", 55)] = {
            "id": 55,
            "display_name": "PBNK1/2026/0055",
            "amount": 4200.5,
            "currency_id": [1, "EUR"],
            "partner_id": [7, "Proveedor SA"],
        }
        await odoo_execute_kw("account.payment", "action_post", [[55]])
        preview = guard.requests[0]["body"]["preview"]
        assert preview["amount_total"] == 4200.5
        assert preview["currency"] == "EUR"
        assert preview["records"][0]["partner"] == "Proveedor SA"


class TestPiiAndSec07Hardening:
    def test_redacts_domain_display_name_name_search_and_extended_fields(self):
        data = [
            {
                "id": 1,
                "display_name": "Juan Perez <ceo@empresa.es>",
                "email_formatted": '"Juan" <ceo@empresa.es>',
                "contact_address": "Calle Mayor 12",
                "bank_account_id": [7, "ES91 2100 0418 4502 0005 1332"],
                "emergency_phone": "+34600112233",
                "x_dni": "12345678Z",
                "x_iban_secundario": "ES7600491500051234567892",
                "vat_number": "ESB12345678",
                "__domain": [["email", "=", "ceo@empresa.es"]],
            }
        ]
        out = redact_pii_output(data, "strict")
        row = out[0]
        assert "ceo@empresa.es" not in json.dumps(row)
        assert "12345678Z" not in json.dumps(row)
        assert "ES91" not in json.dumps(row)
        assert row["__domain"] == PII_REDACTED_VALUE
        assert row["bank_account_id"] == [7, PII_REDACTED_VALUE]

        ns = redact_pii_output([[1, "Juan Perez <ceo@empresa.es>"]], "strict")
        assert "ceo@empresa.es" not in ns[0][1]

    @pytest.mark.parametrize(
        "method,args,kwargs",
        [
            ("name_search", ["", [["user_id.oauth_access_token", "=like", "a%"]]], {}),
            ("name_search", [""], {"args": [["access_token", "!=", ""]]}),
            ("read_group", [[], ["id"], ["user_id.totp_secret"]], {}),
            ("read_group", [[], ["id"], ["state"], 0, 10, "access_token desc"], {}),
            ("search", [[], 0, 10, "password asc"], {}),
            ("search_read", [[], ["name"], 0, 10, "signup_token desc"], {}),
        ],
    )
    def test_positional_credential_oracles_are_forbidden(self, method, args, kwargs):
        res = evaluate_odoo_call("res.partner", method, args, kwargs)
        assert res.level == RiskLevel.FORBIDDEN

    def test_pii_domain_oracle_blocked_when_pii_mode_enabled(self):
        hit = find_pii_read_oracle("search_count", [[["vat", "=like", "ESB12%"]]], {})
        assert hit == "vat"

    @pytest.mark.asyncio
    async def test_preview_redacts_pii_before_sending_to_guard(self, world, monkeypatch):
        odoo, guard = world
        odoo.fields["email"] = {"string": "Email", "type": "char"}
        odoo.fields["vat"] = {"string": "VAT", "type": "char"}
        odoo.records[("res.partner", 10)] = {"id": 10, "display_name": "Cliente", "email": "old@cliente.es", "vat": "ESB11111111"}
        monkeypatch.setenv("ODOO_PII_MODE", "strict")
        await odoo_execute_kw("res.partner", "write", [[10], {"email": "new@cliente.es", "vat": "ESB22222222"}])
        preview_sent = json.dumps(guard.requests[0]["body"]["preview"])
        assert "old@cliente.es" not in preview_sent
        assert "new@cliente.es" not in preview_sent
        assert "ESB11111111" not in preview_sent
        assert "ESB22222222" not in preview_sent

    def test_sanitize_error_scrubs_pii_when_enabled(self, monkeypatch):
        monkeypatch.setenv("ODOO_PII_MODE", "strict")
        cfg = get_config()
        msg = sanitize_error("Duplicate VAT/Email for ceo@empresa.es / ES91 2100 0418 4502 0005 1332", cfg)
        assert "ceo@empresa.es" not in msg and "ES91" not in msg


class TestMultiCompanyAndCompatHardening:
    @pytest.mark.asyncio
    async def test_invalid_allowed_company_ids_fails_closed_and_strips_force_company(self, monkeypatch):
        monkeypatch.setenv("ODOO_ALLOWED_COMPANY_IDS", "bad,0,-1")
        cfg = replace(get_config(), url="http://127.0.0.1:8069", db="db", username="bot", api_key="k")
        with pytest.raises(PermissionError, match="fail-closed"):
            await OdooClient(cfg, client=None).execute("res.partner", "search_read", [[]], {})

        monkeypatch.setenv("ODOO_ALLOWED_COMPANY_IDS", "2")
        cfg2 = replace(get_config(), url="http://127.0.0.1:8069", db="db", username="bot", api_key="k")
        seen = []

        async def fake_rpc(_c, _u, _s, method, args):
            if method == "authenticate":
                return 2
            seen.append(args[6])
            return []

        _UID_CACHE.clear()
        with patch("odoo_safe_mcp.odoo.jsonrpc", new=fake_rpc):
            await OdooClient(cfg2, client=None).execute(
                "sale.order",
                "search_read",
                [[]],
                {"context": {"allowed_company_ids": [1], "force_company": 1, "company_id": 1}},
            )
        assert seen[0]["context"]["allowed_company_ids"] == [2]
        assert "force_company" not in seen[0]["context"]
        assert "company_id" not in seen[0]["context"]

    @pytest.mark.asyncio
    async def test_write_targeting_disallowed_company_id_is_blocked(self, world, monkeypatch):
        monkeypatch.setenv("ODOO_ALLOWED_COMPANY_IDS", "1")
        msg = await call_text(odoo_execute_kw("sale.order", "create", [{"partner_id": 1, "company_id": 2}]))
        assert "Multi-Company Isolation" in msg

    @pytest.mark.asyncio
    async def test_large_describe_model_dict_truncates_to_valid_json(self, monkeypatch):
        monkeypatch.setenv("ODOO_URL", "https://example.odoo.com")
        monkeypatch.setenv("ODOO_DB", "demo")
        monkeypatch.setenv("ODOO_USERNAME", "bot")
        monkeypatch.setenv("ODOO_API_KEY", "secret")
        monkeypatch.delenv("ODOO_DRY_RUN", raising=False)
        _SCHEMA_CACHE.clear()
        huge_schema = {
            f"x_field_{i}": {
                "string": f"Campo Español Número {i} con descripción larga",
                "type": "selection",
                "selection": [[f"opt_{j}", f"Opción {j} — descripción extensa con eñes"] for j in range(12)],
            }
            for i in range(130)
        }
        with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock, return_value=huge_schema):
            raw = await odoo_describe_model("sale.order")
        assert len(raw.encode("utf-8")) <= MAX_OUTPUT_BYTES
        parsed = json.loads(raw)
        assert parsed["_truncated"] is True and parsed["_total_fields"] == 130 and parsed["_returned"] > 0

    @pytest.mark.asyncio
    async def test_search_recovers_when_default_profile_field_missing_in_odoo16(self, monkeypatch):
        monkeypatch.setenv("ODOO_URL", "https://example.odoo.com")
        monkeypatch.setenv("ODOO_DB", "demo")
        monkeypatch.setenv("ODOO_USERNAME", "bot")
        monkeypatch.setenv("ODOO_API_KEY", "secret")
        monkeypatch.delenv("ODOO_DRY_RUN", raising=False)
        _SCHEMA_CACHE.clear()
        calls = []

        async def fake_exec(cfg, model, method, args, kwargs):
            calls.append((method, kwargs.get("fields")))
            if method == "search_read" and "state" in (kwargs.get("fields") or []):
                raise OdooSafeError("Invalid field 'state' on model 'project.task'")
            if method == "fields_get":
                return {"id": {}, "name": {}, "project_id": {}, "stage_id": {}}
            return [{"id": 1, "name": "Task 1"}]

        with patch("odoo_safe_mcp.server._execute_local_odoo", side_effect=fake_exec):
            res = json.loads(await odoo_search("project.task"))
        assert res == [{"id": 1, "name": "Task 1"}]
        assert calls[1][0] == "fields_get"
        assert "state" not in calls[2][1]
