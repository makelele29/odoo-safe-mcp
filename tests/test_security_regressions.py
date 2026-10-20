"""
Regression tests for vulnerabilities confirmed against a live Odoo 18 database (2026-10-20).

Each test names the finding it covers so a future refactor cannot silently reopen it.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest

from odoo_safe_mcp.rules import (
    REDACTED_VALUE,
    RiskLevel,
    evaluate_odoo_call,
    evaluate_rule,
    redact_sensitive_output,
)
from dataclasses import replace

from odoo_safe_mcp.config import get_config
from odoo_safe_mcp.odoo import _UID_CACHE, OdooClient, OdooRPCError
from odoo_safe_mcp.server import odoo_execute_kw


# --- C1: guarded draft create could modify lines of an already confirmed order ---------------

@pytest.mark.parametrize(
    "model,payload",
    [
        # Verified live: price of a line on confirmed order S00016 changed 275.0 -> 0.01 without approval
        ("sale.order", [{"partner_id": 1, "order_line": [[1, 34, {"price_unit": 0.01}]]}]),
        ("sale.order", [{"partner_id": 1, "order_line": [[2, 34, 0]]}]),       # delete foreign line
        ("sale.order", [{"partner_id": 1, "order_line": [[3, 34, 0]]}]),       # detach foreign line
        ("sale.order", [{"partner_id": 1, "order_line": [[4, 34, 0]]}]),       # steal foreign line
        ("sale.order", [{"partner_id": 1, "order_line": [[5, 0, 0]]}]),        # clear
        ("sale.order", [{"partner_id": 1, "order_line": [[6, 0, [34, 35]]]}]), # re-parent lines
        ("purchase.order", [[{"partner_id": 1, "order_line": [[1, 7, {"price_unit": 0}]]}]]),
        ("crm.lead", [{"name": "x", "tag_ids": [[6, 0, [1, 2]]]}]),          # fail-safe without schema
        # Verified live: a bare id list re-parented line 6 from S00003 into the new order
        ("sale.order", [{"partner_id": 1, "order_line": [6]}]),
        ("sale.order", [{"partner_id": 1, "order_line": [[0, 0, {"name": "x"}], 6]}]),
    ],
)
def test_c1_x2many_commands_escalate_guarded_create_to_red(model, payload):
    decision = evaluate_odoo_call(model=model, method="create", args=payload)
    assert decision.level == RiskLevel.RED
    assert decision.requires_guard_proxy is True
    assert "x2many" in decision.reason


def test_c1_nested_command_inside_create_command_is_detected():
    payload = [{"partner_id": 1, "order_line": [[0, 0, {"product_id": 5, "tax_id": [[2, 9, 0]]}]]}]
    decision = evaluate_odoo_call(model="sale.order", method="create", args=payload)
    assert decision.level == RiskLevel.RED
    assert "order_line[0].tax_id[0]" in decision.reason


@pytest.mark.parametrize("kw_name", ["vals", "vals_list"])
def test_c1_commands_in_kwargs_are_detected(kw_name):
    vals = {"partner_id": 1, "order_line": [[1, 34, {"price_unit": 0}]]}
    decision = evaluate_odoo_call(
        model="sale.order",
        method="create",
        args=[],
        kwargs={kw_name: [vals] if kw_name == "vals_list" else vals},
    )
    assert decision.level == RiskLevel.RED


def test_c1_plain_create_commands_stay_yellow():
    payload = [{"partner_id": 1, "state": "sale", "order_line": [[0, 0, {"product_id": 5, "product_uom_qty": 2}]]}]
    decision = evaluate_odoo_call(model="sale.order", method="create", args=payload)
    assert decision.level == RiskLevel.YELLOW
    assert decision.sanitized_args[0]["state"] == "draft"
    assert decision.sanitized_args[0]["order_line"] == [[0, 0, {"product_id": 5, "product_uom_qty": 2}]]


def test_c1_escalated_create_is_blocked_on_free_tier_and_routed_on_pro():
    payload = [{"partner_id": 1, "order_line": [[1, 34, {"price_unit": 0.01}]]}]
    free = evaluate_rule("sale.order", "create", payload, has_pro_license=False)
    pro = evaluate_rule("sale.order", "create", payload, has_pro_license=True)
    assert free.allowed is False
    assert pro.level == RiskLevel.RED and pro.requires_guard_proxy is True


def test_c1_create_does_not_treat_empty_or_dict_lists_as_commands():
    payload = [{"partner_id": 1, "note": "x", "tag_ids": [], "lead_properties": [{"name": "p", "value": "x"}]}]
    assert evaluate_odoo_call("crm.lead", "create", payload).level == RiskLevel.YELLOW


@pytest.mark.parametrize(
    "value",
    [
        ["a", "b"],               # Odoo would SET these as ids: numeric strings are coerced by Postgres
        [6.0],                    # float id: 6.0 == 6, same record
        [[4.0, 34]],              # float command code: LINK
        [[True, 34, {"price_unit": 0}]],  # True == 1: UPDATE
        [[4, 34], "x"],           # Odoo skips the junk item and still applies the LINK
        [[4, 34], [7]],           # unknown codes are skipped silently too
        [[]],
    ],
)
def test_c1_any_list_that_is_not_only_create_commands_escalates(value):
    payload = [{"partner_id": 1, "order_line": value}]
    assert evaluate_odoo_call("sale.order", "create", payload).level == RiskLevel.RED


# --- C2: res.config.settings leaked integration secrets through a GREEN default_get -----------

@pytest.mark.parametrize("method", ["default_get", "read", "search_read", "fields_get", "execute", "create"])
def test_c2_res_config_settings_is_forbidden(method):
    decision = evaluate_odoo_call("res.config.settings", method, [["google_gmail_client_secret"]])
    assert decision.level == RiskLevel.FORBIDDEN
    assert decision.allowed is False


# --- A1: credential fields leaked when the agent omits the 'fields' list ----------------------

def test_a1_redacts_tokens_in_nested_results():
    odoo_result = [
        {"id": 16, "name": "S00016", "access_token": "8f1c-portal", "partner_id": [1, "Azure"]},
        {"id": 1, "account_token": "iap-secret", "child": {"signup_token": "abc", "name": "ok"}},
    ]
    redacted = redact_sensitive_output(odoo_result)
    assert redacted[0]["access_token"] == REDACTED_VALUE
    assert redacted[0]["name"] == "S00016"
    assert redacted[0]["partner_id"] == [1, "Azure"]
    assert redacted[1]["account_token"] == REDACTED_VALUE
    assert redacted[1]["child"]["signup_token"] == REDACTED_VALUE
    assert redacted[1]["child"]["name"] == "ok"


def test_a1_redaction_handles_read_group_aggregates():
    rows = [{"access_token:count": 3, "amount_total:sum": 99.0, "__count": 3}]
    redacted = redact_sensitive_output(rows)
    assert redacted[0]["access_token:count"] == REDACTED_VALUE
    assert redacted[0]["amount_total:sum"] == 99.0


def test_a1_requested_sensitive_fields_are_stripped_by_pattern():
    decision = evaluate_odoo_call(
        "sale.order",
        "search_read",
        [[]],
        {"fields": ["name", "access_token", "google_gmail_client_secret", "amount_total:sum", "tenor_api_key"]},
    )
    assert decision.sanitized_kwargs["fields"] == ["name", "amount_total:sum"]


@pytest.mark.asyncio
async def test_a1_server_redacts_green_results(monkeypatch):
    monkeypatch.setenv("ODOO_URL", "https://example.odoo.com")
    monkeypatch.setenv("ODOO_DB", "demo")
    monkeypatch.setenv("ODOO_USERNAME", "bot")
    monkeypatch.setenv("ODOO_API_KEY", "secret")
    monkeypatch.delenv("ODOO_DRY_RUN", raising=False)
    with patch("odoo_safe_mcp.server._execute_local_odoo", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = [{"id": 16, "name": "S00016", "access_token": "8f1c-portal"}]
        res = await odoo_execute_kw(model="sale.order", method="search_read", args=[[]])
    data = json.loads(res)
    assert data[0]["access_token"] == REDACTED_VALUE
    assert "8f1c-portal" not in res


# --- A2: real API-key model was not blocked (blacklist used the non-existent 'res.apikeys') ---

@pytest.mark.parametrize(
    "model",
    [
        "res.users.apikeys",
        "res.users.apikeys.description",
        "auth.totp.device",
        "iap.account",
        "change.password.user",
        "res.users.identitycheck",
    ],
)
def test_a2_credential_models_are_forbidden_even_for_reads(model):
    for method in ["search_read", "read", "search_count", "fields_get"]:
        decision = evaluate_odoo_call(model, method, [[]])
        assert decision.level == RiskLevel.FORBIDDEN, (model, method)


# --- Hardening: module (un)install wizards, code-bearing actions and global defaults ----------

@pytest.mark.parametrize(
    "model",
    ["base.module.uninstall", "base.module.upgrade", "ir.actions.report", "ir.actions.act_window", "ir.asset", "ir.default"],
)
def test_system_models_cannot_be_mutated_even_with_pro(model):
    for method in ["create", "write", "unlink", "action_uninstall", "upgrade_module"]:
        decision = evaluate_rule(model, method, [[1], {}], has_pro_license=True)
        assert decision.level == RiskLevel.FORBIDDEN, (model, method)
        assert decision.allowed is False


# --- Hardening: a guarded create must not be able to silence the Chatter audit trail ----------

def test_yellow_create_drops_tracking_context_keys():
    decision = evaluate_odoo_call(
        "sale.order",
        "create",
        [{"partner_id": 1}],
        {
            "context": {
                "lang": "es_ES",
                "tz": "Europe/Madrid",
                "default_state": "sale",
                "default_partner_id": 7,
                "tracking_disable": True,
                "mail_notrack": True,
                "mail_create_nolog": True,
                "install_mode": True,
            }
        },
    )
    ctx = decision.sanitized_kwargs["context"]
    assert ctx == {"lang": "es_ES", "tz": "Europe/Madrid", "default_state": "draft", "default_partner_id": 7}


# --- Compatibility: name_get removed in Odoo 17+ (verified on 18: "method does not exist") ---

@pytest.mark.asyncio
async def test_name_get_falls_back_to_display_name_on_odoo_17_plus():
    calls = []

    async def fake_rpc(client, url, service, method, args):
        if method == "authenticate":
            return 2
        calls.append(args[4])
        if args[4] == "name_get":
            raise OdooRPCError("Odoo RPC Error: The method 'res.partner.name_get' does not exist")
        return [{"id": 1, "display_name": "Azure Interior"}, {"id": 3, "display_name": "Deco Addict"}]

    cfg = replace(get_config(), url="http://odoo", db="db", username="bot", api_key="k")
    _UID_CACHE.clear()
    with patch("odoo_safe_mcp.odoo.jsonrpc", new=fake_rpc):
        result = await OdooClient(cfg, client=None).execute("res.partner", "name_get", [[1, 3]], {})
    assert result == [[1, "Azure Interior"], [3, "Deco Addict"]]
    assert calls == ["name_get", "read"]
