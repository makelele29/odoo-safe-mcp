"""
Live integration suite: runs the firewall against a real Odoo started by the testbed
(odoo-test-environments/testbed/run_matrix.py). Skipped unless ODOO_TESTBED=1.

Environment (written by the testbed into .env.v<serie>):
  ODOO_URL, ODOO_DB, ODOO_USERNAME, ODOO_API_KEY   least-privilege bot used through the MCP tool
  ODOO_ADMIN_LOGIN, ODOO_ADMIN_PASSWORD            admin used only to verify the real database state
  ODOO_SERIES                                      expected major version (e.g. "18")
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx
import pytest

from odoo_safe_mcp.server import odoo_execute_kw

from ..conftest import call_text

pytestmark = [
    pytest.mark.odoo,
    pytest.mark.skipif(os.getenv("ODOO_TESTBED") != "1", reason="live Odoo testbed not configured"),
]

URL = os.getenv("ODOO_URL", "").rstrip("/")
DB = os.getenv("ODOO_DB", "")
SERIES = int(os.getenv("ODOO_SERIES", "0") or 0)


def _rpc(service: str, method: str, *args: Any) -> Any:
    response = httpx.post(
        f"{URL}/jsonrpc",
        json={"jsonrpc": "2.0", "method": "call", "params": {"service": service, "method": method, "args": list(args)}, "id": 1},
        timeout=60,
    )
    data = response.json()
    if "error" in data:
        raise RuntimeError((data["error"].get("data") or {}).get("message") or data["error"])
    return data["result"]


class Account:
    def __init__(self, login: str, secret: str):
        self.login, self.secret = login, secret
        self.uid = _rpc("common", "authenticate", DB, login, secret, {})
        assert self.uid, f"authentication failed for {login}"

    def call(self, model: str, method: str, args: list, kwargs: dict | None = None) -> Any:
        return _rpc("object", "execute_kw", DB, self.uid, self.secret, model, method, args, kwargs or {})


@pytest.fixture(scope="module")
def admin() -> Account:
    return Account(os.environ["ODOO_ADMIN_LOGIN"], os.environ["ODOO_ADMIN_PASSWORD"])


@pytest.fixture(scope="module")
def bot() -> Account:
    return Account(os.environ["ODOO_USERNAME"], os.environ["ODOO_API_KEY"])


@pytest.fixture(autouse=True)
def bot_env(monkeypatch):
    """The MCP tool always runs as the least-privilege bot, free tier, dry-run off."""
    monkeypatch.delenv("ODOO_SAFE_GUARD_KEY", raising=False)
    monkeypatch.delenv("ODOO_DRY_RUN", raising=False)
    monkeypatch.setenv("ODOO_TIMEOUT", "60")
    monkeypatch.setenv("ODOO_APPROVAL_WAIT_SECONDS", "0")


async def tool(model: str, method: str, args: Any = None, kwargs: Any = None) -> str:
    return await call_text(odoo_execute_kw(model=model, method=method, args=args, kwargs=kwargs))


def _confirmed_order_line(admin: Account) -> dict:
    lines = admin.call(
        "sale.order.line",
        "search_read",
        [[["order_id.state", "in", ["sale", "done"]], ["display_type", "=", False]]],
        {"fields": ["id", "price_unit", "order_id"], "limit": 1},
    )
    if not lines:
        pytest.skip("no confirmed sale order line in demo data")
    return lines[0]


# --- Version & connectivity ---------------------------------------------------------------------

def test_server_version_matches_expected_series():
    info = _rpc("common", "version")
    assert int(str(info["server_serie"]).split(".")[0].replace("saas~", "")) == SERIES


# --- GREEN: reads work through the MCP tool on every version -----------------------------------

@pytest.mark.asyncio
async def test_green_search_read_returns_partners():
    res = await tool("res.partner", "search_read", [[["is_company", "=", True]]], {"fields": ["name"], "limit": 3})
    data = json.loads(res)
    assert isinstance(data, list) and data and "name" in data[0]


@pytest.mark.asyncio
async def test_green_search_count():
    res = await tool("res.partner", "search_count", [[]])
    assert int(json.loads(res)) > 0


@pytest.mark.asyncio
async def test_green_fields_get_describes_sale_order():
    res = await tool("sale.order", "fields_get", [], {"attributes": ["type", "string"]})
    fields = json.loads(res)
    assert fields["partner_id"]["type"] == "many2one"


@pytest.mark.asyncio
async def test_green_read_group_aggregates_sales():
    res = await tool("sale.order", "read_group", [], {"domain": [], "fields": ["amount_total:sum"], "groupby": ["state"]})
    assert res.lstrip().startswith("["), res[:300]
    assert json.loads(res), "read_group returned no groups"


@pytest.mark.asyncio
async def test_name_get_compat_shim_works_on_every_version(admin):
    partner_id = admin.call("res.partner", "search", [[["is_company", "=", True]]], {"limit": 1})[0]
    res = await tool("res.partner", "name_get", [[partner_id]])
    data = json.loads(res)
    assert data[0][0] == partner_id and isinstance(data[0][1], str) and data[0][1]


@pytest.mark.asyncio
async def test_green_latency_is_reasonable():
    start = time.perf_counter()
    for _ in range(5):
        await tool("res.partner", "search_count", [[]])
    assert (time.perf_counter() - start) / 5 < 2.0


# --- Security: credential exfiltration paths are closed against the real ORM -------------------

@pytest.mark.asyncio
async def test_portal_access_tokens_are_redacted_when_fields_omitted(admin):
    order = admin.call("sale.order", "search_read", [[]], {"fields": ["id"], "limit": 1})[0]
    admin.call("sale.order", "read", [[order["id"]]], {"fields": ["access_url"]})
    token = admin.call("sale.order", "read", [[order["id"]]], {"fields": ["access_token"]})[0]["access_token"]
    res = await tool("sale.order", "search_read", [[["id", "=", order["id"]]]], {"limit": 1})
    assert "REDACTED" in res
    if token:
        assert token not in res


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "model,method,args",
    [
        ("res.config.settings", "default_get", [["google_gmail_client_secret"]]),
        ("res.users.apikeys", "search_read", [[]]),
        ("ir.config_parameter", "search_read", [[["key", "=", "database.secret"]]]),
        ("iap.account", "search_read", [[]]),
        ("res.users", "search_read", [[]]),
    ],
)
async def test_secret_models_blocked_before_reaching_odoo(model, method, args):
    res = await tool(model, method, args)
    assert "SECURITY ALERT" in res


# --- Security: C1 attack (guarded create re-pricing a confirmed order) never executes ----------

@pytest.mark.asyncio
async def test_c1_x2many_attack_is_not_executed_on_free_tier(admin):
    victim = _confirmed_order_line(admin)
    partner_id = admin.call("res.partner", "search", [[]], {"limit": 1})[0]
    payload = [{"partner_id": partner_id, "order_line": [[1, victim["id"], {"price_unit": 0.01}]]}]
    res = await tool("sale.order", "create", payload)
    assert "Read-Only" in res
    after = admin.call("sale.order.line", "read", [[victim["id"]]], {"fields": ["price_unit"]})[0]
    assert after["price_unit"] == victim["price_unit"]


@pytest.mark.asyncio
async def test_c1_id_list_line_theft_is_not_executed(admin):
    victim = _confirmed_order_line(admin)
    res = await tool("sale.order", "create", [{"partner_id": 1, "order_line": [victim["id"]]}])
    assert "Read-Only" in res
    after = admin.call("sale.order.line", "read", [[victim["id"]]], {"fields": ["order_id"]})[0]
    assert after["order_id"][0] == victim["order_id"][0]


@pytest.mark.asyncio
async def test_c1_x2many_attack_is_escalated_to_red_in_dry_run(monkeypatch, admin):
    monkeypatch.setenv("ODOO_DRY_RUN", "true")
    victim = _confirmed_order_line(admin)
    res = await tool("sale.order", "create", [{"partner_id": 1, "order_line": [[1, victim["id"], {"price_unit": 0.01}]]}])
    assert json.loads(res)["risk_level"] == "RED"


@pytest.mark.asyncio
async def test_c1_attack_routed_to_guard_never_runs_locally(monkeypatch, admin):
    """With a Pro key the call must go to the Guard (unreachable here), never straight to Odoo."""
    monkeypatch.setenv("ODOO_SAFE_GUARD_KEY", "testbed-fake-key")
    monkeypatch.setenv("ODOO_GUARD_URL", "http://127.0.0.1:9")
    victim = _confirmed_order_line(admin)
    res = await tool("sale.order", "create", [{"partner_id": 1, "order_line": [[1, victim["id"], {"price_unit": 0.01}]]}])
    assert "Guard Proxy Communication Error" in res
    after = admin.call("sale.order.line", "read", [[victim["id"]]], {"fields": ["price_unit"]})[0]
    assert after["price_unit"] == victim["price_unit"]


# --- Defence in depth: the recommended bot user is least-privilege inside Odoo itself ----------

def test_bot_user_cannot_read_system_parameters_directly(bot):
    with pytest.raises(RuntimeError):
        bot.call("ir.config_parameter", "search_read", [[]], {"limit": 1})


def test_bot_user_cannot_escalate_privileges_directly(bot, admin):
    """Renaming itself is allowed by Odoo (preferences); granting itself admin rights must not be."""
    user_fields = admin.call("res.users", "fields_get", [], {"attributes": ["type"]})
    groups_field = "group_ids" if "group_ids" in user_fields else "groups_id"
    system_group = admin.call(
        "ir.model.data",
        "search_read",
        [[["module", "=", "base"], ["name", "=", "group_system"]]],
        {"fields": ["res_id"], "limit": 1},
    )[0]["res_id"]
    with pytest.raises(RuntimeError):
        bot.call("res.users", "write", [[bot.uid], {groups_field: [[4, system_group]]}])
    with pytest.raises(RuntimeError):
        bot.call("res.users", "write", [[admin.uid], {"login": "pwned"}])
    with pytest.raises(RuntimeError):
        bot.call("res.groups", "create", [{"name": "pwned"}])
    groups = admin.call("res.users", "read", [[bot.uid]], {"fields": [groups_field]})[0][groups_field]
    assert system_group not in groups


# --- Worker compatibility: how the Chatter audit note must be posted on this version -----------

def test_chatter_audit_note_renders_as_html(admin):
    """
    The Guard Worker posts '<b>[Odoo Safe MCP]</b> ...' through message_post over RPC.
    Odoo 17+ escapes plain-string bodies; body_is_html=True is needed there. This test pins
    which strategy renders on the current version so the Worker can use the right one.
    """
    order_id = admin.call("sale.order", "search", [[]], {"limit": 1})[0]
    body = "<b>[Odoo Safe MCP testbed]</b> audit note"
    strategies = [{}, {"body_is_html": True}]
    rendered_with = None
    for extra in strategies:
        try:
            msg_id = admin.call(
                "sale.order",
                "message_post",
                [[order_id]],
                {"body": body, "message_type": "comment", "subtype_xmlid": "mail.mt_note", **extra},
            )
        except RuntimeError:
            continue
        msg_id = msg_id[0] if isinstance(msg_id, list) else msg_id  # Odoo 19+ returns [id]
        stored = admin.call("mail.message", "read", [[msg_id]], {"fields": ["body"]})[0]["body"]
        if "<b>" in stored:
            rendered_with = extra
            break
    print(f"\n[Odoo {SERIES}] chatter HTML renders with: {rendered_with}")
    assert rendered_with is not None, "no message_post strategy renders HTML on this version"


# --- Forward compatibility: JSON-2 API (Odoo 19+) replaces /jsonrpc before Odoo 22 -------------

def test_json2_endpoint_available_on_19_plus():
    if SERIES < 19:
        pytest.skip("JSON-2 API exists from Odoo 19")
    response = httpx.post(
        f"{URL}/json/2/res.partner/search_count",
        json={"domain": []},
        headers={"Authorization": f"bearer {os.environ['ODOO_API_KEY']}", "X-Odoo-Database": DB},
        timeout=60,
    )
    assert response.status_code == 200, response.text[:300]
    assert int(response.json()) > 0


# --- Product UX with the recommended least-privilege user ---------------------------------------

@pytest.mark.asyncio
async def test_list_models_works_for_least_privilege_bot():
    from odoo_safe_mcp.server import odoo_list_models

    data = json.loads(await odoo_list_models())
    models = data["models"] if isinstance(data, dict) else [m["model"] for m in data]
    assert "sale.order" in models and "res.partner" in models


@pytest.mark.asyncio
async def test_curated_search_and_describe_on_real_odoo():
    from odoo_safe_mcp.server import odoo_describe_model, odoo_search

    rows = json.loads(await odoo_search("sale.order", domain=[["state", "in", ["sale", "done"]]], fields=["name", "amount_total"], limit=3))
    assert rows and {"name", "amount_total"} <= set(rows[0])
    schema = json.loads(await odoo_describe_model("sale.order"))
    assert schema["partner_id"]["type"] == "many2one" and "access_token" not in schema


@pytest.mark.asyncio
async def test_doctor_passes_for_testbed_bot(capsys):
    from odoo_safe_mcp.cli import run_doctor
    from odoo_safe_mcp.config import get_config

    assert await run_doctor(get_config()) == 0
    out = capsys.readouterr().out
    assert "Least privilege" in out and "has an email" in out
