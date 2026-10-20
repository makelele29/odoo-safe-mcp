"""
End-to-end: real Odoo (testbed) + real Guard Worker (wrangler dev, local D1) + fake Slack.
Started by odoo-test-environments/testbed/run_e2e.py; skipped unless ODOO_E2E=1.

It proves the product promise on real software:
  * the Guard never stores Odoo URL / user / API key,
  * the approver sees the real change (record names, before -> after),
  * nothing changes in Odoo until a human approves, and an approval executes once,
  * signed links cannot be forged, reused, or turned from "reject" into "approve",
  * the kill-switch stops every AI write.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List

import httpx
import pytest

from odoo_safe_mcp.server import odoo_approval_status, odoo_execute_kw

from ..conftest import call_text

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(os.getenv("ODOO_E2E") != "1", reason="E2E stack (testbed Odoo + wrangler dev) not running"),
]

WORKER = os.getenv("E2E_WORKER_URL", "http://127.0.0.1:8787")
SINK_PORT = int(os.getenv("E2E_SINK_PORT", "8799"))
URL = os.getenv("ODOO_URL", "")
DB = os.getenv("ODOO_DB", "")
LICENSE = os.getenv("ODOO_SAFE_GUARD_KEY", "")


# --- Fake Slack incoming webhook -------------------------------------------------------------------

class _Sink(BaseHTTPRequestHandler):
    messages: List[Dict[str, Any]] = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        _Sink.messages.append(json.loads(body or b"{}"))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module", autouse=True)
def slack_sink():
    server = ThreadingHTTPServer(("127.0.0.1", SINK_PORT), _Sink)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield _Sink.messages
    server.shutdown()


@pytest.fixture(autouse=True)
def pro_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ODOO_GUARD_URL", WORKER)
    monkeypatch.setenv("ODOO_SAFE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ODOO_APPROVAL_WAIT_SECONDS", "0")
    monkeypatch.delenv("ODOO_DRY_RUN", raising=False)
    httpx.post(f"{WORKER}/v2/kill-switch", json={"paused": False}, headers={"Authorization": f"Bearer {LICENSE}"}, timeout=30)


def _admin(model: str, method: str, args: list, kwargs: dict | None = None) -> Any:
    uid = _rpc("common", "authenticate", DB, os.environ["ODOO_ADMIN_LOGIN"], os.environ["ODOO_ADMIN_PASSWORD"], {})
    return _rpc("object", "execute_kw", DB, uid, os.environ["ODOO_ADMIN_PASSWORD"], model, method, args, kwargs or {})


def _rpc(service: str, method: str, *args: Any) -> Any:
    data = httpx.post(f"{URL}/jsonrpc", json={"jsonrpc": "2.0", "method": "call", "params": {"service": service, "method": method, "args": list(args)}}, timeout=60).json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return data["result"]


def _card_text(card: Dict[str, Any]) -> str:
    return json.dumps(card, ensure_ascii=False)


def _review_links(card: Dict[str, Any]) -> Dict[str, str]:
    links = {}
    for block in card["attachments"][0]["blocks"]:
        for element in block.get("elements", []):
            if element.get("type") == "button" and element.get("url"):
                links["approve" if element["action_id"] == "approve_job" else "reject"] = element["url"]
    return links


def _decide(link: str) -> httpx.Response:
    page = httpx.get(link, timeout=30)
    assert page.status_code == 200, page.text[:300]
    form = dict(re.findall(r'name="(intent|action|token)" value="([^"]*)"', page.text))
    return httpx.post(f"{WORKER}/v2/review", data=form, timeout=30)


def _new_lead(name: str) -> int:
    return _admin("crm.lead", "create", [{"name": name}])


async def _propose_rename(lead_id: str | int, new_name: str, sink: list) -> tuple[str, Dict[str, Any]]:
    before = len(sink)
    res = json.loads(await odoo_execute_kw("crm.lead", "write", [[lead_id], {"name": new_name}], justification="Corregir el nombre del lead"))
    assert res["status"] == "PENDING_HUMAN_APPROVAL"
    assert len(sink) == before + 1, "the approver must receive exactly one card"
    return res["intent_id"], sink[-1]


# --- Tests -----------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_guarded_draft_is_created_locally_with_rendered_audit_note():
    name = f"E2E lead {uuid.uuid4().hex[:6]}"
    res = json.loads(await odoo_execute_kw("crm.lead", "create", [{"name": name}], justification="Lead de prueba E2E"))
    assert res["status"] == "EXECUTED" and res["risk_level"] == "YELLOW"
    lead = _admin("crm.lead", "read", [[res["result"]]], {"fields": ["name"]})[0]
    assert lead["name"] == name
    notes = _admin("mail.message", "search_read", [[["model", "=", "crm.lead"], ["res_id", "=", res["result"]], ["body", "ilike", "Odoo Safe MCP"]]], {"fields": ["body"]})
    assert notes and "<b>" in notes[0]["body"], "audit note must render as HTML in the Chatter"


@pytest.mark.asyncio
async def test_critical_write_full_cycle_with_signed_web_approval(slack_sink):
    lead_id = _new_lead("Lead original E2E")
    intent_id, card = await _propose_rename(lead_id, "Lead renombrado E2E", slack_sink)
    text = _card_text(card)
    assert "Lead original E2E" in text, "approver must see the real record name"
    assert "Lead original E2E` → `Lead renombrado E2E" in text, "approver must see before → after"
    assert "no verificado" in text, "agent justification is labelled as unverified"
    assert _admin("crm.lead", "read", [[lead_id]], {"fields": ["name"]})[0]["name"] == "Lead original E2E"

    pending = json.loads(await odoo_approval_status(intent_id))
    assert pending["status"] == "PENDING_HUMAN_APPROVAL"

    decision = _decide(_review_links(card)["approve"])
    assert decision.status_code == 200 and "aprobada" in decision.text.lower()

    done = json.loads(await odoo_approval_status(intent_id))
    assert done["status"] == "EXECUTED" and done["approved_by"] == "web_supervisor"
    assert _admin("crm.lead", "read", [[lead_id]], {"fields": ["name"]})[0]["name"] == "Lead renombrado E2E"

    status = httpx.get(f"{WORKER}/v2/intents/{intent_id}", headers={"Authorization": f"Bearer {LICENSE}"}, timeout=30).json()
    assert status["status"] == "EXECUTED" and "decision" not in status

    again = json.loads(await odoo_approval_status(intent_id))
    assert again["status"] == "EXECUTED"


@pytest.mark.asyncio
async def test_rejected_change_never_touches_odoo(slack_sink):
    lead_id = _new_lead("Lead que no debe cambiar")
    intent_id, card = await _propose_rename(lead_id, "pwned", slack_sink)
    assert _decide(_review_links(card)["reject"]).status_code == 200
    text = await call_text(odoo_approval_status(intent_id))
    assert "Rejected" in text
    assert _admin("crm.lead", "read", [[lead_id]], {"fields": ["name"]})[0]["name"] == "Lead que no debe cambiar"


@pytest.mark.asyncio
async def test_signed_links_cannot_be_forged_swapped_or_reused(slack_sink):
    lead_id = _new_lead("Lead enlaces E2E")
    intent_id, card = await _propose_rename(lead_id, "Lead enlaces cambiado", slack_sink)
    links = _review_links(card)

    forged = re.sub(r"token=[0-9a-f]+", "token=" + "0" * 64, links["approve"])
    assert httpx.get(forged, timeout=30).status_code == 404
    swapped = links["reject"].replace("action=reject", "action=approve")
    assert httpx.get(swapped, timeout=30).status_code == 404, "a reject link must not approve"

    assert _decide(links["approve"]).status_code == 200
    reused = httpx.get(links["approve"], timeout=30)
    assert "ya resuelta" in reused.text.lower()
    json.loads(await odoo_approval_status(intent_id))


@pytest.mark.asyncio
async def test_c1_attack_with_pro_licence_waits_for_human(slack_sink):
    victim = _admin(
        "sale.order.line",
        "search_read",
        [[["order_id.state", "in", ["sale", "done"]], ["display_type", "=", False]]],
        {"fields": ["id", "price_unit"], "limit": 1},
    )[0]
    res = json.loads(await odoo_execute_kw("sale.order", "create", [{"partner_id": 1, "order_line": [[1, victim["id"], {"price_unit": 0.01}]]}]))
    assert res["status"] == "PENDING_HUMAN_APPROVAL" and res["risk_level"] == "RED"
    assert _admin("sale.order.line", "read", [[victim["id"]]], {"fields": ["price_unit"]})[0]["price_unit"] == victim["price_unit"]
    _decide(_review_links(slack_sink[-1])["reject"])


@pytest.mark.asyncio
async def test_kill_switch_stops_every_ai_write():
    headers = {"Authorization": f"Bearer {LICENSE}"}
    assert httpx.post(f"{WORKER}/v2/kill-switch", json={"paused": True}, headers=headers, timeout=30).json() == {"writes_paused": True}
    text = await call_text(odoo_execute_kw("crm.lead", "create", [{"name": "No debe crearse"}]))
    assert "Kill-switch active" in text
    assert not _admin("crm.lead", "search", [[["name", "=", "No debe crearse"]]])
    httpx.post(f"{WORKER}/v2/kill-switch", json={"paused": False}, headers=headers, timeout=30)


def test_guard_database_never_contains_odoo_credentials():
    """Dump every table of the local D1 and look for the bot API key, login and Odoo URL."""
    persist = os.environ["E2E_D1_PERSIST"]
    guard_dir = os.environ["E2E_GUARD_DIR"]
    dump = ""
    for table in ("licenses", "allowed_databases", "frozen_jobs", "audit_logs", "intents"):
        out = subprocess.run(
            ["npx", "wrangler", "d1", "execute", "odoo-safe-enterprise-db", "--local", "--persist-to", persist, "--json", "--command", f"SELECT * FROM {table}"],
            cwd=guard_dir, capture_output=True, text=True, encoding="utf-8", errors="replace", shell=os.name == "nt",
        )
        assert out.returncode == 0, out.stderr[-500:]
        dump += out.stdout
    assert '"intents"' in dump or "intent_id" in dump
    assert os.environ["ODOO_API_KEY"] not in dump
    assert URL not in dump
    assert os.environ["ODOO_USERNAME"] not in dump
