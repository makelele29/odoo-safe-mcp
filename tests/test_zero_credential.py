"""
Zero-credential approval flow (client side): the Guard decides and signs, this client verifies
and executes locally. These tests pin the security properties the product sells.
"""

import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from odoo_safe_mcp.server import odoo_approval_status, odoo_execute_kw

from .conftest import API_KEY, ODOO_URL, call_text


def _intent_id(text: str) -> str:
    return json.loads(text)["intent_id"]


# --- What leaves the machine ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_guard_never_receives_odoo_url_user_or_api_key(world):
    odoo, guard = world
    await call_text(odoo_execute_kw("crm.lead", "create", [{"name": "Nuevo lead"}]))
    await call_text(odoo_execute_kw("sale.order", "write", [[16], {"note": "x"}]))
    assert guard.requests, "the Guard should have been contacted"
    for req in guard.requests:
        assert API_KEY not in req["raw"]
        assert ODOO_URL not in req["raw"] and "erp.example.com" not in req["raw"]
        assert "ai-bot" not in req["raw"]
        assert API_KEY not in json.dumps(req["headers"])


# --- YELLOW: signed auto-approval, local execution, audit report ------------------------------

@pytest.mark.asyncio
async def test_guarded_draft_runs_locally_after_signed_auto_approval(world):
    odoo, guard = world
    res = json.loads(await odoo_execute_kw("crm.lead", "create", [{"name": "Nuevo lead"}], justification="Lead de la feria"))
    assert res["status"] == "EXECUTED" and res["risk_level"] == "YELLOW" and res["result"] == 42
    assert odoo.executed("create") == [("crm.lead", "create", [{"name": "Nuevo lead"}], {})]
    note = odoo.executed("message_post")[0]
    assert note[2] == [[42]] and note[3].get("body_is_html") is True
    assert guard.results[0]["outcome"] == "EXECUTED"
    assert guard.requests[0]["body"]["agent_justification"] == "Lead de la feria"


# --- RED: wait for a human, then execute exactly once ------------------------------------------

@pytest.mark.asyncio
async def test_critical_write_waits_for_approval_then_executes_once(world):
    odoo, guard = world
    pending = await odoo_execute_kw("sale.order", "write", [[16, 17], {"note": "Nuevo"}])
    intent_id = _intent_id(pending)
    assert json.loads(pending)["status"] == "PENDING_HUMAN_APPROVAL"
    assert not odoo.executed("write"), "nothing may change before the approval"

    still = json.loads(await odoo_approval_status(intent_id))
    assert still["status"] == "PENDING_HUMAN_APPROVAL"

    guard.auto_status = "APPROVED"
    done = json.loads(await odoo_approval_status(intent_id))
    assert done["status"] == "EXECUTED" and done["approved_by"] == "slack:U1:maria"
    assert odoo.executed("write") == [("sale.order", "write", [[16, 17], {"note": "Nuevo"}], {})]
    assert "maria" in odoo.executed("message_post")[0][3]["body"]

    again = json.loads(await odoo_approval_status(intent_id))
    assert again["status"] == "EXECUTED"
    assert len(odoo.executed("write")) == 1, "an approval is single-use"
    assert [r["outcome"] for r in guard.results] == ["EXECUTED"]


@pytest.mark.asyncio
async def test_rejected_change_is_never_executed(world):
    odoo, guard = world
    intent_id = _intent_id(await odoo_execute_kw("sale.order", "unlink", [[16]]))
    guard.auto_status = "REJECTED"
    text = await call_text(odoo_approval_status(intent_id))
    assert "Rejected" in text and not odoo.executed("unlink")


@pytest.mark.asyncio
async def test_inline_wait_executes_when_approved_quickly(world, monkeypatch):
    odoo, guard = world
    monkeypatch.setenv("ODOO_APPROVAL_WAIT_SECONDS", "5")
    guard.auto_status = "APPROVED"
    res = json.loads(await odoo_execute_kw("sale.order", "action_confirm", [[16]]))
    assert res["status"] == "EXECUTED"
    assert odoo.executed("action_confirm")


# --- Signature and binding checks: a compromised Guard cannot make us run anything -------------

@pytest.mark.asyncio
async def test_forged_signature_is_refused(world):
    odoo, guard = world
    guard.sign_with = Ed25519PrivateKey.generate()
    text = await call_text(odoo_execute_kw("crm.lead", "create", [{"name": "x"}]))
    assert "Invalid Guard signature" in text
    assert not odoo.executed("create")


@pytest.mark.parametrize(
    "override,label",
    [
        ({"op_sha256": "0" * 64}, "operation hash"),
        ({"db": "other_db"}, "database"),
        ({"license": "f" * 64}, "licence"),
        ({"exp": 1}, "expiry"),
        ({"decision": "REJECTED"}, "approved"),
    ],
)
@pytest.mark.asyncio
async def test_decision_bound_to_operation_db_licence_and_time(world, override, label):
    odoo, guard = world
    guard.decision_overrides = override
    text = await call_text(odoo_execute_kw("crm.lead", "create", [{"name": "x"}]))
    assert label in text and "Nothing was executed" in text
    assert not odoo.executed("create")


@pytest.mark.asyncio
async def test_tampered_local_operation_is_refused(world):
    odoo, guard = world
    intent_id = _intent_id(await odoo_execute_kw("sale.order", "write", [[16], {"note": "ok"}]))
    state = Path(os.environ["ODOO_SAFE_STATE_DIR"]) / "intents" / f"{intent_id}.json"
    data = json.loads(state.read_text(encoding="utf-8"))
    data["op_json"] = data["op_json"].replace('"ok"', '"pwned"')
    state.write_text(json.dumps(data), encoding="utf-8")
    guard.auto_status = "APPROVED"
    text = await call_text(odoo_approval_status(intent_id))
    assert "operation hash" in text and not odoo.executed("write")


@pytest.mark.asyncio
async def test_no_trusted_key_fails_closed(world, monkeypatch):
    odoo, _ = world
    monkeypatch.delenv("ODOO_GUARD_PUBLIC_KEYS")
    text = await call_text(odoo_execute_kw("crm.lead", "create", [{"name": "x"}]))
    assert "No trusted Guard signing key" in text and not odoo.executed("create")


@pytest.mark.parametrize("bad_id", ["../../etc/passwd", "not-a-uuid", "", "12345678-1234-1234-1234-1234567890ab/../x"])
@pytest.mark.asyncio
async def test_approval_status_rejects_invalid_or_foreign_ids(world, bad_id):
    assert "Invalid intent_id" in await call_text(odoo_approval_status(bad_id))


@pytest.mark.asyncio
async def test_approval_status_only_for_intents_proposed_here(world):
    text = await call_text(odoo_approval_status("12345678-1234-1234-1234-1234567890ab"))
    assert "Unknown intent_id on this machine" in text


# --- Kill-switch and licence errors are explained to the agent ----------------------------------

@pytest.mark.asyncio
async def test_kill_switch_blocks_writes_with_clear_message(world):
    odoo, guard = world
    guard.paused = True
    text = await call_text(odoo_execute_kw("crm.lead", "create", [{"name": "x"}]))
    assert "Kill-switch active" in text and not odoo.executed("create")


# --- The approver sees the real change, computed from Odoo, not from the agent's words -----------

@pytest.mark.asyncio
async def test_preview_shows_records_amounts_and_before_after(world):
    _, guard = world
    await odoo_execute_kw("sale.order", "write", [[16, 17], {"note": "Nuevo"}], justification="Solo 1 pedido")
    preview = guard.requests[0]["body"]["preview"]
    assert preview["record_count"] == 2
    assert [r["name"] for r in preview["records"]] == ["S00016", "S00017"]
    assert preview["amount_total"] == 2000.0 and preview["currency"] == "EUR"
    assert preview["changes"] == [{"field": "note", "label": "Terms and conditions", "before": "old", "after": "Nuevo"}]
    assert preview["summary"] == "Modificar 2 registro(s) de Sales Order"


@pytest.mark.asyncio
async def test_preview_flags_irreversible_deletes_and_missing_ids(world):
    _, guard = world
    await odoo_execute_kw("sale.order", "unlink", [[16, 999]])
    preview = guard.requests[0]["body"]["preview"]
    assert any("irreversible" in w for w in preview["warnings"])
    assert any("no existen" in w for w in preview["warnings"])
