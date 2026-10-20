"""
Shared fixtures: an in-memory fake Odoo + fake Guard reachable through httpx.MockTransport,
so the whole zero-credential flow (preview, intent, signed decision, local execution, audit
report) runs in unit tests without any network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Any, Dict, List

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ODOO_URL = "https://erp.example.com"
GUARD_URL = "https://guard.example.com"
API_KEY = "odoo-api-key-SECRET-123"
GUARD_KEY = "LICENSE-KEY-0001"


async def call_text(coro) -> str:
    """Tool result as text, whether it returned or raised an MCP tool error."""
    try:
        return await coro
    except Exception as exc:  # OdooSafeError -> isError=true in MCP
        return str(exc)


def _raw_public(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


class FakeOdoo:
    def __init__(self):
        self.calls: List[tuple] = []
        self.records = {
            ("sale.order", 16): {"id": 16, "display_name": "S00016", "amount_total": 1750.0, "currency_id": [1, "EUR"], "note": "old"},
            ("sale.order", 17): {"id": 17, "display_name": "S00017", "amount_total": 250.0, "currency_id": [1, "EUR"], "note": "old"},
        }
        self.fields = {
            "display_name": {"string": "Display Name", "type": "char"},
            "amount_total": {"string": "Total", "type": "monetary"},
            "currency_id": {"string": "Currency", "type": "many2one"},
            "note": {"string": "Terms and conditions", "type": "html"},
            "name": {"string": "Name", "type": "char"},
        }

    def handle(self, params: Dict[str, Any]) -> Any:
        if params["service"] == "common":
            return 2 if params["method"] == "authenticate" else {"server_version": "18.0"}
        _db, _uid, _key, model, method, args, kwargs = params["args"]
        self.calls.append((model, method, args, kwargs))
        if model == "ir.model":
            return [{"name": "Sales Order"}]
        if method == "fields_get":
            return self.fields
        if method == "read":
            wanted = kwargs.get("fields") or list(self.fields)
            return [
                {"id": rid, **{f: rec.get(f) for f in wanted}}
                for rid in args[0]
                if (rec := self.records.get((model, rid)))
            ]
        if method == "create":
            return 42
        if method in ("write", "unlink", "action_confirm"):
            return True
        if method == "message_post":
            return 99
        if method in ("search_read",):
            return [{"id": 1, "name": "Azure Interior", "access_token": "portal-token"}]
        return True

    def executed(self, method: str) -> List[tuple]:
        return [c for c in self.calls if c[1] == method]


class FakeGuard:
    """Mimics the Worker API v2, including Ed25519 decisions signed with a test key."""

    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.kid = "test"
        self.requests: List[Dict[str, Any]] = []
        self.intents: Dict[str, Dict[str, Any]] = {}
        self.results: List[Dict[str, Any]] = []
        self.paused = False
        self.auto_status = "PENDING"  # what RED intents become on the next GET
        self.sign_with: Ed25519PrivateKey | None = None  # sign with another key (forgery tests)
        self.decision_overrides: Dict[str, Any] = {}

    @property
    def public_b64(self) -> str:
        return _raw_public(self.key)

    def decision_for(self, intent: Dict[str, Any], approver: str) -> Dict[str, str]:
        now = int(time.time())
        payload = {
            "v": 2,
            "kid": self.kid,
            "intent_id": intent["intent_id"],
            "license": hashlib.sha256(GUARD_KEY.encode()).hexdigest(),
            "db": intent["db"],
            "op_sha256": intent["op_sha256"],
            "decision": "APPROVED",
            "risk": intent["risk"],
            "approver": approver,
            "iat": now,
            "exp": now + 3600,
            **self.decision_overrides,
        }
        decision = json.dumps(payload)
        signer = self.sign_with or self.key
        return {"decision": decision, "signature": base64.b64encode(signer.sign(decision.encode())).decode(), "kid": self.kid}

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        self.requests.append({"path": request.url.path, "headers": dict(request.headers), "body": body, "raw": request.content.decode()})
        path = request.url.path
        if path == "/v2/intents" and request.method == "POST":
            if self.paused:
                return httpx.Response(423, json={"status": "WRITES_PAUSED"})
            op = json.loads(body["op_json"])
            risk = "YELLOW" if op["method"] == "create" and op["model"] in ("crm.lead", "sale.order", "purchase.order") else "RED"
            intent = {"intent_id": str(uuid.uuid4()), "db": op["db"], "op_sha256": body["op_sha256"], "risk": risk, "status": "PENDING"}
            self.intents[intent["intent_id"]] = intent
            if risk == "YELLOW":
                intent["status"] = "APPROVED"
                return httpx.Response(200, json={"status": "APPROVED", "risk_level": risk, "intent_id": intent["intent_id"], **self.decision_for(intent, "policy:guarded-draft")})
            return httpx.Response(200, json={"status": "PENDING_HUMAN_APPROVAL", "risk_level": risk, "intent_id": intent["intent_id"], "expires_at": "2099-01-01T00:00:00Z"})
        if path.startswith("/v2/intents/") and path.endswith("/result"):
            self.results.append({"intent_id": path.split("/")[3], **body})
            return httpx.Response(200, json={"status": body.get("outcome")})
        if path.startswith("/v2/intents/") and request.method == "GET":
            intent = self.intents.get(path.split("/")[3])
            if not intent:
                return httpx.Response(404, json={"error": "not found"})
            if intent["status"] == "PENDING" and self.auto_status != "PENDING":
                intent["status"] = self.auto_status
            out = {"intent_id": intent["intent_id"], "status": intent["status"], "resolved_by": "slack:U1:maria"}
            if intent["status"] == "APPROVED":
                out.update(self.decision_for(intent, "slack:U1:maria"))
            return httpx.Response(200, json=out)
        if path == "/v2/license":
            return httpx.Response(200, json={"plan": "PRO", "databases": ["demo"], "max_databases": 5, "approval_channels": {"slack": True}})
        if path == "/v2/keys":
            return httpx.Response(200, json={"keys": [{"kid": self.kid, "public_key": self.public_b64}]})
        return httpx.Response(404, json={"error": "unknown route"})


@pytest.fixture
def world(monkeypatch, tmp_path):
    """Pro-tier environment wired to the fake Odoo and fake Guard."""
    odoo, guard = FakeOdoo(), FakeGuard()

    def route(request: httpx.Request) -> httpx.Response:
        if request.url.host == "erp.example.com":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": odoo.handle(json.loads(request.content)["params"])})
        return guard.handle(request)

    transport = httpx.MockTransport(route)
    factory = lambda cfg: httpx.AsyncClient(transport=transport, timeout=5)  # noqa: E731
    monkeypatch.setattr("odoo_safe_mcp.server.open_client", factory)
    monkeypatch.setattr("odoo_safe_mcp.cli.open_client", factory)
    from odoo_safe_mcp import odoo as odoo_module

    odoo_module._UID_CACHE.clear()
    monkeypatch.setenv("ODOO_URL", ODOO_URL)
    monkeypatch.setenv("ODOO_DB", "demo")
    monkeypatch.setenv("ODOO_USERNAME", "ai-bot")
    monkeypatch.setenv("ODOO_API_KEY", API_KEY)
    monkeypatch.setenv("ODOO_SAFE_GUARD_KEY", GUARD_KEY)
    monkeypatch.setenv("ODOO_GUARD_URL", GUARD_URL)
    monkeypatch.setenv("ODOO_GUARD_PUBLIC_KEYS", f"{guard.kid}:{guard.public_b64}")
    monkeypatch.setenv("ODOO_SAFE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ODOO_APPROVAL_WAIT_SECONDS", "0")
    monkeypatch.delenv("ODOO_DRY_RUN", raising=False)
    return odoo, guard
