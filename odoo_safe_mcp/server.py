"""
Odoo Safe MCP Server.
Provides a deterministic security firewall between AI Agents and Odoo ERP.

Reads (GREEN) run locally. Writes go through the Pro Guard API v2: the Guard decides (policy and/or
a human on Slack/Teams) and signs the decision; this process verifies the signature and executes
locally with the user's own credentials, which never leave the machine.
"""

from __future__ import annotations

import asyncio
import html
import json
import time
from typing import Any, Dict, List, Optional, Union

from odoo_safe_mcp import __version__
from odoo_safe_mcp.config import Config, get_config, sanitize_error
from odoo_safe_mcp.guard import GuardClient, GuardError, canonical_op_json
from odoo_safe_mcp.odoo import OdooClient, open_client
from odoo_safe_mcp.pending import PendingStore, PendingStoreError, valid_intent_id
from odoo_safe_mcp.preview import build_preview
from odoo_safe_mcp.rules import (
    RiskLevel,
    RuleEvaluationResult,
    _is_sensitive_field,
    evaluate_odoo_call,
    evaluate_rule,
    redact_pii_output,
    redact_sensitive_output,
)
from odoo_safe_mcp.trust import DecisionError, sha256_hex, verify_decision

INSTRUCTIONS = (
    "Secure gateway to Odoo ERP. Prefer odoo_search / odoo_read / odoo_count / odoo_aggregate for questions and "
    "odoo_describe_model(model, search=...) before writing (especially to find x_* Studio fields). Writes go through "
    "odoo_execute_kw: drafts may run immediately, critical operations wait for human approval (check pending items "
    "anytime with odoo_pending_approvals and execute them with odoo_approval_status). Always pass a short, honest "
    "'justification' for writes: the approver sees it next to the real change."
)

# Support both mcp 2.x (MCPServer) and mcp 1.x (FastMCP)
try:
    from mcp.server.mcpserver import MCPServer
    from mcp.server.mcpserver.exceptions import ToolError

    mcp_server = MCPServer(name="odoo-safe-mcp", version=__version__, instructions=INSTRUCTIONS)
except ImportError:  # pragma: no cover - exercised only with mcp 1.x
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.exceptions import ToolError

    mcp_server = FastMCP("odoo-safe-mcp", instructions=INSTRUCTIONS)

try:
    from mcp.types import ToolAnnotations

    READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
    MAY_WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False)
except Exception:  # pragma: no cover
    READ_ONLY = MAY_WRITE = None


def _tool(annotations):
    try:
        return mcp_server.tool(annotations=annotations)
    except TypeError:  # pragma: no cover - very old SDKs
        return mcp_server.tool()


class OdooSafeError(ToolError):
    """Reported to the agent as an MCP error result (isError=true)."""


MISSING_CREDENTIALS = (
    "⚠️ Configuration Error: Missing required Odoo credentials. "
    "Please configure ODOO_URL, ODOO_DB, ODOO_USERNAME, and ODOO_API_KEY."
)
MAX_TEXT = 1000
MAX_OUTPUT_BYTES = 60_000
_SCHEMA_CACHE: Dict[tuple, Dict[str, Any]] = {}

# Curated lightweight projections (8-12 key fields) to avoid token bloat on 150+ field models
DEFAULT_FIELD_PROFILES: Dict[str, List[str]] = {
    "res.partner": ["id", "name", "display_name", "is_company", "email", "phone", "vat", "city", "country_id", "customer_rank", "supplier_rank"],
    "sale.order": ["id", "name", "partner_id", "date_order", "state", "amount_untaxed", "amount_total", "currency_id", "invoice_status", "user_id"],
    "purchase.order": ["id", "name", "partner_id", "date_order", "state", "amount_untaxed", "amount_total", "currency_id", "invoice_status", "user_id"],
    "account.move": ["id", "name", "move_type", "partner_id", "invoice_date", "invoice_date_due", "state", "payment_state", "amount_total", "amount_residual", "currency_id"],
    "product.product": ["id", "name", "default_code", "barcode", "type", "list_price", "standard_price", "qty_available", "categ_id", "active"],
    "product.template": ["id", "name", "default_code", "type", "list_price", "standard_price", "qty_available", "categ_id", "sale_ok", "purchase_ok", "active"],
    "crm.lead": ["id", "name", "type", "partner_id", "email_from", "phone", "stage_id", "expected_revenue", "probability", "user_id"],
    "stock.picking": ["id", "name", "picking_type_id", "partner_id", "origin", "scheduled_date", "date_done", "state", "location_id", "location_dest_id"],
    "project.task": ["id", "name", "project_id", "stage_id", "user_ids", "date_deadline", "priority", "state"],
    "hr.employee": ["id", "name", "job_title", "department_id", "work_email", "work_phone", "parent_id", "company_id", "active"],
}


# --- Normalisation of LLM arguments --------------------------------------------------------------

def _normalize_list(val: Any) -> List[Any]:
    if val is None:
        return []
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        val = val.strip()
        if not val:
            return []
        try:
            parsed = json.loads(val)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            return [val]
    return [val]


def _normalize_dict(val: Any) -> Dict[str, Any]:
    if val is None:
        return {}
    if isinstance(val, dict):
        return val
    if isinstance(val, str):
        val = val.strip()
        if not val:
            return {}
        try:
            parsed = json.loads(val)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


def _dumps(data: Any) -> str:
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


def _dumps_bounded(data: Any, max_bytes: int = MAX_OUTPUT_BYTES) -> str:
    """Serialise tool output and enforce a hard byte ceiling so large Odoo pages cannot blow LLM context."""
    raw = _dumps(data)
    if len(raw.encode("utf-8")) <= max_bytes:
        return raw
    compact = json.dumps(data, separators=(",", ":"), default=str, ensure_ascii=False)
    if len(compact.encode("utf-8")) <= max_bytes:
        return compact
    if isinstance(data, list):
        kept: List[Any] = []
        for item in data:
            candidate = json.dumps(
                {
                    "records": [*kept, item],
                    "_truncated": True,
                    "_returned": len(kept) + 1,
                    "_total_in_page": len(data),
                    "_hint": "Response exceeded 60KB budget. Pass explicit 'fields' or reduce 'limit'.",
                },
                separators=(",", ":"),
                default=str,
                ensure_ascii=False,
            )
            if len(candidate.encode("utf-8")) > max_bytes:
                break
            kept.append(item)
        return json.dumps(
            {
                "records": kept,
                "_truncated": True,
                "_returned": len(kept),
                "_total_in_page": len(data),
                "_hint": "Response exceeded 60KB budget. Pass explicit 'fields' or reduce 'limit'.",
            },
            separators=(",", ":"),
            default=str,
            ensure_ascii=False,
        )
    return compact[: max_bytes - 64] + '..."_truncated_bytes":true}'


def _compact(value: Any) -> Any:
    """Trim long texts (HTML bodies, descriptions) so answers stay cheap in tokens."""
    if isinstance(value, str) and len(value) > MAX_TEXT:
        return value[:MAX_TEXT] + f"… [truncated {len(value) - MAX_TEXT} chars]"
    if isinstance(value, list):
        return [_compact(v) for v in value]
    if isinstance(value, dict):
        return {k: _compact(v) for k, v in value.items()}
    return value


# --- Odoo execution seam (patched in unit tests) -----------------------------------------------

async def _execute_local_odoo(cfg: Config, model: str, method: str, args: List[Any], kwargs: Dict[str, Any]) -> Any:
    async with open_client(cfg) as client:
        return await OdooClient(cfg, client).execute(model, method, args, kwargs)


# --- Guarded writes (zero-credential) ----------------------------------------------------------

def _note_html(risk: str, model: str, method: str, approver: str, op_sha: str) -> str:
    if risk == RiskLevel.YELLOW.value:
        return (
            "🤖 <b>[Odoo Safe MCP]</b> Creado en borrador por un agente de IA bajo la política de borradores protegidos."
            f" Huella <code>{op_sha[:12]}</code>."
        )
    who = html.escape(approver.split(":")[-1] if approver else "supervisor")
    return (
        f"🛡️ <b>[Odoo Safe MCP]</b> Operación <code>{html.escape(model)}.{html.escape(method)}</code> aprobada por "
        f"<b>{who}</b> y ejecutada por el agente de IA. Huella <code>{op_sha[:12]}</code>."
    )


def _record_ids_for_note(method: str, args: List[Any], result: Any) -> List[int]:
    if method == "unlink":
        return []
    if method == "create":
        if isinstance(result, int):
            return [result]
        if isinstance(result, list):
            return [r for r in result if isinstance(r, int)][:5]
        return []
    first = args[0] if args else None
    if isinstance(first, list):
        return [r for r in first if isinstance(r, int) and not isinstance(r, bool)][:5]
    return []


async def _execute_approved(cfg: Config, guard: GuardClient, store: PendingStore, intent_id: str, op_json: str, signed: Dict[str, Any]) -> str:
    decision = verify_decision(
        signed.get("decision") or "",
        signed.get("signature") or "",
        signed.get("kid") or "",
        intent_id=intent_id,
        op_json=op_json,
        db=cfg.db,
        guard_key=cfg.guard_key,
    )
    store.claim(intent_id)
    op = json.loads(op_json)
    op_sha = sha256_hex(op_json)
    try:
        result = await _execute_local_odoo(cfg, op["model"], op["method"], op["args"], op["kwargs"])
    except Exception as exc:
        error = sanitize_error(str(exc), cfg)
        await guard.report_result(intent_id, "FAILED", detail=error)
        store.record_result(intent_id, {"status": "EXECUTION_FAILED", "error": error})
        raise OdooSafeError(f"❌ Approved, but Odoo rejected the operation: {error}") from exc

    note_ids = _record_ids_for_note(op["method"], op["args"], result)
    notes_posted = 0
    async with open_client(cfg) as client:
        odoo = OdooClient(cfg, client)
        for record_id in note_ids:
            notes_posted += await odoo.post_note(op["model"], record_id, _note_html(decision["risk"], op["model"], op["method"], decision.get("approver", ""), op_sha))

    await guard.report_result(intent_id, "EXECUTED", result_sha256=sha256_hex(json.dumps(result, default=str)))
    summary = {
        "status": "EXECUTED",
        "risk_level": decision["risk"],
        "intent_id": intent_id,
        "approved_by": decision.get("approver"),
        "result": redact_pii_output(redact_sensitive_output(result), cfg.pii_mode),
    }
    if note_ids and not notes_posted:
        summary["audit_note"] = "Not posted in the Chatter: give the AI user an email address in Odoo (run odoo-safe-mcp doctor)."
    store.record_result(intent_id, summary)
    return _dumps(summary)


def _pending_message(intent_id: str, resp: Dict[str, Any]) -> str:
    return _dumps(
        {
            "status": "PENDING_HUMAN_APPROVAL",
            "intent_id": intent_id,
            "risk_level": resp.get("risk_level", "RED"),
            "expires_at": resp.get("expires_at"),
            "reason": resp.get("reason"),
            "next_step": (
                "A human must approve this in Slack/Teams/Telegram/web. Nothing has changed in Odoo yet. "
                f"Call odoo_approval_status(intent_id='{intent_id}') later to execute it once approved "
                "(or use odoo_pending_approvals to list pending requests in a new session)."
            ),
        }
    )


async def _resolve(cfg: Config, guard: GuardClient, store: PendingStore, intent_id: str, op_json: str, wait: float) -> Optional[str]:
    """Poll the Guard for up to `wait` seconds. Returns the final answer, or None if still pending."""
    deadline = time.monotonic() + wait
    while True:
        status = await guard.get_intent(intent_id)
        state = status.get("status")
        if state == "APPROVED":
            return await _execute_approved(cfg, guard, store, intent_id, op_json, status)
        if state in ("REJECTED", "EXPIRED", "EXECUTED", "EXECUTION_FAILED"):
            previous = store.result(intent_id)
            if previous:
                return _dumps(previous)
            if state == "REJECTED":
                raise OdooSafeError(f"⛔ Rejected by {status.get('resolved_by') or 'the approver'}. Nothing was changed in Odoo.")
            raise OdooSafeError(f"Approval request is {state}. Nothing was executed; propose the change again if still needed.")
        if time.monotonic() >= deadline:
            return None
        await asyncio.sleep(min(3.0, max(0.0, deadline - time.monotonic())))


async def _guarded_write(cfg: Config, model: str, method: str, eval_res: RuleEvaluationResult, justification: str) -> str:
    op_json = canonical_op_json(cfg, model, method, eval_res.sanitized_args, eval_res.sanitized_kwargs)
    store = PendingStore(cfg.state_dir)
    async with open_client(cfg) as client:
        guard = GuardClient(cfg, client)
        try:
            preview = await build_preview(OdooClient(cfg, client), model, method, eval_res.sanitized_args, eval_res.sanitized_kwargs)
        except Exception:
            preview = {"warnings": ["Vista previa no disponible."]}
        require_approval_reason = None
        if (
            cfg.draft_max_amount is not None
            and eval_res.level == RiskLevel.YELLOW
            and isinstance(preview.get("amount_total"), (int, float))
            and float(preview["amount_total"]) > cfg.draft_max_amount
        ):
            require_approval_reason = (
                f"Draft total ({float(preview['amount_total']):.2f}) exceeds ODOO_DRAFT_MAX_AMOUNT ({cfg.draft_max_amount:.2f})."
            )
            preview.setdefault("warnings", []).append(require_approval_reason)
        resp = await guard.create_intent(
            op_json,
            preview,
            justification or eval_res.audit_note or "",
            require_approval_reason=require_approval_reason,
        )
        intent_id = str(resp.get("intent_id") or "")
        if not valid_intent_id(intent_id):
            raise OdooSafeError("Pro Guard returned an invalid intent id. Nothing was executed.")
        store.save(intent_id, op_json, {"model": model, "method": method, "db": cfg.db, "risk": resp.get("risk_level")})
        if resp.get("status") == "APPROVED":
            return await _execute_approved(cfg, guard, store, intent_id, op_json, resp)
        if resp.get("status") != "PENDING_HUMAN_APPROVAL":
            raise OdooSafeError(f"Unexpected Pro Guard answer: {resp.get('status')}. Nothing was executed.")
        final = await _resolve(cfg, guard, store, intent_id, op_json, cfg.approval_wait) if cfg.approval_wait else None
        return final or _pending_message(intent_id, resp)


# --- Core entry point shared by every tool ------------------------------------------------------

async def _run_call(model: str, method: str, args: Any = None, kwargs: Any = None, justification: str = "") -> Any:
    """Apply the firewall and execute. Returns parsed data for reads, text for writes; raises OdooSafeError."""
    cfg = get_config()
    norm_args = _normalize_list(args)
    norm_kwargs = _normalize_dict(kwargs)

    # Dry-Run Simulation Mode (allows zero-risk local testing of YELLOW/RED policies)
    if cfg.dry_run:
        raw = evaluate_odoo_call(model=model, method=method, args=norm_args, kwargs=norm_kwargs)
        if raw.level in (RiskLevel.FORBIDDEN, RiskLevel.BLOCKED):
            raise OdooSafeError(raw.reason)
        if raw.level in (RiskLevel.YELLOW, RiskLevel.RED):
            return _dumps(
                {
                    "status": "DRY_RUN_SIMULATION",
                    "executed_in_odoo": False,
                    "risk_level": raw.level.value,
                    "model": model,
                    "method": method,
                    "sanitized_args": raw.sanitized_args,
                    "sanitized_kwargs": raw.sanitized_kwargs,
                    "audit_note": raw.audit_note,
                    "policy_decision": raw.reason,
                    "message": (
                        "Dry-Run active (ODOO_DRY_RUN=true): No changes were written to Odoo. "
                        "Disable ODOO_DRY_RUN and configure ODOO_SAFE_GUARD_KEY to execute in production."
                    ),
                }
            )

    eval_res = evaluate_rule(model=model, method=method, args=norm_args, kwargs=norm_kwargs, has_pro_license=cfg.has_pro)
    if not eval_res.allowed:
        raise OdooSafeError(eval_res.reason)
    if not cfg.has_credentials:
        raise OdooSafeError(MISSING_CREDENTIALS)

    if eval_res.level == RiskLevel.GREEN:
        try:
            result = await _execute_local_odoo(cfg, model, method, eval_res.sanitized_args, eval_res.sanitized_kwargs)
        except Exception as exc:
            raise OdooSafeError(f"❌ Error querying Odoo: {sanitize_error(str(exc), cfg)}") from exc
        return redact_pii_output(redact_sensitive_output(result), cfg.pii_mode)

    if eval_res.requires_guard_proxy:
        try:
            return await _guarded_write(cfg, model, method, eval_res, justification)
        except OdooSafeError:
            raise
        except (GuardError, DecisionError, PendingStoreError) as exc:
            raise OdooSafeError(sanitize_error(str(exc), cfg)) from exc
        except Exception as exc:
            raise OdooSafeError(f"❌ Guard Proxy Communication Error: {sanitize_error(str(exc), cfg)}") from exc

    raise OdooSafeError("⚠️ Unexpected evaluation state.")


# --- Tools ----------------------------------------------------------------------------------------

@_tool(READ_ONLY)
async def odoo_search(
    model: str,
    domain: Optional[Union[List[Any], str]] = None,
    fields: Optional[List[str]] = None,
    limit: int = 20,
    offset: int = 0,
    order: Optional[str] = None,
    all_fields: bool = False,
) -> str:
    """
    Search Odoo records and return their fields (search_read). Read-only.

    Args:
        model: Technical model, e.g. 'res.partner', 'sale.order', 'account.move'.
        domain: Odoo domain, e.g. [["state", "=", "sale"], ["amount_total", ">", 1000]].
        fields: Fields to return. Use odoo_describe_model to discover them; defaults to a lightweight profile on common models.
        limit: Max records (default 20, max 200).
        offset: Records to skip, for pagination.
        order: Sort, e.g. 'date_order desc'.
        all_fields: Set True only when you explicitly need all fields outside the lightweight default profile.
    """
    kwargs: Dict[str, Any] = {"limit": max(1, min(int(limit or 20), 200)), "offset": max(0, int(offset or 0))}
    norm_model = (model or "").strip().lower()
    if fields:
        kwargs["fields"] = fields
    elif not all_fields and norm_model in DEFAULT_FIELD_PROFILES:
        kwargs["fields"] = list(DEFAULT_FIELD_PROFILES[norm_model])
    else:
        kwargs["context"] = {"bin_size": True}
    if order:
        kwargs["order"] = order
    result = await _run_call(model, "search_read", [_normalize_list(domain)], kwargs)
    return _dumps_bounded(_compact(result))


@_tool(READ_ONLY)
async def odoo_read(model: str, ids: List[int], fields: Optional[List[str]] = None) -> str:
    """Read specific Odoo records by id. Read-only."""
    kwargs: Dict[str, Any] = {"fields": fields} if fields else {"context": {"bin_size": True}}
    return _dumps_bounded(_compact(await _run_call(model, "read", [ids[:200]], kwargs)))


@_tool(READ_ONLY)
async def odoo_count(model: str, domain: Optional[Union[List[Any], str]] = None) -> str:
    """Count Odoo records matching a domain. Read-only."""
    return _dumps(await _run_call(model, "search_count", [_normalize_list(domain)]))


@_tool(READ_ONLY)
async def odoo_aggregate(
    model: str,
    groupby: List[str],
    fields: Optional[List[str]] = None,
    domain: Optional[Union[List[Any], str]] = None,
    limit: Optional[int] = None,
) -> str:
    """
    Aggregate records (read_group): totals and counts grouped by fields. Read-only.

    Example: model='sale.order', groupby=['state'], fields=['amount_total:sum'].
    """
    kwargs: Dict[str, Any] = {"domain": _normalize_list(domain), "fields": fields or [], "groupby": groupby, "lazy": False}
    if limit:
        kwargs["limit"] = int(limit)
    return _dumps(_compact(await _run_call(model, "read_group", [], kwargs)))


@_tool(READ_ONLY)
async def odoo_describe_model(
    model: str,
    search: Optional[str] = None,
    include_readonly: bool = True,
) -> str:
    """
    Describe a model's fields (label, type, relation, required, readonly). Use before writing.

    Pass `search` (e.g. 'x_' or 'iban') to filter matching technical names or labels, or `include_readonly=False`
    to show only writable fields.
    """
    cfg = get_config()
    key = (cfg.url, cfg.db, model)
    if key not in _SCHEMA_CACHE:
        raw = await _run_call(model, "fields_get", [], {"attributes": ["string", "type", "relation", "required", "readonly", "selection"]})
        schema = {}
        for name, meta in (raw or {}).items():
            if _is_sensitive_field(name) or not isinstance(meta, dict):
                continue
            entry = {k: v for k, v in meta.items() if v not in (None, False, [], "")}
            if isinstance(entry.get("selection"), list):
                entry["selection"] = entry["selection"][:30]
            schema[name] = entry
        _SCHEMA_CACHE[key] = schema
    result = _SCHEMA_CACHE[key]
    if search or not include_readonly:
        needle = (search or "").strip().lower()
        result = {
            name: meta
            for name, meta in result.items()
            if (include_readonly or not meta.get("readonly"))
            and (not needle or needle in name.lower() or needle in str(meta.get("string", "")).lower())
        }
    return _dumps_bounded(result)


COMMON_MODELS = [
    "res.partner", "res.company", "res.currency", "product.product", "product.template", "product.category",
    "crm.lead", "crm.stage", "sale.order", "sale.order.line", "purchase.order", "purchase.order.line",
    "account.move", "account.move.line", "account.payment", "account.journal", "account.account", "account.tax",
    "stock.picking", "stock.move", "stock.quant", "stock.warehouse", "project.project", "project.task",
    "hr.employee", "hr.department", "mail.activity", "calendar.event", "helpdesk.ticket", "mrp.production",
]
_ACCESSIBLE_MODELS: Dict[tuple, List[str]] = {}


@_tool(READ_ONLY)
async def odoo_list_models(search: Optional[str] = None, limit: int = 50) -> str:
    """List installed business models (technical name and label), optionally filtered by text. Read-only."""
    domain: List[Any] = [["transient", "=", False]]
    if search:
        domain += ["|", ["model", "ilike", search], ["name", "ilike", search]]
    try:
        result = await _run_call("ir.model", "search_read", [domain], {"fields": ["model", "name"], "limit": max(1, min(int(limit or 50), 200))})
        return _dumps([{"model": r.get("model"), "name": r.get("name")} for r in result or []])
    except OdooSafeError as exc:
        if "not allowed" not in str(exc) and "Access" not in str(exc):
            raise
    # Least-privilege users cannot read ir.model: probe the usual business models instead.
    cfg = get_config()
    key = (cfg.url, cfg.db, cfg.username)
    if key not in _ACCESSIBLE_MODELS:
        found = []
        for model in COMMON_MODELS:
            try:
                await _run_call(model, "search_count", [[["id", "=", 0]]])
                found.append(model)
            except OdooSafeError:
                continue
        _ACCESSIBLE_MODELS[key] = found
    models = [m for m in _ACCESSIBLE_MODELS[key] if not search or search.lower() in m]
    return _dumps({"models": models, "note": "Common business models this user can read (no access to the full model registry)."})


@_tool(MAY_WRITE)
async def odoo_execute_kw(
    model: str,
    method: str,
    args: Optional[Union[List[Any], str]] = None,
    kwargs: Optional[Union[Dict[str, Any], str]] = None,
    justification: Optional[str] = None,
) -> str:
    """
    Safely execute any Odoo ORM method (execute_kw) through the firewall.

    Reads run immediately. Draft creations (sale.order, purchase.order, crm.lead) run under the
    guarded-draft policy. Critical operations (write, unlink, confirm, post...) wait for a human
    approval on Slack/Teams and are executed here only after a signed decision.

    Args:
        model: Odoo technical model name (e.g. 'sale.order', 'res.partner', 'account.move').
        method: ORM method name (e.g. 'search_read', 'create', 'write', 'action_confirm').
        args: Positional arguments (domains, record ids, value dictionaries).
        kwargs: Keyword arguments (e.g. {'fields': ['name'], 'limit': 10}).
        justification: One honest sentence on why (shown to the approver, marked as unverified).
    """
    result = await _run_call(model, method, args, kwargs, justification or "")
    return result if isinstance(result, str) else _dumps(result)


@_tool(MAY_WRITE)
async def odoo_approval_status(intent_id: str) -> str:
    """
    Check a write that is waiting for human approval. If it has been approved, it is executed now
    (once) and the result is returned. If rejected or expired, nothing is changed in Odoo.
    """
    cfg = get_config()
    if not cfg.has_pro:
        raise OdooSafeError("Approvals require ODOO_SAFE_GUARD_KEY (Pro Guard).")
    if not cfg.has_credentials:
        raise OdooSafeError(MISSING_CREDENTIALS)
    if not valid_intent_id(intent_id):
        raise OdooSafeError("Invalid intent_id.")
    store = PendingStore(cfg.state_dir)
    pending = store.load(intent_id)
    if not pending:
        raise OdooSafeError("Unknown intent_id on this machine: only the client that proposed a change can execute it.")
    previous = store.result(intent_id)
    if previous and previous.get("status") != "EXECUTION_FAILED" and "result" in previous:
        return _dumps(previous)
    try:
        async with open_client(cfg) as client:
            guard = GuardClient(cfg, client)
            final = await _resolve(cfg, guard, store, intent_id, pending["op_json"], 0)
        return final or _dumps({"status": "PENDING_HUMAN_APPROVAL", "intent_id": intent_id, "next_step": "Still waiting for a human decision."})
    except OdooSafeError:
        raise
    except (GuardError, DecisionError, PendingStoreError) as exc:
        raise OdooSafeError(sanitize_error(str(exc), cfg)) from exc


@_tool(READ_ONLY)
async def odoo_pending_approvals() -> str:
    """
    List critical Odoo changes proposed from this machine that have not been executed yet.

    Useful when resuming in a new chat after a human approved an operation in Slack, Teams, Telegram, or web.
    """
    cfg = get_config()
    items = PendingStore(cfg.state_dir).list_pending()
    return _dumps(
        {
            "pending": items,
            "count": len(items),
            "next_step": "Call odoo_approval_status(intent_id=...) for any request once a human has approved it.",
        }
    )


def main():  # pragma: no cover - kept for configs that point at odoo_safe_mcp.server:main
    from odoo_safe_mcp.cli import main as cli_main

    cli_main()


if __name__ == "__main__":  # pragma: no cover
    main()
