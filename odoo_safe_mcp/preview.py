"""
Human-readable preview of a proposed change, built locally with the user's own Odoo credentials.

This is what the approver sees on their phone: which records, what changes (before → after) and
the amount at stake. It is computed from the operation itself and from Odoo, never from the text
the agent writes, so a manipulated agent cannot hide what it is really asking for.
"""

from __future__ import annotations

from typing import Any, Dict, List

from odoo_safe_mcp.odoo import OdooClient
from odoo_safe_mcp.rules import redact_sensitive_output

MAX_RECORDS = 10
MAX_CHANGES = 15
AMOUNT_SAMPLE = 50

_VERBS = {
    "create": "Crear",
    "write": "Modificar",
    "unlink": "Eliminar",
    "action_post": "Validar/contabilizar",
    "action_confirm": "Confirmar",
    "button_validate": "Validar",
    "action_cancel": "Cancelar",
    "button_cancel": "Cancelar",
    "copy": "Duplicar",
}


def _short(value: Any) -> Any:
    if isinstance(value, str) and len(value) > 80:
        return value[:77] + "…"
    if isinstance(value, (list, dict)):
        text = str(value)
        return text if len(text) <= 80 else text[:77] + "…"
    return value


def _ids_from_args(args: List[Any]) -> List[int] | None:
    first = args[0] if args else None
    if isinstance(first, list) and first and all(isinstance(x, int) and not isinstance(x, bool) for x in first):
        return first
    if isinstance(first, int) and not isinstance(first, bool):
        return [first]
    return None


async def build_preview(odoo: OdooClient, model: str, method: str, args: List[Any], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    preview: Dict[str, Any] = {
        "summary": "",
        "record_count": None,
        "records": [],
        "changes": [],
        "amount_total": None,
        "currency": None,
        "truncated": False,
        "warnings": [],
    }
    verb = _VERBS.get(method, f"Ejecutar '{method}' en")
    label = model
    fields: Dict[str, Any] = {}
    try:
        # ir.model is admin-only for least-privilege users (verified on Odoo 18): the label is optional
        rows = await odoo.execute("ir.model", "search_read", [[["model", "=", model]]], {"fields": ["name"], "limit": 1})
        if rows:
            label = rows[0]["name"]
    except Exception:
        pass
    try:
        fields = await odoo.execute(model, "fields_get", [], {"attributes": ["string", "type"]}) or {}
    except Exception:
        preview["warnings"].append("No se pudo leer el esquema del modelo; la vista previa es parcial.")

    ids = _ids_from_args(args)
    if method == "create":
        vals_list = args[0] if args else kwargs.get("vals_list") or kwargs.get("vals")
        vals_list = vals_list if isinstance(vals_list, list) else [vals_list] if isinstance(vals_list, dict) else []
        preview["record_count"] = len(vals_list)
        preview["summary"] = f"{verb} {len(vals_list)} registro(s) de {label}"
        first = redact_sensitive_output(vals_list[0]) if vals_list and isinstance(vals_list[0], dict) else {}
        for name, value in list(first.items())[:MAX_CHANGES]:
            label_ = (fields.get(name) or {}).get("string") or name
            if isinstance(value, list):
                value = f"{len(value)} línea(s)"
            preview["changes"].append({"field": name, "label": label_, "before": None, "after": _short(value)})
        return preview

    if ids is None:
        preview["summary"] = f"{verb} {label}"
        preview["warnings"].append("No se identificaron registros concretos en la operación.")
        return preview

    preview["record_count"] = len(ids)
    preview["summary"] = f"{verb} {len(ids)} registro(s) de {label}"
    write_vals = args[1] if method == "write" and len(args) > 1 and isinstance(args[1], dict) else kwargs.get("vals") if method == "write" else None
    write_vals = redact_sensitive_output(write_vals) if isinstance(write_vals, dict) else None

    read_fields = ["display_name"]
    if "amount_total" in fields:
        read_fields.append("amount_total")
    if "currency_id" in fields:
        read_fields.append("currency_id")
    if write_vals:
        read_fields += [f for f in list(write_vals)[:MAX_CHANGES] if f in fields and f not in read_fields]
    try:
        sample = await odoo.execute(model, "read", [ids[:AMOUNT_SAMPLE]], {"fields": read_fields})
    except Exception as exc:
        preview["warnings"].append(f"No se pudieron leer los registros: {str(exc)[:120]}")
        return preview

    sample = redact_sensitive_output(sample or [])
    preview["records"] = [{"id": r["id"], "name": str(r.get("display_name") or r["id"])} for r in sample[:MAX_RECORDS]]
    preview["truncated"] = len(ids) > MAX_RECORDS
    missing = len(set(ids[:AMOUNT_SAMPLE]) - {r["id"] for r in sample})
    if missing:
        preview["warnings"].append(f"{missing} ID(s) no existen o no son accesibles para el usuario de la IA.")
    if "amount_total" in read_fields and sample:
        preview["amount_total"] = round(sum(float(r.get("amount_total") or 0) for r in sample), 2)
        currency = sample[0].get("currency_id")
        preview["currency"] = currency[1] if isinstance(currency, list) and len(currency) > 1 else None
        if len(ids) > AMOUNT_SAMPLE:
            preview["warnings"].append(f"Importe calculado sobre los primeros {AMOUNT_SAMPLE} registros.")
    if write_vals:
        for name, after in list(write_vals.items())[:MAX_CHANGES]:
            befores = {repr(r.get(name)) for r in sample[:5]} if name in read_fields else set()
            before = sample[0].get(name) if len(befores) == 1 else ("(varios valores)" if befores else None)
            preview["changes"].append(
                {"field": name, "label": (fields.get(name) or {}).get("string") or name, "before": _short(before), "after": _short(after)}
            )
    if method == "unlink":
        preview["warnings"].append("El borrado es irreversible.")
    return preview
