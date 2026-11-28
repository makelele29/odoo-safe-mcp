"""
Human-readable preview of a proposed change, built locally with the user's own Odoo credentials.

This is what the approver sees on their phone: which records, what changes (before → after) and
the amount at stake. It is computed from the operation itself and from Odoo, never from the text
the agent writes, so a manipulated agent cannot hide what it is really asking for.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from odoo_safe_mcp.odoo import OdooClient
from odoo_safe_mcp.rules import redact_pii_output, redact_sensitive_output

MAX_RECORDS = 10
MAX_CHANGES = 15
AMOUNT_SAMPLE = 50
_AMOUNT_LINE_KEYS = ("order_line", "invoice_line_ids", "line_ids")

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


def _collect_missing_price_product_ids(model: str, vals_list: List[Any]) -> List[int]:
    """Return product_id values from create lines that omitted price_unit so we can look up list_price."""
    if model not in ("sale.order", "purchase.order", "account.move"):
        return []
    product_ids: List[int] = []
    for vals in vals_list:
        if not isinstance(vals, dict):
            continue
        for line_key in _AMOUNT_LINE_KEYS:
            lines = vals.get(line_key)
            if not isinstance(lines, (list, tuple)):
                continue
            for cmd in lines:
                if isinstance(cmd, (list, tuple)) and len(cmd) >= 3 and isinstance(cmd[2], dict):
                    line = cmd[2]
                    if line.get("price_unit") is None and isinstance(line.get("product_id"), int) and not isinstance(line.get("product_id"), bool):
                        pid = line["product_id"]
                        if pid not in product_ids:
                            product_ids.append(pid)
    return product_ids


def _estimate_create_amount_details(
    model: str,
    vals_list: List[Any],
    product_prices: Optional[Dict[int, float]] = None,
) -> Tuple[Optional[float], bool]:
    """
    Estimate total monetary exposure from create payloads without trusting client-supplied amount_total
    or allowing negative/cancelled lines to net down positive exposure.
    Returns (estimated_amount, uncertain).
    """
    norm_model = (model or "").strip().lower()
    if norm_model not in ("sale.order", "purchase.order", "account.move", "crm.lead"):
        return None, False
    prices = product_prices or {}
    total = 0.0
    found = False
    uncertain = False

    for vals in vals_list:
        if not isinstance(vals, dict):
            continue
        if norm_model == "crm.lead":
            rev = vals.get("expected_revenue")
            if isinstance(rev, (int, float)) and not isinstance(rev, bool):
                total += abs(float(rev))
                found = True
            continue

        # Never trust vals['amount_total']: Odoo computes and ignores it on create().
        record_has_lines = False
        for line_key in _AMOUNT_LINE_KEYS:
            lines = vals.get(line_key)
            if not isinstance(lines, (list, tuple)) or not lines:
                continue
            record_has_lines = True
            for cmd in lines:
                if not (isinstance(cmd, (list, tuple)) and len(cmd) >= 3 and isinstance(cmd[2], dict)):
                    uncertain = True
                    continue
                line = cmd[2]
                qty_raw = (
                    line.get("product_uom_qty")
                    if line.get("product_uom_qty") is not None
                    else line.get("product_qty")
                    if line.get("product_qty") is not None
                    else line.get("quantity", 1)
                )
                price_raw = line.get("price_unit")
                if price_raw is None:
                    pid = line.get("product_id")
                    if isinstance(pid, int) and not isinstance(pid, bool) and pid in prices:
                        price_raw = prices[pid]
                    elif isinstance(line.get("debit"), (int, float)) or isinstance(line.get("credit"), (int, float)):
                        debit = abs(float(line.get("debit") or 0.0))
                        credit = abs(float(line.get("credit") or 0.0))
                        total += max(debit, credit)
                        found = True
                        continue
                    else:
                        uncertain = True
                        continue
                discount_raw = line.get("discount", 0) or 0
                try:
                    qty = abs(float(qty_raw))
                    price = abs(float(price_raw))
                    discount = max(0.0, min(float(discount_raw), 100.0))
                    total += qty * price * (1.0 - discount / 100.0)
                    found = True
                except (TypeError, ValueError):
                    uncertain = True
                    continue
        if norm_model == "account.move" and not record_has_lines:
            # account.move without explicit lines might rely on defaults or later writes
            pass

    return (round(total, 2) if found else None), uncertain


def _estimate_create_amount(model: str, vals_list: List[Any], product_prices: Optional[Dict[int, float]] = None) -> float | None:
    """Backward-compatible wrapper returning only the estimated float or None."""
    amount, _ = _estimate_create_amount_details(model, vals_list, product_prices=product_prices)
    return amount


def _summarize_create_lines(lines: List[Any]) -> str:
    parts: List[str] = []
    for cmd in lines[:5]:
        if isinstance(cmd, (list, tuple)) and len(cmd) >= 3 and isinstance(cmd[2], dict):
            line = cmd[2]
            qty = line.get("product_uom_qty") if line.get("product_uom_qty") is not None else line.get("product_qty", line.get("quantity", 1))
            prod = line.get("name") or (f"prod#{line['product_id']}" if "product_id" in line else "línea")
            price = line.get("price_unit")
            disc = line.get("discount")
            desc = f"{qty}× {prod}"
            if price is not None:
                desc += f" @ {price}"
            if disc:
                desc += f" (-{disc}%)"
            parts.append(desc)
    extra = f" (+{len(lines) - 5} más)" if len(lines) > 5 else ""
    return "; ".join(parts) + extra if parts else f"{len(lines)} línea(s)"


async def build_preview(
    odoo: OdooClient,
    model: str,
    method: str,
    args: List[Any],
    kwargs: Dict[str, Any],
    pii_mode: str = "off",
) -> Dict[str, Any]:
    norm_model = (model or "").strip().lower()
    norm_method = (method or "").strip().lower()
    preview: Dict[str, Any] = {
        "summary": "",
        "record_count": None,
        "records": [],
        "changes": [],
        "amount_total": None,
        "amount_uncertain": False,
        "currency": None,
        "truncated": False,
        "warnings": [],
    }
    verb = _VERBS.get(norm_method, f"Ejecutar '{norm_method}' en")
    label = norm_model or model
    fields: Dict[str, Any] = {}
    try:
        # ir.model is admin-only for least-privilege users (verified on Odoo 18): the label is optional
        rows = await odoo.execute("ir.model", "search_read", [[["model", "=", norm_model]]], {"fields": ["name"], "limit": 1})
        if rows:
            label = rows[0]["name"]
    except Exception:
        pass
    try:
        fields = await odoo.execute(norm_model, "fields_get", [], {"attributes": ["string", "type"]}) or {}
    except Exception:
        preview["warnings"].append("No se pudo leer el esquema del modelo; la vista previa es parcial.")

    ids = _ids_from_args(args)
    if norm_method == "create":
        vals_list = args[0] if args else kwargs.get("vals_list") or kwargs.get("vals")
        vals_list = vals_list if isinstance(vals_list, list) else [vals_list] if isinstance(vals_list, dict) else []
        preview["record_count"] = len(vals_list)
        preview["summary"] = f"{verb} {len(vals_list)} registro(s) de {label}"

        product_prices: Dict[int, float] = {}
        missing_pids = _collect_missing_price_product_ids(norm_model, vals_list)
        if missing_pids:
            try:
                prod_rows = await odoo.execute("product.product", "read", [missing_pids[:50]], {"fields": ["list_price"]}) or []
                for pr in prod_rows:
                    if isinstance(pr, dict) and isinstance(pr.get("id"), int) and isinstance(pr.get("list_price"), (int, float)):
                        product_prices[pr["id"]] = float(pr["list_price"])
            except Exception:
                preview["amount_uncertain"] = True

        estimated, uncertain = _estimate_create_amount_details(norm_model, vals_list, product_prices=product_prices)
        if uncertain:
            preview["amount_uncertain"] = True
            preview["warnings"].append("Alguna línea omite precio unitario o tarifa; el importe real en Odoo puede ser superior.")
        if estimated is not None:
            preview["amount_total"] = estimated

        first = redact_pii_output(redact_sensitive_output(vals_list[0]), pii_mode) if vals_list and isinstance(vals_list[0], dict) else {}
        for name, value in list(first.items())[:MAX_CHANGES]:
            label_ = (fields.get(name) or {}).get("string") or name
            if isinstance(value, list):
                value = _summarize_create_lines(value) if name in _AMOUNT_LINE_KEYS else f"{len(value)} línea(s)"
            preview["changes"].append({"field": name, "label": label_, "before": None, "after": _short(value)})
        if len(vals_list) > 1:
            preview["warnings"].append(f"Lote de {len(vals_list)} registros: revisa los detalles completos antes de aprobar.")
            for idx, extra_item in enumerate(vals_list[1:5], start=2):
                if isinstance(extra_item, dict):
                    est_item, _ = _estimate_create_amount_details(norm_model, [extra_item], product_prices=product_prices)
                    summary_txt = f"#{idx}" + (f" (~{est_item:.2f})" if est_item is not None else "")
                    preview["records"].append({"id": -idx, "name": summary_txt})
        return preview

    if ids is None:
        preview["summary"] = f"{verb} {label}"
        preview["warnings"].append("No se identificaron registros concretos en la operación.")
        return preview

    preview["record_count"] = len(ids)
    preview["summary"] = f"{verb} {len(ids)} registro(s) de {label}"
    write_vals = args[1] if norm_method == "write" and len(args) > 1 and isinstance(args[1], dict) else kwargs.get("vals") if norm_method == "write" else None
    write_vals = redact_pii_output(redact_sensitive_output(write_vals), pii_mode) if isinstance(write_vals, dict) else None

    read_fields = ["display_name"]
    amount_field = (
        "amount"
        if (norm_model == "account.payment" and "amount" in fields)
        else ("amount_total" if "amount_total" in fields else ("amount" if "amount" in fields else None))
    )
    if amount_field:
        read_fields.append(amount_field)
    if "currency_id" in fields:
        read_fields.append("currency_id")
    if "partner_id" in fields:
        read_fields.append("partner_id")
    if "move_type" in fields:
        read_fields.append("move_type")
    if write_vals:
        read_fields += [f for f in list(write_vals)[:MAX_CHANGES] if f in fields and f not in read_fields]
    try:
        sample = await odoo.execute(norm_model, "read", [ids[:AMOUNT_SAMPLE]], {"fields": read_fields})
    except Exception as exc:
        preview["warnings"].append(f"No se pudieron leer los registros: {str(exc)[:120]}")
        return preview

    sample = redact_pii_output(redact_sensitive_output(sample or []), pii_mode)
    records_out = []
    for r in sample[:MAX_RECORDS]:
        rec_entry: Dict[str, Any] = {"id": r["id"], "name": str(r.get("display_name") or r["id"])}
        partner = r.get("partner_id")
        if isinstance(partner, (list, tuple)) and len(partner) > 1 and partner[1]:
            rec_entry["partner"] = str(partner[1])
        records_out.append(rec_entry)
    preview["records"] = records_out
    preview["truncated"] = len(ids) > MAX_RECORDS
    missing = len(set(ids[:AMOUNT_SAMPLE]) - {r["id"] for r in sample})
    if missing:
        preview["warnings"].append(f"{missing} ID(s) no existen o no son accesibles para el usuario de la IA.")
    if amount_field and sample:
        preview["amount_total"] = round(sum(abs(float(r.get(amount_field) or 0)) for r in sample), 2)
        currency = sample[0].get("currency_id")
        preview["currency"] = currency[1] if isinstance(currency, list) and len(currency) > 1 else None
        if len(ids) > AMOUNT_SAMPLE:
            preview["warnings"].append(f"Importe calculado sobre los primeros {AMOUNT_SAMPLE} registros.")
    if write_vals:
        if len(write_vals) > MAX_CHANGES:
            preview["warnings"].append(f"Se muestran {MAX_CHANGES} de {len(write_vals)} campos modificados.")
        for name, after in list(write_vals.items())[:MAX_CHANGES]:
            befores = {repr(r.get(name)) for r in sample[:5]} if name in read_fields else set()
            before = sample[0].get(name) if len(befores) == 1 else ("(varios valores)" if befores else None)
            preview["changes"].append(
                {"field": name, "label": (fields.get(name) or {}).get("string") or name, "before": _short(before), "after": _short(after)}
            )
    if norm_method == "unlink":
        preview["warnings"].append("El borrado es irreversible.")
    return preview
