import pytest
from odoo_safe_mcp.rules import evaluate_odoo_call, RiskLevel


def test_green_read_operations_pass_directly():
    """Las lecturas estándar deben pasar en Nivel VERDE sin requerir licencia de pago."""
    for method in ["search", "read", "search_read", "fields_get", "read_group"]:
        decision = evaluate_odoo_call(
            model="sale.order",
            method=method,
            args=[[["state", "=", "sale"]]],
            kwargs={"limit": 5},
        )
        assert decision.level == RiskLevel.GREEN


def test_reading_res_users_is_forbidden():
    """Evita que un agente lea hashes o tokens de usuarios mediante search_read en res.users."""
    decision = evaluate_odoo_call(
        model="res.users",
        method="search_read",
        args=[[]],
    )
    assert decision.level == RiskLevel.FORBIDDEN


@pytest.mark.parametrize(
    "protected_model",
    [
        "res.users",
        "res.groups",
        "ir.model.access",
        "ir.rule",
        "ir.config_parameter",
        "ir.module.module",
    ],
)
def test_system_models_are_always_forbidden(protected_model: str):
    """Ningún agente puede mutar tablas de permisos o configuración ni siquiera con licencia Pro."""
    for method in ["create", "write", "unlink"]:
        decision = evaluate_odoo_call(
            model=protected_model,
            method=method,
            args=[[1], {"name": "hacked"}],
        )
        assert decision.level == RiskLevel.FORBIDDEN


def test_yellow_draft_creation_forces_draft_state():
    """
    Si el LLM intenta crear un pedido directamente confirmado ('state': 'sale'),
    el firewall debe sobreescribirlo a 'draft' y activar la nota de auditoría en el Chatter.
    """
    malicious_payload = [{"partner_id": 14, "state": "sale", "amount_total": 5000}]
    decision = evaluate_odoo_call(
        model="sale.order",
        method="create",
        args=malicious_payload,
    )
    assert decision.level == RiskLevel.YELLOW
    assert decision.inject_chatter_note is True
    assert decision.sanitized_args[0]["state"] == "draft"


@pytest.mark.parametrize(
    "model,method",
    [
        ("account.move", "action_post"),     # Validar factura ante Hacienda
        ("account.move", "create"),          # Crear asiento/factura contable
        ("account.move", "write"),           # Editar factura
        ("sale.order", "unlink"),            # Borrar pedido de venta
        ("res.partner", "unlink"),           # Borrar cliente
        ("stock.picking", "button_validate"),# Validar salida de almacén
        ("sale.order", "custom_unknown_rpc"),# Método desconocido (Fail-safe a ROJO)
    ],
)
def test_critical_and_accounting_methods_trigger_red_level(model: str, method: str):
    """Operaciones contables, borrados o métodos desconocidos deben congelarse (Nivel ROJO)."""
    decision = evaluate_odoo_call(
        model=model,
        method=method,
        args=[[42]],
    )
    assert decision.level == RiskLevel.RED
