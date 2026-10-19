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


@pytest.mark.parametrize(
    "secret_model",
    [
        "res.users",
        "res.apikeys",
        "ir.config_parameter",
        "ir.mail_server",
        "fetchmail.server",
        "payment.provider",
        "payment.acquirer",
        "payment.token",
    ],
)
def test_reading_secret_models_is_forbidden(secret_model: str):
    """Evita que un agente exfiltre hashes, API keys, SMTP passwords o database.secret mediante search_read."""
    decision = evaluate_odoo_call(
        model=secret_model,
        method="search_read",
        args=[[]],
    )
    assert decision.level == RiskLevel.FORBIDDEN
    assert decision.allowed is False


def test_private_dunder_methods_are_forbidden():
    """Bloquea invocación de métodos privados de Odoo que empiezan por '_'."""
    decision = evaluate_odoo_call(
        model="sale.order",
        method="_action_confirm",
        args=[[1]],
    )
    assert decision.level == RiskLevel.FORBIDDEN
    assert decision.allowed is False


def test_sensitive_fields_stripped_on_green_read():
    """Elimina campos de credenciales si el LLM intenta pedirlos en una lectura verde."""
    decision = evaluate_odoo_call(
        model="res.partner",
        method="search_read",
        args=[[]],
        kwargs={"fields": ["name", "email", "password", "api_key", "totp_secret"]},
    )
    assert decision.level == RiskLevel.GREEN
    assert decision.sanitized_kwargs["fields"] == ["name", "email"]


@pytest.mark.parametrize(
    "protected_model",
    [
        "res.users",
        "res.groups",
        "ir.model.access",
        "ir.rule",
        "ir.config_parameter",
        "ir.module.module",
        "ir.ui.view",
        "ir.model",
    ],
)
def test_system_models_are_always_forbidden(protected_model: str):
    """Ningún agente puede mutar tablas de permisos, vistas o configuración ni siquiera con licencia Pro."""
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
    el firewall debe sobreescribirlo a 'draft' tanto en args como en kwargs (vals y context).
    """
    malicious_payload = [{"partner_id": 14, "state": "sale", "amount_total": 5000}]
    decision = evaluate_odoo_call(
        model="sale.order",
        method="create",
        args=malicious_payload,
        kwargs={
            "vals": {"partner_id": 14, "state": "done"},
            "context": {"default_state": "sale"},
        },
    )
    assert decision.level == RiskLevel.YELLOW
    assert decision.inject_chatter_note is True
    assert decision.sanitized_args[0]["state"] == "draft"
    assert decision.sanitized_kwargs["vals"]["state"] == "draft"
    assert decision.sanitized_kwargs["context"]["default_state"] == "draft"


@pytest.mark.parametrize(
    "model,method",
    [
        ("account.move", "action_post"),     # Validar factura ante Hacienda
        ("account.move", "create"),          # Crear asiento/factura contable
        ("account.move", "write"),           # Editar factura
        ("sale.order", "unlink"),            # Borrar pedido de venta
        ("sale.order", "write"),             # Modificar pedido existente -> ROJO
        ("res.partner", "unlink"),           # Borrar cliente
        ("stock.picking", "button_validate"),# Validar salida de almacén
        ("sale.order", "custom_unknown_rpc"),# Método desconocido (Fail-safe a ROJO)
    ],
)
def test_critical_and_accounting_methods_trigger_red_level(model: str, method: str):
    """Operaciones contables, borrados, ediciones o métodos desconocidos deben congelarse (Nivel ROJO)."""
    decision = evaluate_odoo_call(
        model=model,
        method=method,
        args=[[42]],
    )
    assert decision.level == RiskLevel.RED
