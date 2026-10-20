"""
Exhaustive policy matrix: every model x method x license combination must satisfy the
firewall invariants, whatever the casing or whitespace the LLM sends.
"""

import copy
import itertools

import pytest

from odoo_safe_mcp.rules import (
    CRITICAL_RED_METHODS,
    GREEN_METHODS,
    PROTECTED_SYSTEM_MODELS,
    READ_AND_WRITE_FORBIDDEN_MODELS,
    YELLOW_CREATE_MODELS,
    RiskLevel,
    evaluate_odoo_call,
    evaluate_rule,
)

BUSINESS_MODELS = [
    "res.partner",
    "sale.order",
    "sale.order.line",
    "purchase.order",
    "crm.lead",
    "account.move",
    "account.payment",
    "account.move.line",
    "stock.picking",
    "product.product",
    "product.template",
    "project.task",
    "hr.employee",
    "x_custom.model",
]
MODELS = sorted(set(BUSINESS_MODELS) | READ_AND_WRITE_FORBIDDEN_MODELS | PROTECTED_SYSTEM_MODELS)
METHODS = sorted(
    set(GREEN_METHODS)
    | set(CRITICAL_RED_METHODS)
    | {"create", "write", "message_post", "action_custom_wizard", "execute", "web_read", "_private", "__class__"}
)
FORBIDDEN_LEVELS = (RiskLevel.FORBIDDEN, RiskLevel.BLOCKED)


def _expected_level(model: str, method: str) -> RiskLevel:
    if method.startswith("_"):
        return RiskLevel.FORBIDDEN
    if model in READ_AND_WRITE_FORBIDDEN_MODELS:
        return RiskLevel.FORBIDDEN
    if model in PROTECTED_SYSTEM_MODELS and method not in GREEN_METHODS:
        return RiskLevel.FORBIDDEN
    if model in YELLOW_CREATE_MODELS and method == "create":
        return RiskLevel.YELLOW
    if method in GREEN_METHODS:
        return RiskLevel.GREEN
    return RiskLevel.RED


@pytest.mark.parametrize("model,method", list(itertools.product(MODELS, METHODS)))
def test_policy_matrix(model, method):
    args = [[1, 2], {"name": "x"}]
    kwargs = {"context": {"lang": "es_ES"}}
    args_before, kwargs_before = copy.deepcopy(args), copy.deepcopy(kwargs)

    decision = evaluate_odoo_call(model, method, args, kwargs)
    expected = _expected_level(model, method)
    assert decision.level == expected

    # Inputs are never mutated in place (the agent's payload must stay comparable for hashing).
    assert args == args_before and kwargs == kwargs_before

    # Casing and padding sent by an LLM cannot change the verdict.
    variant = evaluate_odoo_call(f"  {model.upper()} ", f" {method.upper()}  ", args, kwargs)
    assert variant.level == expected

    free = evaluate_rule(model, method, args, kwargs, has_pro_license=False)
    pro = evaluate_rule(model, method, args, kwargs, has_pro_license=True)

    if expected in FORBIDDEN_LEVELS:
        # Hard blocks hold even with a paid licence.
        assert not free.allowed and not pro.allowed
        assert not pro.requires_guard_proxy
    elif expected == RiskLevel.GREEN:
        # Reads run locally and never reach the cloud proxy.
        assert free.allowed and pro.allowed
        assert not free.requires_guard_proxy and not pro.requires_guard_proxy
    else:
        # Every mutation is read-only blocked on the free tier and proxied on Pro.
        assert not free.allowed and not free.requires_guard_proxy
        assert pro.allowed and pro.requires_guard_proxy


@pytest.mark.parametrize("model", ["", "   ", None])
@pytest.mark.parametrize("method", ["", "read", None])
def test_empty_or_missing_identifiers_are_forbidden(model, method):
    decision = evaluate_odoo_call(model, method)
    assert decision.level == RiskLevel.FORBIDDEN
    assert decision.allowed is False
