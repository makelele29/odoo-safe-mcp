"""
Rules Engine & Traffic Light System for Odoo Safe MCP.

Classifies Odoo RPC calls into:
  - GREEN: Safe Read (Free Open Source, instant local JSON-RPC execution)
  - YELLOW: Guarded Drafts (Forces state='draft' and Chatter audit note)
  - RED: Critical / Destructive / Unknown / Wizards (Requires human Slack approval)
  - FORBIDDEN / BLOCKED: Permanent lockdown for sensitive models (res.users, ir.config_parameter, etc.)
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class RiskLevel(str, Enum):
    GREEN = "GREEN"          # Safe read
    YELLOW = "YELLOW"        # Guarded draft creation
    RED = "RED"              # Critical / destructive / state change / wizards / unknown
    BLOCKED = "BLOCKED"      # Privilege escalation / security violation (alias)
    FORBIDDEN = "FORBIDDEN"  # Forbidden operation (res.users, security models)


# Methods safe for read-only consumption on non-sensitive business models
GREEN_METHODS = {
    "search",
    "read",
    "search_read",
    "fields_get",
    "read_group",
    "name_search",
    "name_get",
    "search_count",
    "default_get",
    "check_access_rights",
    "fields_view_get",
    "get_views",
    "load_views",
}

# Models where ANY access (even READ) is strictly forbidden to prevent credential/secret exfiltration
READ_AND_WRITE_FORBIDDEN_MODELS = {
    "res.users",
    "res.apikeys",
    "ir.config_parameter",
    "ir.mail_server",
    "fetchmail.server",
    "payment.provider",
    "payment.acquirer",
    "payment.token",
}

# Critical system models where mutations (create/write/unlink/custom) are strictly forbidden
PROTECTED_SYSTEM_MODELS = READ_AND_WRITE_FORBIDDEN_MODELS | {
    "res.groups",
    "ir.model.access",
    "ir.rule",
    "ir.module.module",
    "ir.actions.server",
    "ir.cron",
    "base.automation",
    "ir.model",
    "ir.model.fields",
    "ir.ui.view",
}

# Backward compatibility alias
BLACKLIST_MODELS = PROTECTED_SYSTEM_MODELS

# Sensitive field names that must never be read via fields list
FORBIDDEN_SENSITIVE_FIELDS = {
    "password",
    "password_crypt",
    "api_key",
    "totp_secret",
    "oauth_access_token",
    "smtp_pass",
    "stripe_secret_key",
}

# Strict Whitelist: Only these models can be created under YELLOW (Guarded Drafts)
YELLOW_CREATE_MODELS = {
    "sale.order",
    "purchase.order",
    "crm.lead",
}

# Critical methods that always trigger RED level alerts
CRITICAL_RED_METHODS = {
    "unlink",
    "action_post",
    "action_confirm",
    "button_validate",
    "action_invoice_open",
    "action_invoice_paid",
    "action_cancel",
    "button_immediate_transfer",
    "button_approve",
    "copy",
    "web_save",
    "name_create",
}

UPGRADE_URL = "https://odoosafemcp.stream/#pricing"


@dataclass
class RuleEvaluationResult:
    level: RiskLevel
    allowed: bool
    requires_guard_proxy: bool
    reason: str
    sanitized_args: List[Any] = field(default_factory=list)
    sanitized_kwargs: Dict[str, Any] = field(default_factory=dict)
    audit_note: Optional[str] = None
    inject_chatter_note: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "allowed": self.allowed,
            "requires_guard_proxy": self.requires_guard_proxy,
            "reason": self.reason,
            "sanitized_args": self.sanitized_args,
            "sanitized_kwargs": self.sanitized_kwargs,
            "audit_note": self.audit_note,
            "inject_chatter_note": self.inject_chatter_note,
        }


def _enforce_draft_on_dict(item: Dict[str, Any], model: str) -> None:
    if model in {"sale.order", "purchase.order"}:
        item["state"] = "draft"


def _sanitize_yellow_payload(
    model: str, method: str, args: List[Any], kwargs: Dict[str, Any]
) -> Tuple[List[Any], Dict[str, Any], str]:
    """
    Enforces state='draft' for sales and purchase orders across positional args,
    keyword vals/vals_list, and context default_state to prevent bypasses.
    """
    new_args = copy.deepcopy(args)
    new_kwargs = copy.deepcopy(kwargs)
    audit_note = f"[Odoo Safe MCP] Created via AI Agent ({model}.{method}) under Guarded Drafts policy."

    if method == "create":
        # 1. Sanitize positional args[0]
        if new_args:
            first_arg = new_args[0]
            if isinstance(first_arg, dict):
                _enforce_draft_on_dict(first_arg, model)
                new_args[0] = first_arg
            elif isinstance(first_arg, list):
                for item in first_arg:
                    if isinstance(item, dict):
                        _enforce_draft_on_dict(item, model)
                new_args[0] = first_arg

        # 2. Sanitize kwargs['vals'] or kwargs['vals_list'] (prevents kwargs bypass)
        if isinstance(new_kwargs.get("vals"), dict):
            _enforce_draft_on_dict(new_kwargs["vals"], model)
        elif isinstance(new_kwargs.get("vals"), list):
            for item in new_kwargs["vals"]:
                if isinstance(item, dict):
                    _enforce_draft_on_dict(item, model)

        if isinstance(new_kwargs.get("vals_list"), list):
            for item in new_kwargs["vals_list"]:
                if isinstance(item, dict):
                    _enforce_draft_on_dict(item, model)

        # 3. Sanitize kwargs['context']['default_state']
        if isinstance(new_kwargs.get("context"), dict) and model in {"sale.order", "purchase.order"}:
            if "default_state" in new_kwargs["context"]:
                new_kwargs["context"]["default_state"] = "draft"

    return new_args, new_kwargs, audit_note


def _sanitize_green_read_kwargs(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Strip any forbidden credential fields from 'fields' parameter in read/search_read."""
    new_kwargs = copy.deepcopy(kwargs)
    fields_param = new_kwargs.get("fields")
    if isinstance(fields_param, list):
        new_kwargs["fields"] = [
            f for f in fields_param
            if isinstance(f, str) and f.strip().lower() not in FORBIDDEN_SENSITIVE_FIELDS
        ]
    return new_kwargs


def evaluate_odoo_call(
    model: str,
    method: str,
    args: Optional[List[Any]] = None,
    kwargs: Optional[Dict[str, Any]] = None,
) -> RuleEvaluationResult:
    """
    Evaluates whether an Odoo execute_kw call is permitted, its intrinsic risk tier,
    and applies automated safety sanitization.

    Returns a RuleEvaluationResult with level: GREEN, YELLOW, RED, or FORBIDDEN.
    """
    args = list(args) if args is not None else []
    kwargs = dict(kwargs) if kwargs is not None else {}
    norm_model = (model or "").strip().lower()
    norm_method = (method or "").strip().lower()

    # 0. Block empty or private/dunder method calls (e.g. '_check_credentials', '__import__')
    if not norm_model or not norm_method or norm_method.startswith("_"):
        return RuleEvaluationResult(
            level=RiskLevel.FORBIDDEN,
            allowed=False,
            requires_guard_proxy=False,
            reason=(
                f"⛔ SECURITY ALERT: Calling private or invalid method '{method}' on '{model}' "
                "is permanently FORBIDDEN."
            ),
            sanitized_args=args,
            sanitized_kwargs=kwargs,
            inject_chatter_note=False,
        )

    # 1. FORBIDDEN: Block reading OR writing secret/credential models (res.users, ir.config_parameter, etc.)
    if norm_model in READ_AND_WRITE_FORBIDDEN_MODELS:
        return RuleEvaluationResult(
            level=RiskLevel.FORBIDDEN,
            allowed=False,
            requires_guard_proxy=False,
            reason=(
                f"⛔ SECURITY ALERT: Direct access to sensitive model '{norm_model}' is permanently FORBIDDEN "
                "by Odoo Safe MCP to prevent credential/token exfiltration or privilege escalation."
            ),
            sanitized_args=args,
            sanitized_kwargs=kwargs,
            inject_chatter_note=False,
        )

    # 2. FORBIDDEN: Prevent mutation of access control, groups, modules, views, automations and crons
    if norm_model in PROTECTED_SYSTEM_MODELS:
        if norm_method not in GREEN_METHODS:
            return RuleEvaluationResult(
                level=RiskLevel.FORBIDDEN,
                allowed=False,
                requires_guard_proxy=False,
                reason=(
                    f"⛔ SECURITY ALERT: Direct mutations on sensitive system model '{model}' "
                    f"(method: '{method}') are permanently FORBIDDEN by Odoo Safe MCP to prevent "
                    "privilege escalation, even with a Pro license."
                ),
                sanitized_args=args,
                sanitized_kwargs=kwargs,
                inject_chatter_note=False,
            )

    # 3. YELLOW TIER: Strict Whitelist - Only guarded draft creation on sales, purchases, leads
    if (norm_model in YELLOW_CREATE_MODELS) and (norm_method == "create"):
        san_args, san_kwargs, note = _sanitize_yellow_payload(
            norm_model, norm_method, args, kwargs
        )
        return RuleEvaluationResult(
            level=RiskLevel.YELLOW,
            allowed=True,
            requires_guard_proxy=True,
            reason="Guarded Draft Creation: enforced state='draft' and AI audit note.",
            sanitized_args=san_args,
            sanitized_kwargs=san_kwargs,
            audit_note=note,
            inject_chatter_note=True,
        )

    # 4. GREEN TIER: Safe Read Operations on standard business models
    if norm_method in GREEN_METHODS:
        san_kwargs = _sanitize_green_read_kwargs(kwargs)
        return RuleEvaluationResult(
            level=RiskLevel.GREEN,
            allowed=True,
            requires_guard_proxy=False,
            reason="Safe read-only operation. Executed instantly via local JSON-RPC.",
            sanitized_args=args,
            sanitized_kwargs=san_kwargs,
            inject_chatter_note=False,
        )

    # 5. RED TIER: All other mutations, accounting, deletions, wizards, or unknown methods (Fail-safe to RED)
    is_critical = norm_method in CRITICAL_RED_METHODS or norm_model.startswith("account.")
    reason = (
        f"Critical operation ('{norm_model}.{norm_method}'): Human-in-the-Loop approval required via Slack."
        if is_critical
        else f"Unguarded mutation or wizard ('{norm_model}.{norm_method}'): Routed through Pro Guard Proxy."
    )
    return RuleEvaluationResult(
        level=RiskLevel.RED,
        allowed=True,
        requires_guard_proxy=True,
        reason=reason,
        sanitized_args=args,
        sanitized_kwargs=kwargs,
        inject_chatter_note=True,
    )


def evaluate_rule(
    model: str,
    method: str,
    args: Optional[List[Any]] = None,
    kwargs: Optional[Dict[str, Any]] = None,
    has_pro_license: bool = False,
) -> RuleEvaluationResult:
    """
    Evaluates whether an Odoo execute_kw call is permitted in the MCP server context,
    taking into account the client's Pro License status.
    """
    decision = evaluate_odoo_call(model=model, method=method, args=args, kwargs=kwargs)

    if decision.level in (RiskLevel.FORBIDDEN, RiskLevel.BLOCKED):
        return decision

    if decision.level == RiskLevel.GREEN:
        return decision

    # If mutation is YELLOW or RED but user has no Pro license -> Strict Read-Only Mode
    if not has_pro_license:
        return RuleEvaluationResult(
            level=decision.level,
            allowed=False,
            requires_guard_proxy=False,
            reason=(
                f"🔒 Odoo Safe MCP (Free Tier) operates in Strict Read-Only Mode. "
                f"Method '{method}' on model '{model}' is classified as {decision.level.value}.\n"
                f"To enable guarded write access and Human-in-the-Loop Slack approvals, "
                f"get a Pro API Key at {UPGRADE_URL} and configure ODOO_SAFE_GUARD_KEY."
            ),
            sanitized_args=decision.sanitized_args,
            sanitized_kwargs=decision.sanitized_kwargs,
            inject_chatter_note=False,
        )

    return decision
