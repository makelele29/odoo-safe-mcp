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
import re
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
    "res.apikeys",  # legacy alias kept for backward compatibility
    "res.users.apikeys",
    "res.users.apikeys.description",
    "res.users.apikeys.show",
    "res.users.identitycheck",
    "auth.totp.device",
    "change.password.wizard",
    "change.password.user",
    "change.password.own",
    "iap.account",
    # default_get/read on settings returns integration secrets (Twilio, Gmail, Google APIs...)
    # stored in ir.config_parameter; execute() installs modules.
    "res.config.settings",
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
    "base.module.update",
    "base.module.upgrade",
    "base.module.uninstall",
    "ir.actions.actions",
    "ir.actions.act_window",
    "ir.actions.client",
    "ir.actions.report",
    "ir.actions.server",
    "ir.actions.todo",
    "ir.cron",
    "base.automation",
    "ir.model",
    "ir.model.fields",
    "ir.ui.view",
    "ir.asset",
    "ir.default",
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
    "access_token",
    "account_token",
    "signup_token",
}

# Any field whose name matches this pattern is treated as a credential, both when requested
# and when returned by Odoo (reads without an explicit 'fields' list return every field).
SENSITIVE_FIELD_PATTERN = re.compile(
    r"password|passwd|secret|token|api_?key|private_?key|access_?key|server_?key|totp|credential",
    re.IGNORECASE,
)

REDACTED_VALUE = "[REDACTED by Odoo Safe MCP]"

# Context keys a YELLOW create may carry. Anything else is dropped: keys such as
# 'tracking_disable' or 'mail_notrack' would silence the audit trail in the Chatter.
YELLOW_ALLOWED_CONTEXT_KEYS = {"lang", "tz", "allowed_company_ids"}

# 'default_<field>' context keys a YELLOW create may carry, per model, with a JSON scalar value. Odoo's
# default_get() reads them for every record created with that context: on the record itself x2many
# defaults are applied as commands (default_order_line=[[4, id]] would skip the x2many check), and records
# created on the side without clean_context() pick up the rest (inbox notifications: default_is_read;
# sequence date ranges: default_number_next). Only many2one/selection fields of the record itself are
# listed; any other default_* key escalates to RED instead of being dropped, because it is data the agent
# asked for (its fields belong in vals). default_state is forced to 'draft' on DRAFT_ENFORCED_MODELS.
YELLOW_ALLOWED_DEFAULT_KEYS = {
    "sale.order": {"default_partner_id", "default_user_id", "default_team_id", "default_state"},
    "purchase.order": {"default_partner_id", "default_user_id", "default_state"},
    "crm.lead": {"default_partner_id", "default_user_id", "default_team_id", "default_type"},
}

# x2many command codes (Odoo Command API): only CREATE (0) is safe inside a guarded create.
# UPDATE (1), DELETE (2), UNLINK (3), LINK (4), CLEAR (5) and SET (6) can modify or re-parent
# records that belong to other documents (e.g. lines of an already confirmed order).
X2MANY_SAFE_COMMANDS = {0}

# Strict Whitelist: Only these models can be created under YELLOW (Guarded Drafts)
YELLOW_CREATE_MODELS = {
    "sale.order",
    "purchase.order",
    "crm.lead",
}

# YELLOW models whose creates are forced to state='draft'
DRAFT_ENFORCED_MODELS = {"sale.order", "purchase.order"}

# Methods (and every 'account.*' model) flagged as critical in the RED reason. Any method that is
# not a read or a guarded create is RED anyway; this list only changes how the alert is worded.
CRITICAL_RED_METHODS = {
    "unlink",
    "action_post",
    "action_confirm",
    "button_validate",
    "button_confirm",
    "action_invoice_open",
    "action_invoice_paid",
    "action_cancel",
    "action_done",
    "action_create_payments",
    "button_immediate_transfer",
    "button_approve",
    "process",
    "copy",
    "web_save",
    "name_create",
}

# Odoo model names only use [a-z0-9_.] and method names are ASCII identifiers. Names with anything
# else (inner spaces, zero-width or full-width characters, BOMs...) are refused rather than cleaned,
# so this engine and the Edge (policy.ts) never disagree on what a Unicode-aware strip()/lower()
# would have produced. Only ASCII whitespace padding is trimmed.
_ASCII_WHITESPACE = " \t\n\r\x0b\x0c"
_MODEL_NAME = re.compile(r"[A-Za-z0-9_.]+")
_METHOD_NAME = re.compile(r"[A-Za-z0-9_]+")

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


def _normalize_identifier(value: Any, pattern: "re.Pattern[str]") -> str:
    """Trimmed, lower-cased name; '' when it is not a string or has characters Odoo never uses."""
    if not isinstance(value, str):
        return ""
    clean = value.strip(_ASCII_WHITESPACE)
    return clean.lower() if pattern.fullmatch(clean) else ""


def _enforce_draft_on_dict(item: Dict[str, Any], model: str) -> None:
    if model in DRAFT_ENFORCED_MODELS:
        item["state"] = "draft"


def _enforce_draft_on_values(values: Any, model: str) -> None:
    # create() takes a dict or a list of dicts: Odoo's model_create_multi wraps a lone dict, so a
    # dict passed as vals_list is created too.
    if isinstance(values, dict):
        _enforce_draft_on_dict(values, model)
    elif isinstance(values, (list, tuple)):
        for item in values:
            if isinstance(item, dict):
                _enforce_draft_on_dict(item, model)


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
        # 1. Sanitize positional args[0], then kwargs['vals'] / kwargs['vals_list'] (prevents kwargs bypass)
        if new_args:
            _enforce_draft_on_values(new_args[0], model)
        for key in ("vals", "vals_list"):
            if key in new_kwargs:
                _enforce_draft_on_values(new_kwargs[key], model)

        # 2. Drop context keys that could silence tracking, then force context['default_state']
        #    (other default_* keys were escalated to RED by _find_unsafe_context_defaults)
        if isinstance(new_kwargs.get("context"), dict):
            allowed_defaults = YELLOW_ALLOWED_DEFAULT_KEYS.get(model, set())
            new_kwargs["context"] = {
                k: v
                for k, v in new_kwargs["context"].items()
                if k in YELLOW_ALLOWED_CONTEXT_KEYS or k in allowed_defaults
            }
            if model in DRAFT_ENFORCED_MODELS and "default_state" in new_kwargs["context"]:
                new_kwargs["context"]["default_state"] = "draft"

    return new_args, new_kwargs, audit_note


def _is_json_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _find_unsafe_context_defaults(model: str, context: Any) -> List[str]:
    """
    Return the 'default_*' context keys a guarded create on `model` may not carry: keys outside
    YELLOW_ALLOWED_DEFAULT_KEYS, or allowed keys whose value is not a JSON scalar.
    """
    if not isinstance(context, dict):
        return []
    allowed = YELLOW_ALLOWED_DEFAULT_KEYS.get(model, set())
    return [
        str(key)
        for key, value in context.items()
        if str(key).startswith("default_") and (key not in allowed or not _is_json_scalar(value))
    ]


def _is_create_command(item: Any) -> bool:
    # Odoo compares command codes with ==, so 0.0 is CREATE as well (and True would be UPDATE).
    return (
        isinstance(item, (list, tuple))
        and len(item) >= 1
        and isinstance(item[0], (int, float))
        and not isinstance(item[0], bool)
        and item[0] in X2MANY_SAFE_COMMANDS
    )


def _find_unsafe_x2many_commands(vals: Any, path: str = "") -> List[str]:
    """
    Return the paths of x2many values inside create() values that could touch existing records,
    recursing into the values of nested CREATE commands.

    A non-empty list is only safe when every item is a CREATE command or a dict: Odoo reads a list
    of bare values as SET (ids, also as floats or numeric strings) and silently skips command codes
    it does not know, so a single LINK hidden next to junk items would still be applied.
    """
    unsafe: List[str] = []
    if isinstance(vals, (list, tuple)):
        for idx, item in enumerate(vals):
            unsafe.extend(_find_unsafe_x2many_commands(item, f"{path}[{idx}]"))
        return unsafe
    if not isinstance(vals, dict):
        return unsafe
    for field_name, value in vals.items():
        if not (isinstance(value, (list, tuple)) and value):
            continue
        field_path = f"{path}.{field_name}" if path else f"{field_name}"
        # A list of bare values is read by Odoo as SET: on a one2many it re-parents existing records.
        if any(not isinstance(item, (list, tuple, dict)) for item in value):
            unsafe.append(f"{field_path} (id list = SET)")
            continue
        for idx, command in enumerate(value):
            command_path = f"{field_path}[{idx}]"
            if isinstance(command, dict):
                continue  # Odoo cannot apply a dict as an x2many command: the whole create fails
            if not _is_create_command(command):
                unsafe.append(f"{command_path} (command {command[0] if command else 'missing'})")
            elif len(command) > 2:
                unsafe.extend(_find_unsafe_x2many_commands(command[2], command_path))
    return unsafe


def _collect_create_values(args: List[Any], kwargs: Dict[str, Any]) -> List[Any]:
    values: List[Any] = []
    if args:
        values.append(args[0])
    for key in ("vals", "vals_list"):
        if key in kwargs:
            values.append(kwargs[key])
    return values


def _is_sensitive_field(name: Any) -> bool:
    if not isinstance(name, str):
        return False
    clean = name.strip().lower()
    return clean in FORBIDDEN_SENSITIVE_FIELDS or bool(SENSITIVE_FIELD_PATTERN.search(clean))


def _sanitize_green_read_kwargs(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Strip any forbidden credential fields from 'fields' parameter in read/search_read."""
    new_kwargs = copy.deepcopy(kwargs)
    fields_param = new_kwargs.get("fields")
    if isinstance(fields_param, list):
        new_kwargs["fields"] = [
            f for f in fields_param
            if isinstance(f, str) and not _is_sensitive_field(f.split(":")[0])
        ]
    return new_kwargs


def redact_sensitive_output(result: Any) -> Any:
    """
    Replace the value of every credential-like key in an Odoo response.

    Odoo returns every readable field when 'fields' is omitted, so filtering the request is not
    enough: portal access_token, iap account_token, etc. must also be scrubbed from the result.
    """
    if isinstance(result, list):
        return [redact_sensitive_output(item) for item in result]
    if isinstance(result, dict):
        return {
            key: REDACTED_VALUE if _is_sensitive_field(str(key).split(":")[0]) else redact_sensitive_output(value)
            for key, value in result.items()
        }
    return result


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
    norm_model = _normalize_identifier(model, _MODEL_NAME)
    norm_method = _normalize_identifier(method, _METHOD_NAME)

    # 0. Block empty, malformed or private/dunder method calls (e.g. '_check_credentials', '__import__')
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
        # Odoo turns a list of pairs into a context (dict(...)), which would skip the key whitelist.
        context = kwargs.get("context")
        if context is not None and not isinstance(context, dict):
            return RuleEvaluationResult(
                level=RiskLevel.RED,
                allowed=True,
                requires_guard_proxy=True,
                reason=(
                    "Guarded draft escalated to RED: 'context' must be a JSON object to be sanitised; "
                    "Human-in-the-Loop approval required."
                ),
                sanitized_args=args,
                sanitized_kwargs=kwargs,
                inject_chatter_note=True,
            )
        unsafe_defaults = _find_unsafe_context_defaults(norm_model, context)
        if unsafe_defaults:
            return RuleEvaluationResult(
                level=RiskLevel.RED,
                allowed=True,
                requires_guard_proxy=True,
                reason=(
                    f"Guarded draft escalated to RED: context defaults ({', '.join(unsafe_defaults[:5])}) "
                    "apply to every record Odoo creates in this transaction, not only this draft; pass the "
                    "values in vals instead. Human-in-the-Loop approval required."
                ),
                sanitized_args=args,
                sanitized_kwargs=kwargs,
                inject_chatter_note=True,
            )
        unsafe_commands = _find_unsafe_x2many_commands(_collect_create_values(args, kwargs))
        if unsafe_commands:
            return RuleEvaluationResult(
                level=RiskLevel.RED,
                allowed=True,
                requires_guard_proxy=True,
                reason=(
                    f"Guarded draft escalated to RED: x2many commands that modify existing records "
                    f"({', '.join(unsafe_commands[:5])}) require Human-in-the-Loop approval."
                ),
                sanitized_args=args,
                sanitized_kwargs=kwargs,
                inject_chatter_note=True,
            )
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
