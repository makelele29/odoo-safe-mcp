# Changelog

## 3.1.1 — 2026-11-25

### Security Hardening
- **Draft Thresholds (Fail-Closed):** Ignored untrusted client `amount_total` overrides on `create`, disallowed negative/over-100% discount netting, looked up `product.product.list_price` when `price_unit` is omitted, flagged uncertain totals fail-closed to human approval, supported `ODOO_DRAFT_MAX_AMOUNT=0` (approve every draft), and added `account.payment.amount` + `partner_id` support in previews.
- **GDPR PII Shield (`mask`/`strict`):** Redacted `__domain` in `read_group`/`formatted_read_group`, scrubbed emails/IBANs in `display_name`/`name_search`/`sanitize_error`, added coverage for `email_formatted`, `contact_address*`, `bank_account_id`, `emergency_*`, `x_dni`/`x_nif`/`x_iban*`, applied PII redaction before sending previews out of the machine, and blocked PII domain/groupby/order oracles when `ODOO_PII_MODE != off`.
- **SEC-07 & Model Hardening:** Extended credential oracle inspection to positional args (`name_search`, `read_group`, `formatted_read_group`, `search`, `search_read`), added `formatted_read_group` (Odoo 19/20) to `GREEN_METHODS`, forbade `certificate.key` (VeriFactu PEM keys), `auth.oauth.provider`, `account.online.link`, `res.users.settings`, and mutations on `base.import.module`.
- **Multi-Company Fail-Closed:** Non-empty invalid `ODOO_ALLOWED_COMPANY_IDS` now fails closed (`PermissionError`), strips out-of-scope `force_company`/`company_id`/`default_company_id` from RPC context, and blocks out-of-scope `vals["company_id"]` on writes.

### Bug Fixes
- Fixed `_dumps_bounded` on `dict` outputs (e.g. `odoo_describe_model` on 150+ field models with UTF-8 accents) so it always emits valid JSON within the 60 KB byte budget, and applied `_dumps_bounded` to `odoo_aggregate` and `odoo_execute_kw`.
- Added automatic schema-aware fallback in `odoo_search` when a curated `DEFAULT_FIELD_PROFILES` field does not exist (e.g. Odoo 16 `project.task.state` or instances without `stock`/`account`).

## 3.1.0 — 2026-11-25

### Security & Privacy
- **GDPR PII Shield (`ODOO_PII_MODE=off|mask|strict`):** Masks or redacts `vat`, `email`, `phone`, `acc_number`/`iban`, `wage`, and street addresses across reads and execution summaries before data enters the LLM context.
- **Strict Multi-Company Isolation (`ODOO_ALLOWED_COMPANY_IDS`):** Enforces and clamps `allowed_company_ids` in the ORM `context` of every local RPC call.
- **SEC-07 Domain Oracle Protection:** Blocks boolean-oracle reads filtering, grouping, or ordering by credential/token fields (including dotted relations like `user_ids.oauth_access_token` and `signup` fields), and strips sensitive fields passed positionally.

### Governance & Product
- **Telegram Bot Approvals & Draft Thresholds:** Added `ODOO_DRAFT_MAX_AMOUNT` local escalation support and preview `amount_total` estimation from inline `sale.order` / `purchase.order` lines `(0, 0, {...})`.
- **Context Efficiency:** Added curated lightweight `DEFAULT_FIELD_PROFILES` on `odoo_search` (overridable via `all_fields=True`), `bin_size` context on full reads, a 60 KB output ceiling (`_truncated` envelope), and fuzzy/writable filtering in `odoo_describe_model(search=..., include_readonly=...)`.
- **Session-Independent Approvals:** Added `odoo_pending_approvals` read-only tool backed by `PendingStore.list_pending()` so approvals can be resumed in any new conversation.
- **Windows Onboarding & MCP Registry:** `init` automatically falls back from `uvx` to `odoo-safe-mcp` or `python -m odoo_safe_mcp.cli`, added `__main__.py`, `server.json`, and `Production/Stable` PyPI classifier.

## 3.0.0 — 2026-10-20

### Security
- **Zero-credential approvals (Guard API v2).** The Odoo URL, user and API key never leave the machine.
  The Guard receives the operation JSON, its SHA-256 and a preview; it returns an Ed25519-signed decision
  bound to that hash, database, licence and expiry. The client verifies it against a pinned key,
  executes once (local single-use marker) and reports the result for the audit trail.
- Guarded drafts can no longer modify, delete or re-parent other documents' records through x2many
  commands or bare id lists (verified exploit on Odoo 18: a confirmed order line re-priced from 275.00 to
  0.01 without approval). Such creates are escalated to RED.
- `res.config.settings` (integration secrets via `default_get`, module installs via `execute`),
  `res.users.apikeys`, `auth.totp.device`, `iap.account` and password wizards are now forbidden.
  Module (un)install wizards, `ir.actions.*`, `ir.asset` and `ir.default` can no longer be mutated.
- Credential-like fields (`access_token`, `account_token`, `*_secret`, `*_api_key`…) are redacted from
  responses, not only from the requested field list.
- Tracking-silencing context keys (`tracking_disable`, `mail_notrack`…) are dropped from guarded drafts.
- Guarded drafts only accept a short per-model list of `default_*` context keys, with a scalar value:
  `default_partner_id`, `default_user_id`, plus `default_team_id` and `default_state` (forced to draft) on
  sales orders, `default_state` on purchase orders, `default_team_id` and `default_type` on leads. Any other
  `default_*` key escalates to RED; pass field values in `vals` instead. Odoo 14-20 applies context defaults
  to every record created in the same transaction: x2many defaults such as
  `default_order_line=[[4, id]]` linked, re-priced or deleted other documents' records without going
  through the x2many check, and records created on the side keep them (inbox notifications created
  already read with `default_is_read`, sequence ranges with `default_number_next`).
- One policy, two engines: the client and the Guard Edge run the same 249 shared vectors
  (`tests/policy_vectors.json`). Aligning them closed further guarded-draft gaps, which now escalate to
  RED: x2many lists hiding a command next to junk items (Odoo skips unknown items and still applies the
  LINK), boolean or float command codes, float or string ids, and a `context` sent as a list of pairs.
  `vals_list` passed as a single dict is now forced to draft too. Model and method names with anything
  but ASCII letters, digits, `_` and `.` (zero-width, full-width, BOM, inner spaces…) are refused.

### Product
- New tools: `odoo_search`, `odoo_read`, `odoo_count`, `odoo_aggregate`, `odoo_describe_model`,
  `odoo_list_models`, `odoo_approval_status`, with read-only / destructive annotations. Blocks are MCP
  errors (`isError=true`). `odoo_execute_kw` accepts a `justification` shown (as unverified) to the approver.
- Approval cards show what really changes: record names, *before → after* values, amount at stake,
  fields touched and warnings (irreversible delete, missing ids).
- `odoo-safe-mcp init` (guided setup for Claude Desktop / Cursor, with backups) and
  `odoo-safe-mcp doctor` (connectivity, least privilege, email for audit notes, licence, signing key).
- Kill-switch: pausing a licence stops every AI write immediately.
- Inline wait for quick approvals (`ODOO_APPROVAL_WAIT_SECONDS`, default 25 s).

### Compatibility
- `name_get` emulated with `display_name` on Odoo 17+.
- Chatter notes use `body_is_html` (Odoo 17+ escapes plain RPC bodies) with a fallback for older versions.
- Least-privilege users (no access to `ir.model`) get previews and model discovery.
- Odoo 20: `read_group(domain, fields, groupby)` was replaced by `read_group(domain, groupby, aggregates)`
  returning tuples; calls are transparently translated to `formatted_read_group` (verified on 20.0).
- Odoo 20 only accepts API keys with the `rpc` scope over RPC; `doctor` explains it when authentication fails.
- Verified with the Docker testbed on Odoo 14, 15, 16, 17, 18, 19 and 20, plus the end-to-end Guard flow
  on 14, 18 and 20.
- Single version source; `setup.py` removed; Python 3.13 / 3.14.

## 2.0.0
- Initial public release: traffic-light firewall, dry-run, Pro Guard proxy with Slack/Teams approvals.
