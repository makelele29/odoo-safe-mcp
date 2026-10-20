# Changelog

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
