# 🛡️ Odoo Safe MCP — The AI Firewall for Odoo ERP

Connect AI Agents (Claude Desktop, Cursor, n8n, LangChain) to **Odoo ERP (v14 to v19+)** without risking accounting disasters, accidental record deletions (`unlink`), or unauthorized invoice validations (`action_post`).

[![PyPI version](https://img.shields.io/badge/pypi-v2.0.0-blue.svg)](https://pypi.org/project/odoo-safe-mcp/)
[![Odoo Compatibility](https://img.shields.io/badge/Odoo-14.0%20to%2019.0-875A7B.svg)](https://www.odoo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## ⚠️ Why you should NEVER connect a raw MCP server to Odoo

Odoo's native permissions were designed for humans, not LLMs. If you give an AI agent an API key for a standard sales or accounting user so it can read data or draft quotes, **that same key can execute `unlink` (delete records) or `action_post` (legally post invoices to tax authorities)**.

One LLM hallucination can corrupt your `account.move` ledger or wipe out `res.partner` records. **Odoo Safe MCP** acts as a deterministic firewall between your AI agent and Odoo's JSON-RPC/XML-RPC API.

---

## 🚦 How the Security Traffic Light Works

| Risk Level | Odoo Methods | Action Taken | Tier |
| :--- | :--- | :--- | :--- |
| **🟢 GREEN (Safe Read)** | `search`, `read`, `search_read`, `fields_get`, `read_group`, `name_search`, `name_get`, `search_count`, `default_get` | Instant execution via local JSON-RPC. | **Free (Open Source)** |
| **🟡 YELLOW (Guarded Drafts)** | `create` on `crm.lead`, `sale.order`, `purchase.order` | Enforces `state='draft'` and injects an AI audit note into the Odoo Chatter (`message_post`). | **Pro Guard** |
| **🔴 RED (Critical / Destructive)** | `unlink` (any model), `action_post`, `action_confirm`, `button_validate`, `write` on `account.move` | **Pauses execution.** Sends an interactive **Approve / Reject** button to Slack or MS Teams. | **Pro Guard** |
| **⛔ BLACKLIST (Zero-Day Protection)** | Mutations on `res.users`, `res.groups`, `ir.rule`, `ir.model.access` | **Blocked unconditionally** (even with Pro). Prevents privilege escalation. | **Hard Block** |

---

## 🚀 Quickstart (2 Minutes)

### 1. Install via `pip` or run directly with `uvx`

```bash
pip install "odoo-safe-mcp==2.0.0"
```

### 2. Add to your Claude Desktop or Cursor configuration

Edit your `claude_desktop_config.json` (or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "odoo-erp": {
      "command": "uvx",
      "args": ["odoo-safe-mcp@2.0.0"],
      "env": {
        "ODOO_URL": "https://your-company.odoo.com",
        "ODOO_DB": "your-database-name",
        "ODOO_USERNAME": "ai-bot@your-company.com",
        "ODOO_API_KEY": "your_odoo_user_api_key",
        "ODOO_DRY_RUN": "false",
        "ODOO_SAFE_GUARD_KEY": "optional_pro_license_key_for_write_access"
      }
    }
  }
}
```

> ⚠️ **Production Best Practice (Version Pinning):** Always pin the exact version in `uvx` (`odoo-safe-mcp@2.0.0`). Running unpinned `uvx odoo-safe-mcp` downloads upstream changes on every launch, which could lead to breaking changes or unexpected behavior in automated production pipelines.
>
> **Note:** Without `ODOO_SAFE_GUARD_KEY`, the server runs in **Strict Read-Only Mode (🟢 Green Level)**. Set `"ODOO_DRY_RUN": "true"` to test and simulate `YELLOW` and `RED` policies locally with zero risk to your database.

---

## 🔓 Unlock Guarded Write Access, AI Defender & Slack Approvals (Pro & Partner Tiers)

Need your agents to create draft quotes, prepare vendor bills, audit payloads with **Llama 3 8B AI Defender**, or request atomic human approval on Slack before posting invoices?

| Plan | Price | Databases | Key Features |
| :--- | :--- | :--- | :--- |
| **Community** | **€0 / forever** | 1 Local DB | Strict Read-Only Mode (🟢 Green), Zero-Risk Dry-Run Simulation (`ODOO_DRY_RUN=true`), Credential Sanitization |
| **Pro Guard** | **€49 / month** | Up to 5 DBs | Guarded Drafts (🟡 Yellow), Slack Interactive Approvals (🔴 Red), D1 Audit Log, **Llama 3 8B AI Defender Included** |
| **Partner Agency** | **€149 / month** | Up to 25 DBs | Multi-tenant Agency Isolation, Custom Slack Signing Secret, MS Teams Alerts, Llama 3 AI Defender |

1. Get your **License Key** at **[tudominio.com/pricing](https://tudominio.com/pricing)**.
2. Connect your Slack webhook in 1 click via the Cloudflare D1 Activation Portal.
3. Add `ODOO_SAFE_GUARD_KEY` to your environment variables.

---

## 📄 License & Terms of Service

Distributed under the **MIT License** — Free forever for read-only local execution and Dry-Run simulation.

### Limitation of Liability, GDPR Privacy & Trademark Disclaimer
> **IMPORTANT NOTICE:** `odoo-safe-mcp` and its associated Enterprise Guard backend are provided on an **"AS IS" and "AS AVAILABLE"** basis without warranties of any kind, either express or implied, including but not limited to implied warranties of merchantability, fitness for a particular purpose, and non-infringement.
>
> 1. **Auxiliary Control Layer & Human-in-the-Loop Responsibility:** This software operates strictly as an auxiliary deterministic filter and does not replace native database security, accounting audits, or operational vigilance. The human supervisor who clicks **"Approve"** in Slack or Microsoft Teams is the sole legal and accounting authorizer of the resulting ERP mutation.
> 2. **Customer Responsibilities:** The user and customer retain sole and exclusive responsibility for configuring least-privilege permissions on the Odoo user account linked to `ODOO_API_KEY`, monitoring AI agent behavior, and maintaining independent, verified daily database backups.
> 3. **Liability Cap:** To the maximum extent permitted by applicable law, the cumulative aggregate liability of the authors, contributors, and operators for any direct, indirect, incidental, special, or consequential damages (including data loss, accounting discrepancy, lost revenue, or business interruption) shall be strictly capped at the total fee actually paid by the customer for the software during the **one (1) month immediately preceding the event** giving rise to liability (maximum €49 for Pro Guard, €149 for Partner Agency, or €0 for Community Tier).
> 4. **GDPR / RGPD Zero-Data-Retention Architecture:** Read-only (`GREEN`) queries execute locally on the user's machine and never transit through the Enterprise Guard cloud. Paused (`RED`) payloads are encrypted in transit and at rest using `AES-GCM-256` and are **purged immediately (`PURGED_AFTER_RESOLUTION`)** upon approval, rejection, or 24-hour TTL expiration. Audit logs store only cryptographic `SHA-256` payload hashes and technical metadata.
> 5. **Trademark & Non-Affiliation Disclaimer:** This project is an independent software product and is **not affiliated with, sponsored by, or endorsed by Odoo S.A.** `Odoo` is a registered trademark of Odoo S.A. `Slack` is a registered trademark of Slack Technologies, LLC. `Microsoft Teams` is a registered trademark of Microsoft Corporation.

