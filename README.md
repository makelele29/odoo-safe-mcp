# 🛡️ Odoo Safe MCP — let AI work in Odoo, with a human in control

Connect Claude, Cursor, n8n or your own agents to **Odoo 14 → 20** through a deterministic firewall:
reads run instantly, drafts are guarded, and anything critical (`write`, `unlink`, confirming orders,
posting invoices…) **waits for a person on your team to approve it from their phone — seeing exactly what
will change.** Your Odoo credentials never leave your machine.

[![PyPI](https://img.shields.io/pypi/v/odoo-safe-mcp.svg)](https://pypi.org/project/odoo-safe-mcp/)
[![Odoo](https://img.shields.io/badge/Odoo-14%20→%2020-875A7B.svg)](#compatibility)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## Why

Odoo 20 ships its own MCP server, and there are several community ones. They connect AI to your ERP;
none of them answers **"who approves what the AI does?"**. An API key that can read quotes can also
`unlink` customers or `action_post` invoices to the tax authority. One hallucination or one
prompt-injected email is enough.

Odoo Safe MCP is the control layer:

| | |
| :-- | :-- |
| 🟢 **Reads** | `search_read`, `read`, `read_group`, `fields_get`… run locally and instantly. Secrets (API keys, portal `access_token`, integration passwords) are redacted even if the agent does not ask for specific fields. |
| 🟡 **Guarded drafts** | `create` on `sale.order`, `purchase.order`, `crm.lead` is forced to draft, stripped of tracking-silencing context and of x2many commands that could touch other records, and stamped in the Chatter. |
| 🔴 **Critical** | Everything else waits for a human on Slack or Teams, who sees the real records, *before → after* values and amounts — not just the agent's own explanation. |
| ⛔ **Never** | Users, groups, access rules, API keys, system parameters, settings, modules, server actions… blocked even with a paid licence. |

## How approvals work (zero-credential)

```text
AI agent ──MCP──► odoo-safe-mcp (your machine, holds the Odoo API key)
                    │ 1. builds a preview from Odoo: records, before → after, amount
                    │ 2. sends the Guard ONLY: operation JSON + SHA-256 + preview  (no URL, no user, no key)
                    ▼
                 Guard cloud ──card──► approver on Slack / Teams / web
                    │ 3. signs the decision (Ed25519) bound to that exact SHA-256, database and licence
                    ▼
                 odoo-safe-mcp verifies the signature with a pinned public key, checks the hash
                 matches the operation it proposed, executes ONCE with your credentials, reports the audit.
```

A compromised cloud cannot make your machine run anything it did not propose itself. No tunnels: it
works the same with Odoo Online, Odoo.sh and on-premise.

## Quickstart (3 minutes)

1. In Odoo, create a user for the AI (e.g. `ai-bot`, **with an email**) with only the business rights it
   needs, and generate an API key for it (*Preferences → Account Security*).
2. Run the guided setup — it checks the connection and permissions and writes the Claude Desktop / Cursor config:

   ```bash
   uvx odoo-safe-mcp init
   ```

3. Restart your AI client and ask *"How many open quotations do we have?"*

Manual configuration (`claude_desktop_config.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "odoo": {
      "command": "uvx",
      "args": ["odoo-safe-mcp@3.0.0"],
      "env": {
        "ODOO_URL": "https://your-company.odoo.com",
        "ODOO_DB": "your-database",
        "ODOO_USERNAME": "ai-bot@your-company.com",
        "ODOO_API_KEY": "the_bot_api_key",
        "ODOO_SAFE_GUARD_KEY": "optional_pro_licence"
      }
    }
  }
}
```

Diagnose anything with `uvx odoo-safe-mcp doctor`. On Windows use `http://127.0.0.1:<port>` rather than
`localhost` for local instances (about 20× faster).

## Tools exposed to the agent

| Tool | What it does |
| :-- | :-- |
| `odoo_search`, `odoo_read`, `odoo_count` | Read records (paginated, long texts trimmed to save tokens) |
| `odoo_aggregate` | Totals and counts grouped by fields (`read_group`) |
| `odoo_describe_model`, `odoo_list_models` | Discover models and fields before writing |
| `odoo_execute_kw` | Any ORM method through the firewall, with an optional `justification` for the approver |
| `odoo_approval_status` | Check a pending approval and execute it once approved |

Read tools carry `readOnlyHint`; write tools `destructiveHint`. Blocks are returned as MCP errors so
agents understand they failed.

## Plans

| Plan | Price | What you get |
| :-- | :-- | :-- |
| **Community** | Free (MIT) | Firewalled reads, secret redaction, dry-run simulation (`ODOO_DRY_RUN=true`) |
| **Pro Guard** | €49 / month | Up to 5 databases, guarded drafts, human approvals on Slack/Teams/web with previews, audit log, kill-switch, AI Defender |
| **Business** | €149 / month | Up to 10 databases, Microsoft Teams, your own Slack app (in-Slack buttons). Need more? Contact us |

Get a licence at **[odoosafemcp.stream](https://odoosafemcp.stream/#pricing)**.

## Security & testing

- Every rule is covered by an exhaustive policy matrix (~1,750 model × method × licence combinations)
  and a regression test for each vulnerability found during our own red-teaming.
- A real testbed starts Odoo 14 → 20 in Docker with a least-privilege bot and runs the integration
  suite; an end-to-end suite runs the real Guard Worker locally and proves, among other things, that the
  Guard database never contains Odoo credentials and that signed approval links cannot be forged,
  reused or swapped.
- Report vulnerabilities privately to **soporte@odoosafemcp.stream**.

## Compatibility

Built for Odoo 14 → 20 (Community & Enterprise, Online / Odoo.sh / on-premise), Python 3.10 → 3.14 and
any MCP client (Claude Desktop, Cursor, Windsurf, VS Code, n8n, custom agents). `name_get` is emulated on
Odoo 17+, and Chatter notes use `body_is_html` where required.

| Odoo | 14 | 15 | 16 | 17 | 18 | 19 | 20 |
| :-- | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| Live integration suite (real Odoo in Docker) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| End-to-end approvals with the real Guard | ✅ | — | — | — | ✅ | — | ✅ |

*Last full run: 20 Oct 2026, 0 failures. Odoo 20 needs an API key with the RPC scope; aggregations are
translated to its new `read_group` API automatically.*

## License & disclaimer

MIT. Provided **"as is"**, without warranties. Odoo Safe MCP is an auxiliary control layer: it does not
replace Odoo's access rights, backups or accounting review, and the person who approves an operation is
its authoriser. Liability is capped at the fees paid in the month preceding the event. Read-only
operations never transit our cloud; approval previews are encrypted at rest and purged on resolution.

*Not affiliated with, sponsored or endorsed by Odoo S.A. "Odoo" is a trademark of Odoo S.A.; "Slack" of
Slack Technologies, LLC; "Microsoft Teams" of Microsoft Corporation.*
