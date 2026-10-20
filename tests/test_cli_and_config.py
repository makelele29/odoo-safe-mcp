"""CLI onboarding (init/doctor), configuration parsing and the local pending store."""

import json

import pytest

from odoo_safe_mcp import __version__
from odoo_safe_mcp.cli import merge_mcp_config, normalize_url, run_doctor, run_init, server_entry, write_client_config
from odoo_safe_mcp.config import _guard_base_url, get_config, localhost_warning
from odoo_safe_mcp.pending import PendingStore, PendingStoreError

INTENT = "12345678-1234-1234-1234-1234567890ab"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("http://localhost:8069/", "http://127.0.0.1:8069"),
        ("https://acme.odoo.com", "https://acme.odoo.com"),
        ("http://LOCALHOST", "http://127.0.0.1"),
    ],
)
def test_init_normalizes_urls(raw, expected):
    assert normalize_url(raw) == expected


def test_localhost_warning_only_on_windows(monkeypatch):
    monkeypatch.setattr("sys.platform", "win32")
    assert "127.0.0.1" in localhost_warning("http://localhost:8069")
    assert localhost_warning("http://127.0.0.1:8069") is None
    monkeypatch.setattr("sys.platform", "linux")
    assert localhost_warning("http://localhost:8069") is None


@pytest.mark.parametrize(
    "raw",
    ["https://odoosafemcp.stream/v1/guard", "https://odoosafemcp.stream/", "https://odoosafemcp.stream/v2", ""],
)
def test_guard_url_accepts_legacy_endpoint_forms(raw):
    assert _guard_base_url(raw) == "https://odoosafemcp.stream"


def test_server_entry_pins_version_and_drops_empty_values():
    entry = server_entry({"ODOO_URL": "https://x", "ODOO_SAFE_GUARD_KEY": ""})
    assert entry["args"] == [f"odoo-safe-mcp@{__version__}"]
    assert entry["env"] == {"ODOO_URL": "https://x"}


def test_merge_keeps_other_mcp_servers():
    existing = {"mcpServers": {"github": {"command": "gh"}}, "theme": "dark"}
    merged = merge_mcp_config(existing, "odoo", {"command": "uvx"})
    assert merged["mcpServers"] == {"github": {"command": "gh"}, "odoo": {"command": "uvx"}}
    assert merged["theme"] == "dark"
    assert existing["mcpServers"] == {"github": {"command": "gh"}}


def test_write_client_config_creates_backup(tmp_path):
    path = tmp_path / "Claude" / "claude_desktop_config.json"
    assert write_client_config(path, "odoo", {"command": "uvx"}) is None
    backup = write_client_config(path, "odoo", {"command": "uvx", "args": ["x"]})
    assert backup and backup.exists()
    assert json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["odoo"]["args"] == ["x"]


def test_pending_store_is_single_use(tmp_path):
    store = PendingStore(tmp_path)
    store.save(INTENT, '{"a":1}', {"model": "sale.order"})
    assert store.load(INTENT)["op_json"] == '{"a":1}'
    store.claim(INTENT)
    with pytest.raises(PendingStoreError):
        store.claim(INTENT)


@pytest.mark.parametrize("bad", ["../x", "a" * 36, "", None])
def test_pending_store_rejects_path_traversal(tmp_path, bad):
    with pytest.raises(PendingStoreError):
        PendingStore(tmp_path).save(bad, "{}", {})


@pytest.mark.asyncio
async def test_doctor_passes_against_fake_world(world, capsys):
    assert await run_doctor(get_config()) == 0
    out = capsys.readouterr().out
    assert "Authenticated as uid 2" in out
    assert "Pro Guard: plan PRO" in out
    assert "Guard signing key verified" in out
    assert "SECRET" not in out


@pytest.mark.asyncio
async def test_doctor_flags_mismatched_signing_key(world, monkeypatch, capsys):
    monkeypatch.setenv("ODOO_GUARD_PUBLIC_KEYS", "test:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    assert await run_doctor(get_config()) == 1
    assert "does not match" in capsys.readouterr().out


def test_init_writes_claude_and_cursor_configs(world, monkeypatch, tmp_path):
    claude, cursor = tmp_path / "claude.json", tmp_path / "cursor.json"
    monkeypatch.setattr("odoo_safe_mcp.cli.client_config_paths", lambda: {"Claude Desktop": claude, "Cursor": cursor})
    answers = iter(["http://localhost:8069", "demo", "ai-bot", "", "y"])
    secrets = iter(["odoo-api-key-SECRET-123", ""])
    # The fake world answers on erp.example.com: point the wizard there regardless of the typed URL.
    monkeypatch.setattr("odoo_safe_mcp.cli.normalize_url", lambda url: "https://erp.example.com")
    assert run_init(ask=lambda _: next(answers), ask_secret=lambda _: next(secrets)) == 0
    for path in (claude, cursor):
        env = json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["odoo"]["env"]
        assert env["ODOO_DB"] == "demo" and "ODOO_SAFE_GUARD_KEY" not in env


@pytest.mark.asyncio
async def test_doctor_explains_rpc_scope_on_odoo_20(world, monkeypatch, capsys):
    odoo, _ = world
    original = odoo.handle

    def handle(params):
        if params["service"] == "common" and params["method"] == "version":
            return {"server_version": "20.0", "server_version_info": [20, 0, 0, "final", 0, ""]}
        if params["service"] == "common" and params["method"] == "authenticate":
            return False
        return original(params)

    monkeypatch.setattr(odoo, "handle", handle)
    assert await run_doctor(get_config()) == 1
    assert "RPC scope" in capsys.readouterr().out
