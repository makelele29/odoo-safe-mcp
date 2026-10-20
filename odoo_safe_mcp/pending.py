"""
Local store of proposed operations awaiting approval.

The exact op_json lives only on this machine; the Guard only ever sees its hash. Approval
decisions are checked against this file, and a '.done' marker created with O_EXCL makes every
approval single-use even if the MCP server restarts or the agent asks twice.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Optional

_INTENT_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class PendingStoreError(Exception):
    pass


def valid_intent_id(intent_id: str) -> bool:
    return bool(_INTENT_ID.match(str(intent_id or "")))


class PendingStore:
    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir) / "intents"

    def _path(self, intent_id: str, suffix: str) -> Path:
        if not valid_intent_id(intent_id):
            raise PendingStoreError(f"Invalid intent id: {intent_id!r}")
        return self.dir / f"{intent_id}{suffix}"

    def save(self, intent_id: str, op_json: str, meta: Dict[str, Any]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self._path(intent_id, ".json")
        payload = json.dumps({"op_json": op_json, "created_at": time.time(), **meta})
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)

    def load(self, intent_id: str) -> Optional[Dict[str, Any]]:
        path = self._path(intent_id, ".json")
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def claim(self, intent_id: str) -> None:
        """Mark as executed; raises if it was already claimed (replay protection)."""
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self._path(intent_id, ".done"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise PendingStoreError("This approval was already executed on this machine.") from exc
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(str(time.time()))

    def record_result(self, intent_id: str, summary: Dict[str, Any]) -> None:
        self._path(intent_id, ".done").write_text(json.dumps(summary, default=str), encoding="utf-8")

    def result(self, intent_id: str) -> Optional[Dict[str, Any]]:
        path = self._path(intent_id, ".done")
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            return {"status": "EXECUTED"}
