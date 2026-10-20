"""
Verification of Guard decisions (zero-credential approvals).

The Guard cloud signs every approval with Ed25519. This client only executes an operation when:
  1. the signature verifies against a public key PINNED here (or added by the operator via env),
  2. the signed op_sha256 equals the hash of the operation stored locally when it was proposed,
  3. database, licence, intent id and expiry match.
A compromised Guard therefore cannot make this client run anything it did not propose itself.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import time
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# kid -> raw Ed25519 public key (base64). Production keys are pinned at release time with
# `node scripts/generate-signing-key.mjs <kid>` in odoo-safe-guard-enterprise.
TRUSTED_GUARD_KEYS: Dict[str, str] = {}


class DecisionError(Exception):
    pass


def trusted_keys() -> Dict[str, str]:
    """Pinned keys plus operator-provided ones (self-hosted Guard or local testbed): 'kid:b64,kid2:b64'."""
    keys = dict(TRUSTED_GUARD_KEYS)
    for item in os.getenv("ODOO_GUARD_PUBLIC_KEYS", "").split(","):
        kid, _, value = item.strip().partition(":")
        if kid and value:
            keys[kid.strip()] = value.strip()
    return keys


def sha256_hex(data: str | bytes) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def verify_decision(
    decision: str,
    signature: str,
    kid: str,
    *,
    intent_id: str,
    op_json: str,
    db: str,
    guard_key: str,
    now: float | None = None,
) -> Dict[str, Any]:
    keys = trusted_keys()
    if not keys:
        raise DecisionError(
            "No trusted Guard signing key is configured: refusing to execute. "
            "Update odoo-safe-mcp or set ODOO_GUARD_PUBLIC_KEYS for a self-hosted Guard."
        )
    public_b64 = keys.get(kid or "")
    if not public_b64:
        raise DecisionError(f"Decision signed with unknown key id '{kid}'. Update odoo-safe-mcp.")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64)).verify(
            base64.b64decode(signature), decision.encode("utf-8")
        )
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise DecisionError("Invalid Guard signature: the approval was not issued by the trusted Guard.") from exc

    data = json.loads(decision)
    checks = {
        "version": data.get("v") == 2,
        "approved": data.get("decision") == "APPROVED",
        "intent": data.get("intent_id") == intent_id,
        "operation hash": data.get("op_sha256") == sha256_hex(op_json),
        "database": data.get("db") == db,
        "licence": data.get("license") == sha256_hex(guard_key),
        "expiry": float(data.get("exp", 0)) > (now if now is not None else time.time()),
    }
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        raise DecisionError(f"Signed decision rejected ({', '.join(failed)} mismatch). Nothing was executed.")
    return data
