"""
Shared policy vectors: the same cases run against src/policy.ts in the Guard Worker (`npm test`), so the
client and the Edge cannot drift apart. The contract is described in the header of policy_vectors.json.
"""

import copy
import json
from pathlib import Path

import pytest

from odoo_safe_mcp import rules
from odoo_safe_mcp.rules import RiskLevel, evaluate_odoo_call

VECTORS_PATH = Path(__file__).with_name("policy_vectors.json")
WORKER_COPY = Path(__file__).resolve().parents[2] / "odoo-safe-guard-enterprise" / "test" / "policy_vectors.json"
SPEC = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
VECTORS = SPEC["vectors"]


def _dumps(value):
    # Order-sensitive on purpose: the Edge compares JSON.stringify output before signing a draft.
    return json.dumps(value, ensure_ascii=False)


def _wire(value):
    # What the Edge parses: canonical_op_json() sends the payload with sorted keys.
    return json.loads(json.dumps(value, sort_keys=True))


def _expectations(vector):
    exp = {**vector, **vector.get("python", {})}
    level = RiskLevel(SPEC["level_mapping"][exp["expected_level"]]["python"])
    return level, exp.get("expected_sanitized_args", vector["args"]), exp.get("expected_sanitized_kwargs", vector["kwargs"])


@pytest.mark.parametrize("vector", VECTORS, ids=[v["id"] for v in VECTORS])
def test_policy_vector(vector):
    args, kwargs = copy.deepcopy(vector["args"]), copy.deepcopy(vector["kwargs"])
    level, exp_args, exp_kwargs = _expectations(vector)

    decision = evaluate_odoo_call(vector["model"], vector["method"], args, kwargs)

    assert decision.level == level, decision.reason
    assert _dumps(decision.sanitized_args) == _dumps(exp_args)
    assert _dumps(decision.sanitized_kwargs) == _dumps(exp_kwargs)
    assert _dumps(args) == _dumps(vector["args"]) and _dumps(kwargs) == _dumps(vector["kwargs"])

    if level == RiskLevel.FORBIDDEN:
        assert not decision.allowed and not decision.requires_guard_proxy
    elif level == RiskLevel.GREEN:
        assert decision.allowed and not decision.requires_guard_proxy
    else:
        assert decision.allowed and decision.requires_guard_proxy

    if level == RiskLevel.YELLOW:
        # The client's sanitised draft must survive re-sanitisation untouched, or the Edge answers 409.
        wire_args, wire_kwargs = _wire(exp_args), _wire(exp_kwargs)
        again = evaluate_odoo_call(vector["model"], vector["method"], wire_args, wire_kwargs)
        assert again.level == RiskLevel.YELLOW
        assert _dumps(again.sanitized_args) == _dumps(wire_args)
        assert _dumps(again.sanitized_kwargs) == _dumps(wire_kwargs)


def test_vector_ids_are_unique_and_overrides_are_documented():
    ids = [v["id"] for v in VECTORS]
    assert len(ids) == len(set(ids))
    for vector in VECTORS:
        assert vector["expected_level"] in SPEC["level_mapping"]
        for engine in ("python", "edge"):
            if engine in vector:
                assert vector[engine].get("difference") in SPEC["intentional_differences"], vector["id"]


def test_tables_match_engine_constants():
    tables = SPEC["tables"]
    assert sorted(rules.READ_AND_WRITE_FORBIDDEN_MODELS) == tables["forbidden_models"]
    assert sorted(rules.PROTECTED_SYSTEM_MODELS - rules.READ_AND_WRITE_FORBIDDEN_MODELS) == tables["protected_system_models"]
    assert sorted(rules.GREEN_METHODS) == tables["read_methods"]
    assert sorted(rules.CRITICAL_RED_METHODS) == tables["critical_methods"]
    assert sorted(rules.YELLOW_CREATE_MODELS) == tables["yellow_create_models"]
    assert sorted(rules.DRAFT_ENFORCED_MODELS) == tables["draft_enforced_models"]
    assert sorted(rules.YELLOW_ALLOWED_CONTEXT_KEYS) == tables["yellow_allowed_context_keys"]
    assert {
        model: sorted(keys) for model, keys in rules.YELLOW_ALLOWED_DEFAULT_KEYS.items()
    } == tables["yellow_allowed_default_keys"]


@pytest.mark.skipif(not WORKER_COPY.exists(), reason="Guard Worker checkout not found next to this repository")
def test_worker_copy_is_identical():
    normalise = lambda path: path.read_text(encoding="utf-8").replace("\r\n", "\n")  # noqa: E731
    assert normalise(WORKER_COPY) == normalise(VECTORS_PATH), "run `npm run sync:vectors` in odoo-safe-guard-enterprise"
