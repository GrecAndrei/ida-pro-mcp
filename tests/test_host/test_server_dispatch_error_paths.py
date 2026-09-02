from __future__ import annotations

import pytest

from ida_pro_mcp.host.config import _bounded_int, _coerce_bool
from ida_pro_mcp.host.policy import (
    PolicyDecision,
    PolicyMode,
    ack_from_args,
    evaluate_policy,
    normalize_mode,
    strictest,
)
from ida_pro_mcp.host.server.postprocess import (
    PP_KEYS,
    apply_post_processing,
    has_post_process,
    prepare_args_for_postprocess,
)
from ida_pro_mcp.host.server.rate_limit import is_rate_limit_exempt
from ida_pro_mcp.host.server.server_dispatch import LONG_RUNNING_ACTIONS


def test_bounded_int_and_coerce_bool() -> None:
    assert _bounded_int("10", default=5, min_value=1, max_value=20) == 10
    assert _bounded_int("100", default=5, min_value=1, max_value=20) == 20
    assert _bounded_int("-5", default=5, min_value=1, max_value=20) == 1
    assert _bounded_int("invalid", default=5, min_value=1, max_value=20) == 5

    assert _coerce_bool(True) is True
    assert _coerce_bool("true") is True
    assert _coerce_bool("1") is True
    assert _coerce_bool("yes") is True
    assert _coerce_bool(False) is False
    assert _coerce_bool("false") is False
    assert _coerce_bool("0") is False


def test_policy_tiers_and_risk_ack() -> None:
    # ack_from_args
    assert ack_from_args({"risk_ack": True}) is True
    assert ack_from_args({"risk_ack": "true"}) is True
    assert ack_from_args({"risk_ack": False}) is False
    assert ack_from_args({}) is False

    # normalize_mode
    assert normalize_mode("off") == PolicyMode.OFF
    assert normalize_mode("assist") == PolicyMode.ASSIST
    assert normalize_mode("enforce") == PolicyMode.ENFORCE

    # strictest
    assert strictest("off", "assist") == PolicyMode.ASSIST
    assert strictest("assist", "enforce") == PolicyMode.ENFORCE
    assert strictest("enforce", "off") == PolicyMode.ENFORCE


def test_postprocess_pipeline() -> None:
    assert "offset" in PP_KEYS
    assert "limit" in PP_KEYS
    assert "grep" in PP_KEYS

    args_with_pp = {"address": "0x401000", "limit": 10, "grep": "main"}
    assert has_post_process(args_with_pp) is True

    stripped_args, pp_opts = prepare_args_for_postprocess("data", args_with_pp)
    assert "limit" not in stripped_args
    assert "grep" not in stripped_args
    assert pp_opts["limit"] == 10
    assert pp_opts["grep"] == "main"

    # Apply post process to list payload
    raw_payload = [
        {"name": "func_main", "addr": "0x401000"},
        {"name": "func_sub_1", "addr": "0x401100"},
        {"name": "func_main_helper", "addr": "0x401200"},
    ]
    processed = apply_post_processing(raw_payload, {"grep": "main"})
    assert len(processed["data"]) == 2


def test_long_running_actions_and_rate_limit() -> None:
    assert ("analysis", "analyze") in LONG_RUNNING_ACTIONS
    assert ("search", "find") in LONG_RUNNING_ACTIONS

    # Rate limit exempt checks
    assert is_rate_limit_exempt("session", "health") is True
    assert is_rate_limit_exempt("bookmarks") is True
    assert is_rate_limit_exempt("random_tool", "random_action") is False
