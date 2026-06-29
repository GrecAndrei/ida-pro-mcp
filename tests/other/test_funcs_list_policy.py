"""Tests for the funcs(action='list') policy classification.

Verifies the action-level (not tool-level) gating: ``funcs(action='list')``
must classify as READ-tier so callers don't need ``_risk_ack=true`` just
to enumerate functions.
"""

from __future__ import annotations

import pytest

from ida_pro_mcp.host.policy import (
    READ_ONLY_ACTIONS,
    RiskTier,
    classify_tool_action,
)


def test_funcs_list_is_read_only():
    """The (funcs, list) pair must be in the READ allowlist."""
    assert ("funcs", "list") in READ_ONLY_ACTIONS


def test_classify_funcs_list():
    """End-to-end: classify_tool_action('funcs', 'list') returns READ."""
    tier = classify_tool_action("funcs", "list")
    assert tier == RiskTier.READ


def test_funcs_write_actions_still_write():
    """Guard against over-broadening: write actions must stay WRITE_IDB."""
    write_actions = {"create", "delete", "set_flags"}
    for action in write_actions:
        tier = classify_tool_action("funcs", action)
        # WRITE_IDB tier is the conservative default; we never downgrade.
        assert tier != RiskTier.READ, f"funcs(action='{action}') downgraded to READ unexpectedly"


def test_funcs_info_still_read():
    """Existing (funcs, info) classification must not regress."""
    assert classify_tool_action("funcs", "info") == RiskTier.READ
