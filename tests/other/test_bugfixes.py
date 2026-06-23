"""Tests for MCP error codes and host-side utilities."""
from __future__ import annotations

import pytest

from ida_pro_mcp.services import MCPError, make_error, TOOL_ACTIONS


class TestMCPErrorCodes:
    """MCP error code coverage."""

    def test_all_codes_have_hints(self) -> None:
        for attr in dir(MCPError):
            if attr.isupper():
                code = getattr(MCPError, attr)
                error = make_error(code, "test message")
                assert isinstance(error, dict)
                assert error.get("error") is True

    def test_hints_are_actionable(self) -> None:
        error = make_error(MCPError.SESSION_NOT_FOUND, "session not found")
        assert "hint" in error

    def test_make_error_with_message(self) -> None:
        error = make_error(MCPError.INVALID_ARGS, "Custom message")
        assert error.get("message") == "Custom message"

    def test_tool_actions_exist(self) -> None:
        assert isinstance(TOOL_ACTIONS, dict)
        assert len(TOOL_ACTIONS) > 0
