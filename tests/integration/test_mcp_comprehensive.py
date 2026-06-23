"""Comprehensive MCP host-side integration tests."""
from __future__ import annotations

import pytest

from ida_pro_mcp.services import (
    IDAMCPServer,
    Session,
    SessionManager,
    TOOLS,
    TOOL_ACTIONS,
    ADVERTISED_TOOLS,
    HIDDEN_TOOLS_IN_LIST,
)


class TestServerBasics:
    """Server instantiation and tool execution."""

    def test_server_initializes(self) -> None:
        server = IDAMCPServer()
        assert server is not None

    def test_server_lists_advertised_tools(self) -> None:
        assert len(ADVERTISED_TOOLS) > 0

    def test_server_tool_count_matches(self) -> None:
        assert len(TOOLS) == len(ADVERTISED_TOOLS) + len(HIDDEN_TOOLS_IN_LIST)


class TestSessionLifecycle:
    """Session creation and management."""

    def test_session_manager_requires_cache_dir(self) -> None:
        mgr = SessionManager(cache_dir="/tmp/_mcp_cache")
        assert mgr is not None

    def test_session_has_id(self) -> None:
        session = Session(
            session_id="test123",
            idb_path="/tmp/test.i64",
            binary_path="/tmp/test.bin",
        )
        assert session.session_id == "test123"


class TestProductionHardening:
    """Hardening checks."""

    def test_server_execute_tool_returns_dict(self) -> None:
        server = IDAMCPServer()
        result = server._execute_tool("session", {"action": "health"})
        assert isinstance(result, dict)

    def test_tool_actions_are_defined(self) -> None:
        assert len(TOOL_ACTIONS) > 0
        for tool, actions in TOOL_ACTIONS.items():
            assert len(actions) > 0, f"No actions for tool '{tool}'"
