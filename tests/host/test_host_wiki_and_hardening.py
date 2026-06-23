"""Tool registry consistency — names and descriptions defined."""
from __future__ import annotations

from ida_pro_mcp.services import ADVERTISED_TOOLS, HIDDEN_TOOLS_IN_LIST, TOOLS, TOOL_DESCRIPTIONS


class TestToolRegistry:
    """Tool registration consistency."""

    def test_advertised_tools_are_nonempty(self) -> None:
        assert len(ADVERTISED_TOOLS) > 0

    def test_hidden_tools_are_nonempty(self) -> None:
        assert len(HIDDEN_TOOLS_IN_LIST) > 0

    def test_tools_has_all_entries(self) -> None:
        assert len(TOOLS) == len(ADVERTISED_TOOLS) + len(HIDDEN_TOOLS_IN_LIST)

    def test_each_tool_has_description(self) -> None:
        for tool in ADVERTISED_TOOLS:
            assert tool in TOOL_DESCRIPTIONS, f"Missing description for {tool}"
