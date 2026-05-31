import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.host.schemas import (  # noqa: E402
    ADVERTISED_TOOLS,
    HIDDEN_TOOLS_IN_LIST,
    TOOL_ACTIONS,
    TOOLS,
    WRAPPER_ACTIONS,
)
from ida_pro_mcp.host.server import IDAMCPServer  # noqa: E402


def test_misc_health_reports_catalog_surface():
    server = IDAMCPServer()
    res = server._execute_tool("misc", {"action": "health"})
    assert isinstance(res, dict)
    assert res.get("ok") is True
    assert res.get("action") == "health"

    tools = res.get("tools", {})
    assert tools.get("registered") == len(TOOLS)
    assert tools.get("advertised") == len(ADVERTISED_TOOLS)
    assert tools.get("hidden_from_tools_list") == len(HIDDEN_TOOLS_IN_LIST)
    assert tools.get("wrappers") == list(WRAPPER_ACTIONS)

    action_surface = tools.get("action_surface", {})
    assert action_surface.get("tool_count_with_actions") == len(TOOL_ACTIONS)
    assert action_surface.get("total_actions") == sum(
        len(list(v or [])) for v in TOOL_ACTIONS.values()
    )
    assert isinstance(action_surface.get("max_actions_tool"), (str, type(None)))
    assert isinstance(action_surface.get("max_actions_count"), int)


def test_misc_health_verbose_includes_per_tool_action_counts():
    server = IDAMCPServer()
    res = server._execute_tool("misc", {"action": "health", "verbose": True})
    tools = res.get("tools", {})
    counts = tools.get("action_counts_by_tool")
    assert isinstance(counts, dict)
    assert counts.get("session") == len(TOOL_ACTIONS.get("session", []))
