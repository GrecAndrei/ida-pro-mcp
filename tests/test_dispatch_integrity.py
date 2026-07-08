"""
Dispatch handlers exist for all advertised tools.
Created: 2025-07-06
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
assert str(SRC) in sys.path or sys.path.insert(0, str(SRC)) is None


@pytest.fixture(scope="module")
def schemas_data():
    return importlib.import_module("ida_pro_mcp.host.schemas_data")


@pytest.fixture(scope="module")
def dispatch_source():
    p = SRC / "ida_pro_mcp" / "host" / "server" / "server_dispatch.py"
    return p.read_text(encoding="utf-8")


class TestDispatchHandlers:
    def test_advertised_tools_have_dispatch(self, schemas_data, dispatch_source):
        """Every advertised tool is host-routed, has a module, or an explicit handler."""
        from pathlib import Path

        tools_dir = SRC / "ida_pro_mcp" / "ida_mcp" / "tools"
        host_only = {
            "session", "truncation", "bookmarks", "background", "workflow",
            "multi_session", "threat_hunt", "batch", "wiki", "blackboard",
        }
        for tool in schemas_data.ADVERTISED_TOOLS:
            has_handler = f"def _handle_{tool}" in dispatch_source
            has_route = f'tool_name == "{tool}"' in dispatch_source
            has_module = (tools_dir / f"{tool}.py").exists() or (
                tools_dir / tool / "__init__.py"
            ).exists()
            if tool in host_only:
                assert has_handler or has_route, (
                    f"Host-only tool '{tool}' has no dispatch route/handler"
                )
            else:
                assert has_handler or has_route or has_module, (
                    f"Tool '{tool}' has no dispatch path or IDA module"
                )

    def test_rpc_arg_filter_rejects_unknown(self, dispatch_source):
        """Contract: unknown kwargs must hard-fail, not silent-strip."""
        assert "Unknown argument(s) for tool" in dispatch_source
        assert "rpc_args = {k: v for k, v in rpc_args.items() if k in allowed}" not in dispatch_source

    def test_dispatch_references_match_tools(self, schemas_data, dispatch_source):
        """Dispatch handlers should only reference tools that exist."""
        import re
        # Known aliases that dispatch may reference
        aliases = {"plugins": "misc"}
        valid_names = set(schemas_data.TOOLS) | set(aliases.keys())
        # Find all tool_name == "X" patterns
        refs = re.findall(r'tool_name\s*==\s*"(\w+)"', dispatch_source)
        for ref in refs:
            assert ref in valid_names, \
                f"Dispatch references tool '{ref}' which is not in TOOLS"
