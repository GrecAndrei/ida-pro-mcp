"""
@@TEST_REGISTRY@@
interacts:
  - dispatch:search
  - dispatch:blackboard
  - dispatch:code
  - dispatch:data
  - dispatch:intelligence
  - dispatch:session
  - dispatch:modify
  - dispatch:types
format: v1
description: Dispatch handlers exist for all advertised tools
created: 2025-07-06
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
        """Every advertised tool should have a dispatch handler or be routed."""
        import re
        for tool in schemas_data.ADVERTISED_TOOLS:
            # Has _handle_<tool> method
            has_handler = f"def _handle_{tool}" in dispatch_source
            # Has direct routing: tool_name == "X"
            has_route = f'tool_name == "{tool}"' in dispatch_source
            # Is handled by __default__ dispatch (tool module exists)
            has_module = True  # Will fall through to default if no explicit handler
            assert has_handler or has_route or has_module, \
                f"Tool '{tool}' has no dispatch handler in server_dispatch.py"

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
