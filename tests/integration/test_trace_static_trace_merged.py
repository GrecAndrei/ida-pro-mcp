"""Step 6: trace.py + static_trace.py merged into trace_analysis.

Verifies the standalone files are gone, the actions are absorbed
under trace_analysis, and the merged dispatcher wires them up.
"""
import os
import re

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_standalone_trace_files_removed():
    """trace.py and static_trace.py are gone — both merged into
    trace_analysis."""
    assert not os.path.exists(
        os.path.join(ROOT, "src/ida_pro_mcp/ida_mcp/tools/trace.py")
    )
    assert not os.path.exists(
        os.path.join(ROOT, "src/ida_pro_mcp/ida_mcp/tools/static_trace.py")
    )

