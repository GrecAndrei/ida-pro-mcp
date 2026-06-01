"""Dynamic test: docs must reflect the live tool surface.

Single source of truth: ``ida_pro_mcp.host.schemas.{TOOLS, ADVERTISED_TOOLS,
HIDDEN_TOOLS_IN_LIST}``.

If this test fails after adding/removing tools, run::

    python -m tools.sync_tool_counts

to update the docs in place. The script is idempotent.
"""

from __future__ import annotations

import importlib
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"


def _import(name: str):
    """Import a module by dotted path with the project root on sys.path."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return importlib.import_module(name)


def _read(rel: str) -> str:
    return (DOCS / rel).read_text(encoding="utf-8")


def test_techref_reports_live_total():
    """``TECHNICAL_REFERENCE.md`` must list the current TOOLS count."""
    from ida_pro_mcp.host.schemas import TOOLS  # noqa: WPS433

    text = _read("TECHNICAL_REFERENCE.md")
    expected = len(TOOLS)
    assert re.search(
        rf"`TOOLS` — ordered list of all {expected} tool names",
        text,
    ), (
        f"TECHNICAL_REFERENCE.md does not match live TOOLS={expected}. "
        f"Run: python -m tools.sync_tool_counts"
    )


def test_techref_reports_live_advertised():
    """``TECHNICAL_REFERENCE.md`` must list the current ADVERTISED_TOOLS count."""
    from ida_pro_mcp.host.schemas import ADVERTISED_TOOLS  # noqa: WPS433

    text = _read("TECHNICAL_REFERENCE.md")
    expected = len(ADVERTISED_TOOLS)
    assert re.search(
        rf"`ADVERTISED_TOOLS` — {expected} tools shown in `tools/list`",
        text,
    ), (
        f"TECHNICAL_REFERENCE.md does not match live ADVERTISED={expected}. "
        f"Run: python -m tools.sync_tool_counts"
    )


def test_techref_reports_live_hidden():
    """``TECHNICAL_REFERENCE.md`` must list the current HIDDEN_TOOLS_IN_LIST count."""
    from ida_pro_mcp.host.schemas import HIDDEN_TOOLS_IN_LIST  # noqa: WPS433

    text = _read("TECHNICAL_REFERENCE.md")
    expected = len(HIDDEN_TOOLS_IN_LIST)
    assert re.search(
        rf"`HIDDEN_TOOLS_IN_LIST` — {expected} tools callable",
        text,
    ), (
        f"TECHNICAL_REFERENCE.md does not match live HIDDEN={expected}. "
        f"Run: python -m tools.sync_tool_counts"
    )


def test_toolsref_reports_live_total():
    """``TOOLS_REFERENCE.md`` headline must list the current TOOLS count."""
    from ida_pro_mcp.host.schemas import TOOLS  # noqa: WPS433

    text = _read("TOOLS_REFERENCE.md")
    expected = len(TOOLS)
    assert re.search(
        rf"Current canonical tool surface: \*\*{expected} tools\*\*",
        text,
    ), (
        f"TOOLS_REFERENCE.md does not match live TOOLS={expected}. "
        f"Run: python -m tools.sync_tool_counts"
    )


def test_sync_script_idempotent():
    """Running the sync script with --check must report in sync."""
    script = ROOT / "tools" / "sync_tool_counts.py"
    if not script.exists():
        pytest.skip("tools/sync_tool_counts.py not found")
    result = subprocess.run(
        [sys.executable, str(script), "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 0, (
        f"sync_tool_counts --check failed:\n"
        f"  stdout: {result.stdout}\n"
        f"  stderr: {result.stderr}"
    )


def test_sync_script_can_run_in_place():
    """Running the sync script must always succeed and not raise."""
    script = ROOT / "tools" / "sync_tool_counts.py"
    if not script.exists():
        pytest.skip("tools/sync_tool_counts.py not found")
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 0, (
        f"sync_tool_counts failed:\n"
        f"  stdout: {result.stdout}\n"
        f"  stderr: {result.stderr}"
    )
