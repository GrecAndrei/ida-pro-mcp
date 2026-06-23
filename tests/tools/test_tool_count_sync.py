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
