"""Regression tests for folding firmware_bootstrap into firmware_view.

Background
----------
The standalone `firmware_bootstrap` tool exposed a single chip-aware
post-load bootstrap pipeline (vector-table definition, MMIO annotation,
auto-reanalyze, string definition). It was redundant with
`firmware_view(action="bootstrap")`, which already delegated to
`run_firmware_bootstrap`. This test pins the new surface: the
`firmware_bootstrap` tool is gone, its implementation helpers live
inside `firmware_view.py` (prefixed `_fwb_`), the `bootstrap` action is
the only entry point, and a `firmware_bootstrap` legacy alias routes
to `firmware_view`.
"""

from __future__ import annotations

import os
import re
import sys

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
HOST_DIR = os.path.join(SRC, "ida_pro_mcp", "host")
TOOLS_DIR = os.path.join(SRC, "ida_pro_mcp", "ida_mcp", "tools")


def _read(path):
    with open(path) as f:
        return f.read()


def test_firmware_bootstrap_tool_file_deleted():
    """The standalone firmware_bootstrap.py module no longer exists."""
    assert not os.path.exists(os.path.join(TOOLS_DIR, "firmware_bootstrap.py"))

