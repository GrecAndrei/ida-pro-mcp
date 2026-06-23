"""Regression tests for merging comment_mgr into annotation.

Background
----------
The standalone `comment_mgr` tool exposed comment CRUD, bulk import/export,
and structured-context summary actions. It was merged into the `annotation`
tool as 6 new actions: get_context, set_structured, bulk_set, export_md,
import_md, summary. This test pins the new surface (action names, schema
listings, file deletion, alias routing) and ensures nothing in the host
or tool registry still points at the deleted `comment_mgr` tool name.

The annotation module itself can't be loaded in CI (it requires zeromcp
and idaapi), so we exercise the host-side wiring (schemas, tools init)
and the in-source docstring/file system directly.
"""

from __future__ import annotations

import os
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


def test_comment_mgr_file_deleted():
    """The standalone comment_mgr.py module no longer exists."""
    assert not os.path.exists(os.path.join(TOOLS_DIR, "comment_mgr.py"))


def test_comment_mgr_wiki_page_deleted():
    """The standalone wiki page for comment_mgr is gone."""
    assert not os.path.exists(
        os.path.join(
            os.path.dirname(__file__),
            "..", "docs", "wiki", "tools", "comment_mgr.md",
        )
    )

