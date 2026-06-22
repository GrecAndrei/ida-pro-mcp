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


def test_tools_init_no_longer_exports_comment_mgr():
    """tools/__init__.py no longer lists comment_mgr in its tool list."""
    text = _read(os.path.join(TOOLS_DIR, "__init__.py"))
    assert "\"comment_mgr\"" not in text


def test_schemas_data_tools_list_drops_comment_mgr():
    """schemas_data.py TOOLS list no longer contains comment_mgr."""
    text = _read(os.path.join(HOST_DIR, "schemas_data.py"))
    assert "\"comment_mgr\"" not in text


def test_schemas_data_legacy_aliases_route_to_annotation():
    """comments_ai is now aliased to annotation, not comment_mgr."""
    text = _read(os.path.join(HOST_DIR, "schemas_data.py"))
    assert "\"comments_ai\": \"annotation\"" in text
    assert "\"comments_ai\": \"comment_mgr\"" not in text


def test_schemas_data_annotation_description_lists_new_actions():
    """The annotation TOOL_DESCRIPTIONS entry advertises 6 new actions."""
    text = _read(os.path.join(HOST_DIR, "schemas_data.py"))
    # Find the annotation entry — should be a single line.
    assert "\"annotation\":" in text
    # Extract the annotation description line
    for line in text.splitlines():
        if line.strip().startswith("\"annotation\":"):
            assert "get_context" in line
            assert "set_structured" in line
            assert "bulk_set" in line
            assert "export_md" in line
            assert "import_md" in line
            assert "summary" in line
            break
    else:
        pytest.fail("annotation description not found in schemas_data.py")


def test_schemas_data_annotation_actions_enum_has_new_actions():
    """TOOL_ACTIONS[\"annotation\"] includes the 6 new actions."""
    text = _read(os.path.join(HOST_DIR, "tool_registry.py"))
    # Locate the annotation: [ list
    idx = text.find("\"annotation\": [")
    assert idx != -1
    # Read until the closing ]
    end = text.find("]", idx)
    block = text[idx:end]
    for action in (
        "get_context",
        "set_structured",
        "bulk_set",
        "export_md",
        "import_md",
        "summary",
    ):
        assert f"\"{action}\"" in block, f"missing {action!r} in annotation TOOL_ACTIONS block"


def test_schemas_data_no_comment_mgr_actions_block():
    """There is no TOOL_ACTIONS block for comment_mgr anymore."""
    text = _read(os.path.join(HOST_DIR, "schemas_data.py"))
    assert "\"comment_mgr\": [" not in text


def test_schemas_data_no_comment_mgr_description():
    """There is no TOOL_DESCRIPTIONS entry for comment_mgr anymore."""
    text = _read(os.path.join(HOST_DIR, "schemas_data.py"))
    assert "\"comment_mgr\":" not in text


def test_schemas_py_tools_list_drops_comment_mgr():
    """The TOOLS list in schemas.py no longer contains comment_mgr."""
    text = _read(os.path.join(HOST_DIR, "schemas.py"))
    assert "\"comment_mgr\"" not in text


def test_policy_drops_comment_mgr():
    """policy.py no longer lists comment_mgr in any tool block."""
    text = _read(os.path.join(HOST_DIR, "policy.py"))
    assert "\"comment_mgr\"" not in text


def test_schemas_alias_hints_drops_comment_mgr_block():
    """The comment_mgr alias block in schemas_alias_hints is gone, with
    the absorbed actions moved under annotation."""
    text = _read(os.path.join(HOST_DIR, "schemas_alias_hints.py"))
    assert "\"comment_mgr\":" not in text
    # And the absorbed actions appear under annotation:
    assert "\"get_context\":" in text
    assert "\"set_structured\":" in text
    assert "\"bulk_set\":" in text
    assert "\"export_md\":" in text
    assert "\"import_md\":" in text
    assert "\"summary\":" in text


def test_annotation_module_contains_merged_actions():
    """The annotation tool file references the 6 merged comment-mgr
    actions in its Literal / dispatcher / helper."""
    text = _read(os.path.join(TOOLS_DIR, "annotation.py"))
    for action in (
        "get_context",
        "set_structured",
        "bulk_set",
        "export_md",
        "import_md",
        "summary",
    ):
        assert action in text, f"missing {action!r} reference in annotation.py"
    # And the helper exists:
    assert "_annotation_comment_mgr_action" in text


def test_annotation_module_param_rename_to_fmt():
    """Old comment_mgr used `format` (a Python builtin); the merged
    version renames it to `fmt`."""
    text = _read(os.path.join(TOOLS_DIR, "annotation.py"))
    # We use the helper signature as the authoritative contract
    assert "fmt" in text
    # The literal parameter `format` is fine in spots (e.g. calls to
    # `format()`), so we don't forbid it globally. We just ensure the
    # helper signature uses `fmt`:
    assert "def _annotation_comment_mgr_action(action, addr, text, items, path, fmt)" in text


def test_tools_reference_doc_drops_comment_mgr_section():
    """The TOOLS_REFERENCE.md no longer documents a separate comment_mgr
    section (its actions now live under annotation)."""
    text = _read(
        os.path.join(
            os.path.dirname(__file__),
            "..", "docs", "TOOLS_REFERENCE.md",
        )
    )
    assert "### comment_mgr" not in text


def test_tools_reference_doc_annotation_lists_merged_actions():
    """The annotation section in TOOLS_REFERENCE.md lists the 6 new
    actions."""
    text = _read(
        os.path.join(
            os.path.dirname(__file__),
            "..", "docs", "TOOLS_REFERENCE.md",
        )
    )
    # The annotation section should mention all 6 actions in its
    # "Actions:" line.
    assert "get_context" in text
    assert "set_structured" in text
    assert "bulk_set" in text
    assert "export_md" in text
    assert "import_md" in text
    assert "summary" in text


def test_tools_reference_alias_table_routes_to_annotation():
    """The legacy alias table routes comments_ai to annotation, not
    comment_mgr."""
    text = _read(
        os.path.join(
            os.path.dirname(__file__),
            "..", "docs", "TOOLS_REFERENCE.md",
        )
    )
    assert "| `comments_ai` | `annotation` |" in text
    assert "| `comments_ai` | `comment_mgr` |" not in text



def test_wiki_index_drops_comment_mgr():
    """docs/wiki/INDEX.md no longer lists the comment_mgr page."""
    text = _read(
        os.path.join(
            os.path.dirname(__file__),
            "..", "docs", "wiki", "INDEX.md",
        )
    )
    assert "comment_mgr" not in text


def test_tool_sweep_probe_routes_to_annotation():
    """tests/probes/tool_sweep_probe.py now uses annotation(get_context)
    in place of comment_mgr(get_context)."""
    text = _read(
        os.path.join(
            os.path.dirname(__file__),
            "probes", "tool_sweep_probe.py",
        )
    )
    assert "comment_mgr" not in text
    assert (
        "(\"annotation\", {\"action\": \"get_context\", \"addr\": entry_addr})"
        in text
    )


def test_schemas_data_tools_count_matches_TOOLS():
    """The TOOLS list in schemas_data.py still matches the active
    tool surface (i.e. nothing is dangling)."""
    from ida_pro_mcp.host.schemas import TOOLS
    text = _read(os.path.join(HOST_DIR, "schemas_data.py"))
    # Find the first TOOLS = [ block
    idx = text.find("TOOLS = [")
    end = text.find("]", idx)
    block = text[idx:end]
    for tool in TOOLS:
        assert f"\"{tool}\"" in block, f"{tool!r} not in TOOLS list"
