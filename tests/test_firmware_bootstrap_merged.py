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


def test_tools_init_no_longer_exports_firmware_bootstrap():
    """tools/__init__.py no longer lists firmware_bootstrap in its
    tool list."""
    text = _read(os.path.join(TOOLS_DIR, "__init__.py"))
    assert "\"firmware_bootstrap\"" not in text


def test_schemas_data_tools_list_drops_firmware_bootstrap():
    """schemas_data.py TOOLS list no longer contains firmware_bootstrap.

    The legacy alias `firmware_bootstrap` -> `firmware_view` IS still
    present, so we just confirm the tool is not in the ordered TOOLS
    list at the top of the file."""
    text = _read(os.path.join(HOST_DIR, "schemas_data.py"))
    idx = text.find("TOOLS = [")
    end = text.find("]", idx)
    block = text[idx:end]
    assert "\"firmware_bootstrap\"" not in block


def test_schemas_data_legacy_alias_routes_to_firmware_view():
    """firmware_bootstrap is now aliased to firmware_view, not
    registered as its own tool."""
    text = _read(os.path.join(HOST_DIR, "schemas_data.py"))
    assert "\"firmware_bootstrap\": \"firmware_view\"" in text
    # And it should not also appear in TOOL_ACTIONS:
    assert "\"firmware_bootstrap\": [" not in text
    # And it should not have its own TOOL_ARG_SCHEMAS block (which had
    # chip_family, load_base, memory_map, peripheral_addresses,
    # post_load_actions). We check by ensuring the unique key combo
    # of that block isn't present:
    assert (
        "\"firmware_bootstrap\": {\n        \"chip_family\":"
        not in text
    )


def test_schemas_data_removed_arg_schema_block():
    """The standalone firmware_bootstrap TOOL_ARG_SCHEMAS block is gone."""
    text = _read(os.path.join(HOST_DIR, "schemas_data.py"))
    # The block had keys like chip_family/load_base/memory_map. After
    # folding into firmware_view these aren't in their own block.
    assert "\"firmware_bootstrap\": {\n        \"chip_family\":" not in text


def test_schemas_data_firmware_view_action_block_has_bootstrap():
    """The firmware_view TOOL_ACTIONS list still includes `bootstrap`."""
    text = _read(os.path.join(HOST_DIR, "schemas_data.py"))
    idx = text.find("\"firmware_view\": [")
    assert idx != -1
    end = text.find("]", idx)
    block = text[idx:end]
    assert "\"bootstrap\"" in block


def test_schemas_data_firmware_view_description_mentions_bootstrap():
    """The firmware_view TOOL_DESCRIPTIONS string still advertises the
    bootstrap action."""
    text = _read(os.path.join(HOST_DIR, "schemas_data.py"))
    for line in text.splitlines():
        if line.strip().startswith("\"firmware_view\":"):
            assert "bootstrap" in line
            break
    else:
        pytest.fail("firmware_view description not found")


def test_schemas_py_tools_list_drops_firmware_bootstrap():
    """The TOOLS list in schemas.py no longer contains firmware_bootstrap."""
    text = _read(os.path.join(HOST_DIR, "schemas.py"))
    assert "\"firmware_bootstrap\"" not in text


def test_policy_drops_firmware_bootstrap():
    """policy.py no longer lists firmware_bootstrap in any tool block."""
    text = _read(os.path.join(HOST_DIR, "policy.py"))
    assert "\"firmware_bootstrap\"" not in text


def test_firmware_view_module_contains_fwb_helpers():
    """The firmware_view tool file contains the absorbed bootstrap
    helpers, prefixed `_fwb_`, and the public `run_firmware_bootstrap`."""
    text = _read(os.path.join(TOOLS_DIR, "firmware_view.py"))
    for fn in (
        "def _fwb_safe_bounds",
        "def _fwb_int_addr",
        "def _fwb_annotate_mmio",
        "def _fwb_define_ascii_strings",
        "def _fwb_run_vector_bootstrap",
        "def _fwb_base_bootstrap_report",
        "def run_firmware_bootstrap",
    ):
        assert fn in text, f"missing {fn!r} in firmware_view.py"


def test_firmware_view_bootstrap_action_calls_local_run_firmware_bootstrap():
    """The bootstrap action handler in firmware_view no longer tries
    to import the deleted firmware_bootstrap module — it calls the
    in-module run_firmware_bootstrap directly."""
    text = _read(os.path.join(TOOLS_DIR, "firmware_view.py"))
    # The old import lines are gone.
    assert "from .firmware_bootstrap import run_firmware_bootstrap" not in text
    assert "from firmware_bootstrap import run_firmware_bootstrap" not in text
    # And the bootstrap action still calls the function (now locally).
    bootstrap_idx = text.find("if action == \"bootstrap\":")
    assert bootstrap_idx != -1
    # The call site can be hundreds of lines below the action header
    # (because the action body contains the arch-profile infer block
    # before calling run_firmware_bootstrap). Take a generous window.
    snippet = text[bootstrap_idx:bootstrap_idx + 5000]
    assert "run_firmware_bootstrap(" in snippet


def test_server_runtime_routes_through_firmware_view():
    """server_runtime now invokes firmware_view(action=bootstrap)
    instead of the deleted firmware_bootstrap tool."""
    text = _read(
        os.path.join(HOST_DIR, "server_runtime.py")
    )
    assert "\"tool\": \"firmware_bootstrap\"" not in text
    assert "\"tool\": \"firmware_view\"" in text
    # And the rpc body uses action=bootstrap
    assert "\"action\": \"bootstrap\"" in text


def test_tools_surface_consistency():
    """The TOOLS list in schemas_data.py still matches the active
    tool surface (no dangling entries)."""
    from ida_pro_mcp.host.schemas import TOOLS
    text = _read(os.path.join(HOST_DIR, "schemas_data.py"))
    idx = text.find("TOOLS = [")
    end = text.find("]", idx)
    block = text[idx:end]
    for tool in TOOLS:
        assert f"\"{tool}\"" in block, f"{tool!r} not in TOOLS list"


def test_load_base_str_is_preserved_by_fwb_base_bootstrap_report():
    """The _fwb_base_bootstrap_report helper preserves a string load_base
    verbatim. (Sanity check; the function lives in firmware_view.py and
    was extracted from the deleted firmware_bootstrap.py.)"""
    src = _read(os.path.join(TOOLS_DIR, "firmware_view.py"))
    m = re.search(
        r"^def _fwb_base_bootstrap_report\(.*?(?=^def |\nclass |\Z)",
        src,
        re.MULTILINE | re.DOTALL,
    )
    assert m, "_fwb_base_bootstrap_report not found in firmware_view.py"
    fn_src = m.group(0)
    ns: dict = {"__name__": "fwb_test_stub"}
    exec(fn_src, ns)
    fn = ns["_fwb_base_bootstrap_report"]
    r = fn("AIC8800D80", 0x120000, ["define_vector_table"])
    assert r["ok"] is True
    assert r["load_base"] == "0x120000"
    # String load_base is preserved as-is.
    r2 = fn("AIC8800D80", "0x80000", [])
    assert r2["load_base"] == "0x80000"
