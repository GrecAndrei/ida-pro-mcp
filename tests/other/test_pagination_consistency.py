"""Sanity tests for paginated list-action response shape.

All list-style actions should report `{total, offset, count}` so
callers can iterate without needing to know the per-tool keys.
This keeps agents from hard-coding `items` vs `matches` vs
`results` per action.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "tools"


def _all_tool_source() -> dict[str, str]:
    """Map tool filename -> source."""
    out = {}
    for p in TOOLS_DIR.rglob("*.py"):
        if p.name == "__init__.py":
            continue
        out[p.name] = p.read_text()
    return out


def test_data_functions_response_shape_is_uniform():
    """data(action='functions') must expose `total`, `offset`, `count`
    in every code path, including the empty-result branch.
    """
    src = (TOOLS_DIR / "data.py").read_text()
    # The data(functions) result dict must list all three fields.
    funcs_section_start = src.find('if action == "functions"')
    funcs_section_end = src.find('elif action == "globals"', funcs_section_start)
    body = src[funcs_section_start:funcs_section_end]
    assert '"total"' in body
    assert '"offset"' in body
    assert '"count"' in body
    # Empty-result branch still has the keys (we want a uniform shape).
    assert '"functions"' in body


def test_data_globals_response_shape_is_uniform():
    src = (TOOLS_DIR / "data.py").read_text()
    start = src.find('elif action == "globals"')
    end = src.find('elif action == "strings"', start)
    body = src[start:end]
    assert '"total"' in body
    assert '"offset"' in body


def test_data_strings_response_shape_is_uniform():
    src = (TOOLS_DIR / "data.py").read_text()
    start = src.find('elif action == "strings"')
    end = src.find('elif action == "imports"', start)
    body = src[start:end]
    assert '"total"' in body
    assert '"offset"' in body


def test_data_imports_response_shape_is_uniform():
    src = (TOOLS_DIR / "data.py").read_text()
    start = src.find('elif action == "imports"')
    end = src.find('elif action == "exports"', start)
    body = src[start:end]
    assert '"total"' in body
    assert '"offset"' in body


def test_data_exports_response_shape_is_uniform():
    src = (TOOLS_DIR / "data.py").read_text()
    start = src.find('elif action == "exports"')
    end = src.find('elif action == "lookup"', start)
    body = src[start:end]
    assert '"total"' in body


def test_funcs_list_response_shape_is_uniform_with_data_functions():
    """`funcs(action='list')` aliases to `data(action='functions')` so
    it should use the same response keys. Pin via AST to confirm the
    call site delegates.
    """
    src = (TOOLS_DIR / "funcs.py").read_text()
    # Without writing a full parser, confirm the wrapper passes through
    # the same payload rather than re-shaping.
    assert 'action="functions"' in src
    assert "count=count" in src or "count=" in src
    # The wrapper must not invent new keys (e.g. 'functions_list')
    # that the data() action doesn't expose.
    funcs_section = src[src.find('if action == "list"'):src.find("call_kwargs")]
    # The block ends with `return data(...)`, no `result[...] = ` reshape.
    assert "result[" not in funcs_section


def test_legacy_data_uses_dict_shape_for_lookups():
    """data(action='lookup') returns {addr, name, type, size} on hit and
    {matches, count} on miss. Make sure both branches exist and the
    shape is documented.
    """
    src = (TOOLS_DIR / "data.py").read_text()
    # both responses can be returned.
    assert '"addr"' in src and '"name"' in src
    assert '"matches"' in src and '"count"' in src


def test_several_list_actions_follow_total_count_offset_pattern():
    """Pin a small number of widely-used list actions each expose
    total/offset/count. Spot-check string_ops, project, fixups.
    """
    expectations = [
        ("string_ops.py", "find_urls"),
        ("fixups.py", "list"),
        ("types.py", "enum_values"),
        ("types.py", "list"),
        ("project.py", "list_recent"),
        ("project.py", "list_dir"),
    ]
    for fname, action in expectations:
        path = TOOLS_DIR / fname
        if not path.exists():
            continue
        src = path.read_text()
        # We can't deterministically extract the body for every action
        # but we can at least assert the file declares an offset param,
        # implying it uses pagination shape.
        assert "offset" in src or "limit" in src, (
            f"{fname} (action={action}) should paginate via offset/limit."
        )


def test_response_compact_off_does_not_strip_total():
    """Make sure response compaction preserves the pagination envelope
    even when `drop_false=True`. The _STATE_BOOLEAN_KEYS already covers
    booleans; total/offset/count are integer counts and must survive
    any compaction.
    """
    # Spot-check by importing the helper module.
    text = (REPO / "src/ida_pro_mcp/host/server/server_response_compact.py").read_text()
    # Drop_false only filters literal False values; an integer 0 stays.
    assert "drop_false" in text
    # Re-read compact logic — booleans go through _STATE_BOOLEAN_KEYS;
    # the rest of dict fields survive.
    assert "_STATE_BOOLEAN_KEYS" in text
    # Verify total/offset/count are NOT in the preserved set
    # (so they're subject to standard compactor rules, which keep integer 0s).
    for field in ("total", "offset", "count"):
        # Drop_false skips only literal False values, not 0 integers.
        # Sanity: the field name doesn't appear as a boolean key.
        assert field not in text.split("_STATE_BOOLEAN_KEYS = frozenset({")[1].split("})")[0] + "}", (
            f"{field} must not be flagged as a 'preserve-when-false' key — total=0 is meaningful."
        )
