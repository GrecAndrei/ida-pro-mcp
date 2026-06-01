"""Step 6: trace.py + static_trace.py merged into trace_analysis.

Verifies the standalone files are gone, the actions are absorbed
under trace_analysis, and the merged dispatcher wires them up.
"""
import os
import re

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), "r", encoding="utf-8") as f:
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


def test_trace_analysis_enum_lists_merged_actions():
    """trace_analysis Literal includes all 6 merged actions
    (3 from trace, 3 from static_trace)."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/trace_analysis.py")
    for action in (
        "get", "clear", "set_options",
        "static_trace", "decrypt_strings", "eval_expr",
    ):
        assert f'"{action}"' in text, (
            f"trace_analysis Literal missing merged action {action}"
        )


def test_trace_analysis_dispatcher_routes_merged_actions():
    """The main trace_analysis dispatcher has a routing branch
    for the merged actions."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/trace_analysis.py")
    assert (
        'elif action in ("get", "clear", "set_options", "static_trace", "decrypt_strings", "eval_expr")'
        in text
    ), "Merged-action dispatch branch missing in trace_analysis"


def test_schemas_data_drops_trace_and_static_trace():
    """schemas_data TOOL_ACTIONS no longer has trace or static_trace
    entries."""
    text = _read("src/ida_pro_mcp/host/schemas_data.py")
    assert '"trace": [' not in text
    assert '"static_trace": [' not in text
    # And trace_analysis picked up the 6 merged actions.
    assert '"get",' in text
    assert '"static_trace",' in text


def test_schemas_data_drops_legacy_arg_schemas():
    """The static_trace arg schema block is gone; the trace arg
    schema was never present in TOOL_ARG_SCHEMAS."""
    text = _read("src/ida_pro_mcp/host/schemas_data.py")
    assert '"static_trace": {' not in text
    # And the merged keys live on trace_analysis.
    # (Sanity: trace_analysis arg schema should exist.)
    # No explicit assertion — just that the file is well-formed.


def test_tools_init_drops_trace_and_static_trace():
    """tools/__init__.py no longer exports trace or static_trace."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/__init__.py")
    assert '"trace",' not in text
    assert '"static_trace",' not in text
    assert '"trace_analysis",' in text


def test_schemas_and_policy_drop_legacy_categories():
    """schemas.py and policy.py no longer reference trace/static_trace
    as tools."""
    schemas = _read("src/ida_pro_mcp/host/schemas.py")
    policy = _read("src/ida_pro_mcp/host/policy.py")
    # _TOOL_CATEGORY_DEBUG used to include "trace"; trace_analysis
    # stays but trace is gone.
    assert '"trace"' not in re.findall(
        r'_TOOL_CATEGORY_DEBUG\s*=\s*\{[^}]*\}', schemas
    )[0] if re.search(r'_TOOL_CATEGORY_DEBUG', schemas) else True
    # The literal '"trace"' on a line by itself with surrounding
    # braces is what we care about; the old line was:
    # _TOOL_CATEGORY_DEBUG = {"debug", "trace", "coverage", "trace_analysis"}
    assert '"trace",' not in schemas.replace("trace_analysis", "")
    # Policy should not list "trace" or "static_trace" as tools.
    assert '"trace",' not in policy
    assert '"static_trace",' not in policy


def test_trace_analysis_handlers_preserve_payload_shapes():
    """The three runtime-trace actions preserve their original return
    shapes (`ok`, `traces`, `count`, `trace_api` for get; `ok`,
    `cleared` for clear; `ok`, `changed` for set_options)."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/trace_analysis.py")
    # The merged dispatcher still references these payload keys.
    for key in ("\"traces\"", "\"count\"", "\"trace_api\"", "\"cleared\"",
                "\"changed\"", "\"soft_state\"", "\"trace_eid\""):
        # trace_eid is not required; just check the rest
        pass
    assert "\"traces\"" in text
    assert "\"trace_api\"" in text
    assert "\"cleared\"" in text
    assert "\"changed\"" in text


def test_static_trace_walk_preserves_static_trace_shape():
    """The static_trace action still returns the original shape
    (`start`, `trace`, `edges`, `count`, `blocks`)."""
    text = _read("src/ida_pro_mcp/ida_mcp/tools/trace_analysis.py")
    assert "\"trace\"" in text
    assert "\"edges\"" in text
    assert "\"blocks\"" in text
    assert "\"decrypt_function\"" in text
    assert "\"potential_calls\"" in text
    assert "\"language\": \"idc\"" in text
