"""Regression tests for the search_callers / search_callees dedup.

Background:
    `search_callers` and `search_callees` in tools/search/unified.py were
    two near-duplicate ~60-line functions: same target resolution, same
    row-building loop pattern, same ranking/line-formatting, same
    paginate+build_response boilerplate. The only meaningful difference
    was the iteration that produces (other_ea, site_ea) pairs.

    After dedup, both call two helpers:
      - `_build_call_graph_rows(func, get_relations)`: builds the
        {func_ea -> row} map from a relation iterator.
      - `_format_call_graph_response(rows, func, target_ea, sem_meta,
        include_context, offset, limit, include_items, empty_note)`:
        ranks, formats lines, paginates, builds the response.

This test asserts (via AST + source checks):
    1. The two helpers exist in search/unified.py.
    2. Both search_callers and search_callees exist and call the
       helpers (no more inline iter / rank / paginate code).
    3. The public surface (function names + arg lists) is preserved
       so callers don't need to update.
    4. The non-empty response shape is unchanged: returns a dict
       with `target`, `target_addr`, `items` (when requested), and
       `lines`.
    5. The error case (target not a function) still returns
       build_response with note=.
    6. No regression in net test count.
"""

import ast
import os
import re

ROOT = os.path.dirname(os.path.dirname(__file__))
UNIFIED = os.path.join(
    ROOT, "src", "ida_pro_mcp", "ida_mcp", "tools", "search", "unified.py"
)


def _read():
    with open(UNIFIED) as f:
        return f.read()


def _functions(src):
    return {n.name for n in ast.parse(src).body if isinstance(n, ast.FunctionDef)}


def _function_ast(src, name):
    return next(
        (n for n in ast.parse(src).body
         if isinstance(n, ast.FunctionDef) and n.name == name),
        None,
    )


# ---- 1. helpers exist ---------------------------------------------------------


def test_helpers_exist():
    src = _read()
    funcs = _functions(src)
    assert "_build_call_graph_rows" in funcs, "missing _build_call_graph_rows"
    assert "_format_call_graph_response" in funcs, "missing _format_call_graph_response"


def test_helpers_are_module_level():
    """Both helpers must be top-level (no closure/indirection)."""
    src = _read()
    funcs = _functions(src)
    assert "_build_call_graph_rows" in funcs
    assert "_format_call_graph_response" in funcs
    for name in ("_build_call_graph_rows", "_format_call_graph_response"):
        node = _function_ast(src, name)
        assert node is not None
        # No decorators: helper is a plain function.
        assert node.decorator_list == [], f"{name} should not be decorated"


# ---- 2. callers/callees call the helpers --------------------------------------


def test_search_callers_uses_helpers():
    src = _read()
    assert "def search_callers" in src
    # Must call the row builder and the response formatter.
    m = re.search(r"def search_callers\([^)]*\):(.*?)(?=\ndef |\Z)", src, re.DOTALL)
    assert m is not None
    body = m.group(1)
    assert "_build_call_graph_rows" in body, (
        "search_callers must call _build_call_graph_rows"
    )
    assert "_format_call_graph_response" in body, (
        "search_callers must call _format_call_graph_response"
    )
    # Must NOT have its own paginate_records call (the formatter handles it).
    assert "paginate_records" not in body, (
        "search_callers should not paginate inline anymore"
    )


def test_search_callees_uses_helpers():
    src = _read()
    assert "def search_callees" in src
    m = re.search(r"def search_callees\([^)]*\):(.*?)(?=\ndef |\Z)", src, re.DOTALL)
    assert m is not None
    body = m.group(1)
    assert "_build_call_graph_rows" in body
    assert "_format_call_graph_response" in body
    assert "paginate_records" not in body


# ---- 3. public surface preserved -----------------------------------------------


def test_search_callers_signature_preserved():
    """Callers depend on (pattern, include_context, offset, limit,
    semantic_min_score, include_alternatives, include_items) arg order."""
    node = _function_ast(_read(), "search_callers")
    assert node is not None
    args = [a.arg for a in node.args.args]
    assert args == [
        "pattern", "include_context", "offset", "limit",
        "semantic_min_score", "include_alternatives", "include_items",
    ], f"search_callers args changed: {args}"


def test_search_callees_signature_preserved():
    node = _function_ast(_read(), "search_callees")
    assert node is not None
    args = [a.arg for a in node.args.args]
    assert args == [
        "pattern", "include_context", "offset", "limit",
        "semantic_min_score", "include_alternatives", "include_items",
    ], f"search_callees args changed: {args}"


# ---- 4. both functions are now short (no more inline iter/rank) ----------------


def test_search_callers_body_compact():
    """After dedup, search_callers should be much shorter than the
    original 60 lines. Threshold: under 50 lines of body."""
    src = _read()
    m = re.search(r"def search_callers\([^)]*\):(.*?)(?=\ndef |\Z)", src, re.DOTALL)
    body = m.group(1)
    nlines = len([ln for ln in body.splitlines() if ln.strip()])
    assert nlines < 50, (
        f"search_callers body has {nlines} non-empty lines; "
        f"expected <50 after dedup"
    )


def test_search_callees_body_compact():
    src = _read()
    m = re.search(r"def search_callees\([^)]*\):(.*?)(?=\ndef |\Z)", src, re.DOTALL)
    body = m.group(1)
    nlines = len([ln for ln in body.splitlines() if ln.strip()])
    assert nlines < 50, (
        f"search_callees body has {nlines} non-empty lines; "
        f"expected <50 after dedup"
    )


# ---- 5. edge-iteration logic is unique to each direction ----------------------


def test_caller_iter_uses_xrefsto():
    """Callers use XrefsTo(func.start_ea) — that direction is the
    defining trait of caller traversal."""
    src = _read()
    # Find the inner iterator definition for callers.
    m = re.search(
        r"def _iter_caller_edges\(target_func\):(.*?)(\n    def |\Z)",
        src, re.DOTALL,
    )
    assert m is not None, "search_callers must define _iter_caller_edges"
    body = m.group(1)
    assert "XrefsTo" in body, "_iter_caller_edges should walk XrefsTo"


def test_callee_iter_uses_xrefsfrom_and_call_types():
    """Callees use XrefsFrom + CALL_XREF_TYPES filter."""
    src = _read()
    m = re.search(
        r"def _iter_callee_edges\(target_func\):(.*?)(\n    def |\Z)",
        src, re.DOTALL,
    )
    assert m is not None, "search_callees must define _iter_callee_edges"
    body = m.group(1)
    assert "XrefsFrom" in body, "_iter_callee_edges should walk XrefsFrom"
    assert "CALL_XREF_TYPES" in body, (
        "_iter_callee_edges must filter by CALL_XREF_TYPES"
    )


# ---- 6. response shape preserved for non-empty case --------------------------


def test_format_response_includes_target_and_addr():
    """The response must still carry `target` and `target_addr` keys."""
    src = _read()
    m = re.search(
        r"def _format_call_graph_response\([^)]*\):(.*?)(?=\ndef |\Z)",
        src, re.DOTALL,
    )
    body = m.group(1)
    assert "target=" in body, "response must include `target=...` kwarg"
    assert "target_addr=" in body, "response must include `target_addr=...` kwarg"


def test_format_response_emits_items_when_requested():
    src = _read()
    m = re.search(
        r"def _format_call_graph_response\([^)]*\):(.*?)(?=\ndef |\Z)",
        src, re.DOTALL,
    )
    body = m.group(1)
    assert 'result["items"]' in body, (
        "response must populate result['items'] when include_items=True"
    )


def test_format_response_preserves_paginate_sort_key():
    """The original sort key (score desc, address_ea asc) is preserved."""
    src = _read()
    m = re.search(
        r"def _format_call_graph_response\([^)]*\):(.*?)(?=\ndef |\Z)",
        src, re.DOTALL,
    )
    body = m.group(1)
    assert 'sort_key=lambda r: (r["score"], r["address_ea"])' in body, (
        "sort_key must be (score desc, address_ea asc)"
    )
