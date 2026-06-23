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

