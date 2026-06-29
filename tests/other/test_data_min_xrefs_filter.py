"""AST-level tests pinning the funcs.list / data(functions) filter API.

The 'functions' listing walks every function in the IDB. On a
real-world binary this returns thousands of stub entries, most of
which an agent has no use for. The `min_xrefs` filter is the cheap
escape valve: it drops functions nobody calls so pagination stays sane.
"""

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (REPO / rel).read_text()


def _module(rel: str) -> ast.Module:
    return ast.parse(_read(rel))


def test_data_functions_declares_min_xrefs_argument():
    """`min_xrefs` must be a parameter to data(action='functions').

    Pinning the literal in the source is more robust than the docstring
    because the parameter flow is what callers depend on at runtime.
    """
    src = _read("src/ida_pro_mcp/ida_mcp/tools/data.py")
    assert "min_xrefs" in src, (
        "data.py should expose a min_xrefs filter on the functions action."
    )
    # Look for the Annotated type-hint, which is how callers see the docstring.
    assert "min_xrefs:" in src or "min_xrefs :" in src
    # The Annotated[...] entry must include a description string (the
    # in-tool docstring LLM callers see).
    tree = _module("src/ida_pro_mcp/ida_mcp/tools/data.py")
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.arg == "min_xrefs":
            found = True
            break
    assert found, "data(action='functions') must declare a min_xrefs parameter"


def test_data_functions_min_xrefs_filter_implementation():
    """When min_xrefs is provided, the loop must check xrefs_to before
    appending. Verify the guard precedes the `total += 1` so the filter
    actually affects the `total` count returned to the caller.
    """
    src = _read("src/ida_pro_mcp/ida_mcp/tools/data.py")
    assert "min_xrefs is not None" in src, (
        "data.py functions loop must guard xref filtering with `min_xrefs is not None` "
        "so it's skipped when callers don't pass a value."
    )
    # The XrefsTo pass must precede the `total += 1` increment; otherwise
    # pagination totals would include filtered-out entries.
    ix_filter = src.index("min_xrefs is not None")
    ix_total = src.index("total += 1", ix_filter)
    # Locate the closing of the filter block (next 'continue' after the xref check).
    ix_continue = src.index("continue", ix_filter)
    assert ix_filter < ix_total and ix_filter < ix_continue, (
        "min_xrefs guard must precede the total counter so totals reflect filtered results."
    )


def test_funcs_list_forwards_min_xrefs_to_data():
    """funcs(action='list') is a thin wrapper around data(functions);
    it must thread min_xrefs through so callers can use one name only.
    """
    src = _read("src/ida_pro_mcp/ida_mcp/tools/funcs.py")
    assert "min_xrefs" in src, (
        "funcs(action='list') should declare and forward min_xrefs."
    )
    # Should be passed positionally/keyword in the data() call.
    assert "min_xrefs=min_xrefs" in src, (
        "funcs.list must forward min_xrefs=min_xrefs to data()."
    )


def test_data_functions_docstring_documents_min_xrefs():
    """Pin the docstring so generated skill docs reflect the new filter."""
    src = _read("src/ida_pro_mcp/ida_mcp/tools/data.py")
    assert "min_xrefs" in src
    # The 'min_xrefs' word must be part of the *params list* — not just
    # the function signature. The Params: header is documented by the
    # function-level docstring above the action.
    assert "min_size, min_xrefs" in src or "min_xrefs (>= N xrefs_to)" in src, (
        "data() functions-action docstring should mention min_xrefs in its Params block."
    )
