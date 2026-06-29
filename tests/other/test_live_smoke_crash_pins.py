"""AST-only tests pinning fixes for crashes found by the live all-actions smoke.

These tests guard against the *exact* regressions that produced the 9 live
CRASH results before the fix. Each test parses the source as AST and
inspects specific patterns; they don't require a real IDA session.

Bugs pinned (one test per bug):
- analysis.get_options: NameError on `_infer_arch` (used by `callable()`).
- emulate tool: used `MCPError.INTERNAL` which doesn't exist in IDA-side
  MCPError catalog.
- search.structured: import of `_DANGEROUS_APIS, _TAG_CATEGORIES` from
  `..annotation` always ImportErrored; real constants live in
  `..support._api_categories`.
- session.action=N where session_mgr method is missing: AttributeError
  bubbled to caller as UNKNOWN_ERROR.
- session.state: returned raw resource shape, missing the {ok: True, ...} envelope.
"""

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def _module(rel: str) -> ast.Module:
    return ast.parse(_read(rel))


def test_analysis_get_options_does_not_reference_undefined_infer_arch():
    """`callable(_infer_arch)` raised NameError when `_infer_arch` was
    undefined. Either the variable is defined as `None` or guarded via
    globals().get().

    This test walks the AST — a literal substring search would falsely
    match the docstring.
    """
    tree = _module("src/ida_pro_mcp/ida_mcp/tools/analysis.py")
    bad_call: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "callable"
        ):
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id == "_infer_arch":
                    bad_call.append(ast.unparse(node))
    assert not bad_call, (
        "analysis.py should not call `callable(_infer_arch)` directly — "
        "that pattern raises NameError when `_infer_arch` is undefined. "
        f"Found: {bad_call}"
    )
    # Belt-and-braces: the resolution helper must use the safe wrapper.
    src = _read("src/ida_pro_mcp/ida_mcp/tools/analysis.py")
    assert "_safe_infer_arch" in src, (
        "analysis.py should provide a _safe_infer_arch() wrapper that "
        "uses globals().get() to guard against NameError."
    )
    assert "_safe_infer_arch(binary_path)" in src, (
        "analysis(action='get_options') should call _safe_infer_arch(binary_path)."
    )


def test_emulate_uses_valid_mcp_error_codes():
    """emulate.py used `MCPError.INTERNAL` which doesn't exist on the
    IDA-side MCPError catalog. Verify only catalog-defined codes remain.
    """
    cat = _read("src/ida_pro_mcp/ida_mcp/error_handling.py")
    # Extract the MCPError attribute names from the IDA-side catalog.
    mcp_error_attrs = set()
    for node in ast.walk(ast.parse(cat)):
        if isinstance(node, ast.ClassDef) and node.name == "MCPError":
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                    t = stmt.targets[0]
                    if isinstance(t, ast.Name) and t.id.isupper():
                        mcp_error_attrs.add(t.id)

    # Scan the full IDA-side tools package for any `MCPError.<NAME>` and
    # require each NAME to be defined on the catalog. This pins emulate
    # *and* any new tool that tries the same anti-pattern.
    bad: list[tuple[str, int, str]] = []
    tools_dir = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "tools"
    for tool_path in tools_dir.rglob("*.py"):
        try:
            tool_tree = ast.parse(tool_path.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tool_tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "MCPError"
                and isinstance(node.attr, str)
            ):
                if node.attr not in mcp_error_attrs:
                    line_no = getattr(node, "lineno", -1)
                    bad.append((str(tool_path), line_no, node.attr))
    assert not bad, (
        "These tools reference MCPError codes not defined on the IDA-side "
        f"catalog (will raise AttributeError at runtime): {bad}"
    )


def test_search_structured_imports_tag_categories_from_support_module():
    """search.structured previously crashed importing `_DANGEROUS_APIS,
    _TAG_CATEGORIES` from `..annotation` (always ImportError). The real
    constants live in `..support._api_categories`.
    """
    tree = _module("src/ida_pro_mcp/ida_mcp/tools/search/advanced.py")
    # Walk only real Import statements, no comments or docstrings.
    bad_in_real_import = False
    good_in_real_import = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if module.endswith("annotation") and alias.name in {
                    "_DANGEROUS_APIS",
                    "_TAG_CATEGORIES",
                }:
                    bad_in_real_import = True
                if module.endswith("_api_categories"):
                    good_in_real_import = True
    assert not bad_in_real_import, (
        "search/advanced.py still does `from ..annotation import "
        "_DANGEROUS_APIS, _TAG_CATEGORIES` in a real Import statement."
    )
    assert good_in_real_import, (
        "search/advanced.py must import the constants from "
        "`..support._api_categories`."
    )


def test_session_run_spec_uses_safe_getattr():
    """`_run_session_spec` previously did `getattr(self.session_mgr, name)`
    with no default, raising AttributeError when the method was missing.
    Must now use `getattr(..., None)` followed by a structured
    NOT_IMPLEMENTED error.
    """
    src = _read("src/ida_pro_mcp/host/server/server_session.py")
    assert "_run_session_spec" in src
    # Extract the function and find any unguarded getattr on session_mgr.
    tree = _module("src/ida_pro_mcp/host/server/server_session.py")
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_run_session_spec":
            for sub in ast.walk(node):
                if (
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Name)
                    and sub.func.id == "getattr"
                ):
                    # Allow get with a default (3rd arg)
                    if len(sub.args) < 3:
                        # Check the attr name is on session_mgr (1st arg)
                        if (
                            len(sub.args) >= 2
                            and isinstance(sub.args[1], ast.Constant)
                            and sub.args[1].value
                            in {"session_mgr", "self.session_mgr"}
                        ):
                            raise AssertionError(
                                "Bare getattr(session_mgr, name) without a "
                                "default must not appear in _run_session_spec — "
                                "use getattr(..., name, None) and check."
                            )
    # Belt: at least one NOT_IMPLEMENTED plumbing site must exist
    assert "NOT_IMPLEMENTED" in src, (
        "_run_session_spec must use NOT_IMPLEMENTED for missing mgr methods"
    )


def test_session_state_returns_envelope():
    """session(action='state') must return a {ok: True, state: ...} shape,
    not the raw resource JSON.
    """
    # Locate _session_action_state and verify the structure of the return
    tree = _module("src/ida_pro_mcp/host/server/server_session.py")
    found_func = False
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_session_action_state":
            found_func = True
            body_src = ast.unparse(node)
            # Must NOT call `_json.loads(content)` and return it directly.
            assert "return _json.loads(content)" not in body_src, (
                "session.state must NOT return raw parsed JSON; wrap in "
                "{ok: True, state: ...} envelope."
            )
            # Must include the wrapping envelope (single-quoted or double-quoted).
            ok_ok = "'ok': True" in body_src or '"ok": True' in body_src
            st_ok = "'state'" in body_src or '"state"' in body_src
            assert ok_ok and st_ok, (
                f"session.state must include ok and state keys. body=\n{body_src}"
            )
    assert found_func
