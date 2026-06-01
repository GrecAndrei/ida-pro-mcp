"""Regression tests for the support/ package move.

Background:
    6 modules in src/ida_pro_mcp/ida_mcp/tools/ had no @tool decorator —
    they were support libraries accidentally sitting alongside tools:
      - arch_utils.py
      - firmware_heuristics.py
      - semantic_matching.py
      - hybrid_search.py
      - query_lang.py
      - _api_categories.py

    They were moved to src/ida_pro_mcp/ida_mcp/support/ to make the
    architectural intent explicit. Importers were updated to:
      from ..support.X import ...  (in tools/)
      from ...support.X import ... (in tools/search/)
    with a fallback to `from support.X import ...` for test environments
    that add the support/ directory to sys.path.

This test asserts (via filesystem + source):
    1. The 6 files now live under support/ (and not in tools/).
    2. support/__init__.py exists and is non-empty.
    3. No remaining file in tools/ imports these modules with the
       old single-dot relative path (which would now fail).
    4. Every importer uses the new ..support.X or ...support.X form.
    5. The 6 modules still have no @tool decorators (they are support,
       not tools).
    6. The _common.py shim still re-exports the symbols that
       depended on these modules.
"""

import os
import re

ROOT = os.path.dirname(os.path.dirname(__file__))
TOOLS = os.path.join(ROOT, "src", "ida_pro_mcp", "ida_mcp", "tools")
SUPPORT = os.path.join(ROOT, "src", "ida_pro_mcp", "ida_mcp", "support")

MOVED = (
    "arch_utils",
    "firmware_heuristics",
    "semantic_matching",
    "hybrid_search",
    "query_lang",
    "_api_categories",
)


def _read(path):
    with open(path) as f:
        return f.read()


# ---- 1. the 6 files now live under support/ ----------------------------------


def test_support_dir_exists():
    assert os.path.isdir(SUPPORT), f"support/ directory missing: {SUPPORT}"


def test_support_init_exists():
    init = os.path.join(SUPPORT, "__init__.py")
    assert os.path.exists(init), f"support/__init__.py missing"
    assert os.path.getsize(init) > 0, "support/__init__.py is empty"


def test_all_moved_files_reside_in_support():
    for name in MOVED:
        path = os.path.join(SUPPORT, f"{name}.py")
        assert os.path.exists(path), f"{name}.py not found in support/"


def test_moved_files_no_longer_in_tools():
    for name in MOVED:
        old_path = os.path.join(TOOLS, f"{name}.py")
        assert not os.path.exists(old_path), (
            f"{name}.py still in tools/ — move to support/ not complete"
        )


# ---- 2. no remaining single-dot imports from tools/ --------------------------


def test_tools_no_longer_uses_single_dot_imports():
    """Every importer in tools/ must use the new path. The old
    `from .X import` form is invalid because X is no longer in tools/."""
    stale = []
    for name in os.listdir(TOOLS):
        if not name.endswith(".py") or name == "__init__.py":
            continue
        if name == "_common.py":
            continue  # _common.py is allowed to do the import shim
        path = os.path.join(TOOLS, name)
        src = _read(path)
        for mod in MOVED:
            if re.search(rf"^from\s+\.{re.escape(mod)}\s+import", src, re.MULTILINE):
                stale.append((name, mod))
    assert not stale, (
        f"stale single-dot imports found: {stale}. "
        f"Should be `from ..support.<module> import ...` instead."
    )


# ---- 3. importers use the new path forms -------------------------------------


def test_tools_importers_use_double_dot():
    """Tools in tools/ that import from a moved module must use
    `from ..support.X import ...` (double dot = parent of tools)."""
    expected_double_dot = {
        "_common.py": ("_api_categories", "arch_utils"),
        "annotation.py": ("_api_categories",),
        "calc.py": ("semantic_matching",),
        "classify.py": ("_api_categories",),
        "firmware_view.py": ("firmware_heuristics",),
        "llm_helpers.py": ("_api_categories",),
        "bridgerag.py": ("hybrid_search",),
        "schemaboot.py": ("hybrid_search",),
    }
    for fname, mods in expected_double_dot.items():
        src = _read(os.path.join(TOOLS, fname))
        for mod in mods:
            assert re.search(
                rf"from\s+\.\.support\.{re.escape(mod)}\s+import",
                src,
            ), f"{fname} does not import `from ..support.{mod}`"


def test_search_importers_use_triple_dot():
    """Files in tools/search/ (one level deeper) must use
    `from ...support.X import ...` (triple dot = up 2 levels)."""
    expected_triple_dot = {
        "search/__init__.py": ("semantic_matching", "query_lang"),
        "search/unified.py": ("semantic_matching",),
        "search/code.py": ("semantic_matching",),
        "search/core.py": ("semantic_matching",),
        "search/meta.py": ("semantic_matching",),
        "search/advanced.py": ("hybrid_search",),
    }
    for fname, mods in expected_triple_dot.items():
        src = _read(os.path.join(TOOLS, fname))
        for mod in mods:
            assert re.search(
                rf"from\s+\.\.\.support\.{re.escape(mod)}\s+import",
                src,
            ), f"{fname} does not import `from ...support.{mod}`"


# ---- 4. fallback paths are consistent ----------------------------------------


def test_fallback_paths_use_support_keyword():
    """For every top-level `from ..support.X` import inside a top-level
    `try/except ImportError:` block, there must be a corresponding
    `from support.X` fallback in the same except block (for test envs
    that put `support/` directly on sys.path). In-function imports are
    out of scope because the original code didn't always have a fallback
    there."""
    for root, _dirs, files in os.walk(TOOLS):
        for f in files:
            if not f.endswith(".py"):
                continue
            path = os.path.join(root, f)
            src = _read(path)
            for mod in MOVED:
                # Top-level: `try:\n    from ..support.X import ...`
                # The `try:` must be at column 0 (no leading whitespace).
                m = re.search(
                    rf"^try:\s*\n\s+from\s+\.\.support\.{re.escape(mod)}\s+import",
                    src,
                    re.MULTILINE,
                )
                if m is None:
                    continue  # only enforce fallback for top-level try/except
                # The except branch must come after with `from support.X` fallback.
                assert re.search(
                    rf"^except\s+ImportError:\s*\n\s+from\s+support\.{re.escape(mod)}\s+import",
                    src,
                    re.MULTILINE,
                ), (
                    f"{path} has top-level `try: from ..support.{mod}` but no "
                    f"`except ImportError: from support.{mod}` fallback"
                )


# ---- 5. none of the moved modules are tools ----------------------------------


def test_moved_modules_have_no_tool_decorator():
    """The 6 support modules must not have @tool decorators —
    they are not tools."""
    for name in MOVED:
        src = _read(os.path.join(SUPPORT, f"{name}.py"))
        assert not re.search(r"^@tool\b", src, re.MULTILINE), (
            f"support/{name}.py has a @tool decorator; "
            f"it is supposed to be a support library, not a tool"
        )


# ---- 6. _common.py still re-exports what depended on these -------------------


def test_common_still_exports_api_categories():
    """tools/_common.py must still re-export API_CATEGORIES
    (callers do `from ._common import *`)."""
    src = _read(os.path.join(TOOLS, "_common.py"))
    assert "API_CATEGORIES" in src, (
        "tools/_common.py no longer re-exports API_CATEGORIES"
    )


def test_common_still_exports_arch_helpers():
    """tools/_common.py must still re-export arch helpers."""
    src = _read(os.path.join(TOOLS, "_common.py"))
    for sym in ("get_arch", "is_x86_family", "is_arm_family", "RETURN_MNEMONICS"):
        assert sym in src, f"tools/_common.py no longer re-exports {sym}"


# ---- 7. tools/__init__.py does not import support modules ------------------


def test_tools_init_does_not_reexport_support_modules():
    """The moved modules are not tools; they should not appear in
    tools/__init__.py as a public name."""
    init = os.path.join(TOOLS, "__init__.py")
    if not os.path.exists(init):
        return
    src = _read(init)
    for mod in MOVED:
        # Look for `"mod"` in the __all__ list specifically.
        assert not re.search(rf'[\"\']{re.escape(mod)}[\"\']', src), (
            f"tools/__init__.py still references {mod}; "
            f"the moved module is not a tool"
        )
