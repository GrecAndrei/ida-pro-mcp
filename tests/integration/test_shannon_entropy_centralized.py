"""Regression tests for the shannon_entropy centralization refactor.

Background:
    6 modules defined their own copy of _shannon_entropy / shannon_entropy.
    After dedup, only string_ops.shannon_entropy is the canonical one.
    The 4 other modules (memory, crypto_id, schemaboot, plus a temporary
    alias in string_ops) should import from string_ops.

This test asserts (via AST + grep on source):
    1. string_ops.shannon_entropy is the canonical implementation
       (function body present).
    2. memory._shannon_entropy is a re-export from string_ops.
    3. crypto_id._shannon_entropy is a re-export from string_ops.
    4. schemaboot._shannon_entropy is a re-export from string_ops.
    5. string_ops._shannon_entropy alias is preserved (back-compat).
    6. firmware_heuristics.shannon_entropy keeps its unique
       (byte_hist, total) signature.
    7. trace_analysis keeps its inline shannon_entropy (returns
       un-rounded float; behavior is intentionally distinct).
    8. The 3 caller modules no longer import math (dead import).
"""

import ast
import os
import re

ROOT = os.path.dirname(os.path.dirname(__file__))
TOOLS = os.path.join(ROOT, "src", "ida_pro_mcp", "ida_mcp", "tools")
SUPPORT = os.path.join(ROOT, "src", "ida_pro_mcp", "ida_mcp", "support")


def _read(path):
    with open(path) as f:
        return f.read()


def _functions(src):
    """Return set of top-level function names defined in `src`."""
    tree = ast.parse(src)
    return {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}


def _top_level_names(src):
    """Return set of all top-level names in `src` (functions, assignments, imports)."""
    tree = ast.parse(src)
    names = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def _imports_from(src, mod):
    """Return True if src has `from <mod> import shannon_entropy as _shannon_entropy`."""
    return re.search(
        rf"from\s+\.{mod}\s+import\s+shannon_entropy\s+as\s+_shannon_entropy",
        src,
    ) is not None


# ---- 1. string_ops has the canonical implementation --------------------------

