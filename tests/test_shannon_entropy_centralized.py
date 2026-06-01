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


def test_string_ops_shannon_entropy_is_canonical():
    src = _read(os.path.join(TOOLS, "string_ops.py"))
    names = _top_level_names(src)
    assert "shannon_entropy" in names, "string_ops.shannon_entropy must exist"
    assert "_shannon_entropy" in names, "string_ops._shannon_entropy alias must exist"
    # body present (counter + log2)
    assert "Counter(data)" in src
    assert "math.log2" in src


# ---- 2-4. callers import from string_ops ------------------------------------


def test_memory_uses_shared_shannon_entropy():
    src = _read(os.path.join(TOOLS, "memory.py"))
    assert _imports_from(src, "string_ops"), (
        "memory.py must `from .string_ops import shannon_entropy as _shannon_entropy`"
    )
    # The local definition must be gone
    assert "def _shannon_entropy" not in src, (
        "memory.py must not re-define _shannon_entropy locally"
    )


def test_crypto_id_uses_shared_shannon_entropy():
    src = _read(os.path.join(TOOLS, "crypto_id.py"))
    assert _imports_from(src, "string_ops"), (
        "crypto_id.py must `from .string_ops import shannon_entropy as _shannon_entropy`"
    )
    assert "def _shannon_entropy" not in src


def test_schemaboot_uses_shared_shannon_entropy():
    src = _read(os.path.join(TOOLS, "schemaboot.py"))
    assert _imports_from(src, "string_ops")
    assert "def _shannon_entropy" not in src


# ---- 5. back-compat alias preserved -----------------------------------------


def test_string_ops_underscore_alias_preserved():
    """string_ops._shannon_entropy is preserved for back-compat as a re-export."""
    src = _read(os.path.join(TOOLS, "string_ops.py"))
    assert "_shannon_entropy = shannon_entropy" in src, (
        "string_ops must keep `_shannon_entropy = shannon_entropy` as a back-compat alias"
    )


# ---- 6. firmware_heuristics keeps its unique signature ---------------------


def test_firmware_heuristics_shannon_entropy_unique_signature():
    """firmware_heuristics.shannon_entropy takes (byte_hist, total) — not bytes."""
    src = _read(os.path.join(TOOLS, "firmware_heuristics.py"))
    funcs = _functions(src)
    assert "shannon_entropy" in funcs
    # The signature contains generics like List[int] so we can't use [^)]+ — match
    # up to the closing `)` of the parameter list.
    m = re.search(
        r"^def\s+shannon_entropy\((.+?)\)\s*->", src, re.MULTILINE
    )
    assert m is not None, "could not find def shannon_entropy(...) -> ..."
    params = [p.strip().split(":")[0].strip() for p in m.group(1).split(",")]
    assert params == ["byte_hist", "total"], (
        f"firmware_heuristics.shannon_entropy signature changed: {params}"
    )


# ---- 7. trace_analysis keeps its inline shannon_entropy ---------------------


def test_trace_analysis_shannon_entropy_inline_kept():
    """trace_analysis has its own inline shannon_entropy (un-rounded float).

    This is intentionally distinct from string_ops.shannon_entropy
    (rounded to 4 decimals). The inline version is preserved to keep
    behavior stable for entropy-trace reporting.
    """
    src = _read(os.path.join(TOOLS, "trace_analysis.py"))
    # The function is nested inside a method, so it does not show up at
    # top-level. Search for the def anywhere in the file.
    assert "def _shannon_entropy" in src, (
        "trace_analysis must keep its inline shannon_entropy implementation"
    )
    # Capture only the body of this specific def (until the next def or
    # the next def's decorator / unindent). Bound to 12 lines max — the
    # inline implementation is short.
    m = re.search(
        r"def _shannon_entropy\([^)]*\)[^:]*:\n((?:\s+[^\n]+\n){1,12})",
        src,
    )
    assert m is not None
    body = m.group(1)
    assert "return entropy" in body, (
        f"inline version should return raw entropy, got body:\n{body}"
    )
    # Must NOT call round() in this body (that would change precision).
    assert "round(" not in body, (
        f"inline version should not round, got body:\n{body}"
    )


# ---- 8. dead imports removed -------------------------------------------------


def test_callers_no_longer_import_math():
    """After dedup, the 3 caller modules no longer need `import math`."""
    for name in ("memory.py", "crypto_id.py", "schemaboot.py"):
        src = _read(os.path.join(TOOLS, name))
        # The string "math" can still appear in other contexts (e.g.
        # type annotations, comments), so we check for `import math`
        # statements specifically.
        assert not re.search(r"^import\s+math\s*$", src, re.MULTILINE), (
            f"{name} still has `import math` (no longer needed after dedup)"
        )


# ---- 9. regression sweep: no leftover local defs elsewhere ------------------


def test_no_other_module_locally_defines_shannon_entropy():
    """No module other than the 3 intentional ones still has a local def."""
    exempt = {"string_ops.py", "firmware_heuristics.py", "trace_analysis.py"}
    for name in os.listdir(TOOLS):
        if not name.endswith(".py"):
            continue
        if name in exempt:
            continue
        path = os.path.join(TOOLS, name)
        src = _read(path)
        # Top-level `def _shannon_entropy(` or `def shannon_entropy(`
        assert not re.search(r"^def\s+_?shannon_entropy\s*\(", src, re.MULTILINE), (
            f"{name} still defines shannon_entropy locally; "
            f"should `from .string_ops import shannon_entropy as _shannon_entropy` instead"
        )
