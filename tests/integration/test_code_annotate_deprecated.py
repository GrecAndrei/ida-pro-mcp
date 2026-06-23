"""Tests for the code(annotate) -> modify(comment) deprecation.

`code(annotate)` was a thin shortcut that only wrote a repeatable
function or address comment, while `modify(comment)` is the canonical
path that supports regular/repeatable/anterior/posterior comment types
plus governance and redaction. The duplicate is now a deprecation
shim that returns the original payload plus a hint pointing at
modify(comment).

Coverage:
  - code(annotate) still works (back-compat for any host that calls it)
  - response includes the new 'deprecated' flag and 'hint'
  - comment text is actually written to IDA (function or address comment)
  - the response shape is unchanged for callers that ignore the new
    flags (ok/addr/comment/type still present)
  - missing 'comment' argument still returns INVALID_ARGS
  - modify(comment) is unchanged — the deprecation is additive only
  - prompts recommend modify(comment) for the new way
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CODE_PY = REPO_ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "code.py"
MODIFY_PY = REPO_ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "modify.py"
SCHEMAS_PY = REPO_ROOT / "src" / "ida_pro_mcp" / "host" / "schemas_data.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_annotate_body() -> str:
    """Extract the body of `elif action == "annotate":` in code.py.
    Stops at the next `elif action ==` (real code, not in a comment)."""
    src = _read(CODE_PY)
    # Match starting at the elif line for annotate, up to (but not
    # including) the next elif that's at the same indentation (16
    # spaces in code.py = "            elif ").
    pat = re.compile(
        r'^(?P<body>            elif\s+action\s*==\s*"annotate"\s*:\n'
        r'(?:.*\n)*?)'
        r'(?=^            elif\s+action\s*==\s*"explain"\s*:)',
        re.MULTILINE,
    )
    m = pat.search(src)
    assert m is not None, "annotate branch not found"
    return m.group("body")

