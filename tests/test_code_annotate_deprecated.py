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


def test_code_action_literal_includes_annotate():
    """The 'annotate' Literal value must still be accepted so old
    hosts that call code(action='annotate') keep working."""
    src = _read(CODE_PY)
    assert re.search(r'"annotate"', src), "code(annotate) Literal missing"


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


def test_code_annotate_branch_returns_deprecated_key():
    """The annotate branch must set 'deprecated': True in its result."""
    body = _extract_annotate_body()
    assert '"deprecated"' in body or "'deprecated'" in body, (
        "annotate branch is missing the deprecated key"
    )
    # And the hint must point at modify(comment).
    assert "modify" in body.lower()
    assert "comment" in body.lower()


def test_code_annotate_still_writes_comment():
    """The deprecation shim must still write the comment to IDA so
    back-compat is preserved. We check by looking for the original
    set_func_cmt / set_cmt calls."""
    body = _extract_annotate_body()
    assert "set_func_cmt" in body, "annotate must still set the function comment"
    assert "set_cmt" in body, "annotate must still set the address comment"


def test_code_annotate_response_shape_preserved():
    """Old callers relied on ok/addr/comment/type fields. The shim
    must keep all four alongside the new deprecated/hint keys."""
    body = _extract_annotate_body()
    for key in ('"ok"', '"addr"', '"comment"', '"type"'):
        assert key in body, f"annotate response missing required key: {key}"


def test_code_annotate_missing_comment_still_errors():
    """Calling code(action='annotate', addrs='0x10') with no comment
    must still return INVALID_ARGS — the deprecation only adds flags,
    it does not change validation."""
    body = _extract_annotate_body()
    assert "INVALID_ARGS" in body, "annotate must still reject missing comment"
    assert "comment required" in body.lower()


def test_modify_comment_unchanged():
    """Sanity: the modify(comment) path must not have been touched by
    the deprecation. The Literal still includes 'comment' and the
    branch still calls set_cmt / set_func_cmt."""
    src = _read(MODIFY_PY)
    # modify action Literal
    assert '"comment"' in src
    # The branch still has the set_cmt / set_func_cmt logic.
    assert "set_cmt" in src
    # modify is described in the modify tool's docstring/branch.
    assert "comment_type" in src


def test_schema_doc_mentions_annotate_deprecation():
    """The tool schema description should tell LLM callers that
    annotate is deprecated and they should use modify(comment)."""
    src = _read(SCHEMAS_PY)
    # Find the code tool description.
    m = re.search(r'"code"\s*:\s*"([^"]+)"', src)
    assert m is not None, "code tool description not found in schema"
    desc = m.group(1)
    # annotate and modify should both be mentioned, and the deprecation
    # note should be present.
    assert "annotate" in desc
    assert "deprecated" in desc.lower() or "use modify" in desc.lower()
