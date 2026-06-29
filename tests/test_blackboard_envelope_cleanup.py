"""Pin that blackboard actions have been migrated off bare {ok, error}
dicts and onto the canonical make_error(MCPError.<code>) envelope.

Skips live IDA — AST + source inspection. The 31 bare returns we
converted all live in tool files (this one included). A future regression
that reintroduces the bare shape (or silently changes an MCPError code)
must update this test first.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "blackboard.py"


def _read() -> str:
    return SRC.read_text()


def test_blackboard_uses_canonical_envelope_in_arg_validation():
    """Argument-required sites use INVALID_ARGS via make_error, not
    bare {ok: False, error: "..."} returns.
    """
    src = _read()
    # A specific small sample of "X required" messages we converted.
    for msg in [
        "title required",
        "query required",
        "entry_id required",
        "proposal_id required",
        "reason required",
        "No fields to update",
        "evidence_type and evidence_value required",
    ]:
        assert f'make_error(MCPError.INVALID_ARGS, "{msg}")' in src, (
            f"Expected make_error(INVALID_ARGS, '{msg}') in blackboard.py"
        )


def test_blackboard_uses_NOT_FOUND_for_missing_entries():
    """Per-id "X not found" misses should surface as NOT_FOUND with
    the id in details, not as a bare error string.
    """
    src = _read()
    raw_needle = (
        "make_error(MCPError.NOT_FOUND, f\"Entry \\'{entry_id}\\' not found\", "
        "details={\"entry_id\": entry_id})"
    )
    assert raw_needle in src, (
        "Expected NOT_FOUND envelope for entry-by-id misses in blackboard.py"
    )


def test_blackboard_uses_ACTION_NOT_FOUND_for_unknown_actions():
    src = _read()
    assert (
        'make_error(MCPError.ACTION_NOT_FOUND, f"Unknown action: {action}")'
        in src
    )


def test_blackboard_has_zero_bare_ok_false_returns():
    """Final pin: any {ok: False} that hasn't been migrated is a
    regression. The asterisk excludes any incidental "ok" appearing
    in a string (the regex requires dict-literal shape).
    """
    src = _read()
    bad = re.findall(r'\{"ok": False, "error":', src)
    assert bad == [], (
        f"blackboard.py still has {len(bad)} bare-error returns: {bad[:3]}…"
    )


def test_blackboard_imports_make_error_via_common():
    """make_error / MCPError are imported via _common wildcard.
    Direct from-imports are also fine; what matters is that they're
    resolvable at module scope so the tests above pass.
    """
    src = _read()
    # Either pattern works — the wildcard from _common or a direct
    # import. The presence of the names in scope is what matters.
    assert "make_error" in src
    assert "MCPError" in src
