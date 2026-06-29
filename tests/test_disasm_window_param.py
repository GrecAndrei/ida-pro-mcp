"""AST + contract tests for the code(disasm) window feature.

The ``window`` parameter on ``code(action='disasm', window=N)`` returns
±N instructions around the input address. This is in contrast to the
default behavior (full function disassembly from the start) and is
useful when an analyst already knows the relevant address and just wants
its surrounding context.

Behavior pinned:
- The signature accepts an int window= parameter.
- The disasm action branch reads window and routes to _disasm_window
  when window is provided (incl. window=0 to anchor on a single line).
- The branch validates types / negative values via make_error envelopes.
- _disasm_window is a real function in code.py (not just an annotation).
- The returned record carries an explicit ``window`` field for cache
  callers and downstream formatters.
"""

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "code.py"


def _read_source() -> str:
    return SRC.read_text()


def _parse() -> ast.Module:
    return ast.parse(_read_source())


def test_window_param_is_defined_on_code_signature():
    """The public action parameter must be visible to clients."""
    tree = _parse()
    func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "code")
    arg_names = {a.arg for a in func.args.args}
    assert "window" in arg_names, (
        "code(...) must expose a `window` parameter for centered disasm."
    )


def test_disasm_branch_routes_to_window_helper():
    """When window is not None, code.py must call _disasm_window."""
    src = _read_source()
    assert "_disasm_window" in src, (
        "code.py must define _disasm_window helper."
    )
    # pin that the call site exists inside the elif action == "disasm" branch
    idx = src.index('elif action == "disasm":')
    # find the next sibling elif / return that ends the branch
    next_branch_idx = src.find('elif action == "xrefs_to":', idx)
    body = src[idx:next_branch_idx]
    assert "_disasm_window(" in body, (
        "The disasm branch must call _disasm_window when window is set."
    )
    assert "radius=radius" in body
    assert "style=disasm_style" in body
    assert "include_bytes=include_bytes" in body


def test_window_branch_emits_envelope_on_bad_type():
    """If window is passed a non-int (str), the response should be an
    MCPError.INVALID_ARGS envelope rather than crashing.
    """
    src = _read_source()
    idx = src.index('elif action == "disasm":')
    body = src[idx:src.find('elif action == "xrefs_to":', idx)]
    assert "MCPError.INVALID_ARGS" in body
    assert "window must be a non-negative integer" in body


def test_window_branch_emits_envelope_on_negative():
    """Negative windows are nonsensical — symmetric radius must clamp
    at zero, never produce an empty centered output.
    """
    src = _read_source()
    idx = src.index('elif action == "disasm":')
    body = src[idx:src.find('elif action == "xrefs_to":', idx)]
    assert "window must be non-negative" in body


def test_window_response_record_carries_window_field():
    """The response object should keep an explicit window=int so
    callers + cache consumers can verify which slice they got.
    """
    src = _read_source()
    idx = src.index('elif action == "disasm":')
    body = src[idx:src.find('elif action == "xrefs_to":', idx)]
    assert '"window": radius' in body


def test_disasm_docstring_mentions_window():
    src = _read_source()
    assert "window=N" in src or "window=20" in src, (
        "Disasm docstring example should mention the window= param."
    )


def test_window_helper_clamps_to_max_items():
    """If the caller passes a huge window but a small max_items,
    the output must be capped (with the center line preserved).
    """
    src = _read_source()
    helper_idx = src.index("def _disasm_window(")
    next_def = src.index("\ndef ", helper_idx + 10)
    body = src[helper_idx:next_def]
    assert "max_items // 2" in body, (
        "radius must be clamped to max_items // 2"
    )
    # center line preserved: confirm the format pattern is built
    # around the center line itself.
    assert "_format_disasm_line(" in body
