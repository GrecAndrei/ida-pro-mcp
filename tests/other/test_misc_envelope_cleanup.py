"""AST-only tests pinning the misc.py error-envelope cleanup.

misc.py had 22 inline `{"error": True, "message": ...}` returns which lacked
codes, hints, and category (and occasionally dumped tracebacks to the MCP
caller). These tests verify the wrapper now uses make_error + handle_error
helpers consistently across every branch.
"""

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MISC = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "misc.py"
COMMON = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "_common.py"
ERROR_HANDLING = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "error_handling.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_yara_scanner_uses_envelope_per_error():
    """yara_scanner.compile_rules used to ship per-file/per-error dicts
    shaped like `{"error": str(e)}`. They must now be full envelopes with
    code/category/hint/details.
    """
    src = (REPO / "src/ida_pro_mcp/host/intelligence/yara_scanner.py").read_text()
    # No remaining legacy `{... "error": str(e) ...}` style error entries.
    bad = re.findall(r'\{[^{}]*"error":\s*str\([^{}]*\)[^{}]*\}', src)
    assert not bad, f"yara_scanner.py still has legacy per-error dicts: {bad}"
    # Codes used must exist in the host catalog.
    for code in ("YARA_DISABLED", "NO_RESULTS", "YARA_COMPILE_ERROR",
                 "YARA_SCAN_ERROR", "IO_ERROR", "FILE_NOT_FOUND"):
        assert f'MCPError.{code}' in src, f"yara_scanner.py must use MCPError.{code}"


def test_host_errors_catalog_includes_security_codes():
    """The host-side MCPError should mirror IDA-side YARA codes so callers
    can match on category without reverse-engineering dict shapes."""
    src = (REPO / "src/ida_pro_mcp/host/errors.py").read_text()
    for code in ("YARA_COMPILE_ERROR", "YARA_SCAN_ERROR", "YARA_DISABLED", "NO_RESULTS"):
        assert code in src, f"host/errors.py MCPError must define {code}"


def test_intelligence_no_legacy_error_only_dict():
    """intelligence.py had ~12 inline `{"error": True, "message": ...}`
    branches in the structural_* actions. Each must now go through
    make_error or handle_error.
    """
    src = (REPO / "src/ida_pro_mcp/ida_mcp/tools/intelligence.py").read_text()
    legacy = re.findall(r'\{\s*"error":\s*True,\s*"message":[^}]*\}', src)
    assert not legacy, (
        "intelligence.py still has legacy inline error dicts (no code/hint):\n"
        + "\n".join(legacy[:10])
    )
    assert "MCPError.NO_RESULTS" in src, (
        "intelligence.py should use MCPError.NO_RESULTS for missing index."
    )


def test_debug_no_legacy_error_only_dict():
    """debug.py had two legacy `{"error": True, "message": ...}` returns
    inside the register access path. They must now use make_error with
    DEBUGGER_NOT_RUNNING / DEBUGGER_REGISTER_ERROR.
    """
    src = (REPO / "src/ida_pro_mcp/ida_mcp/tools/debug.py").read_text()
    legacy = re.findall(r'return\s+\{\s*"error":\s*True,\s*"message":', src)
    assert not legacy, (
        f"debug.py still has legacy inline error returns: {legacy}"
    )
    assert "MCPError.DEBUGGER_NOT_RUNNING" in src
    assert "MCPError.DEBUGGER_REGISTER_ERROR" in src


def test_misc_no_inline_error_dumps_with_traceback():
    """misc.py used to swallow every exception into a `traceback.format_exc()`
    string and ship that to the caller. It must now go through
    handle_error() so the traceback lives in ``details`` and the message is
    user-friendly.
    """
    src = _read(MISC)
    assert "traceback.format_exc()" not in src, (
        "misc.py still returns raw traceback text to MCP callers. Use "
        "handle_error(e, context=...) so the user sees a clean envelope."
    )


def test_misc_no_legacy_unbounded_error_message_dict():
    """misc.py used to return shapes like `{"error": True, "message": "..."}`.
    Verify every such literal return now passes through make_error so the
    envelope carries code + hint.
    """
    src = _read(MISC)
    # Match both `return {"error": ...` and `"error": True,` inside other dicts.
    bad: list[tuple[int, str]] = []
    for ln, line in enumerate(src.splitlines(), 1):
        if '"error": True, "message":' in line:
            # `make_error` adds `error/code/message/hint/details` - the
            # legacy shape is 'error/message' without code. This pattern
            # uniquely identifies the legacy writes; if the line is part
            # of a dict whose FIRST key is `code` it is fine.
            # Detect make_error outputs - the dict starts with code, not error.
            if 'code":' in line[: line.find('"error":')]:
                continue
            bad.append((ln, line.strip()))
    assert not bad, (
        "misc.py still has legacy `{{'error': True, 'message': ...}}` "
        "returns without code/hint. Each must be wrapped with make_error:\n"
        + "\n".join(f"  {ln}: {line}" for ln, line in bad)
    )


def test_misc_uses_make_error_and_handle_error_helpers():
    """misc.py must use make_error/handle_error helpers (transitively
    imported via _common.py) for every error path.
    """
    src = _read(MISC)
    assert "make_error(" in src, "misc.py should use make_error()"
    assert "handle_error(" in src, "misc.py should use handle_error() for except clauses"
    assert "require_one_of(" in src, "misc.py should use require_one_of() for python/idc args"


def test_misc_remove_unused_traceback_import():
    """misc.py used to import traceback solely to dump raw stack traces. With
    handle_error() now providing structured envelope formatting, the import
    is dead.
    """
    src = _read(MISC)
    assert "import traceback" not in src, (
        "misc.py no longer uses traceback; remove the import to satisfy F401."
    )


def test_misc_plugin_run_uses_plugin_not_found_code():
    """plugin_run previously returned `{"error": True, "message":
    f"Plugin not found: {name}"}` with no code. Now must use MCPError.PLUGIN_NOT_FOUND.
    """
    src = _read(MISC)
    assert "MCPError.PLUGIN_NOT_FOUND" in src, (
        "misc(action='plugin_run') should call make_error(MCPError.PLUGIN_NOT_FOUND, ...)."
    )
    assert "MCPError.PLUGIN_ERROR" in src, (
        "misc(action='plugin_run') should also use MCPError.PLUGIN_ERROR for the "
        "`Failed to run plugin` branch."
    )
    # Belt-and-braces: no legacy `{"error": True, "message": f"Plugin not found"}` dict.
    legacy_pat = re.compile(r'\{[^{}]*"error":\s*True[^{}]*"Plugin not found"')
    bad_legacy_msg = legacy_pat.findall(src)
    assert not bad_legacy_msg, (
        f"misc.py still has legacy literal dict containing 'Plugin not found': {bad_legacy_msg}"
    )


def test_misc_no_size_limit_string_in_every_dispatch():
    """`Script exceeds max length` must now use MCPError.SIZE_LIMIT_EXCEEDED."""
    src = _read(MISC)
    assert "MCPError.SIZE_LIMIT_EXCEEDED" in src


def test_misc_unknown_action_returns_action_not_found():
    """Final `return {"error": ...}` for unknown actions must become
    make_error(MCPError.ACTION_NOT_FOUND, ...).
    """
    src = _read(MISC)
    assert "MCPError.ACTION_NOT_FOUND" in src, (
        "misc.py should use MCPError.ACTION_NOT_FOUND for unknown action fallback."
    )


def test_misc_read_file_uses_file_not_found_code():
    """read_file previously emitted `{"error": True, "message": "File not
    found: ..."}` without a code. Must now use MCPError.FILE_NOT_FOUND.
    """
    src = _read(MISC)
    assert "MCPError.FILE_NOT_FOUND" in src
    assert "MCPError.FILE_READ_ERROR" in src  # for OSError fallback
    assert "MCPError.INVALID_FILE_FORMAT" in src  # for "Not a file" fallback


def test_misc_write_file_uses_write_error_and_encoding_codes():
    """write_file now covers FILE_WRITE_ERROR for OSError and
    FILE_ENCODING_ERROR for malformed hex.
    """
    src = _read(MISC)
    assert "MCPError.FILE_WRITE_ERROR" in src
    assert "MCPError.FILE_ENCODING_ERROR" in src
    assert "MCPError.MISSING_REQUIRED_ARG" in src  # for None content


def test_all_mcp_error_codes_used_in_misc_are_canonical():
    """Cross-check the codes used in misc.py against the IDA-side catalog.
    Catches future regressions where a code gets renamed or removed.
    """
    cat_src = _read(ERROR_HANDLING)
    cat_tree = ast.parse(cat_src)
    catalog = set()
    for node in ast.walk(cat_tree):
        if (
            isinstance(node, ast.ClassDef)
            and node.name == "MCPError"
        ):
            for stmt in node.body:
                if (
                    isinstance(stmt, ast.Assign)
                    and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)
                    and stmt.targets[0].id.isupper()
                ):
                    catalog.add(stmt.targets[0].id)

    src = _read(MISC)
    misc_tree = ast.parse(src)
    bad: list[tuple[int, str]] = []
    for node in ast.walk(misc_tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "MCPError"
            and isinstance(node.attr, str)
        ):
            if node.attr not in catalog:
                bad.append((node.lineno, node.attr))
    assert not bad, (
        f"misc.py references MCPError codes not in the catalog: {bad}"
    )
