"""Tests for batched decompilation error envelope shape in tools/code.py.

The bulk_decompile/loop-style actions produce per-address results, each of
which can be an error envelope. Earlier versions used the legacy
``error_code`` field which callers couldn't classify; this test pins the
new contract: each error-bearing result has ``code``, ``category``, and
``message`` keys matching the host error envelope convention
(src/ida_pro_mcp/host/errors.py).
"""

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_PATH = REPO_ROOT / "src/ida_pro_mcp/ida_mcp/tools/code.py"


def test_no_legacy_error_code_in_batch_results():
    """Batched decomp/error results must use ``code``, not ``error_code``.

    Stale `error_code` was a parallel convention the host error system
    replaced. New shape: code, category, message, hint, (optional) details.
    """
    src = CODE_PATH.read_text(encoding="utf-8")

    # The literal string 'error_code' should not appear in code.py now.
    assert "error_code" not in src, (
        "code.py should not return 'error_code' anymore — use the host's "
        "make_error() envelope (code, category, message)."
    )


def test_bulk_results_use_make_error_helper():
    """The bulk decompile path should funnel through make_error.

    Look for at least one site inside the bulk_decompile loop that
    appends a make_error() returned dict, ensuring per-address failures
    have the standard envelope.
    """
    src = CODE_PATH.read_text(encoding="utf-8")

    # Find all `results.append(make_error(` sites
    sites = src.count("results.append(make_error(")
    assert sites >= 1, (
        "Expected at least one `results.append(make_error(...))` site in bulk "
        "decompile flow; found 0. Per-address errors should share the host "
        "error envelope contract."
    )


def test_bulk_results_attach_addr_to_details():
    """Per-address errors must thread the addr into details for diagnostics."""
    src = CODE_PATH.read_text(encoding="utf-8")
    # The recurring pattern we want to verify:
    #   results.append(make_error(MCPError.<X>, ..., details={"addr": addr}))
    # We don't pin exact MCPError value — but verify the keyword is present
    # in at least one bulk-error result.
    assert 'details={"addr": addr}' in src, (
        "bulk error results should include details={'addr': addr} so callers "
        "can correlate the failure back to a specific address."
    )


def test_bulk_exception_handler_has_canonical_envelope():
    """The bare ``except Exception as e`` path inside bulk must use the
    host error envelope (not the legacy ``{"addr": addr, "error": str(e)}``)."""
    src = CODE_PATH.read_text(encoding="utf-8")
    # Find any "except Exception" inside the bulk_decompile handler and
    # assert results.append uses make_error() rather than {"addr": addr, "error": ...}.
    assert 'results.append({"addr": addr, "error": str(e)})' not in src, (
        "Legacy inline {'addr': addr, 'error': str(e)} in bulk decompile "
        "should be replaced with make_error() to keep the envelope uniform."
    )
