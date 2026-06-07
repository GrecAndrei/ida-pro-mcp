# tests/conftest.py
from __future__ import annotations

import contextlib
import os
import sys
import tempfile

import pytest


# ---------------------------------------------------------------------------
# Module-level env-var setup
# ---------------------------------------------------------------------------
# Force the test environment to a known state at import time, BEFORE any
# module-scoped fixtures (e.g., tests/test_mcp_comprehensive.py's `mcp_client`
# with scope="module") construct a server. If we relied on autouse fixtures
# alone, those module-scoped fixtures would race the autouse setup and the
# RateLimiter (constructed in IDAMCPServer.__init__) would see the default
# 30.0/s rate.
#
# Save the developer's original values so the autouse fixture below can
# restore them at the end of each test (audit §7.9 — the previous
# `os.environ.setdefault()` was a no-op when the var was already set).
os.environ["IDA_MCP_DISABLE_STUCK_DETECTION"] = "1"
os.environ["IDA_MCP_DISABLE_RATE_LIMIT"] = "1"
_ORIG_STUCK = os.environ.get("IDA_MCP_DISABLE_STUCK_DETECTION")
_ORIG_RATE = os.environ.get("IDA_MCP_DISABLE_RATE_LIMIT")


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _restore_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore the developer's original env values around each test.

    Combined with the module-level os.environ[...] = "1" above, this gives
    the "force the test env, then put it back" semantics that audit §7.9
    asked for.
    """
    monkeypatch.setenv("IDA_MCP_DISABLE_STUCK_DETECTION", _ORIG_STUCK or "1")
    monkeypatch.setenv("IDA_MCP_DISABLE_RATE_LIMIT", _ORIG_RATE or "1")


@pytest.fixture
def tmp_session_dir():
    """Yield a fresh temporary directory paired with a SessionManager that
    points at it. The directory is cleaned up automatically when the test
    completes.

    Replaces the copy-pasted `SessionManager(self.tmpdir)` + `tearDown`
    rmtre pattern that appears in ~14 unittest classes (audit §7.8).
    """
    from ida_pro_mcp.host.session import SessionManager

    with tempfile.TemporaryDirectory(prefix="ida-mcp-test-") as tmpdir:
        manager = SessionManager(tmpdir)
        try:
            yield tmpdir, manager
        finally:
            # SessionManager does not hold any persistent resources beyond the
            # on-disk files, so the TemporaryDirectory cleanup is sufficient.
            manager = None


_IDA_MODULES = (
    "idaapi", "idc", "idautils", "ida_bytes", "ida_funcs", "ida_ua",
    "ida_segment", "ida_kernwin", "ida_diskio", "ida_loader",
    "ida_name", "ida_netnode", "ida_entry", "ida_hexrays", "ida_nalt",
    "ida_strlist", "ida_typeinf", "ida_struct", "ida_enum", "ida_gdl",
    "ida_frame", "ida_moves", "ida_xref", "ida_search", "ida_expr",
    "ida_offset", "ida_range", "ida_lines", "ida_problems", "ida_regfind",
    "ida_allins", "ida_dbg",
)


@contextlib.contextmanager
def mock_ida_context():
    """Context manager that mocks the entire `ida_*` namespace and tears it
    down on exit.

    Factored out of test_advanced_features.py (audit §7.8) so future tests can
    `from tests.conftest import mock_ida_context` and get the same teardown
    guarantees the original had.
    """
    from unittest.mock import MagicMock

    original_modules = {}
    for name in _IDA_MODULES:
        if name in sys.modules:
            original_modules[name] = sys.modules[name]
        mock_mod = MagicMock()
        if name == "idaapi":
            mock_mod.get_kernel_version.return_value = "9.3"
        elif name == "idc":
            mock_mod.get_idb_path.return_value = ""
        elif name == "ida_loader":
            mock_mod.get_path.return_value = ""
            mock_mod.PATH_TYPE_IDB = 0
        sys.modules[name] = mock_mod
    try:
        yield
    finally:
        for name in _IDA_MODULES:
            if name in original_modules:
                sys.modules[name] = original_modules[name]
            else:
                sys.modules.pop(name, None)


@pytest.fixture
def mock_ida():
    """Pytest fixture wrapper around mock_ida_context() for tests that prefer
    fixture-style injection over the `with` statement.
    """
    with mock_ida_context():
        yield
