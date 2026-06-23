# tests/conftest.py
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Real IDA Pro Python path
# ---------------------------------------------------------------------------
# The test suite runs Python tests directly (not inside `idat`), so the IDA
# Pro pure-Python modules need to be on sys.path. We add a few well-known
# locations and the first one that exists wins. Set IDA_PYTHON_PATH to
# override.
def _resolve_ida_python_path() -> str | None:
    env = os.environ.get("IDA_PYTHON_PATH")
    if env and Path(env).is_dir():
        return env
    candidates = [
        "/home/grec-alexander/ida-pro-9.3/python",
        "/home/grec-alexander/ida-pro-9.2/python",
        os.path.expanduser("~/ida-pro-9.3/python"),
        os.path.expanduser("~/ida-pro-9.2/python"),
    ]
    for c in candidates:
        if Path(c).is_dir():
            return c
    return None


_IDA_PYTHON_PATH = _resolve_ida_python_path()
if _IDA_PYTHON_PATH and _IDA_PYTHON_PATH not in sys.path:
    sys.path.insert(0, _IDA_PYTHON_PATH)


# ---------------------------------------------------------------------------
# Module-level env-var setup
# ---------------------------------------------------------------------------
os.environ["IDA_MCP_DISABLE_STUCK_DETECTION"] = "1"
os.environ["IDA_MCP_DISABLE_RATE_LIMIT"] = "1"
_ORIG_STUCK = os.environ.get("IDA_MCP_DISABLE_STUCK_DETECTION")
_ORIG_RATE = os.environ.get("IDA_MCP_DISABLE_RATE_LIMIT")


# ---------------------------------------------------------------------------
# sys.modules pollution cleanup
# ---------------------------------------------------------------------------
# Many tests mutate `sys.modules` (e.g. to inject stub IDA modules, or
# because they reload an ida_pro_mcp.* submodule). Without cleanup, the
# mutation leaks into the next test, causing partial-import "unknown
# location" errors. We snapshot sys.modules once and restore it between
# tests.
_PRESERVED_SYS_MODULES: dict[str, object] | None = None


def _freeze_sys_modules() -> dict[str, object]:
    return dict(sys.modules)


def _restore_sys_modules(snapshot: dict[str, object]) -> None:
    for name in list(sys.modules.keys()):
        if name not in snapshot:
            del sys.modules[name]
    for name, mod in snapshot.items():
        if sys.modules.get(name) is not mod:
            sys.modules[name] = mod


@pytest.fixture(autouse=True)
def _isolate_sys_modules():
    global _PRESERVED_SYS_MODULES
    if _PRESERVED_SYS_MODULES is None:
        _PRESERVED_SYS_MODULES = _freeze_sys_modules()
    snapshot = _freeze_sys_modules()
    try:
        yield
    finally:
        _restore_sys_modules(snapshot)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _restore_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore the developer's original env values around each test."""
    monkeypatch.setenv("IDA_MCP_DISABLE_STUCK_DETECTION", _ORIG_STUCK or "1")
    monkeypatch.setenv("IDA_MCP_DISABLE_RATE_LIMIT", _ORIG_RATE or "1")


@pytest.fixture
def tmp_session_dir():
    """Yield a fresh temporary directory paired with a SessionManager that
    points at it. The directory is cleaned up automatically when the test
    completes.
    """
    from ida_pro_mcp.services import SessionManager

    with tempfile.TemporaryDirectory(prefix="ida-mcp-test-") as tmpdir:
        manager = SessionManager(tmpdir)
        try:
            yield tmpdir, manager
        finally:
            manager = None

# Stubs for integration tests (no IDA Pro required)
class IDARunner:
    """Stub runner for integration tests."""
    def __init__(self, *args, **kwargs):
        pass

def ida_is_available():
    return False
