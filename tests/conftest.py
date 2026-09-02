# tests/conftest.py
from __future__ import annotations

import contextlib
import os
import sys
import tempfile
import threading
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
    candidates = []
    configured_root = os.environ.get("IDA_ROOT")
    if configured_root:
        candidates.append(os.path.join(configured_root, "python"))
    candidates.extend(
        os.path.expanduser(path)
        for path in ("~/ida-pro-9.4/python", "~/ida-pro-9.3/python", "~/ida-pro-9.2/python")
    )
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
# sys.modules / sys.path pollution cleanup
# ---------------------------------------------------------------------------
# Many tests mutate `sys.modules` (e.g. to inject stub IDA modules, or
# because they reload an ida_pro_mcp.* submodule). Without cleanup, the
# mutation leaks into the next test, causing partial-import "unknown
# location" errors. We snapshot sys.modules once and restore it between
# tests.
#
# Some IDA-side modules also mutate `sys.path` at import time: server_script
# inserts its src/ida_pro_mcp/ida_mcp dirs so the flat plugin layout works,
# and code_helpers/ctree do the same for `_common`. When a test loads one of
# those modules (e.g. test_swarm_q07's bridge tests), those entries leak into
# later tests, making flat `import cache` or a top-level `import ida_mcp`
# succeed when they should not — the q07->t19 (flat _tool_cache resolution)
# and q07->q01 (real ida_mcp/__init__ import) ordering failures. sys.path is
# snapshotted and restored per-test exactly like sys.modules so test order
# does not matter.
_PRESERVED_SYS_MODULES: dict[str, object] | None = None
_ORIGINAL_TOOL_ACTIONS: dict[str, list[str]] | None = None
_PRESERVED_SYS_PATH: list[str] | None = None


def _freeze_sys_modules() -> dict[str, object]:
    return dict(sys.modules)


def _restore_sys_modules(snapshot: dict[str, object]) -> None:
    for name in list(sys.modules.keys()):
        if name not in snapshot:
            del sys.modules[name]
    for name, mod in snapshot.items():
        if sys.modules.get(name) is not mod:
            sys.modules[name] = mod


def _restore_sys_path(snapshot: list[str]) -> None:
    """Restore the exact sys.path list (entries, order, duplicates).

    Mutates the list in place (``del sys.path[:]``) so any module holding a
    reference to ``sys.path`` keeps seeing the same object.
    """
    del sys.path[:]
    sys.path.extend(snapshot)


def _snapshot_package_child_attrs(snapshot: dict[str, object]) -> list[tuple[object, str, object]]:
    """Capture package attributes that mirror entries in ``sys.modules``.

    A few IDA-side tests replace a child module directly in ``sys.modules``.
    Import machinery also updates the parent package's attribute in that case,
    but restoring only the module table leaves a stale object reachable via
    ``from package import child``.  Keep the package namespace isolated along
    with the module table.
    """
    attrs: list[tuple[object, str, object]] = []
    for name in snapshot:
        parent_name, _, child_name = name.rpartition(".")
        if not parent_name:
            continue
        parent = snapshot.get(parent_name)
        if parent is not None and hasattr(parent, child_name):
            attrs.append((parent, child_name, getattr(parent, child_name)))
    return attrs


def _restore_package_child_attrs(attrs: list[tuple[object, str, object]]) -> None:
    for parent, child_name, value in attrs:
        setattr(parent, child_name, value)


# Shared IDA SDK stub module objects that tests mutate IN PLACE (e.g.
# ``ida_funcs.get_func_name = ...``, ``idaapi.get_inf_structure = ...``,
# ``ida_ida.inf_get_max_ea = ...``). Restoring sys.modules *identity* between
# tests is not enough: the module objects persist, so attribute mutations
# survive. We snapshot each stub's ``__dict__`` per test and restore it.
_SHARED_STUB_MODULES = (
    "ida_ida", "idaapi", "idc", "idautils", "ida_funcs", "ida_bytes",
    "ida_segment", "ida_name", "ida_typeinf", "ida_nalt", "ida_hexrays",
    "ida_frame", "ida_struct", "ida_lines", "ida_ua", "ida_kernwin",
    "ida_loader", "ida_dbg",
)


def _snapshot_shared_stub_attrs() -> dict[str, dict[str, object]]:
    snap: dict[str, dict[str, object]] = {}
    for name in _SHARED_STUB_MODULES:
        mod = sys.modules.get(name)
        if mod is not None:
            snap[name] = dict(mod.__dict__)
    return snap


def _monkeypatch_owned_stub_attrs(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[int, set[str]]:
    """Map ``id(module_object) -> {attr names}`` for every attribute the
    monkeypatch fixture will undo in its own teardown.

    pytest tears down ``_isolate_sys_modules`` BEFORE ``monkeypatch``'s undo
    runs (monkeypatch is set up first, hence undone last). If our stub-attr
    restore clears an attribute monkeypatch still expects to ``delattr``
    (``raising=False`` patches on attributes that did not exist), monkeypatch
    raises ``AttributeError``. So we must leave every monkeypatch-tracked
    attribute in place and let monkeypatch's undo handle it.
    """
    owned: dict[int, set[str]] = {}
    for obj, name, _value in monkeypatch._setattr:  # type: ignore[attr-defined]
        owned.setdefault(id(obj), set()).add(name)
    return owned


def _restore_shared_stub_attrs(
    snap: dict[str, dict[str, object]],
    monkeypatch_owned: dict[int, set[str]] | None = None,
) -> None:
    monkeypatch_owned = monkeypatch_owned or {}
    for name, attrs in snap.items():
        mod = sys.modules.get(name)
        if mod is None:
            continue
        owned = monkeypatch_owned.get(id(mod), set())
        # Remove attributes the test added in place — EXCEPT ones the
        # monkeypatch fixture will undo itself (its teardown runs after ours).
        for attr in list(mod.__dict__):
            if attr not in attrs and attr not in owned:
                del mod.__dict__[attr]
        # Restore snapshot values, skipping monkeypatch-tracked attributes
        # (monkeypatch's setattr/delattr will put them back).
        for attr, value in attrs.items():
            if attr in owned:
                continue
            mod.__dict__[attr] = value


def _reset_tool_state() -> None:
    """Reset mutable module-level state that leaks between tests."""
    global _ORIGINAL_TOOL_ACTIONS
    # IDA-side read decorators share an LRU cache across dynamically loaded
    # tool modules.  Keep cache behavior testable within one test, but never
    # let a result from a prior fake IDB answer a later test's query.
    for _module_name in (
        "ida_pro_mcp.ida_mcp.cache",
        "ida_mcp.ida_mcp.cache",
        "cache",
    ):
        _cache_module = sys.modules.get(_module_name)
        _cache = getattr(_cache_module, "TOOL_CACHE", None)
        if _cache is not None and hasattr(_cache, "clear"):
            with contextlib.suppress(Exception):
                _cache.clear()
    with contextlib.suppress(Exception):
        from ida_pro_mcp.ida_mcp.sync import _tool_cache

        _shared_cache = _tool_cache()
        if _shared_cache is not None:
            _shared_cache.clear()
    # Reset tool_registry._TOOL_ACTIONS to original values
    try:
        from ida_pro_mcp.host.server import tool_registry
        if _ORIGINAL_TOOL_ACTIONS is None:
            _ORIGINAL_TOOL_ACTIONS = {k: list(v) for k, v in tool_registry._TOOL_ACTIONS.items()}
        else:
            tool_registry._TOOL_ACTIONS.clear()
            for k, v in _ORIGINAL_TOOL_ACTIONS.items():
                tool_registry._TOOL_ACTIONS[k] = list(v)
    except Exception:
        pass
    # Rebind idautils/idc/idaapi in _common to current sys.modules
    # versions. This is needed because FakeIDB replaces these modules
    # per-test, but _common captured references at import time.
    _common_name = "ida_pro_mcp.ida_mcp.tools._common"
    if _common_name in sys.modules:
        common = sys.modules[_common_name]
        for mod_name in ("idautils", "idc", "idaapi", "ida_funcs", "ida_segment",
                         "ida_nalt", "ida_hexrays", "ida_lines", "ida_name",
                         "ida_typeinf", "ida_bytes", "ida_frame", "ida_struct",
                         "ida_ua", "ida_kernwin", "ida_loader", "ida_dbg"):
            if mod_name in sys.modules:
                setattr(common, mod_name, sys.modules[mod_name])
    # Purge cached ida_mcp.tools.* submodules so they reimport with
    # fresh references. Only purge leaf modules, not _common itself
    # (we just patched it above) and not ida_mcp.rpc/sync/etc.
    _prefix = "ida_pro_mcp.ida_mcp.tools."
    for name in list(sys.modules.keys()):
        if name.startswith(_prefix) and name != _common_name and name in sys.modules:
            del sys.modules[name]


def _reinstall_clean_common() -> None:
    """Replace ``sys.modules["_common"]`` with a clean stub.

    A test module (t13) replaces ``_common`` at COLLECTION time with a
    restricted stub (reduced ``MCPError`` set + real ``make_error`` envelope
    without the ``ok`` key) via ``load_tool_module(common_overrides=...)``.
    Because collection precedes any test, the fixture's sys.modules snapshot
    retains that polluted ``_common``, and a fresh re-import during a test
    (e.g. bb03's ``_fresh_blackboard()``) binds the wrong names. Reinstall a
    clean ``_common`` each test so the snapshot captures the full error set.
    """
    if "ida_pro_mcp.ida_mcp.tools._common" not in sys.modules:
        return
    try:
        from _isolated_repo_loader import install_common_stub

        install_common_stub()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _isolate_sys_modules(monkeypatch: pytest.MonkeyPatch):
    global _PRESERVED_SYS_MODULES, _PRESERVED_SYS_PATH
    if _PRESERVED_SYS_MODULES is None:
        _PRESERVED_SYS_MODULES = _freeze_sys_modules()
    if _PRESERVED_SYS_PATH is None:
        _PRESERVED_SYS_PATH = list(sys.path)
    _reinstall_clean_common()
    # Clear any cache entry created during collection before taking the
    # per-test snapshot.  The cleanup routine runs after the previous test,
    # but collection itself can import and exercise decorated tools.
    with contextlib.suppress(Exception):
        from ida_pro_mcp.ida_mcp.sync import _tool_cache

        _shared_cache = _tool_cache()
        if _shared_cache is not None:
            _shared_cache.clear()
    # Snapshot the shared IDA stub modules BEFORE the test body runs. For
    # unittest classes setUpClass is class-scoped and set up before this
    # function-scoped fixture, so the snapshot already carries class-level
    # state (e.g. q03's CV_PARENTS/CV_FAST on ida_hexrays) and restoring to
    # it preserves that state across the class's tests.
    stub_attrs = _snapshot_shared_stub_attrs()
    snapshot = _freeze_sys_modules()
    package_attrs = _snapshot_package_child_attrs(snapshot)
    path_snapshot = list(sys.path)
    try:
        yield
    finally:
        _restore_sys_modules(snapshot)
        _restore_package_child_attrs(package_attrs)
        # Restore stub-attr mutations, but leave every attribute the
        # monkeypatch fixture will undo in its own teardown (which runs after
        # ours) in place — clearing them here would break monkeypatch's
        # delattr of raising=False patches (e.g. bb03's idaapi.get_path).
        _restore_shared_stub_attrs(
            stub_attrs,
            _monkeypatch_owned_stub_attrs(monkeypatch),
        )
        _restore_sys_path(path_snapshot)
        _reset_tool_state()


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _restore_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore the developer's original env values around each test."""
    monkeypatch.setenv("IDA_MCP_DISABLE_STUCK_DETECTION", _ORIG_STUCK or "1")
    monkeypatch.setenv("IDA_MCP_DISABLE_RATE_LIMIT", _ORIG_RATE or "1")


@pytest.fixture(autouse=True)
def _isolate_real_cache_dir(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Force every test into its own throwaway runtime cache.

    This is a hard safety net: any test that constructs a full
    ``IDAMCPServer`` must never point at the developer's real store. The
    server ``__init__`` runs auto-prune + stale-lease cleanup against
    ``cache_dir``; before this fixture existed, a test that forgot to
    override ``cache_dir`` pruned 341 real sessions from
    ``~/.local/state/ida-pro-mcp`` as a side effect of running the suite.
    """
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "ida-mcp-cache"))
    monkeypatch.setenv("IDA_MCP_DATA_DIR", str(tmp_path / "ida-mcp-cache"))


_HEARTBEAT_THREAD_NAME = "ida-mcp-runtime-lease-heartbeat"


@pytest.fixture(autouse=True)
def _shutdown_leaked_servers() -> None:
    """Shut down ``IDAMCPServer`` instances created during a test.

    Server tests instantiate ``IDAMCPServer()`` inline and often never call
    ``shutdown()``. Each instance starts a ``_lease_heartbeat_loop`` daemon
    thread that pins the instance — and its full module graph — alive for the
    rest of the process. Across the suite that accumulates ~10GB of RSS and
    the process is OOM-killed during the summary phase (exit 137); CI runners
    with ~7GB of RAM hit the same wall and the test job times out.

    We snapshot the heartbeat threads alive *before* the test and only shut
    down owners created during it, so a module-scoped server shared by a
    fixture is never torn down mid-module.
    """
    before = {
        id(t)
        for t in threading.enumerate()
        if t.name == _HEARTBEAT_THREAD_NAME and t.is_alive()
    }
    yield
    for t in list(threading.enumerate()):
        if t.name != _HEARTBEAT_THREAD_NAME or not t.is_alive():
            continue
        if id(t) in before:
            continue
        owner = getattr(getattr(t, "_target", None), "__self__", None)
        if owner is not None and hasattr(owner, "shutdown"):
            with contextlib.suppress(Exception):
                owner.shutdown()


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
