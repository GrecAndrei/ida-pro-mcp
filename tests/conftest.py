# tests/conftest.py
from __future__ import annotations

import atexit
import builtins
import contextlib
import io
import os
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

# ---------------------------------------------------------------------------
# Collection-time filesystem sandbox
# ---------------------------------------------------------------------------
# Application modules are imported by test modules during collection, before
# function-scoped fixtures run.  The host configuration creates its runtime
# directory at import time, so a per-test fixture is too late to protect a
# developer's real home directory.  Give the entire offline pytest process a
# temporary HOME and reject every test write outside temporary/test metadata
# roots.  This is deliberately installed before any application import below.
_TEST_SANDBOX_ROOT = Path(tempfile.mkdtemp(prefix="ida-pro-mcp-pytest-"))
_TEST_SANDBOX_ROOT = _TEST_SANDBOX_ROOT.resolve()
_REAL_OS_PATH = os.path
_REAL_OS_SEP = os.sep
_TEST_TEMP_ROOT = Path(_REAL_OS_PATH.realpath(tempfile.gettempdir()))
_TEST_REPO_ROOT = Path(_REAL_OS_PATH.realpath(os.fspath(Path(__file__).parent.parent)))
_TEST_ALLOWED_WRITE_ROOTS = (
    _REAL_OS_PATH.realpath(os.fspath(_TEST_TEMP_ROOT)),
    _REAL_OS_PATH.realpath(os.fspath(_TEST_SANDBOX_ROOT)),
    _REAL_OS_PATH.realpath(os.fspath(_TEST_REPO_ROOT / ".pytest_cache")),
    _REAL_OS_PATH.realpath(os.fspath(_TEST_REPO_ROOT / ".pytest_tmp")),
    _REAL_OS_PATH.realpath("/dev"),
)


def _path_is_under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + _REAL_OS_SEP)


def _resolved_write_path(value) -> str | None:
    if isinstance(value, int):
        return None
    try:
        raw = os.fsdecode(os.fspath(value))
        return _REAL_OS_PATH.realpath(
            raw if _REAL_OS_PATH.isabs(raw) else _REAL_OS_PATH.join(os.getcwd(), raw)
        )
    except (OSError, TypeError, ValueError):
        return None


def _assert_test_path_safe(value) -> None:
    path = _resolved_write_path(value)
    if path is None:
        return
    if any(_path_is_under(path, root) for root in _TEST_ALLOWED_WRITE_ROOTS):
        return
    # Python bytecode and pytest's coverage database are test machinery. They
    # may be created in the checkout, but source/config/test data must not be.
    if _path_is_under(path, _REAL_OS_PATH.realpath(os.fspath(_TEST_REPO_ROOT))):
        if "__pycache__" in path.split(_REAL_OS_SEP):
            return
        if _REAL_OS_PATH.basename(path).startswith(".coverage"):
            return
    raise RuntimeError(
        "offline pytest filesystem guard blocked a write outside temporary "
        f"roots: {path}"
    )


def _assert_test_path_safe_from_dir_fd(value, dir_fd) -> None:
    """Check a relative filesystem operation against its directory fd."""
    if dir_fd is None or _REAL_OS_PATH.isabs(os.fspath(value)):
        _assert_test_path_safe(value)
        return
    try:
        base = os.readlink(f"/proc/self/fd/{dir_fd}")
    except (OSError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "offline pytest filesystem guard cannot resolve a relative "
            f"write through directory fd {dir_fd}"
        ) from exc
    _assert_test_path_safe(_REAL_OS_PATH.join(base, os.fsdecode(os.fspath(value))))


_REAL_OPEN = builtins.open
_REAL_IO_OPEN = io.open
_REAL_OS_OPEN = os.open
_REAL_OS_CHDIR = os.chdir
_REAL_OS_MKDIR = os.mkdir
_REAL_OS_MAKEDIRS = os.makedirs
_REAL_OS_UNLINK = os.unlink
_REAL_OS_REMOVE = os.remove
_REAL_OS_RMDIR = os.rmdir
_REAL_OS_RENAME = os.rename
_REAL_OS_REPLACE = os.replace
_REAL_OS_CHMOD = os.chmod
_REAL_OS_UTIME = os.utime
_REAL_OS_TRUNCATE = os.truncate
_REAL_OS_SYMLINK = os.symlink
_REAL_SHUTIL_RMTREE = shutil.rmtree
_REAL_SHUTIL_MOVE = shutil.move
_REAL_SHUTIL_COPY = shutil.copy
_REAL_SHUTIL_COPY2 = shutil.copy2
_REAL_SHUTIL_COPYTREE = shutil.copytree
_REAL_SQLITE_CONNECT = sqlite3.connect


def _mode_writes(mode) -> bool:
    return any(flag in str(mode) for flag in ("w", "a", "x", "+"))


def _guarded_open(file, mode="r", *args, **kwargs):
    if _mode_writes(mode):
        _assert_test_path_safe(file)
    return _REAL_OPEN(file, mode, *args, **kwargs)


def _guarded_io_open(file, mode="r", *args, **kwargs):
    if _mode_writes(mode):
        _assert_test_path_safe(file)
    return _REAL_IO_OPEN(file, mode, *args, **kwargs)


def _guarded_os_open(file, flags, *args, **kwargs):
    write_flags = (
        os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    )
    if flags & write_flags:
        _assert_test_path_safe_from_dir_fd(file, kwargs.get("dir_fd"))
    return _REAL_OS_OPEN(file, flags, *args, **kwargs)


def _guarded_mkdir(path, *args, **kwargs):
    _assert_test_path_safe_from_dir_fd(path, kwargs.get("dir_fd"))
    return _REAL_OS_MKDIR(path, *args, **kwargs)


def _guarded_makedirs(name, *args, **kwargs):
    _assert_test_path_safe(name)
    return _REAL_OS_MAKEDIRS(name, *args, **kwargs)


def _guarded_unlink(path, *args, **kwargs):
    _assert_test_path_safe_from_dir_fd(path, kwargs.get("dir_fd"))
    return _REAL_OS_UNLINK(path, *args, **kwargs)


def _guarded_remove(path, *args, **kwargs):
    _assert_test_path_safe_from_dir_fd(path, kwargs.get("dir_fd"))
    return _REAL_OS_REMOVE(path, *args, **kwargs)


def _guarded_rmdir(path, *args, **kwargs):
    _assert_test_path_safe_from_dir_fd(path, kwargs.get("dir_fd"))
    return _REAL_OS_RMDIR(path, *args, **kwargs)


def _guarded_rename(src, dst, *args, **kwargs):
    _assert_test_path_safe_from_dir_fd(src, kwargs.get("src_dir_fd"))
    _assert_test_path_safe_from_dir_fd(dst, kwargs.get("dst_dir_fd"))
    return _REAL_OS_RENAME(src, dst, *args, **kwargs)


def _guarded_replace(src, dst, *args, **kwargs):
    _assert_test_path_safe_from_dir_fd(src, kwargs.get("src_dir_fd"))
    _assert_test_path_safe_from_dir_fd(dst, kwargs.get("dst_dir_fd"))
    return _REAL_OS_REPLACE(src, dst, *args, **kwargs)


def _guarded_chmod(path, *args, **kwargs):
    _assert_test_path_safe(path)
    return _REAL_OS_CHMOD(path, *args, **kwargs)


def _guarded_utime(path, *args, **kwargs):
    _assert_test_path_safe(path)
    return _REAL_OS_UTIME(path, *args, **kwargs)


def _guarded_truncate(path, *args, **kwargs):
    _assert_test_path_safe(path)
    return _REAL_OS_TRUNCATE(path, *args, **kwargs)


def _guarded_symlink(src, dst, *args, **kwargs):
    _assert_test_path_safe(dst)
    return _REAL_OS_SYMLINK(src, dst, *args, **kwargs)


def _guarded_rmtree(path, *args, **kwargs):
    _assert_test_path_safe(path)
    return _REAL_SHUTIL_RMTREE(path, *args, **kwargs)


def _guarded_move(src, dst, *args, **kwargs):
    _assert_test_path_safe(src)
    _assert_test_path_safe(dst)
    return _REAL_SHUTIL_MOVE(src, dst, *args, **kwargs)


def _guarded_copy(src, dst, *args, **kwargs):
    _assert_test_path_safe(dst)
    return _REAL_SHUTIL_COPY(src, dst, *args, **kwargs)


def _guarded_copy2(src, dst, *args, **kwargs):
    _assert_test_path_safe(dst)
    return _REAL_SHUTIL_COPY2(src, dst, *args, **kwargs)


def _guarded_copytree(src, dst, *args, **kwargs):
    _assert_test_path_safe(dst)
    return _REAL_SHUTIL_COPYTREE(src, dst, *args, **kwargs)


def _guarded_sqlite_connect(database, *args, **kwargs):
    raw = os.fsdecode(os.fspath(database)) if not isinstance(database, str) else database
    if raw not in {":memory:", ""}:
        if raw.startswith("file:"):
            parsed = urlsplit(raw)
            raw = unquote(parsed.path)
            if raw in {"", ":memory:"}:
                return _REAL_SQLITE_CONNECT(database, *args, **kwargs)
        _assert_test_path_safe(raw)
    return _REAL_SQLITE_CONNECT(database, *args, **kwargs)


_REAL_SOCKET_CONNECT = socket.socket.connect


def _is_loopback_address(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "::") or host.startswith("127.")


def _guarded_socket_connect(self, address, *args, **kwargs):
    family = getattr(self, "family", None)
    if family in (socket.AF_INET, socket.AF_INET6):
        host = ""
        if isinstance(address, tuple) and len(address) > 0:
            host = str(address[0])
        elif isinstance(address, str):
            host = address
        if not _is_loopback_address(host):
            raise RuntimeError(
                f"offline pytest network guard blocked outbound connection to {host!r}"
            )
    return _REAL_SOCKET_CONNECT(self, address, *args, **kwargs)


def _install_offline_filesystem_guard() -> None:
    if os.environ.get("IDA_MCP_LIVE_TEST") == "1":
        return
    socket.socket.connect = _guarded_socket_connect
    builtins.open = _guarded_open
    io.open = _guarded_io_open
    os.open = _guarded_os_open
    os.mkdir = _guarded_mkdir
    os.makedirs = _guarded_makedirs
    os.unlink = _guarded_unlink
    os.remove = _guarded_remove
    os.rmdir = _guarded_rmdir
    os.rename = _guarded_rename
    os.replace = _guarded_replace
    os.chmod = _guarded_chmod
    os.utime = _guarded_utime
    os.truncate = _guarded_truncate
    os.symlink = _guarded_symlink
    shutil.rmtree = _guarded_rmtree
    shutil.move = _guarded_move
    shutil.copy = _guarded_copy
    shutil.copy2 = _guarded_copy2
    shutil.copytree = _guarded_copytree
    sqlite3.connect = _guarded_sqlite_connect


def _configure_offline_environment() -> None:
    if os.environ.get("IDA_MCP_LIVE_TEST") == "1":
        return
    safe = _TEST_SANDBOX_ROOT
    safe_home = safe / "home"
    safe_home.mkdir(parents=True, exist_ok=True)
    path_env = {
        "HOME": safe_home,
        "USERPROFILE": safe / "userprofile",
        "LOCALAPPDATA": safe / "localappdata",
        "APPDATA": safe / "appdata",
        "XDG_CONFIG_HOME": safe / "xdg-config",
        "XDG_DATA_HOME": safe / "xdg-data",
        "XDG_STATE_HOME": safe / "xdg-state",
        "XDG_CACHE_HOME": safe / "xdg-cache",
        "UV_CACHE_DIR": safe / "uv-cache",
        "IDA_PRO_MCP_HOME": safe / "ida-pro-mcp",
        "IDA_MCP_CACHE_DIR": safe / "runtime",
        "IDA_MCP_DATA_DIR": safe / "runtime",
        "IDA_MCP_BATCH_STATE_DIR": safe / "batch",
        "IDA_MCP_SESSION_LOG_DIR": safe / "session-logs",
        "IDA_MCP_PORT_FILE": safe / "port-file",
        "CODEX_HOME": safe / "codex",
        "CODEX_SKILL_ROOT": safe / "codex-skills",
    }
    for name, value in path_env.items():
        if isinstance(value, Path) and not name.endswith("_FILE"):
            value.mkdir(parents=True, exist_ok=True)
        os.environ[name] = str(value)
    src_dir = str(_TEST_REPO_ROOT / "src")
    cur_pythonpath = os.environ.get("PYTHONPATH", "")
    os.environ["PYTHONPATH"] = f"{src_dir}{os.pathsep}{cur_pythonpath}" if cur_pythonpath else src_dir
    # Offline tests must not discover or start a developer's licensed IDA or
    # reuse a developer-selected IDB/model/native library.
    for name in (
        "IDA_ROOT",
        "IDA_PYTHON_PATH",
        "IDA_MCP_IDAT",
        "IDA_MCP_IDB_PATH",
        "IDA_MCP_NATIVE_LIB",
        "IDA_MCP_EMBED_MODEL",
        "IDA_MCP_EMBED_SERVER_BIN",
        "IDA_MCP_RERANK_MODEL",
        "IDA_MCP_R2_BIN",
        "IDA_MCP_R2_BININFO_BIN",
    ):
        os.environ.pop(name, None)


_configure_offline_environment()
_install_offline_filesystem_guard()
atexit.register(_REAL_SHUTIL_RMTREE, str(_TEST_SANDBOX_ROOT), True)


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
_PRESERVE_FAKE_IDB_RUNTIME = False
_FAKE_IDB_MODULES = {
    "idaapi", "idc", "idautils", "ida_funcs", "ida_bytes", "ida_segment",
    "ida_name", "ida_typeinf", "ida_nalt", "ida_hexrays", "ida_frame",
    "ida_struct", "ida_lines", "ida_ua", "ida_kernwin", "ida_loader",
    "ida_dbg", "ida_fixup", "ida_ida", "ida_entry", "ida_auto", "ida_gdl",
    "_ida_gdl", "ida_idp", "ida_segregs", "ida_netnode",
}
_ORIGINAL_TIME_FUNCS = {
    name: getattr(__import__("time"), name)
    for name in ("time", "monotonic", "sleep")
}
# Native extension modules cannot always be unloaded and imported again in
# one interpreter. NumPy raises "cannot load module more than once" when its
# extension graph is removed from sys.modules between two tests. Keep that
# third-party graph resident while still restoring application and fake-IDA
# modules normally.
_PRESERVE_EXTENSION_MODULE_PREFIXES = ("numpy",)


def _is_preserved_extension_module(name: str) -> bool:
    return any(
        name == prefix or name.startswith(f"{prefix}.")
        for prefix in _PRESERVE_EXTENSION_MODULE_PREFIXES
    )


def _freeze_sys_modules() -> dict[str, object]:
    return dict(sys.modules)


def _ensure_canonical_services_module() -> None:
    """Keep collection-time isolated service stubs out of the baseline.

    A unittest ``setUpClass`` can install a fake ``ida_pro_mcp.services``
    before the first function-scoped fixture snapshots sys.modules. If that
    fake becomes the baseline, later host tests import the wrong MCPError
    class and lose host-only codes such as IDA_BUSY.
    """
    service = sys.modules.get("ida_pro_mcp.services")
    if service is not None:
        try:
            if service.MCPError.IDA_BUSY == "IDA_BUSY":
                return
        except Exception:
            pass
    sys.modules.pop("ida_pro_mcp.services", None)
    package = sys.modules.get("ida_pro_mcp")
    if package is not None:
        with contextlib.suppress(AttributeError):
            delattr(package, "services")
    with contextlib.suppress(Exception):
        import importlib

        importlib.import_module("ida_pro_mcp.services")


def _restore_sys_modules(snapshot: dict[str, object]) -> None:
    for name in list(sys.modules.keys()):
        if name not in snapshot and not (
            _is_preserved_extension_module(name)
            or _PRESERVE_FAKE_IDB_RUNTIME and name in _FAKE_IDB_MODULES
        ):
            del sys.modules[name]
    for name, mod in snapshot.items():
        if (
            (
                _is_preserved_extension_module(name)
                or _PRESERVE_FAKE_IDB_RUNTIME and name in _FAKE_IDB_MODULES
            )
            and name in sys.modules
        ):
            continue
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
    "ida_loader", "ida_dbg", "ida_gdl", "ida_idp", "ida_pro_mcp.ida_mcp.compat",
    "ida_mcp.compat",
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
    # The data listing actions keep their own bounded walk cache. Its IDB
    # fingerprint intentionally stays small for production, so a fresh fake
    # database can share the same filename/function-count pair with a prior
    # test. Clear it at the test boundary while preserving cache-hit behavior
    # inside each individual test.
    _data_modules = []
    for _module_name in (
        "ida_pro_mcp.ida_mcp.tools.data",
        "ida_mcp.tools.data",
        "ida_mcp.ida_mcp.tools.data",
    ):
        _data_module = sys.modules.get(_module_name)
        if _data_module is not None:
            _data_modules.append(_data_module)
    # Eagerly imported test modules can retain a reference after the isolated
    # loader removes the canonical name from sys.modules. Include those
    # references too, or an old fake-IDB walk can survive into the next test.
    for _holder in list(sys.modules.values()):
        try:
            for _value in vars(_holder).values():
                if getattr(_value, "__name__", "").endswith(".tools.data"):
                    _data_modules.append(_value)
        except Exception:
            pass
    for _data_module in set(map(id, _data_modules)):
        # Resolve the object again without depending on a module name; the
        # identity set above only deduplicates repeated eager references.
        _module = next((m for m in _data_modules if id(m) == _data_module), None)
        _walk_cache = getattr(_module, "_WALK_CACHE", None)
        if _walk_cache is not None and hasattr(_walk_cache, "clear"):
            with contextlib.suppress(Exception):
                _walk_cache.clear()
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
    if not _PRESERVE_FAKE_IDB_RUNTIME:
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
        _ensure_canonical_services_module()
        _PRESERVED_SYS_MODULES = _freeze_sys_modules()
    if _PRESERVED_SYS_PATH is None:
        _PRESERVED_SYS_PATH = list(sys.path)
    # A few legacy tests patch the process-wide time module directly instead
    # of using pytest's monkeypatch fixture. Restore the real clock before
    # each body so a prior fake clock cannot turn a 50 ms assertion into a
    # multi-hour wait.
    _time_module = __import__("time")
    for _name, _value in _ORIGINAL_TIME_FUNCS.items():
        setattr(_time_module, _name, _value)
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
def _restore_process_environment_and_cwd() -> None:
    """Undo direct process mutations made by legacy tests.

    ``monkeypatch`` cannot restore a test that assigns ``os.environ`` or calls
    ``os.chdir`` directly.  Snapshot both at the test boundary so one test
    cannot redirect the next test's default paths or working directory.
    """
    original_env = dict(os.environ)
    original_cwd = os.getcwd()
    yield
    _REAL_OS_CHDIR(original_cwd)
    os.environ.clear()
    os.environ.update(original_env)


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
