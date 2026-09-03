"""Pytest configuration for tests/test_ida_mcp suite.

Ensures that the FakeDatabase and simulated IDA SDK modules from `tests.fakes.ida_fake`
are installed into `sys.modules` and package paths are configured before tests execute.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

# Ensure repository root and src are on sys.path
REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"

for p in (str(REPO_ROOT), str(SRC_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

_SDK_KEYS = [
    "idaapi", "idc", "idautils", "ida_bytes", "ida_segment",
    "ida_funcs", "ida_name", "ida_typeinf", "ida_hexrays",
    "ida_ua", "ida_lines", "ida_frame", "ida_struct", "ida_ida",
    "ida_loader", "ida_entry", "ida_nalt", "ida_auto", "ida_dbg",
    "ida_fixup", "ida_kernwin", "ida_idp", "ida_segregs", "ida_netnode",
    "ida_gdl", "_ida_gdl",
]

_ORIGINAL_MODULES = {k: sys.modules.get(k) for k in _SDK_KEYS}

from tests.fakes.ida_fake import FakeDatabase, create_sample_c_binary_idb, install_fake_idb

install_fake_idb(FakeDatabase())

import importlib.util


def _ensure_real_common():
    for name, rel_path in [
        ("error_handling", "ida_pro_mcp/ida_mcp/error_handling.py"),
        ("compat", "ida_pro_mcp/ida_mcp/compat.py"),
        ("rpc", "ida_pro_mcp/ida_mcp/rpc.py"),
        ("sync", "ida_pro_mcp/ida_mcp/sync.py"),
        ("tools._common", "ida_pro_mcp/ida_mcp/tools/_common.py"),
    ]:
        full_path = SRC_ROOT / rel_path
        spec = importlib.util.spec_from_file_location(f"ida_pro_mcp.ida_mcp.{name}", full_path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for target in (f"ida_pro_mcp.ida_mcp.{name}", f"ida_mcp.{name}"):
                existing = sys.modules.get(target)
                if existing is not None and existing is not mod:
                    existing.__dict__.clear()
                    existing.__dict__.update(mod.__dict__)
                else:
                    sys.modules[target] = mod


def _refresh_loaded_tool_globals() -> None:
    """Rebind eagerly imported tools to the current real fake-IDA runtime.

    The repository also has isolated-loader tests that load a canonical tool
    name with a temporary ``_common`` module during collection.  Test modules
    under this directory import tool functions eagerly, so those function
    objects can retain the temporary helper globals even after this suite
    installs the authentic fake SDK.  Update their existing globals in place;
    callers holding the imported function/module objects then see the same
    runtime as a fresh import.
    """
    common = sys.modules.get("ida_pro_mcp.ida_mcp.tools._common")
    if common is None:
        return
    sdk_names = {
        "idaapi", "idc", "idautils", "ida_funcs", "ida_bytes", "ida_segment",
        "ida_name", "ida_typeinf", "ida_nalt", "ida_hexrays", "ida_frame",
        "ida_struct", "ida_lines", "ida_ua", "ida_kernwin", "ida_loader",
        "ida_dbg", "ida_fixup", "ida_ida", "ida_entry", "ida_auto", "ida_gdl",
        "ida_idp", "ida_segregs", "ida_netnode",
    }
    candidates = []
    protected_by_namespace: dict[int, set[str]] = {}

    def refreshable_namespace(namespace):
        module_name = str(namespace.get("__name__", ""))
        if module_name.startswith(("ida_pro_mcp.ida_mcp.", "ida_mcp.")):
            return True
        if module_name.startswith("tests.test_ida_mcp."):
            return True
        return Path(str(namespace.get("__file__", ""))).parent.name == "test_ida_mcp"

    def collect(value):
        if inspect.ismodule(value) and refreshable_namespace(value.__dict__):
            candidates.append(value.__dict__)
        elif inspect.isfunction(value) and refreshable_namespace(value.__globals__):
            candidates.append(value.__globals__)
        elif inspect.isclass(value):
            for member in vars(value).values():
                if (
                    inspect.isfunction(member)
                    and refreshable_namespace(member.__globals__)
                ):
                    candidates.append(member.__globals__)

    for name, module in list(sys.modules.items()):
        if name.startswith(("ida_pro_mcp.ida_mcp.", "ida_mcp.")):
            candidates.append(module.__dict__)
            protected_by_namespace[id(module.__dict__)] = set(
                getattr(module, "__isolated_common_overrides__", ())
            )
        elif (
            name.startswith("tests.test_ida_mcp.")
            or Path(str(getattr(module, "__file__", ""))).parent.name == "test_ida_mcp"
        ):
            # Refresh direct ``import idc`` / ``import idaapi`` bindings in
            # the test module itself as well as the tool functions it holds.
            # Otherwise monkeypatching the test's stale SDK object would not
            # affect the tool's current fake runtime.
            candidates.append(module.__dict__)
            for value in vars(module).values():
                collect(value)

    seen: set[int] = set()
    for namespace in candidates:
        if id(namespace) in seen:
            continue
        seen.add(id(namespace))
        protected = set(protected_by_namespace.get(id(namespace), set()))
        marker = namespace.get("__isolated_common_overrides__", ())
        if isinstance(marker, (set, frozenset, tuple, list)):
            protected.update(marker)
        for name, value in common.__dict__.items():
            # Module metadata is specific to the eagerly imported module.
            # Copying ``__package__``/``__name__`` from _common makes relative
            # imports resolve as ``tools.*`` and can turn a real tool object
            # into an apparently different module after mixed-suite runs.
            if (
                not name.startswith("__")
                and name not in protected
                and name in namespace
            ):
                namespace[name] = value
        # A few tools retain intentionally short private aliases to common
        # classifiers at import time (for example gadgets._is_x86_family).
        # Refresh those aliases too; otherwise a stale isolated lambda can
        # reject a valid architecture even though the public helper is fresh.
        for name in tuple(namespace):
            if name.startswith("_") and not name.startswith("__"):
                public_name = name[1:]
                if public_name in common.__dict__:
                    namespace[name] = common.__dict__[public_name]
        for name in sdk_names:
            if name not in protected and name in namespace and name in sys.modules:
                namespace[name] = sys.modules[name]

_ensure_real_common()


@pytest.fixture(autouse=True)
def fresh_fake_idb():
    """Ensure each test runs against a clean, isolated in-memory FakeDatabase and cleans up on teardown."""
    root_conftest = sys.modules.get("conftest")
    if root_conftest is not None:
        root_conftest._PRESERVE_FAKE_IDB_RUNTIME = True
    _ensure_real_common()
    db = create_sample_c_binary_idb()
    # Add dummy bytes to .data segment for deref / struct reading
    # 0x140003000: int id = 42 (0x0000002A), ptr name = 0x140002010
    db.patch_bytes(0x140003000, (42).to_bytes(4, "little") + (0x140002010).to_bytes(8, "little"))
    db.patch_bytes(0x140002010, b"sample_name\x00")
    install_fake_idb(db)
    _refresh_loaded_tool_globals()
    try:
        yield db
    finally:
        # This preservation window is needed only while a test in this
        # directory uses eagerly imported fake-IDA tool objects. Leaving it
        # enabled poisons later "SDK unavailable" tests in other directories.
        if root_conftest is not None:
            root_conftest._PRESERVE_FAKE_IDB_RUNTIME = False
