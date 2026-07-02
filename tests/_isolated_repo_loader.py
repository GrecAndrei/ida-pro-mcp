from __future__ import annotations

import importlib.util
import os
import sys
import types
import typing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"
TESTS_ROOT = ROOT / "tests"
PACKAGE_ROOT = SRC_ROOT / "ida_pro_mcp"
IDA_MCP_ROOT = PACKAGE_ROOT / "ida_mcp"
TOOLS_ROOT = IDA_MCP_ROOT / "tools"
SUPPORT_ROOT = IDA_MCP_ROOT / "support"
HOST_ROOT = PACKAGE_ROOT / "host"
HOST_ANALYSIS_ROOT = HOST_ROOT / "analysis"
HOST_SERVER_ROOT = HOST_ROOT / "server"
HOST_STORES_ROOT = HOST_ROOT / "stores"
HOST_INTELLIGENCE_ROOT = HOST_ROOT / "intelligence"


def _ensure_namespace_package(name: str, path: Path, *, attrs: dict | None = None) -> types.ModuleType:
    """Register a namespace package pointing at the given source path.

    Only registers when the module is not already in ``sys.modules`` — that
    way callers that already imported ``ida_pro_mcp.host`` from the regular
    install (e.g. tests that need it for side-effect-free host unit tests)
    aren't clobbered with a partial namespace-package placeholder.
    """
    mod = sys.modules.get(name)
    if mod is None:
        mod = types.ModuleType(name)
        mod.__path__ = [str(path)]  # type: ignore[attr-defined]
        mod.__package__ = name
        sys.modules[name] = mod
    elif not hasattr(mod, "__path__"):
        mod.__path__ = [str(path)]  # type: ignore[attr-defined]
    if attrs:
        for key, value in attrs.items():
            setattr(mod, key, value)
    return mod


def _ensure_package_layout() -> None:
    # Only register the namespaces the source-tree tools actually need.
    # `ida_pro_mcp.host` is intentionally NOT registered here so that
    # host-side unit tests (which import from the regular install) keep
    # working without their cached package getting clobbered by a partial
    # placeholder.
    _ensure_namespace_package("ida_pro_mcp", PACKAGE_ROOT, attrs={"__version__": "test"})
    _ensure_namespace_package("ida_pro_mcp.ida_mcp", IDA_MCP_ROOT)
    _ensure_namespace_package("ida_pro_mcp.ida_mcp.tools", TOOLS_ROOT)
    _ensure_namespace_package("ida_pro_mcp.ida_mcp.support", SUPPORT_ROOT)


def install_common_stub(overrides: dict | None = None) -> types.ModuleType:
    _ensure_package_layout()

    common = types.ModuleType("ida_pro_mcp.ida_mcp.tools._common")
    common.Annotated = typing.Annotated
    common.Optional = typing.Optional
    common.Literal = typing.Literal
    common.Union = typing.Union
    common.Any = typing.Any
    common.tool = lambda fn: fn
    common.idaread = lambda fn: fn
    common.idawrite = lambda fn: fn
    common.unsafe = lambda fn: fn
    common.normalize_list_input = lambda val: [val] if not isinstance(val, list) else val
    common.get_prototype = lambda *a, **kw: "void func()"
    common.hex_ea = lambda ea: hex(int(ea))
    common.hex_size = lambda val: hex(int(val))
    common.parse_address = lambda val, *a, **kw: int(str(val), 0)
    common.normalize_dict_list = lambda val: val
    common.get_function = lambda *a, **kw: None
    common.get_image_size = lambda *a, **kw: 0
    def _default_looks_like_address(val):
        if val is None:
            return False
        s = str(val).strip().lower()
        if s.startswith("0x") or s.startswith("0x"):
            return True
        if len(s) >= 6 and all(c in "0123456789abcdef" for c in s):
            return True
        if s.endswith("h") and len(s) > 1 and all(c in "0123456789abcdef" for c in s[:-1]):
            return True
        return False
    common.looks_like_address = _default_looks_like_address
    common.get_stack_frame_variables_internal = lambda *a, **kw: []
    common.get_type_by_name = lambda *a, **kw: None
    common.smart_match = lambda *a, **kw: False
    def _default_compile_smart_pattern(pattern, case_sensitive=False, **kwargs):
        """Build a simple substring callable (matches FakeIDB test expectations)."""
        if not pattern:
            return lambda v: False
        pat = pattern if case_sensitive else pattern.lower()
        if case_sensitive:
            return lambda v: pat in str(v) if v else False
        return lambda v: pat in str(v).lower() if v else False
    common.compile_smart_pattern = _default_compile_smart_pattern
    common.resolve_symbol = lambda *a, **kw: None
    common.validate_range = lambda *a, **kw: (None, None)
    common.check_debugger = lambda *a, **kw: None
    common.validate_path_safe = lambda *a, **kw: None
    common.require_arg = lambda *a, **kw: None
    common.require_one_of = lambda *a, **kw: None
    common.validate_action = lambda *a, **kw: None
    common.validate_count = lambda val, *a, **kw: int(val)
    common.validate_addr = lambda addr, *a, **kw: (
        int(str(addr), 0) if addr is not None else 0,
        None,
    )
    common.make_error = lambda code, message, **kw: {"ok": False, "code": code, "message": message, **kw}
    common.handle_error = lambda e, *a, **kw: {"ok": False, "error": str(e)}
    common.ERROR_HINTS = {}

    class _MCPError:
        INVALID_ARGS = "INVALID_ARGS"
        DECOMPILER_FAILED = "DECOMPILER_FAILED"
        DECOMPILER_UNAVAILABLE = "DECOMPILER_UNAVAILABLE"
        FUNCTION_NOT_FOUND = "FUNCTION_NOT_FOUND"
        ACTION_NOT_FOUND = "ACTION_NOT_FOUND"
        FILE_NOT_FOUND = "FILE_NOT_FOUND"
        NO_RESULTS = "NO_RESULTS"
        NOT_FOUND = "NOT_FOUND"
        IDA_ERROR = "IDA_ERROR"

    common.MCPError = _MCPError

    for name in (
        "idaapi", "idc", "idautils", "ida_funcs", "ida_bytes", "ida_segment",
        "ida_name", "ida_typeinf", "ida_nalt", "ida_hexrays", "ida_frame",
        "ida_struct", "ida_lines", "ida_ua", "ida_kernwin", "ida_loader",
        "ida_dbg",
    ):
        mod = sys.modules.setdefault(name, types.ModuleType(name))
        setattr(common, name, mod)

    if overrides:
        for key, value in overrides.items():
            setattr(common, key, value)

    sys.modules["_common"] = common
    sys.modules["ida_pro_mcp.ida_mcp.tools._common"] = common
    return common


def _load_module(fullname: str, path: Path):
    spec = importlib.util.spec_from_file_location(fullname, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[fullname] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _ensure_nested_namespace(base_name: str, base_path: Path, module_relpath: str) -> None:
    parts = [part for part in module_relpath.split(".") if part]
    current_name = base_name
    current_path = base_path
    for part in parts[:-1]:
        current_name = f"{current_name}.{part}"
        current_path = current_path / part
        _ensure_namespace_package(current_name, current_path)


def load_tool_module(module_basename: str, *, common_overrides: dict | None = None):
    install_common_stub(common_overrides)
    fullname = f"ida_pro_mcp.ida_mcp.tools.{module_basename}"
    path = TOOLS_ROOT / f"{module_basename}.py"
    return _load_module(fullname, path)


def load_tool_submodule(module_relpath: str, *, common_overrides: dict | None = None):
    install_common_stub(common_overrides)
    _ensure_nested_namespace("ida_pro_mcp.ida_mcp.tools", TOOLS_ROOT, module_relpath)
    rel = module_relpath.replace(".", "/")
    path = TOOLS_ROOT / rel
    path = path / "__init__.py" if path.is_dir() else path.with_suffix(".py")
    fullname = f"ida_pro_mcp.ida_mcp.tools.{module_relpath}"
    return _load_module(fullname, path)


def load_package_module(module_relpath: str):
    _ensure_package_layout()
    _ensure_nested_namespace("ida_pro_mcp", PACKAGE_ROOT, module_relpath)
    rel = module_relpath.replace(".", "/")
    path = PACKAGE_ROOT / rel
    path = path / "__init__.py" if path.is_dir() else path.with_suffix(".py")
    fullname = f"ida_pro_mcp.{module_relpath}"
    return _load_module(fullname, path)


def load_ida_module(module_relpath: str):
    _ensure_package_layout()
    _ensure_nested_namespace("ida_pro_mcp.ida_mcp", IDA_MCP_ROOT, module_relpath)
    rel = module_relpath.replace(".", "/")
    path = IDA_MCP_ROOT / f"{rel}.py"
    fullname = f"ida_pro_mcp.ida_mcp.{module_relpath}"
    return _load_module(fullname, path)


def load_support_module(module_basename: str):
    _ensure_package_layout()
    fullname = f"ida_pro_mcp.ida_mcp.support.{module_basename}"
    path = SUPPORT_ROOT / f"{module_basename}.py"
    return _load_module(fullname, path)


def load_host_module(module_relpath: str):
    _ensure_package_layout()
    rel = module_relpath.replace(".", "/")
    # Search in host root, then subdirectories — use the ACTUAL path
    path = HOST_ROOT / f"{rel}.py"
    sub_prefix = ""
    if not path.exists():
        for subdir_name, subdir in (("analysis", HOST_ANALYSIS_ROOT),
                                     ("server", HOST_SERVER_ROOT),
                                     ("stores", HOST_STORES_ROOT)):
            candidate = subdir / f"{rel}.py"
            if candidate.exists():
                path = candidate
                sub_prefix = f".{subdir_name}"
                break
    fullname = f"ida_pro_mcp.host{sub_prefix}.{module_relpath}"
    _ensure_nested_namespace("ida_pro_mcp.host", HOST_ROOT, module_relpath)
    return _load_module(fullname, path)


def load_test_module(module_relpath: str, *, module_name: str | None = None):
    relpath = Path(module_relpath)
    fullname = module_name or f"_tests_support_{relpath.stem}"
    return _load_module(fullname, TESTS_ROOT / relpath)


def load_repo_module(module_filename: str, *, module_name: str | None = None):
    path = ROOT / module_filename
    fullname = module_name or Path(module_filename).stem
    return _load_module(fullname, path)
