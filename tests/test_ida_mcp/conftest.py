"""Pytest configuration for tests/test_ida_mcp suite.

Ensures that the FakeDatabase and simulated IDA SDK modules from `tests.fakes.ida_fake`
are installed into `sys.modules` and package paths are configured before tests execute.
"""

from __future__ import annotations

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

_ensure_real_common()


@pytest.fixture(autouse=True)
def fresh_fake_idb():
    """Ensure each test runs against a clean, isolated in-memory FakeDatabase and cleans up on teardown."""
    _ensure_real_common()
    db = create_sample_c_binary_idb()
    # Add dummy bytes to .data segment for deref / struct reading
    # 0x140003000: int id = 42 (0x0000002A), ptr name = 0x140002010
    db.patch_bytes(0x140003000, (42).to_bytes(4, "little") + (0x140002010).to_bytes(8, "little"))
    db.patch_bytes(0x140002010, b"sample_name\x00")
    install_fake_idb(db)
    yield db
