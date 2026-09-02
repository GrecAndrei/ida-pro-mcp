"""Offline contract coverage for the debug-symbol tool's action matrix."""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_module  # noqa: E402


def _tool():
    mod = load_tool_module("symbols")
    mod.validate_path_safe = lambda value: (str(value), None)
    mod.idaapi.BADADDR = -1
    return mod


def test_load_pdb_and_dwarf_cover_success_failure_and_safe_path(tmp_path, monkeypatch):
    mod = _tool()
    loader = types.ModuleType("ida_loader")
    loaded = []
    loader.load_and_run_plugin = lambda name, arg: loaded.append((name, arg)) or True
    monkeypatch.setitem(sys.modules, "ida_loader", loader)

    pdb = tmp_path / "sample.pdb"
    pdb.write_bytes(b"pdb")
    result = mod.symbols("load_pdb", path=str(pdb))
    assert result["loaded"] is True
    assert loaded == [("pdb", 0)]
    assert os.environ["IDA_PDB_PATH"] == str(pdb)

    assert mod.symbols("load_pdb", path=str(tmp_path / "missing.pdb"))["code"] == "FILE_NOT_FOUND"
    loader.load_and_run_plugin = lambda name, arg: False
    assert mod.symbols("load_pdb")["code"] == "IDA_ERROR"
    loader.load_and_run_plugin = lambda name, arg: True
    assert mod.symbols("load_dwarf")["loaded"] is True
    loader.load_and_run_plugin = lambda name, arg: False
    assert mod.symbols("load_dwarf")["code"] == "IDA_ERROR"


def test_status_handles_named_counts_type_count_and_empty_sdk(monkeypatch):
    mod = _tool()
    mod.idautils.Functions = lambda: list(range(12))
    mod.idc.get_func_name = lambda ea: f"named_{ea}" if ea != 0 else "sub_0"
    til = object()
    mod.ida_typeinf.get_idati = lambda: til
    mod.ida_typeinf.get_ordinal_qty = lambda value: 7 if value is til else 0
    result = mod.symbols("status")
    assert result == {
        "ok": True,
        "has_debug_info": True,
        "named_functions": 11,
        "type_count": 7,
    }

    mod.idautils.Functions = list
    mod.ida_typeinf.get_idati = lambda: None
    delattr(mod.ida_typeinf, "get_ordinal_qty")
    assert mod.symbols("status")["type_count"] == 0


def test_apply_covers_screen_address_existing_type_and_til_fallback(monkeypatch):
    mod = _tool()
    mod.idaapi.get_screen_ea = lambda: -1
    assert mod.symbols("apply")["code"] == "INVALID_ARGS"

    mod.idaapi.get_screen_ea = lambda: 0x401000
    class _Tinfo:
        def __str__(self):
            return "int fn()"

    tif = _Tinfo()
    mod.ida_typeinf.tinfo_t = lambda: tif
    mod.ida_typeinf.TINFO_DEFINITE = 1
    mod.ida_nalt.get_tinfo = lambda _tif, _ea: True
    mod.ida_typeinf.apply_tinfo = lambda _ea, _tif, _flags: True
    assert mod.symbols("apply")["applied"] is True
    mod.ida_typeinf.apply_tinfo = lambda _ea, _tif, _flags: False
    assert mod.symbols("apply")["applied"] is False

    mod.ida_nalt.get_tinfo = lambda _tif, _ea: False
    mod._compat.get_func_start = lambda _ea: 0x401000
    mod.idc.get_func_name = lambda _ea: "known_type"
    til = object()
    mod.ida_typeinf.get_idati = lambda: til
    mod.ida_typeinf.NTF_TYPE = 1
    mod.ida_typeinf.get_named_type = lambda *_args: True
    mod.ida_typeinf.apply_tinfo = lambda _ea, _tif, _flags: True
    result = mod.symbols("apply", addr="0x401000")
    assert result["source"] == "til" and result["applied"] is True

    mod.ida_typeinf.get_named_type = lambda *_args: False
    assert mod.symbols("apply", addr="0x401000")["applied"] is False
    mod.validate_addr = lambda _value: (0, {"error": True, "code": "ADDRESS_INVALID"})
    assert mod.symbols("apply", addr="bad")["code"] == "ADDRESS_INVALID"


def test_export_unknown_action_and_error_handler(tmp_path, monkeypatch):
    mod = _tool()
    assert mod.symbols("export")["code"] == "INVALID_ARGS"
    assert mod.symbols("unknown")["code"] == "INVALID_ARGS"

    mod.idautils.Functions = lambda: [0x1000, 0x2000, 0x3000]
    mod.idc.get_func_name = lambda ea: {
        0x1000: "main",
        0x2000: "sub_2000",
        0x3000: "helper",
    }[ea]
    class _ExportTinfo:
        def __str__(self):
            return "int main()"

    mod.ida_typeinf.tinfo_t = _ExportTinfo
    mod.ida_nalt.get_tinfo = lambda _tif, ea: ea == 0x1000
    output = tmp_path / "symbols.json"
    result = mod.symbols("export", path=str(output))
    assert result == {"ok": True, "exported": True, "count": 2}
    data = json.loads(output.read_text(encoding="utf-8"))
    assert [item["name"] for item in data["functions"]] == ["main", "helper"]
    assert data["functions"][0]["type"] == "int main()"

    mod.ida_nalt.get_tinfo = lambda *_args: (_ for _ in ()).throw(RuntimeError("SDK"))
    failed = mod.symbols("export", path=str(tmp_path / "failed.json"))
    assert failed["ok"] is False and "SDK" in failed["error"]
