"""Behavior coverage for the symbols tool across load, inspect, apply, and export."""

import json
import sys
import types

from tests._isolated_repo_loader import load_support_module, load_tool_module


def _load_symbols(monkeypatch):
    from tests.ida_mcp.test_support_engines_and_integration import _make_fake_ida

    for name, module in _make_fake_ida().items():
        monkeypatch.setitem(sys.modules, name, module)
    loader = types.ModuleType("ida_loader")
    loader.load_and_run_plugin = lambda _name, _arg: True
    monkeypatch.setitem(sys.modules, "ida_loader", loader)
    mod = load_tool_module("symbols")
    mod.validate_path_safe = lambda path: (path, None)
    mod.validate_addr = lambda addr: (int(addr, 0), None)
    return mod


def test_symbol_load_actions_validate_paths_and_plugin_results(monkeypatch, tmp_path):
    mod = _load_symbols(monkeypatch)
    pdb = tmp_path / "symbols.pdb"
    pdb.write_bytes(b"PDB")

    loaded = mod.symbols(action="load_pdb", path=str(pdb))
    assert loaded == {"ok": True, "loaded": True, "path": str(pdb)}
    assert mod.os.environ["IDA_PDB_PATH"] == str(pdb)

    sys.modules["ida_loader"].load_and_run_plugin = lambda _name, _arg: False
    assert mod.symbols(action="load_pdb", path=str(pdb))["code"] == "IDA_ERROR"
    assert mod.symbols(action="load_pdb")["code"] == "IDA_ERROR"
    assert mod.symbols(action="load_dwarf")["code"] == "IDA_ERROR"

    sys.modules["ida_loader"].load_and_run_plugin = lambda _name, _arg: True
    assert mod.symbols(action="load_dwarf") == {"ok": True, "loaded": True}


def test_symbol_status_composes_named_functions_types_and_runtime(monkeypatch):
    mod = _load_symbols(monkeypatch)
    addresses = [0x401000, *range(11)]
    names = {ea: ("sub_401000" if ea == 0x401000 else "named_" + str(ea)) for ea in addresses}
    mod.idautils.Functions = lambda: addresses
    mod.idc.get_func_name = lambda ea: names[ea]
    til = object()
    mod.ida_typeinf.get_idati = lambda: til
    mod.ida_typeinf.get_ordinal_qty = lambda value: 7 if value is til else 0
    mod.ida_typeinf.get_ordinal_count = None
    runtime = load_support_module("runtime_engine")
    runtime.detect_runtime_environment = lambda: {"runtimes": [{"name": "Golang"}]}

    result = mod.symbols(action="status")

    assert result == {
        "ok": True,
        "has_debug_info": True,
        "named_functions": 11,
        "type_count": 7,
        "detected_runtimes": [{"name": "Golang"}],
    }


def test_symbol_apply_covers_existing_til_and_no_type_paths(monkeypatch):
    mod = _load_symbols(monkeypatch)

    class TInfo:
        def __str__(self):
            return "int()"

    mod.ida_typeinf.tinfo_t = TInfo
    mod.ida_typeinf.TINFO_DEFINITE = 1
    mod.ida_typeinf.NTF_TYPE = 1
    mod.ida_nalt.get_tinfo = lambda _tif, _ea: True
    mod.ida_typeinf.apply_tinfo = lambda _ea, _tif, _flags: True
    assert mod.symbols(action="apply", addr="0x401000")["applied"] is True

    mod.ida_typeinf.apply_tinfo = lambda _ea, _tif, _flags: False
    result = mod.symbols(action="apply", addr="0x401000")
    assert result["applied"] is False
    assert "re-apply failed" in result["note"]

    mod.ida_nalt.get_tinfo = lambda _tif, _ea: False
    mod._compat.get_func_start = lambda _ea: 0x401000
    mod.idc.get_func_name = lambda _ea: "known_function"
    til = object()
    mod.ida_typeinf.get_idati = lambda: til
    mod.ida_typeinf.get_named_type = lambda _til, _name, _flags, _tif: True
    mod.ida_typeinf.apply_tinfo = lambda _ea, _tif, _flags: True
    assert mod.symbols(action="apply", addr="0x401000")["source"] == "til"

    mod._compat.get_func_start = lambda _ea: None
    no_type = mod.symbols(action="apply", addr="0x401000")
    assert no_type["applied"] is False
    assert "No type info" in no_type["note"]


def test_symbol_apply_uses_screen_address_and_rejects_bad_input(monkeypatch):
    mod = _load_symbols(monkeypatch)
    mod.ida_typeinf.tinfo_t = type("TInfo", (), {"__str__": lambda self: "void()"})
    mod.idaapi.get_screen_ea = lambda: mod.idaapi.BADADDR
    assert mod.symbols(action="apply")["code"] == "INVALID_ARGS"
    mod.idaapi.get_screen_ea = lambda: 0x401000
    mod.ida_nalt.get_tinfo = lambda *_args: False
    mod._compat.get_func_start = lambda _ea: None
    assert mod.symbols(action="apply")["addr"] == "0x401000"
    mod.validate_addr = lambda _addr: (None, {"code": "ADDRESS_INVALID"})
    assert mod.symbols(action="apply", addr="bad")["code"] == "ADDRESS_INVALID"


def test_symbol_export_writes_named_types_and_handles_action_errors(monkeypatch, tmp_path):
    mod = _load_symbols(monkeypatch)
    mod.idautils.Functions = lambda: [0x401000, 0x402000, 0x403000]
    mod.idc.get_func_name = lambda ea: {0x401000: "main", 0x402000: "sub_402000", 0x403000: "helper"}.get(ea, "")

    class TInfo:
        def __str__(self):
            return "void()"

    mod.ida_typeinf.tinfo_t = TInfo
    mod.ida_nalt.get_tinfo = lambda _tif, ea: ea == 0x401000
    destination = tmp_path / "symbols.json"
    result = mod.symbols(action="export", path=str(destination))
    assert result == {"ok": True, "exported": True, "count": 2}
    assert json.loads(destination.read_text()) == {
        "functions": [
            {"addr": "0x401000", "name": "main", "type": "void()"},
            {"addr": "0x403000", "name": "helper"},
        ],
        "types": [],
    }

    assert mod.symbols(action="export")["code"] == "INVALID_ARGS"
    assert mod.symbols(action="unknown")["code"] == "INVALID_ARGS"
