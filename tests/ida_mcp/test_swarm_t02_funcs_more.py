"""Additional offline coverage for the function-management surface.

The tests model the stable IDA seams (functions, xrefs, bytes, and the
compatibility layer) instead of depending on an installed IDA database.
"""

from __future__ import annotations

import sys
import types

from tests._isolated_repo_loader import load_tool_module

BADADDR = 0xFFFFFFFFFFFFFFFF


def _load_funcs():
    mod = load_tool_module("funcs")
    mod.idaapi.BADADDR = BADADDR
    mod.idaapi.MFF_READ = 1
    mod.idaapi.MFF_WRITE = 2
    mod.idaapi.FUNC_LIB = 1
    mod.ida_bytes.DELIT_SIMPLE = 0
    mod.ida_name.SN_FORCE = 1
    mod.idc.FUNCATTR_FLAGS = 1
    mod.idc.STRTYPE_C = 0
    mod.idc.PT_SILENT = 0
    mod.idc.get_name = lambda _ea: ""
    mod.idc.get_func_name = lambda _ea: ""
    mod.idc.get_idb_path = lambda: ""
    mod.idc.get_func_cmt = lambda *_args: ""
    mod.idc.set_name = lambda *_args: True
    mod.idautils.Functions = lambda: iter(())
    mod.idautils.FuncItems = lambda _ea: iter(())
    mod.idautils.CodeRefsFrom = lambda *_args: iter(())
    mod.idautils.CodeRefsTo = lambda *_args: iter(())
    mod.idautils.DataRefsFrom = lambda *_args: iter(())
    mod.idautils.Chunks = lambda _ea: iter(())
    mod._compat.get_func_start = lambda ea: ea
    mod._compat.get_func_info = lambda _ea: None
    mod.validate_addr = lambda value, **_kwargs: (int(str(value), 0), None)

    def make_error(code, message, hint=None, **kwargs):
        result = {"ok": False, "error": True, "code": code, "message": message}
        if hint is not None:
            result["hint"] = hint
        result.update(kwargs)
        return result

    mod.make_error = make_error
    return mod


def _fn(start=0x1000, end=0x1100, name="fn", flags=0):
    return types.SimpleNamespace(start_ea=start, end_ea=end, flags=flags, name=name)


def test_overlap_filter_and_delete_contracts():
    mod = _load_funcs()
    overlaps = [_fn(0x1000, 0x1100), _fn(0x1200, 0x1300), _fn(0x2000, 0x2100)]
    mod.idautils.Functions = lambda: iter([f.start_ea for f in overlaps])
    mod._compat.get_func_info = lambda ea: next((f for f in overlaps if f.start_ea == ea), None)
    assert [f.start_ea for f in mod._iter_overlapping_functions(0x1080, 0x1280)] == [0x1000, 0x1200]
    mod.ida_funcs.get_func_name = lambda ea: f"fn_{ea:x}"
    mod.ida_funcs.del_func = lambda _ea: True
    removed = mod._remove_overlapping_functions(0x1080, 0x1280)
    assert removed == [
        {"addr": "0x1000", "end": "0x1100", "name": "fn_1000"},
        {"addr": "0x1200", "end": "0x1300", "name": "fn_1200"},
    ]
    mod.ida_funcs.del_func = lambda _ea: False
    try:
        mod._remove_overlapping_functions(0x1080, 0x1280)
    except RuntimeError as exc:
        assert "Failed to delete" in str(exc)
    else:
        raise AssertionError("failed deletion must be surfaced")


def test_code_conversion_retries_and_thumb_fallback():
    mod = _load_funcs()
    mod.ida_bytes.get_flags = lambda _ea: 1
    mod.ida_bytes.is_code = lambda _flags: True
    assert mod._ensure_code_at(0x1000) is True

    mod.ida_bytes.is_code = lambda flags: flags == 1
    mod._inf_procname = lambda: "ARM Cortex"
    thumb_calls = []
    set_thumb = mod._set_thumb_mode
    def record_thumb(ea):
        thumb_calls.append(ea)

    mod._set_thumb_mode = record_thumb
    create_calls = []
    mod._try_create_insn = lambda ea: create_calls.append(ea) or 1
    flags = iter([0, 1])
    mod.ida_bytes.get_flags = lambda _ea: next(flags)
    assert mod._ensure_code_at(0x1010) is True
    assert thumb_calls == [0x1010]
    assert create_calls == [0x1010]

    mod.ida_bytes.get_flags = lambda _ea: 0
    mod._try_create_insn = lambda _ea: 0
    mod.ida_bytes.del_items = lambda *_args: True
    assert mod._ensure_code_at(0x1020) is False

    split = []
    mod.idc.SR_auto = 7
    mod.idc.split_sreg_range = lambda *args: split.append(args)
    set_thumb(0x2000)
    assert split == [(0x2000, "T", 1, 7)]
    mod.idc.split_sreg_range = lambda *_args: (_ for _ in ()).throw(RuntimeError("old idc"))
    sys.modules.setdefault("ida_segregs", types.ModuleType("ida_segregs"))
    sys.modules["ida_segregs"].split_sreg_range = lambda *args: split.append(args)
    set_thumb(0x2004)
    assert split[-1] == (0x2004, "T", 1, 2)


def test_try_create_insn_and_xref_collectors():
    mod = _load_funcs()
    mod.idc.create_insn = lambda _ea: 9
    sys.modules["ida_ua"].create_insn = lambda _ea: 1
    assert mod._try_create_insn(0x1000) == 1
    sys.modules["ida_ua"].create_insn = lambda _ea: 0
    assert mod._try_create_insn(0x1000) == 9
    sys.modules["ida_ua"].create_insn = lambda _ea: (_ for _ in ()).throw(RuntimeError("no ua"))
    assert mod._try_create_insn(0x1000) == 9

    mod.idautils.CodeRefsTo = lambda *_args: iter([0x2000, 0x1000, 0x2000])
    mod._compat.get_func_start = lambda ea: ea
    assert mod._collect_callers(0x1000) == [0x2000]
    mod.idautils.FuncItems = lambda _ea: iter([0x1000, 0x1004])
    mod.idautils.CodeRefsFrom = lambda ea, _flow: iter([0x3000, 0x1000]) if ea == 0x1000 else iter([0x4000])
    assert mod._collect_callees(0x1000) == [0x3000, 0x4000]
    mod._compat.get_func_start = lambda _ea: None
    assert mod._collect_callees(0x1000) == []


def test_runtime_address_mapping_and_address_resolution():
    mod = _load_funcs()
    mod.idaapi.is_mapped = lambda ea: ea == 0x2000
    assert mod._try_map_raw_runtime_addr(0x2000) == (0x2000, None)
    mod.idaapi.is_mapped = lambda _ea: False
    mod._compat.get_first_segment_ea = lambda: 1
    mod._compat.get_next_segment_ea = lambda _ea: None
    mod._compat.get_segment = lambda _ea: types.SimpleNamespace(start_ea=0, end_ea=0x400)
    mod.idaapi.is_mapped = lambda ea: ea == 0x234
    mapped, note = mod._try_map_raw_runtime_addr(0x100234)
    assert mapped == 0x234 and "offset=0x234" in note
    mod._compat.get_first_segment_ea = lambda: None
    assert mod._try_map_raw_runtime_addr(0x1000) == (None, None)
    mod._compat.get_first_segment_ea = lambda: 1
    segment_steps = iter([2, None])
    mod._compat.get_next_segment_ea = lambda _ea: next(segment_steps)
    assert mod._try_map_raw_runtime_addr(0x1000) == (None, None)
    mod._compat.get_next_segment_ea = lambda _ea: None
    mod._compat.get_segment = lambda _ea: types.SimpleNamespace(start_ea=1, end_ea=0x400)
    assert mod._try_map_raw_runtime_addr(0x1000) == (None, None)

    assert mod._resolve_func_addr(None)[1]["code"] == "INVALID_ARGS"
    assert mod._resolve_func_addr(0x1000) == (0x1000, None)
    mod.validate_addr = lambda _txt: (None, {"code": "ADDRESS_INVALID"})
    mod.idc.get_name_ea_simple = lambda txt: 0x3000 if txt == "named" else BADADDR
    assert mod._resolve_func_addr("named") == (0x3000, None)
    assert mod._resolve_func_addr("missing")[1]["code"] == "ADDRESS_INVALID"


def test_persist_symbol_knowledge_and_embedding_boundaries(monkeypatch):
    mod = _load_funcs()
    mod.idc.get_idb_path = lambda: "/tmp/sample.i64"
    mod._collect_callers = lambda _ea: [0x2000]
    mod._collect_callees = lambda _ea, max_items=0: [0x3000]
    mod._compat.get_func_start = lambda ea: ea
    mod.idautils.FuncItems = lambda _ea: iter([0x1000])
    mod.idautils.DataRefsFrom = lambda _ea: iter([0x4000])
    mod.idc.get_strlit_contents = lambda *_args: b"hello"
    records = []
    services = types.ModuleType("ida_pro_mcp.services")

    class SymbolDB:
        def upsert_symbol(self, record):
            records.append(record)

    services.SymbolDB = SymbolDB
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    mod._persist_symbol_knowledge(0x1000, "known")
    assert records[0]["strings"] == ["hello"]
    before = len(records)
    mod._persist_symbol_knowledge(0x1000, "sub_1000")
    assert len(records) == before

    services.BgeCodeEmbedder = lambda: None
    services.FunctionEmbeddingIndex = lambda *_args: None
    services._extract_signature = lambda text, max_idents: text
    mod.idc.get_idb_path = lambda: ""
    assert mod._embedding_rename_suggestions()["code"] == "INVALID_ARGS"

    class Embedder:
        backend = "fake"

    class Index:
        size = 0

        def __init__(self, *_args):
            pass

    services.BgeCodeEmbedder = Embedder
    services.FunctionEmbeddingIndex = Index
    services._extract_signature = lambda text, max_idents: text
    mod.idc.get_idb_path = lambda: "/tmp/sample.i64"
    assert mod._embedding_rename_suggestions()["code"] == "NOT_FOUND"


def test_embedding_suggestions_threshold_and_fallback_signature(monkeypatch):
    mod = _load_funcs()
    services = types.ModuleType("ida_pro_mcp.services")

    class Embedder:
        backend = "fake"

    class Index:
        size = 2

        def __init__(self, *_args):
            pass

        def similar(self, *_args, **_kwargs):
            return [
                {"name": "named_best", "ea": "0x5000", "similarity": 0.95},
                {"name": "sub_ignored", "ea": "0x5004", "similarity": 0.99},
                {"name": "named_alt", "ea": "0x5008", "similarity": 0.90},
            ]

    services.BgeCodeEmbedder = Embedder
    services.FunctionEmbeddingIndex = Index
    services._extract_signature = lambda text, max_idents: text[:max_idents]
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    mod.idc.get_idb_path = lambda: "/tmp/sample.i64"
    mod.validate_addr = lambda _addr, **_kwargs: (0x1000, None)
    mod.idc.get_func_name = lambda _ea: "sub_1000"
    mod.ida_hexrays.decompile = lambda _ea: "int f(void)"
    result = mod._embedding_rename_suggestions(addr="0x1000", threshold=0.8, nearest_top_k=3)
    assert result["count"] == 1
    assert result["suggestions"][0]["suggested_name"] == "named_best"
    assert result["suggestions"][0]["alternatives"] == [{"name": "named_alt", "confidence": 0.9}]


def test_funcs_impl_create_delete_change_flags_and_info():
    mod = _load_funcs()
    current = {0x1000: _fn(0x1000, 0x1010, "old", 2)}
    mod._compat.get_func_info = lambda ea: current.get(0x1000) if 0x1000 <= ea < 0x1010 else None
    mod._compat.get_func_start = lambda ea: 0x1000 if 0x1000 <= ea < 0x1010 else None
    mod.ida_funcs.get_func_name = lambda ea: current.get(ea, _fn(name="" )).name
    mod.idc.get_func_name = mod.ida_funcs.get_func_name
    mod.idc.set_name = lambda ea, name, _flags: current[ea].__setattr__("name", name) or True
    mod._ensure_code_at = lambda _ea: True
    assert mod._funcs_impl("create", addr="0x1000", name="renamed")["note"].startswith("Function already")
    assert current[0x1000].name == "renamed"
    assert mod._funcs_impl("create", addr="0x1004")["code"] == "ADDRESS_INVALID"
    assert mod._funcs_impl("change", addr="0x1000")["code"] == "INVALID_ARGS"
    mod.validate_addr = lambda val, **_kwargs: (int(str(val), 0), None)
    mod.ida_funcs.set_func_end = lambda _start, _end: True
    assert mod._funcs_impl("change", addr="0x1000", end="0x1020")["changed"] is True
    mod._compat.get_func_info = lambda _ea: current.get(0x1000)
    mod._compat.get_func_flags = lambda _ea: 2
    mod._compat.set_func_flags = lambda _ea, _flags: True
    assert mod._funcs_impl("set_flags", addr="0x1000", flags=4)["flags"] == "0x4"
    mod.idautils.Chunks = lambda _ea: iter([(0x1000, 0x1020)])
    mod.idc.get_func_cmt = lambda _ea, repeat: "comment" if repeat == 0 else "repeat"
    assert mod._funcs_impl("info", addr="0x1000")["function"]["comment"] == "comment"
    mod.ida_funcs.del_func = lambda _ea: True
    assert mod._funcs_impl("delete", addr="0x1004")["addr"] == "0x1000"
    assert mod._funcs_impl("bogus")["code"] == "INVALID_ARGS"


def test_funcs_impl_metrics_and_find_similar_paths():
    mod = _load_funcs()
    target = _fn(0x1000, 0x1008, "target")
    other = _fn(0x2000, 0x2008, "other")
    funcs = {0x1000: target, 0x2000: other}
    mod._compat.get_func_info = funcs.get
    mod._compat.get_func_start = lambda ea: ea if ea in funcs else None
    mod.idc.get_func_name = lambda ea: funcs[ea].name
    mod.ida_funcs.get_func_name = mod.idc.get_func_name
    mod.idautils.FuncItems = lambda ea: iter([ea, ea + 4])
    block = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1008, succs=lambda: iter([types.SimpleNamespace(start_ea=0x1000)]))
    mod._compat.get_flow_chart = lambda _ea: [block]
    mnems = {0x1000: "call", 0x1004: "ret"}
    mod.idc.print_insn_mnem = lambda ea: mnems.get(ea, "")
    mod.idc.generate_disasm_line = lambda ea, _flags: mnems.get(ea, "")
    mod.idc.next_head = lambda ea, _end: ea + 4 if ea == 0x1000 else BADADDR
    assert mod._funcs_impl("metrics", addr="0x1000")["metrics"]["return_count"] == 1

    mod.ida_bytes.get_bytes = lambda _ea, _size: b"abcdefgh"
    mod.idautils.Functions = lambda: iter([0x1000, 0x2000])
    similar = mod._funcs_impl("find_similar", addr="0x1000", limit=1, min_score=0)
    assert similar["count"] == 1 and similar["similar_functions"][0]["name"] == "other"
    mod.idautils.Functions = lambda: iter([0x1000])
    assert mod._funcs_impl("find_similar", addr="0x1000")["count"] == 0
