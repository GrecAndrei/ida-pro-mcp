"""Additional offline coverage for the function-management surface.

The tests model the stable IDA seams (functions, xrefs, bytes, and the
compatibility layer) instead of depending on an installed IDA database.
"""

from __future__ import annotations

import builtins
import sys
import types
from unittest.mock import patch

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


def test_function_helpers_cover_defensive_and_fallback_paths():
    mod = _load_funcs()

    exact = _fn(0x1000, 0x1100)
    overlap = _fn(0x1080, 0x1180)
    mod.idautils.Functions = lambda: iter([0x1000, 0x1080, 0x1200])
    mod._compat.get_func_info = {
        0x1000: exact,
        0x1080: overlap,
        0x1200: None,
    }.get
    assert list(mod._iter_overlapping_functions(0x1000, 0x1200)) == [exact, overlap]
    mod.ida_funcs.get_func_name = lambda ea: f"fn_{ea:x}"
    mod.ida_funcs.del_func = lambda _ea: True
    removed = mod._remove_overlapping_functions(0x1000, 0x1100)
    assert removed == [{"addr": "0x1080", "end": "0x1180", "name": "fn_1080"}]

    # Exercise the processor-info failure, auto-analysis hook, and successful
    # second carve attempt.  These are all expected to be harmless in old IDA
    # builds where one or more APIs are missing.
    mod.ida_bytes.is_code = lambda flags: flags == 1
    flags = iter([0, 1])
    mod.ida_bytes.get_flags = lambda _ea: next(flags)
    mod._inf_procname = lambda: (_ for _ in ()).throw(RuntimeError("no inf"))
    creates = iter([0, 0, 1])
    mod._try_create_insn = lambda _ea: next(creates)
    auto_calls = []
    auto = types.ModuleType("ida_auto")
    auto.auto_make_code = auto_calls.append
    with patch.dict(sys.modules, {"ida_auto": auto}):
        assert mod._ensure_code_at(0x1300) is True
    assert auto_calls == [0x1300, 0x1300]

    segregs = types.ModuleType("ida_segregs")
    segregs.split_sreg_range = lambda *_args: (_ for _ in ()).throw(RuntimeError("no segreg")).throw(RuntimeError())
    with patch.dict(sys.modules, {"ida_segregs": segregs}):
        mod.idc.split_sreg_range = lambda *_args: (_ for _ in ()).throw(RuntimeError("old idc"))
        mod._set_thumb_mode(0x1304)

    mod._compat.get_func_start = lambda ea: ea
    mod.idautils.FuncItems = lambda _ea: iter([1, 2])
    mod.idautils.CodeRefsFrom = lambda _ea, _flow: iter([0x3000])
    assert mod._collect_callees(0x1000, max_items=1) == [0x3000]


def test_symbol_persistence_fallback_strings_and_failures():
    mod = _load_funcs()
    records = []
    fallback = types.ModuleType("host.symbol_db")

    class SymbolDB:
        def upsert_symbol(self, row):
            records.append(row)

    fallback.SymbolDB = SymbolDB
    real_import = builtins.__import__

    def import_fallback(name, *args, **kwargs):
        if name == "ida_pro_mcp.services":
            raise ImportError("services unavailable")
        if name == "host.symbol_db":
            return fallback
        return real_import(name, *args, **kwargs)

    mod.idc.get_idb_path = lambda: "/tmp/sample.i64"
    mod._collect_callers = lambda _ea: []
    mod._collect_callees = lambda _ea, max_items=0: []
    mod._compat.get_func_start = lambda ea: ea
    mod.idautils.FuncItems = lambda _ea: iter([0x1000])
    refs = iter([0x4000, 0x4004, 0x4008])
    mod.idautils.DataRefsFrom = lambda _ea: refs
    strings = {0x4000: b"", 0x4004: b"same", 0x4008: b"same"}
    mod.idc.get_strlit_contents = lambda ea, *_args: strings[ea]
    with patch.object(builtins, "__import__", import_fallback):
        mod._persist_symbol_knowledge(0x1000, "known")
    assert records[-1]["strings"] == ["same"]

    # Both loop guards fire after collecting the maximum number of strings.
    refs = iter(range(24))
    mod.idautils.DataRefsFrom = lambda _ea: refs
    mod.idc.get_strlit_contents = lambda ea, *_args: f"s{ea}".encode()
    with patch.object(builtins, "__import__", import_fallback):
        mod._persist_symbol_knowledge(0x1000, "many_strings")
    assert len(records[-1]["strings"]) == 24

    # A missing function start still produces a useful symbol record, while a
    # storage failure is swallowed by design.
    mod._compat.get_func_start = lambda _ea: None
    with patch.object(builtins, "__import__", import_fallback):
        mod._persist_symbol_knowledge(0x1000, "no_start")

    class BrokenDB:
        def upsert_symbol(self, _row):
            raise RuntimeError("database unavailable")

    fallback.SymbolDB = BrokenDB
    with patch.object(builtins, "__import__", import_fallback):
        mod._persist_symbol_knowledge(0x1000, "broken_store")

    def import_everywhere_broken(name, *args, **kwargs):
        if name in {"ida_pro_mcp.services", "host.symbol_db"}:
            raise ImportError("all symbol stores unavailable")
        return real_import(name, *args, **kwargs)

    with patch.object(builtins, "__import__", import_everywhere_broken):
        mod._persist_symbol_knowledge(0x1000, "no_store")


def test_runtime_mapping_and_address_validation_edges():
    mod = _load_funcs()
    mod.idaapi.is_mapped = lambda _ea: (_ for _ in ()).throw(RuntimeError("mapping unavailable"))
    assert mod._try_map_raw_runtime_addr(0x401000) == (None, None)

    mod.idaapi.is_mapped = lambda _ea: False
    mod._compat.get_first_segment_ea = lambda: 1
    mod._compat.get_next_segment_ea = lambda _ea: None
    mod._compat.get_segment = lambda _ea: None
    assert mod._try_map_raw_runtime_addr(0x401000) == (None, None)

    mod._compat.get_segment = lambda _ea: types.SimpleNamespace(start_ea=0, end_ea=0x100)
    # The candidate offset is outside the sole segment for every alignment.
    assert mod._try_map_raw_runtime_addr(0x401234) == (None, None)

    def candidate_failure(ea):
        if ea == 0x401000:
            return False
        return False

    mod.idaapi.is_mapped = candidate_failure
    assert mod._try_map_raw_runtime_addr(0x401000) == (None, None)
    def candidate_exception(ea):
        if ea == 0x401000:
            return False
        raise RuntimeError("candidate mapping unavailable")

    mod.idaapi.is_mapped = candidate_exception
    assert mod._try_map_raw_runtime_addr(0x401000) == (None, None)
    assert mod._resolve_func_addr("   ")[1]["code"] == "INVALID_ARGS"


def test_embedding_rename_import_and_filter_edges():
    mod = _load_funcs()
    core = types.ModuleType("host.intelligence.core")
    services = types.ModuleType("ida_pro_mcp.services")

    class Embedder:
        backend = "fallback"

    responses = [
        [{"name": "sub_2000", "ea": "0x2000", "similarity": 0.99}],
        [{"name": "weak_name", "ea": "0x2004", "similarity": 0.1}],
    ]

    class Index:
        size = 2

        def __init__(self, *_args):
            pass

        def similar(self, *_args, **_kwargs):
            return responses.pop(0)

    core.BgeCodeEmbedder = services.BgeCodeEmbedder = Embedder
    core.FunctionEmbeddingIndex = services.FunctionEmbeddingIndex = Index
    core._extract_signature = services._extract_signature = lambda text, max_idents: text[:max_idents]
    real_import = builtins.__import__

    def import_core(name, *args, **kwargs):
        if name == "ida_pro_mcp.services":
            raise ImportError("use host fallback")
        if name == "host.intelligence.core":
            return core
        return real_import(name, *args, **kwargs)

    mod.idc.get_idb_path = lambda: "/tmp/sample.i64"
    mod.idautils.Functions = lambda: iter([0x1000])
    mod.idc.get_func_name = lambda _ea: "named_function"
    with patch.object(builtins, "__import__", import_core):
        mod.validate_addr = lambda _addr, **_kwargs: (None, {"code": "ADDRESS_INVALID"})
        assert mod._embedding_rename_suggestions(addr="bad")["code"] == "ADDRESS_INVALID"
        mod.validate_addr = lambda _addr, **_kwargs: (0x1000, None)
        # No unnamed targets means the batch path returns an empty result.
        assert mod._embedding_rename_suggestions()["count"] == 0
        mod.idc.get_func_name = lambda _ea: "sub_1000"
        mod.ida_hexrays.decompile = lambda _ea: None
        assert mod._embedding_rename_suggestions(addr="0x1000")["count"] == 0
        mod.ida_hexrays.decompile = lambda _ea: (_ for _ in ()).throw(RuntimeError("decompiler unavailable"))
        assert mod._embedding_rename_suggestions(addr="0x1000")["count"] == 0
        mod.ida_hexrays.decompile = lambda _ea: "int f(void)"
        assert mod._embedding_rename_suggestions(addr="0x1000")["count"] == 0
        assert mod._embedding_rename_suggestions(addr="0x1000", threshold=0.9)["count"] == 0


def test_funcs_impl_create_and_mutation_boundary_envelopes():
    mod = _load_funcs()
    invalid = {"error": True, "code": "ADDRESS_INVALID", "message": "invalid"}
    mod.validate_addr = lambda value, **_kwargs: (
        (None, invalid) if value in {"raw", "bad-end"} else (int(str(value), 0), None)
    )
    mod.parse_address_safe = lambda _value: (0x401234, None)
    mod._try_map_raw_runtime_addr = lambda _ea: (None, None)
    assert mod._funcs_impl("create", addr="raw")["code"] == "ADDRESS_INVALID"
    mod._try_map_raw_runtime_addr = lambda _ea: (0x1234, "runtime remapped")
    assert mod._funcs_impl("create", addr="raw", end="bad-end")["code"] == "ADDRESS_INVALID"

    mod._remove_overlapping_functions = lambda *_args: (_ for _ in ()).throw(RuntimeError("overlap delete failed"))
    assert mod._funcs_impl("create", addr="0x1300", force=True)["code"] == "IDA_ERROR"

    fn = _fn(0x1234, 0x1244, "mapped")
    created = False

    def current_fn(_ea):
        return fn if created else None

    def add_fn(*_args):
        nonlocal created
        created = True
        return fn

    mod._compat.get_func_info = current_fn
    mod._remove_overlapping_functions = lambda *_args: [{"addr": "0x1200"}]
    mod._ensure_code_at = lambda _ea: True
    mod.ida_funcs.add_func = add_fn
    mod.ida_funcs.get_func_name = lambda _ea: "mapped"
    mod.idc.set_name = lambda *_args: True
    created_result = mod._funcs_impl("create", addr="raw", force=True)
    assert created_result["addr_remap"] == "runtime remapped"
    assert created_result["removed_overlaps"] == [{"addr": "0x1200"}]

    # The force path without an explicit end must skip the byte-carve call.
    created = False
    mod._remove_overlapping_functions = lambda *_args: []
    assert mod._funcs_impl("create", addr="0x1300", force=True)["ok"] is True

    mod._compat.get_func_info = lambda _ea: fn
    mod._resolve_func_addr = lambda _addr: (0x1234, None)
    mod.validate_addr = lambda value, **_kwargs: (
        (None, invalid) if value == "bad-end" else (int(str(value), 0), None)
    )
    assert mod._funcs_impl("change", addr="0x1234", end="bad-end")["code"] == "ADDRESS_INVALID"

    mod._compat.get_func_info = lambda _ea: None
    mod._ensure_code_at = lambda _ea: False
    mod._inf_filetype_id = lambda: (_ for _ in ()).throw(RuntimeError("no filetype"))
    failed_code = mod._funcs_impl("create", addr="0x1400")
    assert failed_code["code"] == "ADDRESS_INVALID"

    # Resolve failures are returned consistently by every read/write action.
    resolve_error = {"error": True, "code": "FUNCTION_NOT_FOUND"}
    mod._resolve_func_addr = lambda _addr: (None, resolve_error)
    assert mod._funcs_impl("delete", addr="0x1000") is resolve_error
    assert mod._funcs_impl("change", addr="0x1000") is resolve_error
    assert mod._funcs_impl("set_flags", addr="0x1000") is resolve_error
    assert mod._funcs_impl("info", addr="0x1000") is resolve_error
    assert mod._funcs_impl("metrics", addr="0x1000") is resolve_error
    assert mod._funcs_impl("find_similar", addr="0x1000") is resolve_error

    # Deleting from the middle reports the containing function start.
    mod._resolve_func_addr = lambda _addr: (0x1004, None)
    mod._compat.get_func_start = lambda _ea: 0x1000
    mod.ida_funcs.get_func_name = lambda _ea: "containing"
    mod.ida_funcs.del_func = lambda _ea: True
    deleted = mod._funcs_impl("delete", addr="0x1004")
    assert "containing function" in deleted["note"]

    # An unexpected implementation error still becomes the standard envelope.
    mod.validate_addr = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("unexpected"))
    assert mod._funcs_impl("create", addr="0x1500")["ok"] is False


def test_funcs_info_metrics_and_similarity_defensive_paths():
    mod = _load_funcs()
    fn = _fn(0x1000, 0x1010, "target")
    mod.validate_addr = lambda value, **_kwargs: (int(str(value), 0), None)
    mod._resolve_func_addr = lambda _addr: (0x1000, None)
    mod._compat.get_func_info = lambda _ea: fn
    mod._compat.get_func_flags = lambda _ea: 0
    mod.ida_funcs.get_func_name = lambda _ea: "target"
    mod.idautils.Chunks = lambda _ea: iter(())
    mod.idc.get_func_cmt = lambda *_args: ""
    mod._compat.get_prototype_string = lambda _ea: "void target()"

    class FalseDetails:
        def is_func(self):
            return True

        def get_func_details(self, _out):
            return False

    mod.ida_typeinf.tinfo_t = FalseDetails
    mod.ida_typeinf.func_type_data_t = object
    mod.ida_nalt.get_tinfo = lambda *_args: True
    info = mod._funcs_impl("info", addr="0x1000", include_prototype=True)
    assert info["ok"] is True and "parameters" not in info["function"], info
    mod.ida_nalt.get_tinfo = lambda *_args: False
    assert mod._funcs_impl("info", addr="0x1000", include_prototype=True)["ok"] is True

    class ParamDetails:
        rettype = "void"
        cc = "cdecl"

        def size(self):
            return 2

        def __getitem__(self, index):
            return types.SimpleNamespace(name="", type="", loc=None if index == 0 else types.SimpleNamespace(reg=None, offset=None))

    class TrueDetails:
        def is_func(self):
            return True

        def get_func_details(self, _out):
            return True

    mod.ida_typeinf.tinfo_t = TrueDetails
    mod.ida_typeinf.func_type_data_t = ParamDetails
    mod.ida_nalt.get_tinfo = lambda *_args: True
    info = mod._funcs_impl("info", addr="0x1000", include_prototype=True)
    assert info["function"]["parameters"][0]["name"] == "arg0"
    mod.ida_nalt.get_tinfo = lambda *_args: (_ for _ in ()).throw(RuntimeError("type unavailable"))
    assert mod._funcs_impl("info", addr="0x1000", include_prototype=True)["ok"] is True

    mod._compat.get_func_info = lambda _ea: None
    assert mod._funcs_impl("metrics", addr="0x1000")["code"] == "FUNCTION_NOT_FOUND"
    mod._compat.get_func_info = lambda _ea: fn
    block = types.SimpleNamespace(start_ea=0, end_ea=600000, succs=lambda: iter(()))
    mod._compat.get_flow_chart = lambda _ea: [block]
    mod.idc.print_insn_mnem = lambda _ea: ""
    mod.idc.next_head = lambda ea, _end: ea + 1
    mod.idc.generate_disasm_line = lambda *_args: (_ for _ in ()).throw(RuntimeError("no disasm"))
    short_block = types.SimpleNamespace(start_ea=0, end_ea=1, succs=lambda: iter(()))
    mod._compat.get_flow_chart = lambda _ea: [short_block]
    assert mod._funcs_impl("metrics", addr="0x1000")["ok"] is True
    mod._compat.get_flow_chart = lambda _ea: [block]
    old_disasm = getattr(mod.idc, "generate_disasm_line", None)
    if hasattr(mod.idc, "generate_disasm_line"):
        delattr(mod.idc, "generate_disasm_line")
    try:
        metrics = mod._funcs_impl("metrics", addr="0x1000")
    finally:
        if old_disasm is not None:
            mod.idc.generate_disasm_line = old_disasm
    assert metrics["metrics"]["instruction_count"] == 500000


def test_funcs_similarity_limits_timeout_and_empty_byte_paths():
    mod = _load_funcs()
    target = _fn(0x1000, 0x1008, "target")
    mod._resolve_func_addr = lambda _addr: (0x1000, None)
    mod._compat.get_func_info = lambda _ea: target
    mod.ida_funcs.get_func_name = lambda _ea: "candidate"
    mod.idautils.FuncItems = lambda _ea: iter([1])
    mod.ida_bytes.get_bytes = lambda _ea, _size: b"abcdefgh"
    assert mod._funcs_impl("find_similar", addr=None)["code"] == "INVALID_ARGS"
    mod._resolve_func_addr = lambda _addr: (None, {"error": True, "code": "ADDRESS_INVALID"})
    assert mod._funcs_impl("find_similar", addr="bad")["code"] == "ADDRESS_INVALID"
    mod._resolve_func_addr = lambda _addr: (0x1000, None)
    mod._compat.get_func_info = lambda _ea: None
    assert mod._funcs_impl("find_similar", addr="0x1000")["code"] == "FUNCTION_NOT_FOUND"

    # Candidate-level skips: missing metadata, empty bytes, and zero-length
    # comparisons all remain safe and simply do not enter the result set.
    empty_candidate = _fn(0x2010, 0x2018, "empty")
    mod._compat.get_func_info = lambda ea: target if ea == 0x1000 else (None if ea == 0x2000 else empty_candidate)
    mod.idautils.Functions = lambda: iter([0x1000, 0x2000, 0x2010])
    mod.ida_bytes.get_bytes = lambda ea, _size: b"abcdefgh" if ea == 0x1000 else b""
    assert mod._funcs_impl("find_similar", addr="0x1000")["count"] == 0

    zero = _fn(0x2000, 0x2000, "zero")
    mod._compat.get_func_info = lambda ea: target if ea == 0x1000 else zero
    mod.idautils.Functions = lambda: iter([0x1000, 0x2000])
    mod.ida_bytes.get_bytes = lambda ea, _size: b"" if ea == 0x1000 else b"x"
    assert mod._funcs_impl("find_similar", addr="0x1000")["count"] == 0

    # A huge instruction iterator is bounded at the documented 500k limit.
    deep = _fn(0x2000, 0x2008, "deep")
    mod._compat.get_func_info = lambda ea: target if ea == 0x1000 else deep
    mod.idautils.FuncItems = lambda ea: iter(range(500000)) if ea == 0x2000 else iter([1])
    mod.ida_bytes.get_bytes = lambda _ea, _size: b"abcdefgh"
    assert mod._funcs_impl("find_similar", addr="0x1000", min_score=0)["count"] == 1

    # The candidate cap is ten times the requested result limit.
    candidates = [_fn(0x2000 + i * 0x10, 0x2008 + i * 0x10, f"c{i}") for i in range(11)]
    by_addr = {0x1000: target, **{f.start_ea: f for f in candidates}}
    mod._compat.get_func_info = by_addr.get
    mod.idautils.Functions = lambda: iter([0x1000] + [f.start_ea for f in candidates])
    mod.idautils.FuncItems = lambda _ea: iter([1])
    mod.ida_bytes.get_bytes = lambda _ea, _size: b"abcdefgh"
    capped = mod._funcs_impl("find_similar", addr="0x1000", limit=1, min_score=0)
    assert capped.get("scanned") == 10, capped

    # The function-count guard stops pathological databases before expensive
    # byte and instruction work begins.
    huge_addresses = range(0x8000, 0x8000 + 50000 * 0x10, 0x10)
    mod._compat.get_func_info = lambda ea: target if ea == 0x1000 else _fn(ea, ea + 0x100, "large")
    mod.idautils.Functions = lambda: iter([0x1000, *huge_addresses])
    mod.ida_bytes.get_bytes = lambda _ea, _size: b"abcdefgh"
    bounded = mod._funcs_impl("find_similar", addr="0x1000", limit=10000, min_score=0)
    assert bounded["scanned"] == 50000

    # At the 500-function checkpoint the elapsed-time guard stops the scan and
    # annotates the otherwise valid partial result.
    many = [_fn(0x4000 + i * 0x10, 0x4008 + i * 0x10, f"m{i}") for i in range(500)]
    by_addr = {0x1000: target, **{f.start_ea: f for f in many}}
    mod._compat.get_func_info = by_addr.get
    mod.idautils.Functions = lambda: iter([0x1000] + [f.start_ea for f in many])
    with patch("time.monotonic", side_effect=[0, 61]):
        timed = mod._funcs_impl("find_similar", addr="0x1000", limit=100, min_score=0)
    assert "timed out" in timed["note"]


def test_funcs_wrapper_invalidates_write_cache():
    mod = _load_funcs()
    invalidated = []
    mod._tool_cache = lambda: types.SimpleNamespace(invalidate_all=lambda: invalidated.append(True))
    mod.sync_wrapper = lambda fn, _mode: fn()
    mod._funcs_impl = lambda **_kwargs: {"ok": True}
    assert mod.funcs(action="create", address="0x1000")["ok"] is True
    assert invalidated == [True]
    mod._tool_cache = lambda: None
    assert mod.funcs(action="create", address="0x1000")["ok"] is True
