"""Exercise less common primitive and analysis branches in every backend mode."""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

from tests._isolated_repo_loader import load_tool_submodule


def _module():
    return load_tool_submodule("search.combinators")


def test_call_edges_cover_direct_import_fallback_and_bad_xrefs(monkeypatch):
    comb = _module()
    call_type = next(iter(comb.CALL_XREF_TYPES))
    def func_start(ea):
        return {0x1000: 0x1000, 0x2000: 0x2000, 0x4000: 0x4000}.get(ea)

    monkeypatch.setattr(comb._compat, "get_func_start", func_start)
    monkeypatch.setattr(comb.idautils, "FuncItems", lambda _ea: [0x1000, 0x1004])
    monkeypatch.setattr(
        comb.idautils,
        "XrefsFrom",
        lambda ea, _flags: (
            [SimpleNamespace(type=call_type, to=0x2000), SimpleNamespace(type=999, to=0x9999)]
            if ea == 0x1000
            else [SimpleNamespace(type=call_type, to=0x3000)]
        ),
    )
    monkeypatch.setattr(comb.idc, "get_name", lambda ea: "._imported" if ea == 0x3000 else "")
    monkeypatch.setattr(comb.idc, "get_name_ea_simple", lambda name: 0x4000 if name == "imported" else comb.idaapi.BADADDR)
    assert comb._func_callees(0x1000) == {0x2000, 0x4000}

    monkeypatch.setattr(comb.idautils, "XrefsFrom", lambda *_a: (_ for _ in ()).throw(RuntimeError("bad xrefs")))
    assert comb._func_callees(0x1000) == set()
    monkeypatch.setattr(comb._compat, "get_func_start", lambda _ea: None)
    assert comb._func_callees(0x1000) == set()


def test_bool_primitives_cover_strings_api_mnemonics_callers_and_args(monkeypatch):
    comb = _module()
    names = {0x1000: "Main", 0x2000: "worker"}
    spans = {ea: SimpleNamespace(start_ea=ea, end_ea=ea + (4 if ea == 0x1000 else 20)) for ea in names}
    monkeypatch.setattr(comb.idautils, "Functions", lambda: list(names))
    monkeypatch.setattr(comb, "_func_name", lambda ea: names[ea])
    monkeypatch.setattr(comb._compat, "get_func_info", spans.get)
    monkeypatch.setattr(comb.idc, "print_insn_mnem", lambda ea: "ret" if ea == 0x1000 else "call")
    monkeypatch.setattr(comb.idc, "next_head", lambda ea, _end: comb.idaapi.BADADDR if ea >= 0x1000 else ea + 1)
    monkeypatch.setattr(comb, "_func_callees", lambda ea: {0x2000} if ea == 0x1000 else set())
    monkeypatch.setattr(comb.idc, "get_name", lambda ea, *_a: "memcpy" if ea == 0x2000 else "")
    monkeypatch.setattr(comb.idc, "get_name_ea_simple", lambda _name: comb.idaapi.BADADDR)
    monkeypatch.setattr(comb.idaapi, "GN_VISIBLE", 0, raising=False)
    monkeypatch.setattr(comb.idautils, "FuncItems", lambda _ea: [0x1000])
    monkeypatch.setattr(comb.idautils, "XrefsFrom", lambda *_a: [])

    hexrays = types.ModuleType("ida_hexrays")
    hexrays.decompile = lambda ea: "return secret" if ea == 0x1000 else None
    monkeypatch.setitem(sys.modules, "ida_hexrays", hexrays)
    assert comb._prim_funcs_by_string("secret") == {0x1000}
    assert comb._prim_funcs_by_mnem("ret") == {0x1000}
    assert comb._prim_funcs_by_api("memcpy") == {0x1000}
    assert comb._prim_size(">10-30") == {0x2000}
    assert comb._prim_size("nonsense") == set()

    comb._compat.get_func_start = lambda ea: ea if ea in names else None
    monkeypatch.setattr(comb, "resolve_target", lambda _target: (0x2000, None, {}))
    monkeypatch.setattr(comb.idautils, "XrefsTo", lambda _ea, *_a: [SimpleNamespace(frm=0x1000, iscode=True), SimpleNamespace(frm=0x2000, iscode=False)])
    assert comb._prim_callers("worker") == {0x1000}
    assert comb._prim_callees("worker") == set()

    class FuncData:
        def size(self):
            return 2

    typeinf = types.ModuleType("ida_typeinf")
    typeinf.tinfo_t = lambda: SimpleNamespace(get_func_details=lambda data: True)
    typeinf.func_type_data_t = FuncData
    monkeypatch.setitem(sys.modules, "ida_typeinf", typeinf)
    monkeypatch.setattr(comb.ida_nalt, "get_tinfo", lambda _tif, ea: ea == 0x1000, raising=False)
    assert comb._prim_args("2+") == {0x1000}
    assert comb._prim_args("bad") == set()


def test_search_bool_and_reachability_report_parser_and_resolution_errors(monkeypatch):
    comb = _module()
    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000, 0x2000])
    def func_name(ea):
        return hex(ea)

    monkeypatch.setattr(comb, "_func_name", func_name)
    monkeypatch.setattr(comb, "_func_callees", lambda _ea: set())
    assert comb.search_bool("unknown:value", False, 0, 5)["error"] is True
    assert comb.search_bool("name:main AND", False, 0, 5)["error"] is True
    monkeypatch.setattr(comb, "resolve_target", lambda _target: (comb.idaapi.BADADDR, "no target", {}))
    assert comb.search_path("bad", "bad", 2)["error"] is True
    assert comb.search_reach("bad", 2, 0, 5)["error"] is True
    monkeypatch.setattr(comb, "resolve_target", lambda _target: (0x9999, None, {}))
    monkeypatch.setattr(comb._compat, "get_func_start", lambda _ea: None)
    assert comb.search_path("x", "y", 2)["error"] is True
    assert comb.search_reach("x", 2, 0, 5)["error"] is True


def test_analyze_index_failures_and_direct_fallbacks(monkeypatch):
    comb = _module()
    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "/tmp/sample.i64", raising=False)
    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000])
    monkeypatch.setattr(comb, "_func_name", lambda _ea: "main")
    monkeypatch.setattr(comb._compat, "get_func_info", lambda _ea: SimpleNamespace(start_ea=0x1000, end_ea=0x1008))

    services = types.ModuleType("ida_pro_mcp.services")
    services.get_assembler = lambda: (_ for _ in ()).throw(RuntimeError("index unavailable"))
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    for metric in ("size", "tiny", "huge", "bb_count"):
        result = comb.search_analyze(scope="outlier", metric=metric, limit=5)
        assert result["ok"] is True
    assert comb.search_analyze(scope="outlier", metric="complexity")["error"] is True

    monkeypatch.setattr(comb, "resolve_target", lambda _target: (0x1000, None, {}))
    monkeypatch.setattr(comb._compat, "get_func_start", lambda ea: ea if ea == 0x1000 else None)
    monkeypatch.setattr(comb, "_get_embedding_similar", lambda *_a, **_k: [])
    similar = comb.search_analyze(scope="similar", addr="main")
    assert similar["ok"] is True and similar["items"] == []
    monkeypatch.setattr(comb._compat, "get_func_info", lambda _ea: None)
    assert comb.search_analyze(scope="neighborhood", addr="main")["error"] is True
    assert comb.search_analyze(scope="wat", addr="main")["error"] is True


def test_analyze_semantic_and_vulnerable_backend_errors_are_safe(monkeypatch):
    comb = _module()
    services = types.ModuleType("ida_pro_mcp.services")
    services.get_assembler = lambda: types.SimpleNamespace(_get_index=lambda _path: (_ for _ in ()).throw(RuntimeError("query failed")))
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "/tmp/sample.i64", raising=False)
    assert comb.search_analyze(scope="semantic", pattern="crypto")["error"] is True
    monkeypatch.setattr(comb, "_get_call_graph", lambda: {"callers": {}, "callees": {}})
    monkeypatch.setattr(comb.idautils, "Functions", list)
    monkeypatch.setattr(comb.idautils, "Names", list)
    result = comb.search_analyze(scope="vulnerable", depth=1, pattern="memcpy")
    assert result["ok"] is True and result["count"] == 0
