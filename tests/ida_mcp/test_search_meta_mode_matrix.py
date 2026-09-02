"""Composed coverage for type, export, and summary search modes."""

import sys

from tests._isolated_repo_loader import load_tool_submodule


def _load_meta(monkeypatch):
    from tests.ida_mcp.test_support_engines_and_integration import _make_fake_ida

    for name, module in _make_fake_ida().items():
        monkeypatch.setitem(sys.modules, name, module)
    return load_tool_submodule("search.meta")


def test_search_type_combines_til_and_address_type_matches(monkeypatch):
    meta = _load_meta(monkeypatch)
    meta.idaapi.BADADDR = -1

    class Tif:
        def __init__(self):
            self.kind = "ordinal"
            self.idx = -1

        def get_type_by_ordinal(self, _til, idx):
            self.idx = idx
            self.kind = "ordinal"
            return idx != 0

        def get_type_name(self):
            return "FooStruct" if self.kind == "ordinal" else "FooAlias"

        def get_size(self):
            return -1 if self.idx == 2 else 16

    til = object()
    meta.ida_typeinf.get_idati = lambda: til
    meta.ida_typeinf.get_ordinal_qty = lambda _til: 3
    meta.ida_typeinf.tinfo_t = Tif
    meta.iter_segments = lambda _a, _b, require_exec=False: [(0x1000, 0x1008)]
    meta.idc.next_head = lambda ea, _end: ea + 4
    meta.ida_nalt.get_tinfo = lambda tif, ea: setattr(tif, "kind", "address") or ea == 0x1000
    meta.idc.get_name = lambda _ea: "typed_global"

    result = meta.search_type("foo", False, 0, 10, True)

    assert result["ok"] is True
    assert result["count"] == 3
    assert result["items"] == [
        {"ordinal": 1, "name": "FooStruct", "size": 16},
        {"ordinal": 2, "name": "FooStruct", "size": None},
        {"addr": "0x1000", "type": "FooAlias", "name": "typed_global"},
    ]
    assert "size=?" in result["results"]


def test_search_export_handles_offsets_limits_and_bad_entries(monkeypatch):
    meta = _load_meta(monkeypatch)
    meta.ida_nalt.get_entry_qty = lambda: 4
    meta.ida_nalt.get_entry_ordinal = lambda idx: idx + 1
    meta.ida_nalt.get_entry = lambda ordinal: {1: 0x1000, 2: 0x2000, 3: 0x3000, 4: 0x4000}[ordinal]
    meta.ida_nalt.get_entry_name = lambda ordinal: {1: "start", 2: "helper", 3: "other", 4: "helper2"}[ordinal]

    result = meta.search_export("helper", False, 0, 1, True)
    assert result["count"] == 1
    assert result["total"] == 1
    assert result["truncated"] is True
    assert result["items"] == [{"addr": "0x2000", "ordinal": 2, "name": "helper"}]

    meta.ida_nalt.get_entry = lambda ordinal: (_ for _ in ()).throw(RuntimeError("bad entry")) if ordinal == 2 else 0x1000
    assert meta.search_export("start", False, 0, 10, False)["count"] == 1


def test_search_summary_composes_unfiltered_and_filtered_categories(monkeypatch):
    meta = _load_meta(monkeypatch)
    meta.idautils.Functions = lambda: [0x1000, 0x2000]
    meta.idautils.Names = lambda: [(0x1000, "alpha"), (0x2000, "beta")]
    meta.idc.get_func_name = lambda ea: {0x1000: "alpha_fn", 0x2000: "beta_fn"}[ea]
    meta.safe_get_strlist_items = lambda: iter([type("S", (), {"name": "alpha string"})(), type("S", (), {"name": "beta"})()])
    meta.get_cached_strings = lambda: [{"string": "alpha literal"}, {"string": "gamma literal"}]
    meta.get_cached_imports = lambda: [{"name": "alpha_import"}, {"name": "other_import"}]
    meta.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x3000, 0x3004)], "", "")
    meta.iter_code = lambda _start, _end, force=False: iter([0x3000])
    meta.safe_generate_disasm_line = lambda _ea: "mov alpha, eax"
    meta.ida_lines.tag_remove = lambda line: line
    meta.idc.print_insn_mnem = lambda _ea: "mov"
    meta.ida_typeinf.get_idati = lambda: None
    meta.ida_nalt.get_entry_qty = lambda: 0

    no_filter = meta.search_summary(None, False, None, None)
    assert no_filter["summary"] == {"functions": 2, "names": 2, "strings": 2}
    assert no_filter["total"] == 6

    filtered = meta.search_summary("alpha", False, None, None)
    assert filtered["summary"]["names"] == 1
    assert filtered["summary"]["strings"] == 1
    assert filtered["summary"]["imports"] == 1
    assert filtered["summary"]["functions"] == 1
    assert filtered["summary"]["instructions"] == 1
    assert filtered["total"] == 5


def test_search_meta_degrades_when_type_and_export_apis_are_unavailable(monkeypatch):
    meta = _load_meta(monkeypatch)
    meta.idaapi.BADADDR = -1

    def missing_til():
        raise RuntimeError("type library unavailable")

    meta.ida_typeinf.get_idati = missing_til
    meta.iter_segments = lambda *_args, **_kwargs: [(0x1000, 0x1002)]
    meta.idc.next_head = lambda _ea, _end: meta.idaapi.BADADDR
    meta.ida_nalt.get_tinfo = lambda *_args: (_ for _ in ()).throw(RuntimeError("no tinfo"))
    type_result = meta.search_type("missing", False, 0, 10, False)
    assert type_result["ok"] is True
    assert type_result["count"] == 0

    meta.ida_nalt.get_entry_qty = lambda: (_ for _ in ()).throw(RuntimeError("entry API unavailable"))
    export_result = meta.search_export("missing", False, 0, 10, True)
    assert export_result["ok"] is True
    assert export_result["items"] == []


def test_search_summary_filtered_fallback_handles_sparse_sdk_modes(monkeypatch):
    meta = _load_meta(monkeypatch)
    calls = {"functions": 0}

    def functions_with_initial_failure():
        calls["functions"] += 1
        if calls["functions"] == 1:
            raise RuntimeError("functions unavailable")
        return iter([0x1000])

    meta.idautils.Functions = functions_with_initial_failure
    meta.idautils.Names = lambda: iter([(0x1000, "alpha"), (0x2000, "beta")])
    meta.get_cached_strings = lambda: [{"string": "alpha literal"}, {"string": "beta literal"}]
    meta.get_cached_imports = lambda: [{"name": "alpha_import"}]
    meta.idc.get_func_name = lambda _ea: "alpha_fn"
    meta.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x3000, 0x3002)], "forced", None)
    meta.iter_code = lambda *_args, **_kwargs: iter([0x3000, 0x3001])
    meta.safe_generate_disasm_line = lambda _ea: None
    meta.ida_typeinf.get_idati = lambda: (_ for _ in ()).throw(RuntimeError("no types"))
    meta.ida_nalt.get_entry_qty = lambda: (_ for _ in ()).throw(RuntimeError("no exports"))

    fallback = meta.search_summary(None, False, None, None)
    assert fallback["ok"] is True
    result = meta.search_summary("alpha", False, None, None)
    assert result["ok"] is True
    assert result["summary"]["names"] == 1
    assert result["summary"]["strings"] == 1
    assert result["summary"]["imports"] == 1
    assert result["summary"]["functions"] == 1
    assert result["summary"]["instructions"] == 0
