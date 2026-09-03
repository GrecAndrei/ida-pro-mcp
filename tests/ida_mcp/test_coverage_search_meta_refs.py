"""Offline behavior coverage for search metadata and reference modes."""

from __future__ import annotations

import types

from tests._isolated_repo_loader import load_tool_submodule

BADADDR = -1


def test_search_type_covers_library_and_explicit_type_uses():
    meta = load_tool_submodule("search.meta")
    meta.idaapi.BADADDR = BADADDR

    class Tinfo:
        def __init__(self):
            self.name = ""

        def get_type_by_ordinal(self, _til, ordinal):
            self.name = "WantedType" if ordinal == 0 else "OtherType"
            return ordinal == 0

        def get_type_name(self):
            return self.name

        def get_size(self):
            return BADADDR

    meta.ida_typeinf.tinfo_t = Tinfo
    meta.ida_typeinf.get_idati = object
    meta.ida_typeinf.get_ordinal_qty = lambda _til: 2
    meta.iter_segments = lambda *_args, **_kwargs: iter(())
    result = meta.search_type("wanted", False, 0, 5, True)
    assert result["items"] == [{"ordinal": 0, "name": "WantedType", "size": None}]
    assert "size=?" in result["results"]

    meta.ida_typeinf.get_idati = lambda: None
    meta.iter_segments = lambda *_args, **_kwargs: iter([(0x1000, 0x1002)])
    def _get_tinfo(tif, _ea):
        tif.name = "WantedType"
        return True

    meta.ida_nalt.get_tinfo = _get_tinfo
    meta.idc.get_name = lambda _ea: ""
    meta.idc.next_head = lambda _ea, _end: BADADDR
    result = meta.search_type("wanted", False, 0, 5, True)
    assert result["items"] == [{"addr": "0x1000", "type": "WantedType", "name": ""}]


def test_search_type_and_export_fail_open_and_paginate():
    meta = load_tool_submodule("search.meta")
    meta.idaapi.BADADDR = BADADDR
    meta.ida_typeinf.get_idati = lambda: (_ for _ in ()).throw(RuntimeError("no til"))
    meta.iter_segments = lambda *_args, **_kwargs: iter(())
    assert meta.search_type("wanted", False, 0, 5, False)["ok"] is True

    meta.ida_nalt.get_entry_qty = lambda: 2
    meta.ida_nalt.get_entry_ordinal = lambda idx: idx + 10
    meta.ida_nalt.get_entry = lambda ordinal: 0x2000 + ordinal
    meta.ida_nalt.get_entry_name = lambda ordinal: (
        "Exported" if ordinal == 10 else (_ for _ in ()).throw(RuntimeError("bad export"))
    )
    result = meta.search_export("export", False, 0, 1, True)
    assert result["items"] == [{"addr": "0x200a", "ordinal": 10, "name": "Exported"}]

    meta.ida_nalt.get_entry_qty = lambda: (_ for _ in ()).throw(RuntimeError("count"))
    assert meta.search_export("export", False, 0, 5, False)["ok"] is True

    meta.ida_typeinf.get_idati = object
    meta.ida_typeinf.get_ordinal_qty = lambda _til: 2
    meta.ida_typeinf.tinfo_t = type(
        "OneType",
        (),
        {
            "get_type_by_ordinal": lambda self, _til, idx: idx == 0,
            "get_type_name": lambda _self: "WantedType",
            "get_size": lambda _self: 4,
        },
    )
    meta.iter_segments = lambda *_args, **_kwargs: iter(())
    limited = meta.search_type("wanted", False, 0, 1, False)
    assert limited["truncated"] is True

    meta.ida_typeinf.get_idati = lambda: None
    meta.iter_segments = lambda *_args, **_kwargs: iter([(0x1000, 0x1002)])
    meta.ida_typeinf.tinfo_t = type(
        "AddressType",
        (),
        {"get_type_name": lambda _self: "WantedType"},
    )
    meta.ida_nalt.get_tinfo = lambda _tif, _ea: True
    meta.idc.get_name = lambda _ea: ""
    meta.idc.next_head = lambda _ea, _end: BADADDR
    limited_use = meta.search_type("wanted", False, 0, 1, False)
    assert limited_use["truncated"] is True


def test_search_summary_counts_each_category_and_empty_fallback(monkeypatch):
    meta = load_tool_submodule("search.meta")
    meta.idaapi.BADADDR = BADADDR
    meta.idautils.Names = lambda: iter([(0x1, "needle_name")])
    meta.get_cached_strings = lambda: [{"string": "needle_string"}]
    meta.get_cached_imports = lambda: [{"name": "needle_import"}]
    meta.idautils.Functions = lambda: iter([0x1000])
    meta.idc.get_func_name = lambda _ea: "needle_function"
    meta.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x1000, 0x1001)], "sample note", None)
    meta.iter_code = lambda *_args, **_kwargs: iter([0x1000])
    meta.safe_generate_disasm_line = lambda _ea: "needle instruction"
    meta.ida_lines.tag_remove = lambda line: line
    meta.idc.print_insn_mnem = lambda _ea: "mov"

    class Tinfo:
        def get_type_by_ordinal(self, _til, _idx):
            return True

        def get_type_name(self):
            return "needle_type"

    meta.ida_typeinf.tinfo_t = Tinfo
    meta.ida_typeinf.get_idati = object
    meta.ida_typeinf.get_ordinal_qty = lambda _til: 1
    meta.ida_nalt.get_entry_qty = lambda: 1
    meta.ida_nalt.get_entry_ordinal = lambda _idx: 7
    meta.ida_nalt.get_entry_name = lambda _ordinal: "needle_export"
    summary = meta.search_summary("needle", False, None, None)
    assert summary["summary"] == {
        "names": 1, "strings": 1, "imports": 1, "instructions": 1,
        "functions": 1, "types": 1, "exports": 1,
    }
    assert summary["total"] == 7 and summary["note"]

    meta.safe_get_strlist_items = lambda: [{"string": "one"}, {"string": "two"}]
    empty = meta.search_summary(None, False, None, None)
    assert empty["summary"] == {"functions": 1, "names": 1, "strings": 2}

    meta.iter_code = lambda *_args, **_kwargs: iter(range(5001))
    sampled = meta.search_summary("never", False, None, None)
    assert sampled["summary"].get("instructions_sampled") is True


def test_search_reference_context_and_regex_boundaries(monkeypatch):
    refs = load_tool_submodule("search.refs")
    refs.idaapi.BADADDR = BADADDR
    refs.resolve_target = lambda *_args, **_kwargs: (0x4000, None, {"semantic": True})
    refs.idautils.XrefsTo = lambda *_args: iter([
        types.SimpleNamespace(iscode=False, frm=0x1100, to=0x4000),
        types.SimpleNamespace(iscode=True, frm=0x1200, to=0x4000),
    ])
    refs.idc.get_name = lambda _ea: "data_owner"
    data = refs.search_data_ref("target", True, 0, 10, 0.0, False)
    assert data["count"] == 1 and "data_owner" in data["results"]

    refs._compat.get_func_start = lambda _ea: 0x1200
    refs.ida_funcs.get_func_name = lambda _ea: "caller"
    refs.safe_generate_disasm_line = lambda _ea: "call target"
    refs.ida_lines.tag_remove = lambda line: line
    code = refs.search_code_ref("target", True, 0, 10, 0.0, False)
    assert code["count"] == 1 and "caller  call target" in code["results"]

    refs.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x1000, 0x1002)], "bounded", None)
    refs.iter_code = lambda *_args, **_kwargs: iter([0x1000])
    regex = refs.search_regex("needle", False, None, None, False, 0, 5)
    assert regex["ok"] is True and regex["note"] == "bounded"

    monkeypatch.setattr(refs, "resolve_scan_segments", lambda *_args, **_kwargs: ([], None, "no executable range"))
    missing = refs.search_regex("needle", False, None, None, False, 0, 5)
    assert missing["code"] == "NOT_FOUND"

    refs.idautils.XrefsTo = lambda *_args: iter([
        types.SimpleNamespace(iscode=False, frm=0x1100, to=0x4000),
        types.SimpleNamespace(iscode=False, frm=0x1104, to=0x4000),
    ])
    limited_data = refs.search_data_ref("target", False, 0, 1, 0.0, False)
    assert limited_data["truncated"] is True

    refs.idautils.XrefsTo = lambda *_args: iter([
        types.SimpleNamespace(iscode=True, frm=0x1200, to=0x4000),
        types.SimpleNamespace(iscode=True, frm=0x1204, to=0x4000),
    ])
    limited_code = refs.search_code_ref("target", False, 0, 1, 0.0, False)
    assert limited_code["truncated"] is True

    assert refs._is_dangerous_regex("x" * 257) is True
    assert refs._is_dangerous_regex("(a|b)+") is True

    class Timeout:
        def __init__(self, _timeout):
            self.calls = 0

        def check(self):
            self.calls += 1
            raise TimeoutError

    monkeypatch.setattr(refs, "SearchTimeout", Timeout)
    refs.resolve_scan_segments = lambda *_args, **_kwargs: ([(0x1000, 0x1001), (0x2000, 0x2001)], None, None)
    refs.iter_code = lambda *_args, **_kwargs: iter([0x1000])
    timed = refs.search_regex("needle", False, None, None, False, 0, 5)
    assert timed["timed_out"] is True

    refs.SearchTimeout = lambda _timeout: types.SimpleNamespace(check=lambda: None)
    refs.iter_code = lambda *_args, **_kwargs: iter([0x1000, 0x1004])
    refs.safe_generate_disasm_line = lambda _ea: "call needle"
    limited_regex = refs.search_regex("needle", False, None, None, False, 0, 1)
    assert limited_regex["truncated"] is True and limited_regex["count"] >= 1


def test_search_func_by_sig_covers_aliases_reasons_and_skips():
    refs = load_tool_submodule("search.refs")
    refs.idaapi.BADADDR = BADADDR
    refs.idautils.Functions = lambda: iter([0x1000, 0x2000])
    refs.ida_funcs.get_func_name = lambda ea: {0x1000: "worker", 0x2000: "missing"}[ea]
    refs._compat.get_func_info = lambda ea: (
        None if ea == 0x2000 else types.SimpleNamespace(start_ea=ea, end_ea=ea + 15)
    )
    refs.idautils.XrefsTo = lambda *_args: iter([])
    refs.idautils.XrefsFrom = lambda *_args: iter([])
    refs.compile_smart_pattern = lambda pattern, **_kwargs: lambda text: pattern.lower() in str(text).lower()

    ranged = refs.search_func_by_sig("larger than 1 size:10-20", 0, 10)
    assert ranged["count"] == 1 and "in [10,20]" in ranged["results"]
    exact = refs.search_func_by_sig("size:15", 0, 10)
    assert exact["count"] == 1 and "size=15" in exact["results"]

    assert refs.search_func_by_sig("smaller than 20", 0, 1)["count"] == 1
