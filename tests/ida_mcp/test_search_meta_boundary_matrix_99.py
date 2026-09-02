"""Additional failure and truncation coverage for metadata searches."""

from __future__ import annotations

import types

from tests.ida_mcp.test_search_meta_mode_matrix import _load_meta


def test_type_search_handles_empty_library_bad_items_and_truncation(monkeypatch):
    meta = _load_meta(monkeypatch)
    meta.ida_typeinf.get_idati = object
    meta.ida_typeinf.get_ordinal_qty = lambda _til: 4

    class Tif:
        def __init__(self):
            self.index = -1

        def get_type_by_ordinal(self, _til, index):
            self.index = index
            return index != 2

        def get_type_name(self):
            return "needle"

        def get_size(self):
            return 8

    meta.ida_typeinf.tinfo_t = Tif
    meta.iter_segments = lambda *_args, **_kwargs: [(0x1000, 0x1008)]
    meta.idc.next_head = lambda ea, _end: meta.idaapi.BADADDR if ea >= 0x1004 else ea + 4
    meta.ida_nalt.get_tinfo = lambda tif, ea: setattr(tif, "index", ea) or ea == 0x1000
    meta.idc.get_name = lambda _ea: "global"

    result = meta.search_type("needle", False, 0, 1, False)
    assert result["truncated"] is True and result["count"] == 1
    assert "items" not in result

    meta.ida_typeinf.get_idati = lambda: None
    meta.iter_segments = lambda *_args, **_kwargs: []
    empty = meta.search_type("needle", False, 0, 4, True)
    assert empty["count"] == 0 and empty["items"] == []


def test_type_and_export_searches_survive_sdk_exceptions(monkeypatch):
    meta = _load_meta(monkeypatch)
    meta.ida_typeinf.get_idati = object
    meta.ida_typeinf.get_ordinal_qty = lambda _til: 1

    class BrokenTif:
        def get_type_by_ordinal(self, *_args):
            raise RuntimeError("type")

    meta.ida_typeinf.tinfo_t = BrokenTif
    meta.iter_segments = lambda *_args, **_kwargs: [(0x1000, 0x1004)]
    meta.ida_nalt.get_tinfo = lambda *_args: (_ for _ in ()).throw(RuntimeError("address type"))
    meta.idc.next_head = lambda _ea, _end: meta.idaapi.BADADDR
    assert meta.search_type("x", False, 0, 4, True)["items"] == []

    meta.ida_nalt.get_entry_qty = lambda: 3
    meta.ida_nalt.get_entry_ordinal = lambda index: index
    meta.ida_nalt.get_entry = lambda ordinal: 0x1000 + ordinal
    meta.ida_nalt.get_entry_name = lambda ordinal: (_ for _ in ()).throw(RuntimeError("entry")) if ordinal == 1 else "needle"
    result = meta.search_export("needle", False, 0, 4, True)
    assert result["count"] == 2 and len(result["items"]) == 2


def test_summary_type_sample_cap_and_export_fallback(monkeypatch):
    meta = _load_meta(monkeypatch)
    meta.idautils.Names = lambda: iter([])
    meta.idautils.Functions = lambda: iter([])
    meta.get_cached_strings = list
    meta.get_cached_imports = list
    meta.resolve_scan_segments = lambda *_args, **_kwargs: ([], "", None)
    meta.ida_typeinf.get_idati = object
    meta.ida_typeinf.get_ordinal_qty = lambda _til: 501
    meta.ida_typeinf.tinfo_t = lambda: types.SimpleNamespace(
        get_type_by_ordinal=lambda *_args: True,
        get_type_name=lambda: "needle",
    )
    meta.ida_nalt.get_entry_qty = lambda: 1
    meta.ida_nalt.get_entry_ordinal = lambda _idx: 1
    meta.ida_nalt.get_entry_name = lambda _ordinal: "needle"
    result = meta.search_summary("needle", False, None, None)
    assert result["summary"]["types"] == 500
    assert result["summary"]["types_sampled"] is True
    assert result["summary"]["exports"] == 1

    meta.ida_nalt.get_entry_qty = lambda: (_ for _ in ()).throw(RuntimeError("exports"))
    fallback = meta.search_summary("needle", False, None, None)
    assert fallback["summary"]["exports"] == 0
