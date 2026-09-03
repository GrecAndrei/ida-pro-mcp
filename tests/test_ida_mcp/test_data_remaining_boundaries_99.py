"""Boundary coverage for the IDA data/listing surface."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

from tests.fakes.ida_fake import FF_DATA

data_module = importlib.import_module("ida_pro_mcp.ida_mcp.tools.data")


def _ok(result):
    assert result.get("ok") is True, result
    return result


def test_data_walk_helpers_are_bounded_and_fail_closed(monkeypatch, fresh_fake_idb):
    assert list(data_module._iter_byte_hits(b"")) == []
    monkeypatch.setattr(data_module.idautils, "Segments", lambda: (_ for _ in ()).throw(RuntimeError("segments")))
    assert list(data_module._iter_byte_hits(b"needle")) == []

    monkeypatch.setattr(data_module.idautils, "Segments", lambda: iter([0x140003000, 0xDEAD]))
    monkeypatch.setattr(data_module.idc, "get_segm_end", lambda ea: ea + 16 if ea != 0xDEAD else ea - 1)
    monkeypatch.setattr(data_module.ida_bytes, "get_bytes", lambda ea, size: b"--needle-needle"[:size] if ea == 0x140003000 else None)
    hits = list(data_module._iter_byte_hits(b"needle", max_hits=1))
    assert hits == [0x140003002]

    monkeypatch.setattr(data_module.ida_bytes, "get_byte", lambda ea: 0 if ea == 0x140002010 else 65)
    monkeypatch.setattr(data_module.ida_bytes, "get_bytes", lambda _ea, _size: b"prefix\x00ignored")
    assert data_module._cstring_containing(0x140002011) == (0x140002011, "prefix")
    monkeypatch.setattr(data_module.ida_bytes, "get_byte", lambda _ea: (_ for _ in ()).throw(RuntimeError("byte")))
    assert data_module._cstring_containing(0x140002011)[0] == 0x140002011

    assert data_module._literal_query_bytes("abc") is None
    assert data_module._literal_query_bytes("ab[c]") is None
    assert data_module._literal_query_bytes("/regex/") is None

    class BadEncoding(str):
        def encode(self, encoding, *args, **kwargs):
            if encoding == "utf-8":
                raise UnicodeError("encoding")
            return super().encode(encoding, *args, **kwargs)

    assert data_module._literal_query_bytes(BadEncoding("valid")) == b"valid"
    assert len(data_module._walk_fingerprint()) == 2


def test_data_strings_uses_legacy_string_list_and_literal_scan(monkeypatch, fresh_fake_idb):
    class StringInfo:
        ea = 0
        length = 0
        type = 0

    monkeypatch.setattr(data_module.idautils, "Strings", lambda: (_ for _ in ()).throw(RuntimeError("no Strings")), raising=False)
    monkeypatch.setattr(data_module.idaapi, "string_info_t", StringInfo, raising=False)
    monkeypatch.setattr(data_module.idaapi, "get_strlist_qty", lambda: 1, raising=False)
    monkeypatch.setattr(
        data_module.idaapi,
        "get_strlist_item",
        lambda info, _index: (setattr(info, "ea", 0x140002100) or setattr(info, "length", 14) or True),
        raising=False,
    )
    monkeypatch.setattr(data_module.idc, "get_strlit_contents", lambda *_args: b"fallback string", raising=False)
    monkeypatch.setattr(data_module, "_iter_byte_hits", lambda _needle: iter([0x140002200]))
    monkeypatch.setattr(data_module, "_cstring_containing", lambda _ea: (0x140002200, "fallback literal"))
    result = _ok(data_module.data(action="strings", query="fallback", min_len=4, count=0))
    assert result["total"] == 2
    assert "fallback string" in result["strings"]
    assert "fallback literal" in result["strings"]

    fresh_fake_idb.filetype = data_module.idaapi.f_BIN
    short = _ok(data_module.data(action="strings", query=None, min_len=2, count=0))
    assert short["total"] == 1


def test_data_import_export_and_lookup_fallbacks(monkeypatch, fresh_fake_idb):
    import ida_entry

    monkeypatch.setattr(data_module.ida_nalt, "get_import_module_qty", lambda: 1)
    monkeypatch.setattr(data_module.ida_nalt, "get_import_module_name", lambda _i: "kernel32")
    monkeypatch.setattr(
        data_module.ida_nalt,
        "enum_import_names",
        lambda _i, cb: (cb(0x140004000, "CreateFileW", 1) and cb(0x140004008, None, 2)),
    )
    imports = _ok(data_module.data(action="imports", query="CreateFile"))
    assert imports["total"] == 1 and "CreateFileW" in imports["imports"]

    monkeypatch.setattr(data_module.idaapi, "get_entry_qty", None, raising=False)
    monkeypatch.setattr(ida_entry, "get_entry_qty", lambda: 1, raising=False)
    monkeypatch.setattr(ida_entry, "get_entry_ordinal", lambda _i: 7, raising=False)
    monkeypatch.setattr(ida_entry, "get_entry", lambda _ordinal: 0x140001000, raising=False)
    monkeypatch.setattr(ida_entry, "get_entry_name", lambda _ordinal: "exported", raising=False)
    exports = _ok(data_module.data(action="exports", query="export"))
    assert exports["total"] == 1 and "exported" in exports["exports"]

    monkeypatch.setattr(data_module, "resolve_symbol", lambda _query: {"addr": "0x140001000", "name": "start"})
    exact = _ok(data_module.data(action="lookup", query="start"))
    assert exact["exact_match"] is True and exact["is_function"] is True
    monkeypatch.setattr(data_module, "resolve_symbol", lambda _query: (_ for _ in ()).throw(RuntimeError("not exact")))
    monkeypatch.setattr(data_module.idautils, "Names", lambda: iter([(0x140001000, "start"), (0x140003000, "config"), (0x140003010, "")]))
    fallback = _ok(data_module.data(action="lookup", query="config"))
    assert fallback["exact_match"] is False and fallback["items"][0]["type"] == "symbol"
    monkeypatch.setattr(data_module.idautils, "Names", lambda: iter(()))
    assert data_module.data(action="lookup", query="missing")["error"] is True


def test_data_bulk_capability_and_read_bytes_error_modes(monkeypatch, fresh_fake_idb):
    assert data_module.data(action="bulk_query")["error"] is True
    bulk = _ok(
        data_module.data(
            action="bulk_query",
            items=[None, {}, {"kind": "functions", "count": 0}],
        )
    )
    assert bulk["count"] == 3

    monkeypatch.setattr(data_module.ida_nalt, "get_import_module_qty", lambda: 1)
    monkeypatch.setattr(data_module.ida_nalt, "enum_import_names", lambda _i, cb: cb(0x140004000, "VirtualAlloc", 1))
    matrix = _ok(data_module.data(action="capability_matrix"))
    assert "VirtualAlloc" in matrix["risk_indicators"]

    assert data_module.data(action="read_bytes")["error"] is True
    monkeypatch.setattr(data_module, "validate_addr", lambda _addr: (None, {"error": True, "code": "bad"}))
    assert data_module.data(action="read_bytes", query="0x140003000")["error"] is True
    monkeypatch.setattr(data_module, "validate_addr", lambda _addr: (0x140003000, None))
    monkeypatch.setattr(data_module.ida_bytes, "get_bytes", lambda *_args: None)
    assert data_module.data(action="read_bytes", query="0x140003000", size=99)["error"] is True
    monkeypatch.setattr(data_module.ida_bytes, "get_bytes", lambda _ea, size: bytes(range(min(size, 20))))
    dump = _ok(data_module.data(action="read_bytes", query="0x140003000", size=20))
    assert dump["size"] == 20 and "|" in dump["dump"]
    assert data_module.data(action="unknown")["error"] is True


def test_data_string_xrefs_keeps_unreferenced_and_deduplicates(monkeypatch, fresh_fake_idb):
    class String:
        def __init__(self, ea, text):
            self.ea = ea
            self.text = text

        def __str__(self):
            return self.text

    strings = [String(0x140002100, ""), String(0x140002110, "x"), String(0x140002120, "version=1.2"), String(0x140002130, "error: failed")]
    monkeypatch.setattr(data_module.idautils, "Strings", lambda: iter(strings), raising=False)
    monkeypatch.setattr(
        data_module.idautils,
        "XrefsTo",
        lambda ea: iter(
            [SimpleNamespace(frm=0x140001004), SimpleNamespace(frm=0x140001004)]
            if ea == 0x140002130
            else []
        ),
    )
    monkeypatch.setattr(data_module._compat, "get_func_start", lambda _ea: 0x140001000)
    monkeypatch.setattr(data_module.ida_funcs, "get_func_name", lambda _ea: "caller")
    monkeypatch.setattr(data_module, "_inf_filetype_id", lambda: 17)
    monkeypatch.setattr(data_module, "is_riscv_family", lambda: False)
    result = _ok(data_module.data(action="string_xrefs", min_len=4))
    assert result["total_strings_scanned"] == 2
    assert result["strings_without_refs"]
    assert "raw blobs" in result["note"]
    assert result["top_strings"][0]["referencing_functions"][0]["name"] == "caller"


def test_data_global_struct_metadata_and_unknown_runtime_errors(monkeypatch, fresh_fake_idb):
    fresh_fake_idb.set_name(0x140003050, "data_record")
    fresh_fake_idb.flags[0x140003050] = FF_DATA
    monkeypatch.setattr(data_module.idautils, "Names", lambda: iter([(0x140003050, "data_record")]))
    monkeypatch.setattr(data_module.ida_nalt, "get_tinfo", lambda _tif, _ea: True)
    monkeypatch.setattr(data_module.idc, "get_item_size", lambda _ea: 8)
    monkeypatch.setattr(data_module.ida_bytes, "get_bytes", lambda _ea, _size: b"12345678")
    result = _ok(data_module.data(action="globals", include_xrefs=True))
    assert result["total"] == 1 and "size=8" in result["globals"]

    monkeypatch.setattr(data_module, "_walk_fingerprint", lambda: (_ for _ in ()).throw(RuntimeError("fingerprint")))
    assert data_module.data(action="functions")["error"] is True
