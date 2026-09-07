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


def test_data_scan_segments_empty_blob_and_c_string_decode_fallback(monkeypatch):
    monkeypatch.setattr(data_module.idautils, "Segments", lambda: iter([0x140001000]))
    monkeypatch.setattr(data_module.idc, "get_segm_end", lambda ea: ea + 100)
    monkeypatch.setattr(data_module.ida_bytes, "get_bytes", lambda *_args: None)
    assert list(data_module._iter_byte_hits(b"test")) == []

    class BrokenBytes(bytes):
        def __getitem__(self, item):
            return BrokenBytes(super().__getitem__(item))

        def decode(self, encoding="utf-8", errors="strict"):
            if encoding == "utf-8":
                raise UnicodeError("broken utf-8")
            return "decoded latin-1"

    monkeypatch.setattr(data_module.ida_bytes, "get_byte", lambda _ea: 0)
    monkeypatch.setattr(data_module.ida_bytes, "get_bytes", lambda *_args: BrokenBytes(b"raw\x00"))
    assert data_module._cstring_containing(0x140001000)[1] == "decoded latin-1"


def test_data_functions_min_xrefs_filtering(fresh_fake_idb):
    res = _ok(data_module.data(action="functions", min_xrefs=50, count=10))
    assert res["total"] == 0


def test_data_strings_adaptive_ratio_and_needle_seen(monkeypatch, fresh_fake_idb):
    class FakeStr:
        def __init__(self, val, ea=0x140002000):
            self.val = val
            self.ea = ea

        def __str__(self):
            return self.val

    many_strings = [FakeStr("abc") for _ in range(300)] + [FakeStr("!!!???") for _ in range(300)] + [FakeStr("hello_world_test") for _ in range(300)]

    class BytesStr:
        ea = 0x140002050
        def __str__(self):
            return b"bytes_sample"  # noqa: PLE0307

    many_strings.append(BytesStr())

    monkeypatch.setattr(data_module.idautils, "Strings", lambda: iter(many_strings), raising=False)
    monkeypatch.setattr(data_module._compat, "get_segment_perm", lambda _ea: data_module.idaapi.SEGPERM_EXEC)
    monkeypatch.setattr(data_module, "_iter_byte_hits", lambda _n: iter([0x140002000, 0x140002000]))
    monkeypatch.setattr(data_module, "_cstring_containing", lambda ea: (0x140002000, "hello_world_test"))

    res = _ok(data_module.data(action="strings", query="hello_world_test", min_len=4))
    assert res["total"] >= 1


def test_data_strings_legacy_strlist_empty_and_exception(monkeypatch, fresh_fake_idb):
    class StringInfo:
        ea = 0x140002100
        length = 10
        type = 0

    calls = [0]

    def fake_strlit(*args):
        calls[0] += 1
        if calls[0] == 1:
            return None
        raise RuntimeError("strlit error")

    monkeypatch.setattr(data_module.idautils, "Strings", lambda: (_ for _ in ()).throw(RuntimeError("no Strings")), raising=False)
    monkeypatch.setattr(data_module.idaapi, "string_info_t", StringInfo, raising=False)
    monkeypatch.setattr(data_module.idaapi, "get_strlist_qty", lambda: 2, raising=False)
    monkeypatch.setattr(data_module.idaapi, "get_strlist_item", lambda _info, _i: True, raising=False)
    monkeypatch.setattr(data_module.idc, "get_strlit_contents", fake_strlit, raising=False)

    res = _ok(data_module.data(action="strings", min_len=4))
    assert res["total"] == 0


def test_data_exports_nalt_fallback_and_lookup_limit(monkeypatch, fresh_fake_idb):
    import ida_entry

    monkeypatch.delattr(data_module.idaapi, "get_entry_qty", raising=False)
    monkeypatch.delattr(ida_entry, "get_entry_qty", raising=False)
    monkeypatch.setattr(data_module.ida_nalt, "get_entry_qty", lambda: 2, raising=False)
    monkeypatch.setattr(data_module.ida_nalt, "get_entry_ordinal", lambda i: i + 1, raising=False)
    monkeypatch.setattr(data_module.ida_nalt, "get_entry", lambda ord: 0x140001000 + ord * 4, raising=False)
    monkeypatch.setattr(data_module.ida_nalt, "get_entry_name", lambda ord: "target_export" if ord == 1 else "other_export", raising=False)

    res = _ok(data_module.data(action="exports", query="target"))
    assert res["total"] == 1
    assert "target_export" in res["exports"]

    monkeypatch.setattr(data_module, "resolve_symbol", lambda _q: (_ for _ in ()).throw(RuntimeError("not exact")))
    names = [(0x140001000 + i * 4, f"match_sym_{i}") for i in range(250)]
    monkeypatch.setattr(data_module.idautils, "Names", lambda: iter(names))
    lookup_res = _ok(data_module.data(action="lookup", query="match_sym", count=10))
    assert lookup_res["exact_match"] is False
    assert len(lookup_res["items"]) == 10


def test_data_bulk_query_extended_args_and_capability_limits(monkeypatch, fresh_fake_idb):
    res = _ok(
        data_module.data(
            action="bulk_query",
            items=[{
                "kind": "functions",
                "include_prototype": True,
                "include_xrefs": True,
                "min_size": 16,
                "named_only": True,
            }],
        )
    )
    assert res["count"] == 1

    funcs = list(range(0x140001000, 0x140001000 + 210))
    monkeypatch.setattr(data_module.idautils, "Functions", lambda: iter(funcs))

    def fake_func_info(ea):
        if ea == 0x140001000:
            return None
        return SimpleNamespace(start_ea=ea, end_ea=ea + 4)

    monkeypatch.setattr(data_module._compat, "get_func_info", fake_func_info)
    monkeypatch.setattr(data_module.idautils, "Heads", lambda *_a: iter([]))
    cap = _ok(data_module.data(action="capability_matrix"))
    assert "top_categories" in cap


def test_data_string_xrefs_branches_and_exceptions(monkeypatch, fresh_fake_idb):
    class StringObj:
        def __init__(self, ea, text):
            self.ea = ea
            self.text = text

        def __str__(self):
            return self.text

    strings = [
        StringObj(0x140002100, "%s error status"),
        StringObj(0x140002110, "   "),
        StringObj(0x140002120, b"raw bytes msg"),
    ]

    class ThrowingString:
        ea = 0x140002130
        def __str__(self):
            raise RuntimeError("string err")

    strings.append(ThrowingString())

    monkeypatch.setattr(data_module.idautils, "Strings", lambda: iter(strings), raising=False)

    def fake_xrefs(ea):
        if ea == 0x140002100:
            return iter([
                SimpleNamespace(frm=None),
                SimpleNamespace(frm=0x140009999),
            ])
        return iter([])

    monkeypatch.setattr(data_module.idautils, "XrefsTo", fake_xrefs)
    monkeypatch.setattr(data_module._compat, "get_func_start", lambda frm: None if frm == 0x140009999 else 0x140001000)

    monkeypatch.setattr(data_module, "_inf_filetype_id", lambda: (_ for _ in ()).throw(RuntimeError("filetype err")))
    monkeypatch.setattr(data_module, "is_riscv_family", lambda: (_ for _ in ()).throw(RuntimeError("riscv err")))

    res = _ok(data_module.data(action="string_xrefs", min_len=2))
    assert res["total_strings_scanned"] >= 1


def test_data_strings_and_matrix_rare_branches(monkeypatch, fresh_fake_idb):
    # 1. Test line 449 (q75 > q50) and line 460 (_accept with empty content)
    class StrSample:
        def __init__(self, ea, s):
            self.ea = ea
            self.s = s
        def __str__(self):
            return self.s

    # Need q75 > q50: 3 low ratio, 2 high ratio items
    # [0.1, 0.1, 0.1, 1.0, 1.0] -> q50 = 0.1, q75 = 1.0 -> q75 > q50!
    samples = [
        StrSample(0x1000, "\x00\x01\x02\x03\x04\x05\x06\x07\x08x"),  # ratio 0.1
        StrSample(0x1002, "\x00\x01\x02\x03\x04\x05\x06\x07\x08y"),  # ratio 0.1
        StrSample(0x1004, "\x00\x01\x02\x03\x04\x05\x06\x07\x08z"),  # ratio 0.1
        StrSample(0x1006, "hello"),                                    # ratio 1.0
        StrSample(0x1008, "world"),                                    # ratio 1.0
        StrSample(0x1010, ""),                                         # empty content -> line 460
    ]
    monkeypatch.setattr(data_module.idautils, "Strings", lambda: iter(samples), raising=False)
    # Also test line 512: hit in needle walk whose start is already in seen
    monkeypatch.setattr(data_module, "_iter_byte_hits", lambda _needle: iter([0x1007]))
    monkeypatch.setattr(data_module, "_cstring_containing", lambda _ea: (0x1006, "hello"))

    res = _ok(data_module.data(action="strings", query="hello", min_len=1, count=0))
    assert res["total"] >= 1

    # 2. Test line 764: gate = 0.0 when vals is empty in capability_matrix (API_CATEGORIES empty)
    monkeypatch.setattr(data_module, "API_CATEGORIES", {})
    cap_err = data_module.data(action="capability_matrix")
    assert cap_err.get("error") is True

    # 3. Test line 822: _module_key returns "misc" when text has len >= 4 but strip() is empty
    whitespace_sample = [StrSample(0x2000, "    ")]
    monkeypatch.setattr(data_module.idautils, "Strings", lambda: iter(whitespace_sample), raising=False)
    monkeypatch.setattr(data_module.idautils, "XrefsTo", lambda _ea: iter([SimpleNamespace(frm=0x140001000)]))
    xref_res = _ok(data_module.data(action="string_xrefs", min_len=4))
    assert "misc" in xref_res["module_map"]
