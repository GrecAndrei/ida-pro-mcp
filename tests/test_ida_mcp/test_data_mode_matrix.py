"""Cross-mode data listing and lookup tests."""

from __future__ import annotations

import importlib
import types

import pytest

from ida_pro_mcp.ida_mcp.tools.data import (
    _cstring_containing,
    _iter_byte_hits,
    _literal_query_bytes,
    _walk_cache_get,
    _walk_cache_put,
    data,
)

data_module = importlib.import_module("ida_pro_mcp.ida_mcp.tools.data")


class _String:
    def __init__(self, ea, value):
        self.ea = ea
        self.value = value

    def __str__(self):
        return self.value


def _assert_ok(result):
    assert result.get("ok") is True, result
    return result


def test_data_helpers_cover_cache_literal_search_and_cstring(monkeypatch, fresh_fake_idb):
    import ida_bytes
    import idautils
    import idc

    data_module._WALK_CACHE.clear()
    key = ("test",)
    assert _walk_cache_get(key) is None
    _walk_cache_put(key, [1])
    assert _walk_cache_get(key) == [1]
    assert _literal_query_bytes("abcd") == b"abcd"
    assert _literal_query_bytes("ab") is None
    assert _literal_query_bytes("a*bcd") is None
    assert _literal_query_bytes("/regex/") is None
    assert _literal_query_bytes("écho") == "écho".encode()

    fresh_fake_idb.patch_bytes(0x140002100, b"config-value=42\x00")
    monkeypatch.setattr(idautils, "Segments", lambda: iter([0x140002000]), raising=False)
    monkeypatch.setattr(idc, "get_segm_end", lambda _ea: 0x140003000, raising=False)
    def read_bytes(ea, size):
        return fresh_fake_idb.get_bytes(ea, size)

    monkeypatch.setattr(ida_bytes, "get_bytes", read_bytes, raising=False)
    hits = list(_iter_byte_hits(b"value"))
    assert hits == [0x140002107]
    start, content = _cstring_containing(0x140002107)
    assert start == 0x140002100
    assert content == "config-value=42"


def test_data_functions_annotations_globals_and_strings_cover_filters(monkeypatch, fresh_fake_idb):
    import ida_nalt
    import idautils
    import idc

    data_module._WALK_CACHE.clear()
    fresh_fake_idb.set_cmt(0x140001000, "analysis notes", 0)
    functions = _assert_ok(data(action="functions", count=0, include_prototype=True, include_xrefs=True, structured=True))
    assert functions["total"] == 2
    assert functions["items"][0]["xrefs_to"] >= 0
    named = _assert_ok(data(action="functions", named_only=True, query="main"))
    assert "main" in named["functions"]
    assert _assert_ok(data(action="functions", min_size=0x100))["total"] == 0

    annotations = _assert_ok(data(action="annotations", query="main"))
    assert annotations["total"] == 1
    assert annotations["annotations"][0]["comment"] == "analysis notes"

    fresh_fake_idb.set_name(0x140003020, "global_config")
    fresh_fake_idb.patch_bytes(0x140003020, b"\x01" * 16)
    monkeypatch.setattr(idautils, "Names", lambda: iter([(0x140003020, "global_config"), (0x140003030, "unk_noise")]), raising=False)
    globals_result = _assert_ok(data(action="globals", include_xrefs=True, structured=True))
    assert globals_result["total"] == 2
    assert "global_config" in globals_result["globals"]

    strings = [_String(0x140002100, "config-value=42"), _String(0x140002120, "xy"), _String(0x140002130, b"bytes-value")]
    monkeypatch.setattr(idautils, "Strings", lambda: iter(strings), raising=False)
    monkeypatch.setattr(idautils, "XrefsTo", lambda ea: iter([types.SimpleNamespace(frm=0x140001000)]) if ea == 0x140002100 else iter(()), raising=False)
    string_result = _assert_ok(data(action="strings", query="config", min_len=4))
    assert string_result["total"] == 1
    assert "config-value" in string_result["strings"]
    data_module._WALK_CACHE.clear()
    short = _assert_ok(data(action="strings", min_len=20))
    assert short["total"] == 0


def test_import_export_lookup_bulk_capability_and_read_bytes(monkeypatch, fresh_fake_idb):
    import ida_nalt
    import idautils
    import idc

    monkeypatch.setattr(ida_nalt, "get_import_module_qty", lambda: 2, raising=False)
    monkeypatch.setattr(ida_nalt, "get_import_module_name", lambda i: ["KERNEL32.dll", "libc.so"][i], raising=False)

    def enum_imports(index, callback):
        items = [
            [(0x140002100, "VirtualAlloc", 1), (0x140002108, None, 2)],
            [(0x140002110, "socket", 3)],
        ]
        for item in items[index]:
            callback(*item)
        return len(items[index])

    monkeypatch.setattr(ida_nalt, "enum_import_names", enum_imports, raising=False)
    imports = _assert_ok(data(action="imports", query="virtual"))
    assert imports["total"] == 1
    assert "VirtualAlloc" in imports["imports"]

    exported = _assert_ok(data(action="exports", query="main"))
    assert exported["total"] >= 1
    assert "main" in exported["exports"]
    exact = _assert_ok(data(action="lookup", query="main"))
    assert exact["exact_match"] is True
    fallback = _assert_ok(data(action="lookup", query="sub_"))
    assert fallback["exact_match"] is False
    assert data(action="lookup").get("ok") is not True

    bulk = _assert_ok(data(action="bulk_query", items=[
        {"kind": "functions", "count": 1},
        {"kind": "strings", "query": "config"},
        {"kind": "missing"},
        None,
        {},
    ]))
    assert bulk["count"] == 5
    assert data(action="bulk_query").get("ok") is not True

    monkeypatch.setattr(idautils, "Functions", lambda: iter([0x140001000]), raising=False)
    monkeypatch.setattr(idautils, "Heads", lambda *_args: iter([0x140001008]), raising=False)
    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda *_args: iter([0x140002100]), raising=False)
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "VirtualAlloc", raising=False)
    capability = _assert_ok(data(action="capability_matrix"))
    assert capability["total_imports"] == 2
    assert "VirtualAlloc" in capability["risk_indicators"]

    read = _assert_ok(data(action="read_bytes", addr="0x140003000", size=20))
    assert read["size"] == 20
    assert "|" in read["dump"]
    assert data(action="read_bytes").get("ok") is not True


def test_string_xrefs_keeps_unreferenced_and_raw_notes(monkeypatch, fresh_fake_idb):
    import idautils

    strings = [
        _String(0x140002100, "error: failed to connect"),
        _String(0x140002120, "orphan-config-value"),
        _String(0x140002130, "tin"),
    ]
    monkeypatch.setattr(idautils, "Strings", lambda: iter(strings), raising=False)
    monkeypatch.setattr(idautils, "XrefsTo", lambda ea: iter([types.SimpleNamespace(frm=0x140001000)]) if ea == 0x140002100 else iter(()), raising=False)
    result = _assert_ok(data(action="string_xrefs", min_len=4))
    assert result["total_strings_scanned"] == 2
    assert result["top_strings"]
    assert result["strings_without_refs"]
    assert "unreferenced strings" in result["note"]
    data_module._WALK_CACHE.clear()


def test_data_string_list_fallback_and_structured_global_metadata(monkeypatch, fresh_fake_idb):
    import ida_nalt
    import idaapi
    import idautils
    import idc

    # Exercise the older IDA string-list API used when idautils.Strings is not
    # available (or fails during a partially initialized database).
    class StringInfo:
        ea = 0x140002180
        length = 14
        type = 0

    monkeypatch.setattr(idautils, "Strings", lambda: (_ for _ in ()).throw(RuntimeError("string list unavailable")), raising=False)
    monkeypatch.setattr(idaapi, "get_strlist_qty", lambda: 1, raising=False)
    monkeypatch.setattr(idaapi, "get_strlist_item", lambda info, index: index == 0, raising=False)
    monkeypatch.setattr(idaapi, "string_info_t", StringInfo, raising=False)
    monkeypatch.setattr(idc, "get_strlit_contents", lambda *_args: b"fallback string", raising=False)
    data_module._WALK_CACHE.clear()
    strings = _assert_ok(data(action="strings", query="fallback", min_len=4))
    assert strings["total"] == 1
    assert "fallback string" in strings["strings"]

    record = fresh_fake_idb.type_lib.get("target_struct")
    fresh_fake_idb.set_name(0x140003040, "typed_global")
    monkeypatch.setattr(idautils, "Names", lambda: iter([(0x140003040, "typed_global")]), raising=False)

    def get_tinfo(tif, _ea):
        tif._copy_from(record)
        return True

    monkeypatch.setattr(ida_nalt, "get_tinfo", get_tinfo, raising=False)
    globals_result = _assert_ok(data(action="globals", include_xrefs=True))
    assert "typed_global" in globals_result["globals"]
    assert "fields=[" in globals_result["globals"]
    assert "xrefs=0" in globals_result["globals"]


def test_data_lookup_fallback_and_read_error_modes(monkeypatch, fresh_fake_idb):
    import ida_bytes
    import idautils

    data_module._WALK_CACHE.clear()
    monkeypatch.setattr(data_module, "resolve_symbol", lambda _query: (_ for _ in ()).throw(RuntimeError("no exact match")))
    monkeypatch.setattr(idautils, "Names", lambda: iter([
        (0x140001000, "main_handler"),
        (0x140003050, "config_value"),
    ]), raising=False)
    fallback = _assert_ok(data(action="lookup", query="*handler*"))
    assert fallback["exact_match"] is False
    assert fallback["items"][0]["type"] == "function"
    assert _assert_ok(data(action="lookup", query="*config*"))["items"][0]["type"] == "symbol"

    assert data(action="read_bytes", addr="bad")["error"] is True
    monkeypatch.setattr(ida_bytes, "get_bytes", lambda *_args: None, raising=False)
    failed = data(action="read_bytes", addr="0x140003000", size=8)
    assert failed["error"] is True
    assert "Could not read" in failed["message"]


def test_data_listing_covers_pagination_filters_and_legacy_entry_apis(monkeypatch, fresh_fake_idb):
    import ida_entry
    import ida_nalt
    import idaapi
    import idautils
    import idc

    data_module._WALK_CACHE.clear()
    monkeypatch.setattr(idautils, "Names", lambda: iter([
        (0x140001000, "main"),
        (0x140003060, "off_noise"),
        (0x140003070, "typed_value"),
    ]), raising=False)
    monkeypatch.setattr(idc, "get_item_size", lambda _ea: 8, raising=False)
    monkeypatch.setattr(idautils, "XrefsTo", lambda _ea: iter([1, 2]), raising=False)
    named = _assert_ok(data(action="globals", named_only=True, include_xrefs=True, offset=0, count=1))
    assert named["total"] == 1
    assert "typed_value" in named["globals"]

    monkeypatch.setattr(ida_nalt, "get_import_module_qty", lambda: 2, raising=False)
    monkeypatch.setattr(ida_nalt, "get_import_module_name", lambda i: None if i == 0 else "libc.so", raising=False)

    def enum_imports(index, callback):
        rows = [[(0x140004000, None, 7)], [(0x140004008, "read", 8)]]
        for row in rows[index]:
            callback(*row)
        return len(rows[index])

    monkeypatch.setattr(ida_nalt, "enum_import_names", enum_imports, raising=False)
    imports = _assert_ok(data(action="imports", query="ord_", offset=0, count=1))
    assert imports["total"] == 1
    assert "ord_7" in imports["imports"]

    monkeypatch.setattr(idaapi, "get_entry_qty", None, raising=False)
    monkeypatch.setattr(idaapi, "get_entry_ordinal", None, raising=False)
    monkeypatch.setattr(idaapi, "get_entry", None, raising=False)
    monkeypatch.setattr(idaapi, "get_entry_name", None, raising=False)
    monkeypatch.setattr(ida_entry, "get_entry_qty", lambda: 1, raising=False)
    monkeypatch.setattr(ida_entry, "get_entry_ordinal", lambda _idx: 1, raising=False)
    monkeypatch.setattr(ida_entry, "get_entry", lambda _ord: 0x140001000, raising=False)
    monkeypatch.setattr(ida_entry, "get_entry_name", lambda _ord: "main", raising=False)
    exports = _assert_ok(data(action="exports", query="main"))
    assert exports["total"] == 1 and "main" in exports["exports"]


def test_data_strings_and_lookup_cover_fallback_errors_and_aliases(monkeypatch, fresh_fake_idb):
    import ida_bytes
    import idaapi
    import idautils
    import idc

    data_module._WALK_CACHE.clear()

    class _BadString(_String):
        @property
        def ea(self):
            raise RuntimeError("bad string address")

        @ea.setter
        def ea(self, value):
            self._ea = value

    monkeypatch.setattr(idautils, "Strings", lambda: iter([
        _String(0x140002200, "short"),
        _String(0x140002210, "\x01\x02\x03\x04\x05\x06"),
        _BadString(0x140002220, "ignored"),
    ]), raising=False)
    monkeypatch.setattr(idaapi, "get_file_type_name", lambda: "binary", raising=False)
    monkeypatch.setattr(idc, "get_segm_end", lambda _ea: 0x140002300, raising=False)
    strings = _assert_ok(data(action="strings", query="short", min_len="not-an-int"))
    assert strings["total"] == 0

    monkeypatch.setattr(data_module, "resolve_symbol", lambda _query: {"name": "not-address"})
    exact = _assert_ok(data(action="lookup", query="not-address"))
    assert exact["exact_match"] is True
    assert exact["query"] == "not-address"

    monkeypatch.setattr(data_module, "resolve_symbol", lambda _query: (_ for _ in ()).throw(RuntimeError("missing")))
    monkeypatch.setattr(idautils, "Names", lambda: iter(()), raising=False)
    missing = data(action="lookup", query="nothing")
    assert missing["error"] is True

    monkeypatch.setattr(ida_bytes, "get_bytes", lambda _ea, size: b"\x00" * size, raising=False)
    read = _assert_ok(data(action="read_bytes", address="0x140003000", size=99999))
    assert read["size"] == 4096


def test_data_capability_matrix_and_cache_eviction_modes(monkeypatch, fresh_fake_idb):
    import ida_nalt
    import idautils

    data_module._WALK_CACHE.clear()
    monkeypatch.setattr(data_module, "_WALK_CACHE_MAX", 1)
    _walk_cache_put(("a",), [1])
    _walk_cache_put(("b",), [2])
    assert _walk_cache_get(("a",)) is None
    assert _walk_cache_get(("b",)) == [2]

    monkeypatch.setattr(ida_nalt, "get_import_module_qty", lambda: 1, raising=False)
    monkeypatch.setattr(ida_nalt, "enum_import_names", lambda _i, cb: cb(1, "socket", 1), raising=False)
    monkeypatch.setattr(idautils, "Functions", lambda: iter(()), raising=False)
    capability = _assert_ok(data(action="capability_matrix"))
    assert capability["matrix"]["network"] >= 1
    assert capability["binary_type_heuristic"] in {
        "server_or_network_app", "malware_or_security_tool", "unknown"
    }


def test_data_helpers_fail_closed_across_sdk_and_encoding_modes(monkeypatch, fresh_fake_idb):
    import ida_bytes
    import ida_nalt
    import idaapi
    import idautils
    import idc

    data_module._WALK_CACHE.clear()
    key = ("same",)
    _walk_cache_put(key, [1])
    _walk_cache_put(key, [2])
    assert _walk_cache_get(key) == [2]

    monkeypatch.setattr(ida_nalt, "get_root_filename", lambda: (_ for _ in ()).throw(RuntimeError()), raising=False)
    monkeypatch.setattr(idaapi, "get_func_qty", lambda: (_ for _ in ()).throw(RuntimeError()), raising=False)
    assert data_module._walk_fingerprint() == ("", -1)

    monkeypatch.setattr(idautils, "Segments", lambda: (_ for _ in ()).throw(RuntimeError()), raising=False)
    assert list(_iter_byte_hits(b"needle")) == []

    monkeypatch.setattr(idautils, "Segments", lambda: iter(["bad", 0x140002000]), raising=False)
    monkeypatch.setattr(
        idc,
        "get_segm_end",
        lambda ea: (_ for _ in ()).throw(RuntimeError()) if ea == "bad" else 0x140002020,
        raising=False,
    )
    monkeypatch.setattr(ida_bytes, "get_bytes", lambda _ea, _size: b"xxneedle-needle", raising=False)
    assert list(_iter_byte_hits(b"needle", max_hits=1)) == [0x140002002]

    class _BadUtf8(bytes):
        def decode(self, encoding="utf-8", errors="strict"):
            if encoding == "utf-8":
                raise UnicodeError("invalid utf8")
            return super().decode(encoding, errors)

    monkeypatch.setattr(ida_bytes, "get_byte", lambda _ea: 65, raising=False)
    monkeypatch.setattr(ida_bytes, "get_bytes", lambda _ea, _size: _BadUtf8(b"abc\x00"), raising=False)
    start, value = _cstring_containing(0, max_back=4)
    assert start == 0 and value == "abc"

    class _BadQuery(str):
        def encode(self, encoding="utf-8", errors="strict"):
            if encoding == "utf-8":
                raise UnicodeError("unsupported")
            return super().encode(encoding, errors)

    assert _literal_query_bytes(_BadQuery("latin-value")) == b"latin-value"


def test_data_listing_and_lookup_defensive_modes(monkeypatch, fresh_fake_idb):
    import ida_funcs
    import ida_nalt
    import ida_typeinf
    import idautils
    import idc

    data_module._WALK_CACHE.clear()
    funcs = {
        0x140001000: ("sub_140001000", None),
        0x140001010: ("orphan", None),
        0x140001020: ("too_small", types.SimpleNamespace(start_ea=0x140001020, end_ea=0x140001024)),
        0x140001030: ("worker", types.SimpleNamespace(start_ea=0x140001030, end_ea=0x140001070)),
    }
    monkeypatch.setattr(idautils, "Functions", lambda: iter(funcs), raising=False)
    monkeypatch.setattr(ida_funcs, "get_func_name", lambda ea: funcs[ea][0], raising=False)
    monkeypatch.setattr(ida_nalt, "get_root_filename", lambda: "listing.bin", raising=False)
    monkeypatch.setattr(ida_nalt, "get_tinfo", lambda *_args: (_ for _ in ()).throw(TypeError("bad type")), raising=False)
    monkeypatch.setattr(ida_typeinf, "tinfo_t", object, raising=False)
    monkeypatch.setattr(idc, "get_func_cmt", lambda *_args: (_ for _ in ()).throw(RuntimeError("no comments")), raising=False)
    monkeypatch.setattr(idautils, "XrefsTo", lambda ea: iter([1, 2]) if ea == 0x140001030 else iter(()), raising=False)
    monkeypatch.setattr(idautils, "XrefsFrom", lambda _ea: iter([1]), raising=False)
    monkeypatch.setattr(data_module._compat, "get_func_info", lambda ea: funcs.get(ea, (None, None))[1], raising=False)
    monkeypatch.setattr(data_module._compat, "get_func_start", lambda ea: 0x140001000 if ea == 0x140001000 else None, raising=False)
    monkeypatch.setattr(data_module._compat, "get_prototype_string", lambda _ea: "int worker(void)", raising=False)
    monkeypatch.setattr(data_module, "compile_smart_pattern", lambda query, **_kw: lambda name: query in name, raising=False)

    listed = _assert_ok(
        data(
            action="functions",
            query="worker",
            min_size=0x20,
            min_xrefs=2,
            include_prototype=True,
            include_xrefs=True,
            structured=True,
        )
    )
    assert listed["total"] == 1
    assert listed["items"][0]["prototype"] == "int worker(void)"
    assert "xrefs_from=1" in listed["functions"]

    annotations = _assert_ok(data(action="annotations", query="missing"))
    assert annotations["total"] == 0

    monkeypatch.setattr(
        idautils,
        "Names",
        lambda: iter([
            (0x140003000, ""),
            (0x140001000, "function_name"),
            (0x140003010, "off_auto"),
            (0x140003020, "global_value"),
        ]),
        raising=False,
    )
    monkeypatch.setattr(idc, "get_item_size", lambda _ea: 8, raising=False)
    globals_result = _assert_ok(data(action="globals", named_only=True, include_xrefs=True, query="global"))
    assert globals_result["total"] == 1
    assert "global_value" in globals_result["globals"]

    monkeypatch.setattr(data_module, "resolve_symbol", lambda _query: {"addr": "0x140003020", "name": "global_value"})
    exact = _assert_ok(data(action="lookup", query="global_value"))
    assert exact["is_function"] is False
    assert exact["size"] == 8


def test_data_string_fallback_and_import_export_failure_modes(monkeypatch, fresh_fake_idb):
    import ida_entry
    import ida_nalt
    import idaapi
    import idautils
    import idc

    data_module._WALK_CACHE.clear()

    class _Info:
        ea = 0x140002200
        length = 12
        type = 0

    calls = {"strings": 0}

    def unavailable_strings():
        calls["strings"] += 1
        raise RuntimeError("string list unavailable")

    monkeypatch.setattr(idautils, "Strings", unavailable_strings, raising=False)
    monkeypatch.setattr(idaapi, "get_strlist_qty", lambda: 2, raising=False)
    monkeypatch.setattr(idaapi, "get_strlist_item", lambda info, index: index == 0, raising=False)
    monkeypatch.setattr(idaapi, "string_info_t", _Info, raising=False)
    monkeypatch.setattr(idc, "get_strlit_contents", lambda *args: b"fallback-text" if len(args) == 1 else (_ for _ in ()).throw(TypeError()), raising=False)
    monkeypatch.setattr(data_module._compat, "get_segment_perm", lambda _ea: idaapi.SEGPERM_EXEC, raising=False)
    fallback = _assert_ok(data(action="strings", query="fallback", min_len=4))
    assert fallback["total"] == 1
    assert calls["strings"] == 2

    monkeypatch.setattr(idaapi, "get_entry_qty", None, raising=False)
    monkeypatch.setattr(idaapi, "get_entry_ordinal", None, raising=False)
    monkeypatch.setattr(idaapi, "get_entry", None, raising=False)
    monkeypatch.setattr(idaapi, "get_entry_name", None, raising=False)
    monkeypatch.delattr(ida_entry, "get_entry_qty", raising=False)
    monkeypatch.delattr(ida_entry, "get_entry_ordinal", raising=False)
    monkeypatch.delattr(ida_entry, "get_entry", raising=False)
    monkeypatch.delattr(ida_entry, "get_entry_name", raising=False)
    monkeypatch.delattr(ida_nalt, "get_entry_qty", raising=False)
    monkeypatch.delattr(ida_nalt, "get_entry_ordinal", raising=False)
    monkeypatch.delattr(ida_nalt, "get_entry", raising=False)
    monkeypatch.delattr(ida_nalt, "get_entry_name", raising=False)
    failed = data(action="exports")
    assert failed["error"] is True and failed["code"] == "IDA_ERROR"


@pytest.mark.parametrize(
    ("names", "expected"),
    [
        (["net_a", "net_b", "crypt_a"], "malware_or_security_tool"),
        (["net_a", "net_b", "ui_a", "file_a", "str_a"], "server_or_network_app"),
        (["ui_a", "ui_b", "file_a", "str_a"], "gui_application"),
        (["file_a", "file_b", "str_a", "str_b", "ui_a"], "utility"),
        (["crypt_a", "crypt_b", "ui_a", "other_a"], "crypto_tool"),
        (["proc_a", "proc_b", "ui_a", "other_a"], "system_tool"),
    ],
)
def test_data_capability_classifier_covers_all_binary_modes(monkeypatch, names, expected, fresh_fake_idb):
    import ida_nalt
    import idautils

    categories = {
        "network": ["net"],
        "crypto": ["crypt"],
        "ui": ["ui"],
        "file_io": ["file"],
        "string_ops": ["str"],
        "process": ["proc"],
        "other": ["other"],
    }
    monkeypatch.setattr(data_module, "API_CATEGORIES", categories)
    monkeypatch.setattr(ida_nalt, "get_import_module_qty", lambda: 1, raising=False)
    monkeypatch.setattr(ida_nalt, "enum_import_names", lambda _i, cb: [cb(i, name, i) for i, name in enumerate(names)], raising=False)
    monkeypatch.setattr(idautils, "Functions", lambda: iter(()), raising=False)
    result = _assert_ok(data(action="capability_matrix"))
    assert result["binary_type_heuristic"] == expected
