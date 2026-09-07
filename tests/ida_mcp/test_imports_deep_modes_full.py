"""Offline coverage for PE, ELF, ordinal, and API-set import paths."""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_module  # noqa: E402


@pytest.fixture(autouse=True)
def _restore_compat_module():
    """Prevent fake segment lookups from leaking through shared compat."""
    compat = sys.modules.get("ida_pro_mcp.ida_mcp.compat")
    before = dict(compat.__dict__) if compat is not None else None
    yield
    if compat is not None and before is not None:
        compat.__dict__.clear()
        compat.__dict__.update(before)


def _module():
    mod = load_tool_module("imports_deep")
    mod.idaapi.BADADDR = -1
    mod.validate_addr = lambda value: (int(str(value), 0), None)
    mod.ida_nalt.get_import_module_qty = lambda: 0
    mod.idautils.Segments = list
    mod._IMPORT_MAP_CACHE.clear()
    return mod


def _imports(mod, modules):
    mod.ida_nalt.get_import_module_qty = lambda: len(modules)
    mod.ida_nalt.get_root_filename = lambda: "fixture"
    mod.ida_nalt.get_import_module_name = lambda index: modules[index][0]

    def enum(index, callback):
        for record in modules[index][1]:
            if callback(*record) is False:
                break

    mod.ida_nalt.enum_import_names = enum


def test_import_map_and_iter_records_are_cached_and_ordinal_safe():
    mod = _module()
    modules = [
        ("kernel32.dll", [(0x1000, "CreateFileA", 0), (0x1008, None, 7)]),
        ("", [(0x2000, "ignored", 0)]),
    ]
    _imports(mod, modules)
    mapping = mod._import_ea_map()
    assert mapping == {
        0x1000: ("kernel32.dll", "CreateFileA"),
        0x1008: ("kernel32.dll", "ordinal_7"),
    }
    assert mod._import_ea_map() is mapping
    assert list(mod._iter_import_records()) == [
        (0x1000, "kernel32.dll", "CreateFileA"),
        (0x1008, "kernel32.dll", "ordinal_7"),
    ]
    mod.ida_nalt.get_root_filename = lambda: "changed"
    assert mod._import_ea_map() is not mapping


def test_thunks_covers_pe_filter_and_no_import_note():
    mod = _module()
    seg = types.SimpleNamespace(start_ea=0x2000, end_ea=0x2010)
    mod.idautils.Segments = lambda: [0x2000]
    mod._compat.get_segment = lambda _ea: seg
    mod.idc.get_segm_name = lambda _ea: ".idata"
    targets = {0x2000: 0x5000, 0x2008: 0}
    names = {0x2000: "CreateFileA", 0x2008: "unused"}
    mod.idc.get_qword = targets.get
    mod.idc.get_name = names.get
    mod._inf_bitness = lambda: 64
    mod.ida_nalt.get_import_module_qty = lambda: 1

    result = mod.imports_deep("thunks", query="Create", count=10)
    assert result["thunks"] == "0x2000  -> 0x5000  CreateFileA"
    assert result["total"] == 1

    mod.ida_nalt.get_import_module_qty = lambda: 0
    empty = mod.imports_deep("thunks")
    assert empty["note"] == "no import table — raw/embedded binary"


def test_elf_plt_thunks_resolve_got_names_and_query(monkeypatch):
    mod = _module()
    plt = types.SimpleNamespace(start_ea=0x1100, end_ea=0x1108)
    got = types.SimpleNamespace(start_ea=0x3000, end_ea=0x3008)
    segments = {0x1100: plt, 0x3000: got}
    mod.idautils.Segments = lambda: [0x1100, 0x3000]
    mod._compat.get_segment = segments.get
    mod.idc.get_segm_name = lambda ea: ".plt" if ea == 0x1100 else ".got.plt"
    mod._inf_bitness = lambda: 64
    mod.idc.get_qword = lambda ea: {0x3000: 0x5000}.get(ea, 0)
    mod.idc.get_name = lambda ea: {0x3000: "off_3000", 0x5000: "puts"}.get(ea, "")
    _imports(mod, [("libc.so", [(0x1100, "puts", 0), (0x1108, "other", 0)])])
    assert mod._elf_plt_thunks() == [
        {
            "thunk_addr": "0x1100",
            "got_slot": "0x3000",
            "target": "0x5000",
            "name": "puts",
            "dll": "libc.so",
        }
    ]
    assert mod._elf_plt_thunks(lambda value: "other" in value) == []

    mod._compat.get_segment = lambda _ea: None
    assert mod._elf_plt_thunks() == []


def test_delay_imports_group_and_paginate_with_badaddr_guard():
    mod = _module()
    seg = types.SimpleNamespace(start_ea=0x4000, end_ea=0x4008)
    mod.idautils.Segments = lambda: [0x4000]
    mod._compat.get_segment = lambda _ea: seg
    mod.idc.get_segm_name = lambda _ea: ".didat"
    names = {0x4000: "kernel32_LoadLibraryA", 0x4004: "user32_MessageBoxA"}
    mod.idc.get_name = names.get
    mod.idc.next_head = lambda ea, _end: ea + 4 if ea == 0x4000 else -1
    mod.ida_nalt.get_import_module_qty = lambda: 1
    result = mod.imports_deep("delay", query="kernel32", count=10)
    assert result["delay_imports"] == "[kernel32]\n  0x4000  kernel32_LoadLibraryA"
    assert result["total"] == 2


def test_forwarded_and_ordinal_imports_filter_and_stop_at_limits():
    mod = _module()
    _imports(
        mod,
        [("kernel32", [(0x1000, "NTDLL.RtlExit", 0), (0x1004, "plain", 0), (0x1008, None, 12)])],
    )
    forwarded = mod.imports_deep("forwarded", query="Rtl")
    assert "NTDLL.RtlExit" in forwarded["forwarded"]
    assert "plain" not in forwarded["forwarded"]
    ordinal = mod.imports_deep("ordinal", query="kernel32")
    assert "ord=12" in ordinal["ordinal_imports"]
    assert "Ordinal_12" in ordinal["ordinal_imports"]
    assert mod.imports_deep("ordinal", query="user32")["ordinal_imports"] == ""


def test_api_sets_resolve_and_unknown_actions():
    mod = _module()
    _imports(
        mod,
        [
            ("api-ms-win-core-file-l1-1-0.dll", []),
            ("api-ms-win-crt-runtime-l1-1-0.dll", []),
            ("kernel32.dll", []),
        ],
    )
    result = mod.imports_deep("api_sets")
    assert "kernelbase.dll" in result["api_sets"]
    assert "ucrtbase.dll" in result["api_sets"]
    assert mod.imports_deep("api_sets", query="crt")["count"] == 1

    modules = [("kernel32", [(0x1000, "CreateFileA", 0)])]
    _imports(mod, modules)
    mod.idc.get_name = lambda ea: "off_unknown" if ea == 0x2000 else ""
    assert "CreateFileA" in mod.imports_deep("resolve")["resolved"]
    known = mod.imports_deep("resolve", addr="0x1000")
    assert known["type"] == "import" and known["dll"] == "kernel32"
    unknown = mod.imports_deep("resolve", addr="0x2000")
    assert unknown["type"] == "unknown" and unknown["name"] == "off_unknown"
    mod.validate_addr = lambda _value: (None, {"error": True, "code": "ADDRESS_INVALID"})
    assert mod.imports_deep("resolve", addr="bad")["code"] == "ADDRESS_INVALID"
    assert mod.imports_deep("not-real")["code"] == "INVALID_ARGS"


def test_imports_deep_handles_sdk_failures_with_error_envelope(monkeypatch):
    mod = _module()
    monkeypatch.setattr(mod.ida_nalt, "get_import_module_qty", lambda: (_ for _ in ()).throw(RuntimeError("imports unavailable")))
    result = mod.imports_deep("resolve")
    assert result["ok"] is False and "imports unavailable" in result["error"]


def test_imports_deep_cache_limits_and_thunk_query_edges():
    mod = _module()

    # line 67: _IMPORT_MAP_CACHE pop when reaching max
    mod._IMPORT_MAP_CACHE_MAX = 1
    _imports(mod, [("kernel32.dll", [(0x1000, "CreateFileA", 0)])])
    mod._import_ea_map()
    mod.ida_nalt.get_root_filename = lambda: "second"
    mod._import_ea_map()

    # line 205: seg is None in thunks idata segment scan
    mod.idautils.Segments = lambda: [0x2000]
    mod.idc.get_segm_name = lambda _ea: ".idata"
    mod._compat.get_segment = lambda _ea: None
    res = mod.imports_deep("thunks")
    assert res["ok"] is True

    # lines 214-215: query_matcher filters out thunk name and advances stride
    seg = types.SimpleNamespace(start_ea=0x2000, end_ea=0x2010)
    mod.idautils.Segments = lambda: [0x2000]
    mod._compat.get_segment = lambda _ea: seg
    mod.idc.get_segm_name = lambda _ea: ".idata"
    mod.idc.get_qword = lambda _ea: 0x5000
    mod.idc.get_name = lambda ea: "SkipMe" if ea == 0x2000 else "KeepMe"
    mod._inf_bitness = lambda: 64
    res_query = mod.imports_deep("thunks", query="Keep")
    assert res_query["count"] == 1

    # line 257: delay item limit reached
    seg_del = types.SimpleNamespace(start_ea=0x4000, end_ea=0x4020)
    mod.idautils.Segments = lambda: [0x4000]
    mod._compat.get_segment = lambda _ea: seg_del
    mod.idc.get_segm_name = lambda _ea: ".didat"
    mod.idc.get_name = lambda ea: f"dll_{ea:x}"
    mod.idc.next_head = lambda ea, _end: ea + 4 if ea < 0x4010 else -1
    res_del = mod.imports_deep("delay", count=1)
    assert res_del["count"] == 1

    # line 279 & 284: forwarded limit reached early stop and query mismatch filter
    _imports(
        mod,
        [("kernel32", [(0x1000, "NTDLL.Skip", 0), (0x1004, "NTDLL.Rtl1", 0), (0x1008, "NTDLL.Rtl2", 0)])],
    )
    res_fwd_filter = mod.imports_deep("forwarded", query="Rtl")
    assert "NTDLL.Rtl1" in res_fwd_filter["forwarded"]
    res_fwd = mod.imports_deep("forwarded", count=1)
    assert res_fwd["count"] == 1

    # line 307: ordinal limit reached early callback stop
    _imports(mod, [("kernel32", [(0x1000, None, 1), (0x1004, None, 2)])])
    res_ord = mod.imports_deep("ordinal", count=1)
    assert res_ord["count"] == 1
