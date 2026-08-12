"""Regression tests for the s03-q05-imports-data fixes.

Covers:
- imports_deep thunks: ELF PLT/.got/.got.plt thunk resolution maps PLT stub
  addresses to their symbols. Only imports whose address lands inside a .plt
  segment are treated as thunks; the resolved target comes from the .got.plt
  slot value keyed by the symbol IDA attached to the slot.
- imports_deep: every action returns the crisp "no import table — raw/embedded
  binary" note when get_import_module_qty()==0 instead of a bare empty list.
- imports_deep resolve: answered from a memoized ea -> (module, name) map, so
  with-addr lookups are O(1) and the underlying import table is only
  re-enumerated when the root filename or import-module count changes.
- data string_xrefs: zero-ref strings are kept with ref_count:0 and scored as
  interesting (unreferenced version/config blobs); on RISC-V the note names
  the GP-unset data-xref incompleteness.
- data functions/strings/globals: the full filtered walk is cached per
  (action, filters, idb fingerprint) and pagination slices offset/count
  without re-walking on every page.

Host-side tests: ida_* modules are stubbed via tests._isolated_repo_loader;
no live IDA session is required.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_module  # noqa: E402

# ---------------------------------------------------------------------------
# imports_deep — ELF PLT / .got.plt thunk resolution
# ---------------------------------------------------------------------------


class _Seg:
    def __init__(self, start_ea, end_ea, name=""):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.name = name


def _install_elf(monkeypatch, *, imports, got_slots, segs, bitness=64, root="elf_test.bin"):
    """Wire an ELF-like fake: .plt/.got.plt segments, import modules, GOT slots.

    imports: list of (ea, module, name) records.
    got_slots: dict slot_ea -> (value, slot_name).
    segs: list of (seg_ea, name, start, end).
    """
    mod = load_tool_module("imports_deep")
    mod.idaapi.BADADDR = -1
    mod._inf_bitness = lambda: bitness

    nalt = sys.modules["ida_nalt"]
    modules = {}
    for ea, module, name in imports:
        modules.setdefault(module, []).append((ea, name))
    mod_names = list(modules.keys())

    monkeypatch.setattr(nalt, "get_root_filename", lambda: root, raising=False)
    monkeypatch.setattr(nalt, "get_import_module_qty", lambda: len(mod_names), raising=False)
    monkeypatch.setattr(nalt, "get_import_module_name", lambda i: mod_names[i], raising=False)

    def _enum(mod_idx, cb):
        for ea, name in modules[mod_names[mod_idx]]:
            cb(ea, name, 0)
        return True

    monkeypatch.setattr(nalt, "enum_import_names", _enum, raising=False)

    seg_by_ea = {ea: _Seg(start, end, name) for ea, name, start, end in segs}
    monkeypatch.setattr(sys.modules["idautils"], "Segments", lambda: list(seg_by_ea.keys()), raising=False)
    monkeypatch.setattr(sys.modules["idc"], "get_segm_name", lambda ea: seg_by_ea[ea].name, raising=False)
    monkeypatch.setattr(sys.modules["ida_segment"], "getseg", lambda ea: seg_by_ea[ea], raising=False)

    if bitness == 64:
        monkeypatch.setattr(sys.modules["idc"], "get_qword", lambda ea: got_slots.get(ea, (0, ""))[0], raising=False)
    else:
        monkeypatch.setattr(sys.modules["idc"], "get_wide_dword", lambda ea: got_slots.get(ea, (0, ""))[0], raising=False)
    monkeypatch.setattr(sys.modules["idc"], "get_name", lambda ea: got_slots.get(ea, (0, ""))[1], raising=False)
    return mod


def test_thunks_resolves_elf_plt_stubs_to_symbols(monkeypatch):
    mod = _install_elf(
        monkeypatch,
        imports=[
            (0x4010, "libc.so.6", "printf"),
            (0x4020, "libc.so.6", "malloc"),
            (0x4030, "libc.so.6", "putchar"),
            (0x4040, "libc.so.6", "write"),   # in .plt but no named GOT slot
            (0x2000, "libc.so.6", "strlen"),  # in .text — NOT a PLT thunk
        ],
        got_slots={
            0x6000: (0x7F1234, "printf"),
            0x6008: (0x7F5678, "malloc"),
            0x6010: (0x7F9ABC, "putchar"),
            0x6018: (0xDEADBEEF, ""),  # unnamed slot -> cannot resolve write
        },
        segs=[
            (0x1000, ".text", 0x1000, 0x2000),
            (0x4000, ".plt", 0x4000, 0x4060),
            (0x6000, ".got.plt", 0x6000, 0x6020),
        ],
    )

    res = mod.imports_deep(action="thunks", offset=0, count=100)
    assert res["ok"] is True
    # PLT stubs with a named GOT slot resolve to the slot's target value.
    assert "0x4010  -> 0x7f1234  printf  [libc.so.6]" in res["thunks"]
    assert "0x4020  -> 0x7f5678  malloc  [libc.so.6]" in res["thunks"]
    assert "0x4030  -> 0x7f9abc  putchar  [libc.so.6]" in res["thunks"]
    # In-PLT import without a resolvable GOT slot still reports the stub.
    assert "0x4040  -> -  write  [libc.so.6]" in res["thunks"]
    # strlen lives in .text, not .plt — it must NOT be reported as a thunk.
    assert "strlen" not in res["thunks"]
    assert res["total"] == 4
    # Imports exist, so no no-import-table note is attached.
    assert "note" not in res


def test_thunks_honors_query_filter(monkeypatch):
    mod = _install_elf(
        monkeypatch,
        imports=[
            (0x4010, "libc.so.6", "printf"),
            (0x4020, "libc.so.6", "malloc"),
        ],
        got_slots={
            0x6000: (0x7F1234, "printf"),
            0x6008: (0x7F5678, "malloc"),
        },
        segs=[
            (0x4000, ".plt", 0x4000, 0x4030),
            (0x6000, ".got.plt", 0x6000, 0x6010),
        ],
    )

    res = mod.imports_deep(action="thunks", query="print", offset=0, count=100)
    assert res["ok"] is True
    assert "printf" in res["thunks"]
    assert "malloc" not in res["thunks"]
    assert res["total"] == 1


def test_thunks_32bit_stride_uses_wide_dword(monkeypatch):
    mod = _install_elf(
        monkeypatch,
        bitness=32,
        imports=[(0x4010, "libm.so.6", "sin")],
        got_slots={0x6000: (0x7F1234, "sin")},
        segs=[
            (0x4000, ".plt", 0x4000, 0x4020),
            (0x6000, ".got.plt", 0x6000, 0x6004),
        ],
    )
    res = mod.imports_deep(action="thunks", offset=0, count=100)
    assert res["ok"] is True
    assert "0x4010  -> 0x7f1234  sin  [libm.so.6]" in res["thunks"]


# ---------------------------------------------------------------------------
# imports_deep — crisp note when get_import_module_qty()==0 (raw/embedded)
# ---------------------------------------------------------------------------


def test_no_import_table_note_on_every_action(monkeypatch):
    mod = load_tool_module("imports_deep")
    mod.idaapi.BADADDR = -1
    # _inf_bitness ships in _common.__all__ in IDA; the isolated stub has no
    # __all__ so the thunks action needs it bound explicitly here.
    mod._inf_bitness = lambda: 64
    nalt = mod.ida_nalt
    monkeypatch.setattr(nalt, "get_import_module_qty", lambda: 0, raising=False)
    monkeypatch.setattr(nalt, "get_import_module_name", lambda i: "", raising=False)
    # A bare raw blob: only a .text segment, nothing that looks like IAT/PLT.
    monkeypatch.setattr(mod.idautils, "Segments", lambda: [0x1000], raising=False)
    monkeypatch.setattr(mod.idc, "get_segm_name", lambda ea: ".text", raising=False)
    monkeypatch.setattr(mod.ida_segment, "getseg", lambda ea: _Seg(0x1000, 0x2000, ".text"), raising=False)
    monkeypatch.setattr(mod.idc, "next_head", lambda ea, end: ea + 1, raising=False)
    # resolve-with-addr falls back to idc.get_name when the import map is empty.
    monkeypatch.setattr(mod.idc, "get_name", lambda ea: "", raising=False)

    for kwargs in (
        {"action": "thunks"},
        {"action": "delay"},
        {"action": "forwarded"},
        {"action": "ordinal"},
        {"action": "api_sets"},
        {"action": "resolve"},                       # batch form
        {"action": "resolve", "addr": "0x1000"},     # single-addr form
    ):
        res = mod.imports_deep(**kwargs, offset=0, count=100)
        assert res["ok"] is True, kwargs
        # Pre-fix these returned a bare empty list with no explanation.
        assert res.get("note") == "no import table — raw/embedded binary", kwargs
        if kwargs["action"] == "resolve" and "addr" not in kwargs:
            assert res["resolved"] == ""
            assert res["total"] == 0
        elif kwargs["action"] == "resolve":
            assert res["type"] == "unknown"


# ---------------------------------------------------------------------------
# imports_deep resolve — memoized ea -> (module, name) map
# ---------------------------------------------------------------------------


def _install_imports(monkeypatch, root="kernel32_test.dll", qty=1):
    mod = load_tool_module("imports_deep")
    mod.idaapi.BADADDR = -1
    nalt = sys.modules["ida_nalt"]
    calls = {"enum": 0}

    monkeypatch.setattr(nalt, "get_root_filename", lambda: root, raising=False)
    monkeypatch.setattr(nalt, "get_import_module_qty", lambda: qty, raising=False)
    monkeypatch.setattr(nalt, "get_import_module_name", lambda i: "kernel32.dll", raising=False)

    def _enum(_mod_idx, cb):
        calls["enum"] += 1
        cb(0x1000, "CreateFileW", 0)
        cb(0x1008, "ReadFile", 0)
        return True

    monkeypatch.setattr(nalt, "enum_import_names", _enum, raising=False)
    monkeypatch.setattr(sys.modules["idc"], "get_name", lambda ea: "", raising=False)
    return mod, calls


def test_resolve_with_addr_uses_memoized_map(monkeypatch):
    mod, calls = _install_imports(monkeypatch)

    res = mod.imports_deep(action="resolve", addr="0x1000", offset=0, count=100)
    assert res["ok"] is True
    assert res["addr"] == "0x1000"
    assert res["name"] == "CreateFileW"
    assert res["dll"] == "kernel32.dll"
    assert res["type"] == "import"

    # Non-import address falls back to the IDA name and reports unknown.
    res2 = mod.imports_deep(action="resolve", addr="0x9999", offset=0, count=100)
    assert res2["ok"] is True
    assert res2["dll"] is None
    assert res2["type"] == "unknown"

    # The map is memoized: two resolve calls must not re-enumerate imports.
    assert calls["enum"] == 1


def test_resolve_batch_lists_all_imports_and_respects_query(monkeypatch):
    mod, calls = _install_imports(monkeypatch)

    res = mod.imports_deep(action="resolve", offset=0, count=100)
    assert res["ok"] is True
    assert "0x1000  kernel32.dll  CreateFileW" in res["resolved"]
    assert "0x1008  kernel32.dll  ReadFile" in res["resolved"]
    assert res["total"] == 2

    filtered = mod.imports_deep(action="resolve", query="ReadFile", offset=0, count=100)
    assert "ReadFile" in filtered["resolved"]
    assert "CreateFileW" not in filtered["resolved"]
    assert filtered["total"] == 1

    # Memoization survives the additional calls.
    assert calls["enum"] == 1


def test_resolve_map_rebuilds_on_module_count_change(monkeypatch):
    # A session that re-analyzes (or IDA finishing import processing) changes
    # get_import_module_qty; the memoized map must rebuild, not serve stale.
    mod, calls = _install_imports(monkeypatch, qty=1)

    first = mod.imports_deep(action="resolve", addr="0x1000", offset=0, count=100)
    assert first["dll"] == "kernel32.dll"

    nalt = sys.modules["ida_nalt"]
    monkeypatch.setattr(nalt, "get_import_module_qty", lambda: 0, raising=False)

    second = mod.imports_deep(action="resolve", addr="0x1000", offset=0, count=100)
    # Qty dropped to 0 -> map rebuilt empty -> entry gone, note attached.
    assert second["dll"] is None
    assert second["note"] == "no import table — raw/embedded binary"


# ---------------------------------------------------------------------------
# data string_xrefs — zero-ref strings kept, scored, and (on RISC-V) noted
# ---------------------------------------------------------------------------


def _install_string_xrefs(monkeypatch, *, filetype, riscv):
    class StrItem:
        def __init__(self, ea, text):
            self.ea = ea
            self.text = text

        def __str__(self):
            return self.text

    items = [
        StrItem(0x1000, "WIFI_SSID_PREFIX"),   # 0 refs -> unreferenced blob
        StrItem(0x1001, "APP_VERSION_2_3_1"),  # 0 refs -> version blob
        StrItem(0x2000, "hello world"),        # 2 refs
        StrItem(0x2001, "fatal_error_hook"),   # 1 ref
    ]

    # Xref target functions keyed by frm address. ref_count counts distinct
    # referencing FUNCTIONS, so two xrefs from distinct functions count twice.
    funcs = {0x1111: 0x2000, 0x2222: 0x2100, 0x3333: 0x2001}
    refs = {0x2000: [0x1111, 0x2222], 0x2001: [0x3333]}

    def _get_func(frm):
        if frm in funcs:
            return types.SimpleNamespace(start_ea=funcs[frm])
        return None

    def _func_name(ea):
        return {0x2000: "parse_config", 0x2100: "render_config", 0x2001: "fail_hard"}.get(ea, "")

    mod = load_tool_module("data")
    # _inf_filetype_id ships in _common.__all__ in IDA; the isolated stub has
    # no __all__ so it never reaches the tool via `import *` — bind it (and
    # the RISC-V probe) on the loaded module explicitly.
    mod._inf_filetype_id = lambda: filetype
    mod.is_riscv_family = lambda: riscv

    monkeypatch.setattr(mod.idautils, "Strings", lambda: iter(list(items)), raising=False)
    monkeypatch.setattr(mod.idautils, "XrefsTo", lambda ea: iter([types.SimpleNamespace(frm=f) for f in refs.get(ea, [])]), raising=False)
    monkeypatch.setattr(mod.idaapi, "get_func", _get_func, raising=False)
    # compat.get_func_start resolves ida_funcs via sys.modules; expose both the
    # legacy get_func and the 9.4 EA surface off the same _get_func mock.
    monkeypatch.setattr(mod.ida_funcs, "get_func", _get_func, raising=False)
    monkeypatch.setattr(mod.ida_funcs, "get_func_start", lambda frm: (_get_func(frm).start_ea if _get_func(frm) else -1), raising=False)
    monkeypatch.setattr(mod.ida_funcs, "ida_idaapi", types.SimpleNamespace(BADADDR=-1), raising=False)
    monkeypatch.setattr(mod.ida_funcs, "func_entry_info_t", types.SimpleNamespace, raising=False)

    def _func_entry_info(out, frm, flags=0):
        f = _get_func(frm)
        if f is None:
            return False
        out.start_ea = f.start_ea
        out.end_ea = f.start_ea
        return True

    monkeypatch.setattr(mod.ida_funcs, "get_func_entry_info", _func_entry_info, raising=False)
    monkeypatch.setattr(mod.ida_funcs, "get_func_flags", lambda ea: None, raising=False)
    monkeypatch.setattr(mod.ida_funcs, "set_func_flags", lambda ea, flags: True, raising=False)
    monkeypatch.setattr(mod.ida_funcs, "get_func_name", _func_name, raising=False)
    return mod


def test_string_xrefs_keeps_zero_ref_strings_scored(monkeypatch):
    mod = _install_string_xrefs(monkeypatch, filetype=7, riscv=False)

    res = mod.data(action="string_xrefs", min_len=4)
    assert res["ok"] is True
    # Referenced strings land in top_strings with their ref counts.
    top_names = [t["string"] for t in res["top_strings"]]
    assert "hello world" in top_names
    hello = next(t for t in res["top_strings"] if t["string"] == "hello world")
    assert hello["ref_count"] == 2
    # Zero-ref strings survive into strings_without_refs (they were dropped
    # before) and carry ref_count:0 plus a non-trivial interesting score.
    unref = {u["string"]: u for u in res.get("strings_without_refs", [])}
    assert "WIFI_SSID_PREFIX" in unref
    assert "APP_VERSION_2_3_1" in unref
    for u in unref.values():
        assert u["ref_count"] == 0
        assert u["interesting_score"] >= 2.0  # 0 refs + version/wifi signal + short bonus
    # ELF, no RISC-V: generic data-xref note.
    assert "data xref resolution may be incomplete" in res["note"]


def test_string_xrefs_riscv_gp_unset_note(monkeypatch):
    mod = _install_string_xrefs(monkeypatch, filetype=11, riscv=True)

    res = mod.data(action="string_xrefs", min_len=4)
    assert res["ok"] is True
    assert res.get("strings_without_refs")
    # On RISC-V the note must name the GP-unset cause of incomplete data xrefs.
    assert "RISC-V GP register is unset" in res["note"]


# ---------------------------------------------------------------------------
# data functions/strings/globals — cached full walk, sliced per page
# ---------------------------------------------------------------------------


def test_functions_pagination_does_not_rewalk(monkeypatch):
    func_ea = [0x1000, 0x2000, 0x3000, 0x4000]
    names = {0x1000: "main", 0x2000: "sub_1", 0x3000: "sub_2", 0x4000: "sub_3"}
    walk_calls = {"n": 0}

    def _functions():
        walk_calls["n"] += 1
        return iter(list(func_ea))

    mod = load_tool_module("data")
    monkeypatch.setattr(mod.idautils, "Functions", _functions, raising=False)
    monkeypatch.setattr(mod.idautils, "XrefsTo", lambda ea: iter([]), raising=False)
    monkeypatch.setattr(mod.idautils, "XrefsFrom", lambda ea, f=0: iter([]), raising=False)

    def _get_func(ea):
        return types.SimpleNamespace(start_ea=ea, end_ea=ea + 0x100)

    monkeypatch.setattr(mod.idaapi, "get_func", _get_func, raising=False)
    # compat.get_func_info resolves ida_funcs via sys.modules; expose both the
    # legacy get_func and the 9.4 EA surface off the same _get_func mock.
    monkeypatch.setattr(mod.ida_funcs, "get_func", _get_func, raising=False)
    monkeypatch.setattr(mod.ida_funcs, "get_func_start", lambda ea: _get_func(ea).start_ea, raising=False)
    monkeypatch.setattr(mod.ida_funcs, "ida_idaapi", types.SimpleNamespace(BADADDR=-1), raising=False)
    monkeypatch.setattr(mod.ida_funcs, "func_entry_info_t", types.SimpleNamespace, raising=False)

    def _func_entry_info(out, ea, flags=0):
        out.start_ea = ea
        out.end_ea = ea + 0x100
        return True

    monkeypatch.setattr(mod.ida_funcs, "get_func_entry_info", _func_entry_info, raising=False)
    monkeypatch.setattr(mod.ida_funcs, "get_func_flags", lambda ea: 0, raising=False)
    monkeypatch.setattr(mod.ida_funcs, "set_func_flags", lambda ea, flags: True, raising=False)
    monkeypatch.setattr(mod.idaapi, "get_func_qty", lambda: len(func_ea), raising=False)
    monkeypatch.setattr(mod.ida_funcs, "get_func_name", lambda ea: names.get(ea, ""), raising=False)
    monkeypatch.setattr(mod.ida_nalt, "get_root_filename", lambda: "walk_test.bin", raising=False)

    page1 = mod.data(action="functions", offset=0, count=2)
    assert page1["ok"] is True
    assert page1["total"] == 4
    assert "main" in page1["functions"] and "sub_1" in page1["functions"]
    assert walk_calls["n"] == 1

    page2 = mod.data(action="functions", offset=2, count=2)
    assert page2["total"] == 4
    assert "sub_2" in page2["functions"] and "sub_3" in page2["functions"]
    assert "main" not in page2["functions"]
    # Second page sliced from the cached walk — Functions() not re-invoked.
    assert walk_calls["n"] == 1


def test_globals_pagination_does_not_rewalk(monkeypatch):
    names_list = [(0x5000, "g_a"), (0x5001, "g_b"), (0x5002, "g_c"), (0x5003, "g_d")]
    walk_calls = {"n": 0}

    def _names():
        walk_calls["n"] += 1
        return iter(list(names_list))

    mod = load_tool_module("data")
    monkeypatch.setattr(mod.idautils, "Names", _names, raising=False)
    monkeypatch.setattr(mod.idautils, "XrefsTo", lambda ea: iter([]), raising=False)
    monkeypatch.setattr(mod.idaapi, "get_func", lambda ea: None, raising=False)  # not a function -> global
    # compat.get_func_start resolves ida_funcs via sys.modules; mirror the
    # idaapi.get_func miss so globals classifies these names as non-functions.
    monkeypatch.setattr(mod.ida_funcs, "get_func", lambda ea: None, raising=False)
    monkeypatch.setattr(mod.ida_funcs, "get_func_start", lambda ea: -1, raising=False)
    monkeypatch.setattr(mod.ida_funcs, "ida_idaapi", types.SimpleNamespace(BADADDR=-1), raising=False)
    monkeypatch.setattr(mod.ida_funcs, "get_func_flags", lambda ea: None, raising=False)
    monkeypatch.setattr(mod.ida_funcs, "set_func_flags", lambda ea, flags: True, raising=False)
    monkeypatch.setattr(mod.idaapi, "get_func_qty", lambda: 0, raising=False)
    monkeypatch.setattr(mod.idc, "get_item_size", lambda ea: 8, raising=False)
    monkeypatch.setattr(mod.ida_nalt, "get_tinfo", lambda tif, ea: False, raising=False)
    monkeypatch.setattr(mod.ida_nalt, "get_root_filename", lambda: "walk_test.bin", raising=False)
    # tinfo_t is constructed outside the type-guard try/except in globals.
    monkeypatch.setattr(mod.ida_typeinf, "tinfo_t", types.SimpleNamespace, raising=False)

    page1 = mod.data(action="globals", offset=0, count=2)
    assert page1["ok"] is True
    assert page1["total"] == 4
    assert "g_a" in page1["globals"] and "g_b" in page1["globals"]
    assert walk_calls["n"] == 1

    page2 = mod.data(action="globals", offset=2, count=2)
    assert page2["total"] == 4
    assert "g_c" in page2["globals"] and "g_d" in page2["globals"]
    assert "g_a" not in page2["globals"]
    assert walk_calls["n"] == 1


def test_strings_pagination_does_not_rewalk(monkeypatch):
    class StrItem:
        def __init__(self, ea, text):
            self.ea = ea
            self.text = text

        def __str__(self):
            return self.text

    items = [StrItem(0x1000 + i, f"text_{i:02d}") for i in range(4)]
    walk_calls = {"n": 0}

    def _strings():
        walk_calls["n"] += 1
        return iter(list(items))

    mod = load_tool_module("data")
    mod._inf_filetype_id = lambda: 7
    monkeypatch.setattr(mod.idautils, "Strings", _strings, raising=False)
    monkeypatch.setattr(mod.idautils, "XrefsTo", lambda ea: iter([]), raising=False)
    monkeypatch.setattr(mod.idaapi, "getseg", lambda ea: None, raising=False)
    # compat.get_segment_perm resolves ida_segment via sys.modules; mirror the
    # idaapi.getseg miss on the live segment module.
    monkeypatch.setattr(mod.ida_segment, "getseg", lambda ea: None, raising=False)
    monkeypatch.setattr(mod.ida_segment, "ida_idaapi", types.SimpleNamespace(BADADDR=-1), raising=False)
    monkeypatch.setattr(mod.ida_segment, "segment_info_t", types.SimpleNamespace, raising=False)
    monkeypatch.setattr(mod.ida_segment, "get_segment_info", lambda out, ea, flags=0: False, raising=False)
    monkeypatch.setattr(mod.idaapi, "get_func_qty", lambda: 0, raising=False)
    monkeypatch.setattr(mod.ida_nalt, "get_root_filename", lambda: "walk_test.bin", raising=False)

    page1 = mod.data(action="strings", offset=0, count=2)
    assert page1["ok"] is True
    assert page1["total"] == 4
    assert "text_00" in page1["strings"] and "text_01" in page1["strings"]

    page2 = mod.data(action="strings", offset=2, count=2)
    assert page2["total"] == 4
    assert "text_02" in page2["strings"] and "text_03" in page2["strings"]
    assert "text_00" not in page2["strings"]
    # The strings action calls Strings() twice within one walk build (adaptive
    # printable-gate probe + real iteration); a page-2 slice must add nothing.
    assert walk_calls["n"] == 2
