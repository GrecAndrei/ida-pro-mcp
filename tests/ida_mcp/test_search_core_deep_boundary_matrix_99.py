"""Offline boundary coverage for the shared search-core compatibility layer."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_submodule  # noqa: E402


class _Seg:
    def __init__(self, start, end):
        self.start_ea = start
        self.end_ea = end


class _TimerSource:
    def __init__(self, md5):
        self.md5 = md5

    def __call__(self):
        return self.md5


def _core():
    return load_tool_submodule("search.core")


def test_cache_helpers_cover_fallbacks_caps_and_cache_hits(monkeypatch):
    core = _core()

    # A failing MD5 API falls back to the cheap database cardinalities.
    core.ida_nalt.retrieve_input_file_md5 = lambda: (_ for _ in ()).throw(RuntimeError("old IDA"))
    core.idautils.Functions = lambda: [1, 2]
    core.idautils.Segments = lambda: [1]
    core.idautils.Names = lambda: [(1, "a")]
    assert core._get_db_fingerprint() == "fallback:2:1:1"

    # Constant cache rebuilds once after a fingerprint change and then hits.
    builds = []
    core._CONSTANT_DB_CACHE = None
    core._db_changed = lambda: True
    core.build_constant_db = lambda: builds.append("build") or {1: "ONE"}
    assert core.get_cached_constant_db() == {1: "ONE"}
    core._db_changed = lambda: False
    assert core.get_cached_constant_db() == {1: "ONE"}
    assert builds == ["build"]

    # Imports retain only named entries, use a fallback module name, and stop
    # at the configured memory cap.
    core._IMPORTS_CACHE = None
    core._db_changed = lambda: True
    core._MAX_DB_CACHE_ITEMS = 1
    core.ida_nalt.get_import_module_qty = lambda: 2
    core.ida_nalt.get_import_module_name = lambda i: None if i == 0 else "libc"

    def enum_imports(index, callback):
        callback(0x1000 + index, None, 0)
        callback(0x1001 + index, "read", 7)
        callback(0x1002 + index, "write", 8)

    core.ida_nalt.enum_import_names = enum_imports
    imports = core.get_cached_imports()
    assert imports == [{"ea": 0x1001, "name": "read", "module": "mod_0", "ordinal": 7}]
    core._db_changed = lambda: False
    assert core.get_cached_imports() is imports
    core._IMPORTS_CACHE = None
    core._db_changed = lambda: True
    core._MAX_DB_CACHE_ITEMS = 10
    assert len(core.get_cached_imports()) == 4

    # String cache skips None values, tolerates a decoder failure, caps rows,
    # and then returns the same list on a stable database.
    core._STRINGS_CACHE = None
    core._db_changed = lambda: True
    core._MAX_DB_CACHE_ITEMS = 2
    core.safe_get_strlist_items = lambda: [
        SimpleNamespace(ea=1), SimpleNamespace(ea=2), SimpleNamespace(ea=3)
    ]

    def string_value(ea):
        if ea == 1:
            return None
        if ea == 2:
            raise RuntimeError("bad string")
        return "third"

    core.safe_get_strlit_contents = string_value
    strings = core.get_cached_strings()
    assert strings == [{"ea": 3, "string": "third"}]
    core._db_changed = lambda: False
    assert core.get_cached_strings() is strings


def test_segment_and_code_iterators_cover_range_perms_and_badaddr(monkeypatch):
    core = _core()
    core.idaapi.SEGPERM_EXEC = 4
    segs = {0x1000: _Seg(0x1000, 0x1100), 0x1100: _Seg(0x1100, 0x1200)}
    nexts = {0x1100: 0x1100, 0x1200: None}
    core._compat.get_segment = lambda ea: segs.get(0x1000 if ea < 0x1100 else 0x1100)  # noqa: PLW0108
    core._compat.get_segment_perm = lambda ea: 4 if ea == 0x1000 else 0
    core._compat.get_next_segment_ea = lambda ea: nexts.get(ea)  # noqa: PLW0108
    core._compat.get_first_segment_ea = lambda: 0x1000

    assert list(core.iter_segments(0x1050, 0x1150, require_exec=True)) == [(0x1050, 0x1100)]
    assert list(core.iter_segments(0x1050, 0x1150, require_exec=False)) == [
        (0x1050, 0x1100), (0x1100, 0x1150)
    ]
    assert list(core.iter_segments()) == [(0x1000, 0x1100)]

    # A stale first-segment lookup must terminate rather than dereference None.
    core._compat.get_segment = lambda _ea: None
    assert list(core.iter_segments()) == []
    core.iter_segments = lambda *args, **kwargs: [(1, 2)]
    assert core.resolve_scan_segments(require_exec=False) == ([(1, 2)], "", "")

    core.idaapi.BADADDR = -1
    flags = {0x2000: 1, 0x2001: 0}
    core.ida_bytes.get_flags = lambda ea: flags.get(ea, 0)  # noqa: PLW0108
    core.ida_bytes.is_code = lambda value: bool(value)  # noqa: PLW0108
    core.idc.next_head = lambda ea, end: ea + 1 if ea + 1 < end else -1
    assert list(core.iter_code(0x2000, 0x2002)) == [0x2000]
    assert list(core.iter_code(0x2000, 0x2002, force=True)) == [0x2000, 0x2001]


def test_response_identifiers_and_demangle_fallbacks():
    core = _core()
    core.idaapi.BADADDR = -1

    assert core.clip_text(None) == ""
    assert core.clip_text("a  b") == "a b"
    assert core.clip_text("x" * 10, 5) == "xx..."
    assert core.paginate_records([{"n": 1}, {"n": 3}, {"n": 2}], 1, 1, sort_key=lambda r: r["n"]) == (
        [{"n": 2}], 3, True
    )
    core.idautils.XrefsTo = lambda *_args: []
    assert core.xref_count_limited(1, 0) == 0

    item = core.make_item(addr=16, name="fn", type="function", score="bad", snippet="a  b", extra=None)
    assert item == {"addr": "0x10", "name": "fn", "type": "function", "score": "bad", "snippet": "a b"}
    assert core._item_from_text_line("  0x401000  mov eax, ebx") == {
        "addr": "0x401000", "line": "0x401000  mov eax, ebx"
    }
    assert core._item_from_text_line(" plain result ") == {"line": "plain result"}

    assert core.normalize_search_result({"error": "bad"}, action="x") == {"error": "bad"}
    normalized = core.normalize_search_result(
        {"matches": "0x10 hit\n\nplain", "items": [{"address": 16}, "bad", {}, {"ea": "0x20"}]},
        action="name",
        query="needle",
    )
    assert normalized["results"] == normalized["matches"] == "0x10 hit\n\nplain"
    assert normalized["items"] == [
        {"address": 16, "addr": "0x10"},
        {},
        {"ea": "0x20", "addr": "0x20", "address": "0x20"},
    ]
    text_items = core.normalize_search_result({"results": "0x10 hit\nplain"})
    assert text_items["count"] == 2
    assert core.normalize_search_result([]) == []

    core.looks_like_address = lambda value: value == "0x10"
    assert core.looks_like_identifier("0x10") is True
    assert core.looks_like_identifier("48 89 e5") is False
    assert core.looks_like_identifier("two words") is False
    assert core.looks_like_identifier("foo::bar") is True

    core.idc.get_inf_attr = lambda _flag: (_ for _ in ()).throw(RuntimeError("no attr"))
    core.idc.demangle_name = lambda _name, _flags: None
    assert core.demangle_safe("_Zfoo") == "_Zfoo"
    core.idc.demangle_name = lambda _name, _flags: (_ for _ in ()).throw(RuntimeError("bad demangler"))
    assert core.demangle_safe("_Zfoo") == "_Zfoo"
    assert core.demangle_safe("") == ""

    core._db_changed = lambda: False
    core._DEMANGLE_CACHE = {str(i): "cached" for i in range(20000)}
    core.demangle_safe = lambda name: name
    assert core.demangle_cached("overflow") == "overflow"
    assert len(core._DEMANGLE_CACHE) == 1


def test_riscv_pair_rejects_malformed_operands_and_values(monkeypatch):
    core = _core()
    core.idaapi.BADADDR = -1
    core.ida_ua.o_reg = 1
    core.ida_ua.o_imm = 5

    class Insn:
        def __init__(self, mnem, ops):
            self.ops = ops
            self._mnem = mnem
            self.ea = 0x1004

        def get_canon_mnem(self):
            return self._mnem

    class Op:
        def __init__(self, typ, reg=0, value=0):
            self.type, self.reg, self.value = typ, reg, value

    lui = Insn("lui", [Op(1, reg=5), Op(5, value=1)])
    addi = Insn("addi", [Op(1, reg=5), Op(1, reg=5), Op(5, value="bad")])
    assert core.riscv_lui_addi_pair(Insn("lui", []), addi) is None
    assert core.riscv_lui_addi_pair(lui, Insn("addi", [Op(1), Op(1), Op(1)])) is None
    assert core.riscv_lui_addi_pair(Insn("lui", [Op(2), Op(5)]), addi) is None
    assert core.riscv_lui_addi_pair(Insn("lui", [Op(1, reg=5), Op(5)]), addi) is None
    assert core.riscv_lui_addi_pair(lui, Insn("addi", [Op(1, reg=5), Op(1, reg=6), Op(5)])) is None
    assert core.riscv_lui_addi_pair(lui, Insn("addi", [Op(1, reg=6), Op(1, reg=6), Op(5)])) is None
    assert core.riscv_lui_addi_pair(lui, addi) is None


def test_resolve_target_fast_paths_and_blackboard_boundaries(monkeypatch):
    core = _core()
    core.idaapi.BADADDR = -1
    core._compat.get_func_start = lambda _ea: None
    core.looks_like_address = lambda value: value == "0x1000"
    core.validate_addr = lambda _value: (0x1000, None)
    assert core.resolve_target("0x1000", require_function=True)[1] == "No function at 0x1000"

    core.looks_like_address = lambda _value: False
    core.idc.get_name_ea_simple = lambda value: 0x2000 if value == "exact" else -1
    assert core.resolve_target("exact", require_function=True)[1] == "No function at 0x2000"
    core.idc.get_name_ea_simple = lambda _value: -1
    core.idautils.Names = lambda: [(1, None), (2, "OtherName"), (3, "needle_fn")]
    assert core.resolve_target("needle", require_function=False)[0] == 3
    core._compat.get_func_start = lambda ea: None if ea == 3 else ea
    assert core.resolve_target("needle", require_function=True)[1] is not None

    # An address-shaped target with a validation error must continue to the
    # name/semantic paths rather than returning a malformed address.
    core.looks_like_address = lambda value: value == "0xdead"
    core.validate_addr = lambda _value: (-1, "invalid")
    core.idautils.Names = list
    assert core.resolve_target("0xdead")[0] == -1

    # Case-insensitive exact names that are not functions are skipped when a
    # function is required; more than eight substring hits stop the scan.
    core.looks_like_address = lambda _value: False
    core._compat.get_func_start = lambda _ea: None
    core.idautils.Names = lambda: [(0x5000, "Needle")]
    assert core.resolve_target("needle", require_function=True)[0] == -1
    core.idautils.Names = lambda: [(i, f"needle_{i}") for i in range(9)]
    core._compat.get_func_start = lambda _ea: None
    core.compile_smart_pattern = lambda *_args, **_kwargs: lambda _value: False
    assert core.resolve_target("needle")[0] == -1

    # Blackboard lookup accepts both address spellings, but rejects malformed
    # and non-function entries without leaking an exception.
    bb = types.ModuleType("ida_pro_mcp.ida_mcp.tools.blackboard")

    class Store:
        def list(self, **_kwargs):
            return [
                {"title": "broken", "addr": "not-hex"},
                {"title": "data needle", "address": 0x3000},
                {"title": "function needle", "addr": "0x4000"},
            ]

    bb.BlackboardStore = Store
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.tools.blackboard", bb)
    core.idautils.Names = list
    core._compat.get_func_start = lambda ea: 0x4000 if ea == 0x4000 else None
    ea, err, info = core.resolve_target("function needle", require_function=True)
    assert (ea, err, info["match"]) == (0x4000, None, "blackboard_name")
    core._compat.get_func_start = lambda _ea: None
    ea, err, _info = core.resolve_target("data needle", require_function=True)
    assert ea == -1 and err

    # A sentinel blackboard address is ignored, malformed addresses are
    # swallowed, and a broken store is isolated from name resolution.
    class SentinelStore:
        def list(self, **_kwargs):
            return [{"title": "sentinel", "addr": "-1"}]

    bb.BlackboardStore = SentinelStore
    core.idautils.Names = list
    assert core.resolve_target("sentinel")[0] == -1
    bb.BlackboardStore = lambda: types.SimpleNamespace(
        list=lambda **_kwargs: [{"title": "bad", "addr": "not-an-address"}]
    )
    assert core.resolve_target("bad")[0] == -1
    bb.BlackboardStore = lambda: (_ for _ in ()).throw(RuntimeError("store unavailable"))
    assert core.resolve_target("gone")[0] == -1


def test_resolve_target_semantic_names_imports_threshold_and_alternatives(monkeypatch):
    core = _core()
    core.idaapi.BADADDR = -1
    core.looks_like_address = lambda _value: False
    core.idc.get_name_ea_simple = lambda _value: -1
    core._compat.get_func_start = lambda ea: ea if ea in {0x1000, 0x2000} else None
    core.idautils.Names = lambda: [
        (0x1000, "alpha_fn"),
        (0x1100, "alpha_helper"),
        (0x2000, "_Z3foov"),
        (0x3000, "unrelated"),
        (0x4000, None),
    ]
    core.compile_smart_pattern = lambda pattern, **_kwargs: lambda value: pattern.lower() in str(value).lower()
    core.demangle_cached = lambda name: "foo()" if name == "_Z3foov" else name
    core.semantic_score_cheap = lambda *_args, **_kwargs: 10.0
    core.semantic_scores = lambda _target, names, **_kwargs: [80.0 - i for i, _ in enumerate(names)]
    bb = types.ModuleType("ida_pro_mcp.ida_mcp.tools.blackboard")
    bb.BlackboardStore = lambda: types.SimpleNamespace(list=lambda **_kwargs: [])
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.tools.blackboard", bb)

    ea, err, info = core.resolve_target("alpha", include_alternatives=True)
    assert ea == 0x1100 and err is None
    assert info["match"] == "semantic"
    assert info["semantic_alternatives"]

    core.semantic_scores = lambda *_args, **_kwargs: [1.0, 2.0]
    ea, err, info = core.resolve_target("alpha", semantic_min_score=50.0)
    assert ea == -1 and "below threshold" in err and info == {}

    # An import callback must ignore empty/nonmatching names and still expose
    # the module in a successful semantic match.
    core.idautils.Names = list
    core.ida_nalt.get_import_module_qty = lambda: 1
    core.ida_nalt.get_import_module_name = lambda _idx: None
    core.ida_nalt.enum_import_names = lambda _idx, cb: (
        cb(0x5000, None, 0), cb(0x5001, "alpha", 1)
    )
    core.semantic_scores = lambda *_args, **_kwargs: [3.0]
    ea, err, info = core.resolve_target("alpha", include_imports=True)
    assert (ea, err, info["semantic_kind"], info["semantic_module"]) == (0x5001, None, "import", "mod_0")

    core.idautils.Names = list
    core.ida_nalt.enum_import_names = lambda _idx, cb: cb(0x5000, "other", 1)
    ea, err, _info = core.resolve_target("missing", include_imports=True)
    assert ea == -1 and "not found" in err

    # Demangled fast paths cover unchanged names, nonmatching demangles,
    # function filtering, and the hit cap.
    core.idautils.Names = lambda: [(0x6000, "_Zbad")]
    core.demangle_cached = lambda _name: "_Zbad"
    assert core.resolve_target("bad()")[0] == -1
    core.idautils.Names = lambda: [(0x6000, "_Zfoo")]
    core.demangle_cached = lambda _name: "foo()"
    assert core.resolve_target("bar()", require_function=False)[0] == -1
    core._compat.get_func_start = lambda _ea: None
    assert core.resolve_target("foo()", require_function=True)[0] == -1
    core.idautils.Names = lambda: [(0x6000 + i, f"_Zfoo{i}") for i in range(9)]
    core.demangle_cached = lambda _name: "foo()"
    core.compile_smart_pattern = lambda *_args, **_kwargs: lambda _value: False
    assert core.resolve_target("foo()")[0] == -1

    # Slow semantic resolution maps a matched symbol to its function start.
    core.idautils.Names = lambda: [(0x6101, "alpha_behavior_fn"), (0x6200, "unrelated")]
    core.compile_smart_pattern = lambda _pattern, **_kwargs: lambda value: "alpha" in str(value)
    core.semantic_scores = lambda _target, names, **_kwargs: [9.0 for _ in names]
    core._compat.get_func_start = lambda ea: 0x6100 if ea == 0x6101 else None
    ea, err, info = core.resolve_target("alpha behavior", require_function=True)
    assert (ea, err, info["match"]) == (0x6100, None, "semantic")

    # A function can disappear between candidate collection and final
    # normalization; preserve the resolved candidate without failing.
    func_states = iter((0x6100, None))
    core.idautils.Names = lambda: [(0x6101, "alpha_behavior_fn"), (0x6200, "unrelated")]
    core._compat.get_func_start = lambda _ea: next(func_states)
    ea, err, info = core.resolve_target("alpha behavior", require_function=True)
    assert (ea, err, info["match"]) == (0x6101, None, "semantic")

    # The slow path must add its exact-name bonus before ranking.
    calls = iter(([], [], [(0x6300, "exact_name")]))
    core.idautils.Names = lambda: next(calls)
    core.compile_smart_pattern = lambda _pattern, **_kwargs: lambda value: True
    core.semantic_scores = lambda _target, names, **_kwargs: [1.0 for _ in names]
    core._compat.get_func_start = lambda _ea: None
    ea, err, _info = core.resolve_target("exact_name")
    assert (ea, err) == (0x6300, None)


def test_safe_ida_compatibility_fallbacks_and_constant_builder(monkeypatch):
    core = _core()
    core.idaapi.BADADDR = -1
    assert core.safe_generate_disasm_line(-1) is None
    values = iter(("", "second", "never"))
    core.ida_lines.GENDSM_FORCE_CODE = 1
    core.ida_lines.generate_disasm_line = lambda *_args: next(values)
    core.idc.generate_disasm_line = lambda *_args: "third"
    assert core.safe_generate_disasm_line(1) == "second"

    def all_fail(*_args):
        raise RuntimeError("unsupported")

    core.ida_lines.generate_disasm_line = all_fail
    core.idc.generate_disasm_line = all_fail
    assert core.safe_generate_disasm_line(1) is None

    # Prefer ida_strlist when present, then use the legacy idaapi path.
    modern = types.ModuleType("ida_strlist")
    modern.get_strlist_qty = lambda: 2
    modern.string_info_t = lambda: SimpleNamespace()  # noqa: PLW0108
    modern.get_strlist_item = lambda obj, index: setattr(obj, "ea", index + 10) or index == 1
    monkeypatch.setitem(sys.modules, "ida_strlist", modern)
    assert [row.ea for row in core.safe_get_strlist_items()] == [11]
    monkeypatch.delitem(sys.modules, "ida_strlist")
    core.idaapi.get_strlist_qty = lambda: 2
    core.idaapi.string_info_t = lambda: SimpleNamespace()  # noqa: PLW0108
    core.idaapi.get_strlist_item = lambda obj, index: setattr(obj, "ea", index + 20) or index == 0
    assert [row.ea for row in core.safe_get_strlist_items()] == [20]

    core.idc.get_str_type = lambda _ea: 1
    core.idc.get_strlit_contents = lambda *_args: b"caf\xc3\xa9"
    assert core.safe_get_strlit_contents(1) == "café"
    core.idc.get_strlit_contents = lambda _ea, *_args: "plain"
    assert core.safe_get_strlit_contents(1) == "plain"
    core.idc.get_str_type = lambda _ea: -1
    assert core.safe_get_strlit_contents(1) == "plain"
    contents = iter((b"", b"fallback"))
    core.idc.get_str_type = lambda _ea: 1
    core.idc.get_strlit_contents = lambda *_args: next(contents)
    assert core.safe_get_strlit_contents(1) == "fallback"
    contents = iter((b"", b""))
    core.idc.get_strlit_contents = lambda *_args: next(contents)
    assert core.safe_get_strlit_contents(1) is None
    core.idc.get_str_type = lambda _ea: (_ for _ in ()).throw(RuntimeError("type API"))
    core.idc.get_strlit_contents = lambda *_args: (_ for _ in ()).throw(RuntimeError("contents API"))
    assert core.safe_get_strlit_contents(1) is None

    crypto = types.ModuleType("ida_pro_mcp.ida_mcp.support.crypto_registry")
    crypto.CRYPTO_CONSTANT_NAMES = {2: "CRYPTO"}
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.support.crypto_registry", crypto)
    core.MAGIC_CONSTANTS = {1: "MAGIC"}
    assert core.build_constant_db() == {1: "MAGIC", 2: "CRYPTO"}
    del core.MAGIC_CONSTANTS
    assert core.build_constant_db() == {2: "CRYPTO"}


@pytest.mark.parametrize("raw", [None, "   "])
def test_resolve_target_requires_nonempty_target(raw):
    core = _core()
    core.idaapi.BADADDR = -1
    ea, err, info = core.resolve_target(raw)
    assert ea == -1 and err == "target is required" and info == {}


def test_xref_count_limited_when_xrefs_to_missing(monkeypatch):
    core = _core()
    monkeypatch.delattr(core.idautils, "XrefsTo", raising=False)
    assert core.xref_count_limited(0x1000) == 0
