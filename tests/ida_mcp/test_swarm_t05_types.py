"""Regression tests for t05_types swarm fixes.

Covers:
- modify(comment): set_cmt / add_extra_cmt failures now return an
  ANNOTATION_ERROR envelope instead of an ok:true result.
- types(search_structs): anonymous types (get_type_name -> None) no longer
  crash the smart-pattern matcher.
- types(vtable): repeated function pointers are skipped (not treated as the
  end of the vtable), so legit multi-slot vtables are not truncated; the
  demangle call uses the portable idc.demangle_name API so IDA 9 (which has
  no ida_nalt.demangle_name) still demangles.
- types(apply): kind='stack' / unknown kinds are rejected with INVALID_ARGS
  instead of silently performing a global apply.
- modify(patch_bytes nop): architecture detection uses _inf_procname() so
  IDA 9 (no get_inf_structure) still emits ARM/RISC-V NOP bytes.
"""

from __future__ import annotations

import struct
import sys
import types
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_host_module, load_ida_module, load_tool_module  # noqa: E402

REPO = TESTS.parent
TOOLS = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "tools"


def _real_errors(module):
    """Rebind a tool module to the real IDA-side error contract.

    The isolated-loader _common stub ships a bare make_error that returns
    {"ok": False, ...}; the tests assert on the real envelope (error: True,
    code, category), so swap in the actual error_handling module.
    """
    err = load_ida_module("error_handling")
    module.make_error = err.make_error
    module.handle_error = err.handle_error
    module.MCPError = err.MCPError
    module.ERROR_HINTS = err.ERROR_HINTS
    return module


def _load_types():
    mod = load_tool_module("types")
    _real_errors(mod)
    # Portable infra helpers re-exported by the real _common via `import *`;
    # the isolated stub does not define them, so install stand-ins.
    mod._inf_is_64bit = lambda: True
    mod._inf_is_be = lambda: False
    return mod


def _load_modify():
    mod = load_tool_module("modify")
    _real_errors(mod)
    return mod


def _func(start, end):
    return type("_F", (), {"start_ea": start, "end_ea": end})


def _wire_funcs(mod, get_func):
    """Dual-surface ida_funcs wiring: compat.get_func_* resolves ida_funcs via
    sys.modules, so expose the legacy get_func (mirroring idaapi.get_func) and
    the 9.4 EA surface off the same mock."""
    mod.ida_funcs.get_func = get_func
    mod.ida_funcs.ida_idaapi = types.SimpleNamespace(BADADDR=-1)
    mod.ida_funcs.func_entry_info_t = types.SimpleNamespace
    mod.ida_funcs.get_func_entry_info = lambda out, ea, flags=0: False


# ---------------------------------------------------------------------------
# modify(comment) — set_cmt / add_extra_cmt failure must not return ok:true
# ---------------------------------------------------------------------------

def test_comment_failure_returns_annotation_error():
    mod = _load_modify()
    mod.idc.set_cmt = lambda *a, **k: False
    r = mod.modify(action="comment", addr="0x401000", value="hi", governed=False)
    assert r.get("error") is True
    assert r["code"] == "ANNOTATION_ERROR"
    assert r["category"] == "runtime"
    assert "comment" in r["message"].lower()


def test_comment_success_still_ok():
    mod = _load_modify()
    mod.idc.set_cmt = lambda *a, **k: True
    r = mod.modify(action="comment", addr="0x401000", value="hi", governed=False)
    assert r.get("ok") is True
    assert r["comment"] == "hi"


def test_comment_repeatable_failure_returns_annotation_error():
    mod = _load_modify()
    mod.idc.set_cmt = lambda ea, value, rptble: False
    r = mod.modify(action="comment", addr="0x401000", value="hi",
                   comment_type="repeatable", governed=False)
    assert r.get("error") is True
    assert r["code"] == "ANNOTATION_ERROR"


def test_comment_anterior_failure_returns_annotation_error():
    mod = _load_modify()
    mod.idc.set_cmt = lambda *a, **k: True
    mod.ida_lines.add_extra_cmt = lambda *a, **k: False
    r = mod.modify(action="comment", addr="0x401000", value="hi",
                   comment_type="anterior", governed=False)
    assert r.get("error") is True
    assert r["code"] == "ANNOTATION_ERROR"


def test_comment_fallback_merged_set_cmt_failure_returns_annotation_error():
    # Binding without ida_lines.add_extra_cmt: the anterior/posterior intent
    # is folded into a merged regular comment; a failure there must also error.
    mod = _load_modify()
    mod.idc.get_cmt = lambda ea, rptble: ""
    mod.idc.set_cmt = lambda *a, **k: False
    r = mod.modify(action="comment", addr="0x401000", value="hi",
                   comment_type="posterior", governed=False)
    assert r.get("error") is True
    assert r["code"] == "ANNOTATION_ERROR"


# ---------------------------------------------------------------------------
# types(search_structs) — anonymous types must not crash the matcher
# ---------------------------------------------------------------------------

def test_search_structs_skips_anonymous_types_without_crashing():
    mod = _load_types()
    # Use the REAL host smart-pattern matcher, which crashes on None (its
    # lambdas call `_t.lower()`); the tool must guard None before calling it.
    patterns = load_host_module("analysis.patterns")
    mod.compile_smart_pattern = patterns.compile_smart_pattern
    mod.ida_typeinf.get_ordinal_qty = lambda til: 2

    class Member:
        def __init__(self, name):
            self.name = name

    class Udt:
        def __init__(self):
            self._members = []

        def size(self):
            return len(self._members)

        def __getitem__(self, i):
            return self._members[i]

    class Tif:
        _seq = iter([1, 2])

        def __init__(self):
            self.ordinal = next(Tif._seq)

        def get_numbered_type(self, til, ordinal):
            return True

        def is_struct(self):
            return True

        def is_union(self):
            return False

        def get_type_name(self):
            # Ordinal 1 is an anonymous struct/union: get_type_name -> None.
            return None if self.ordinal == 1 else "Packet"

        def get_udt_details(self, udt):
            if self.ordinal == 2:
                udt._members = [Member("callback"), Member(None), Member("size")]
            return True

    mod.ida_typeinf.tinfo_t = Tif
    mod.ida_typeinf.udt_type_data_t = Udt

    r = mod.types(action="search_structs", query="callback")
    # Pre-fix this raised AttributeError inside the matcher on the anonymous
    # type and the whole action came back as an error envelope.
    assert r.get("ok") is True
    assert r["total"] == 1
    assert r["matches"][0]["name"] == "Packet"
    assert r["matches"][0]["match"] == "field"
    assert r["matches"][0]["field"] == "callback"


# ---------------------------------------------------------------------------
# types(vtable) — duplicate targets skipped, not treated as end-of-vtable
# ---------------------------------------------------------------------------

def test_vtable_skips_duplicate_targets_instead_of_truncating():
    mod = _load_types()
    # vtable base 0x1000 with 8-byte slots. Slot 2 repeats the slot-0 target —
    # a legitimate "multiple interfaces collapse to one method" layout — and
    # must NOT end the scan (pre-fix it silently truncated the vtable here).
    slots = {0x1000: 0x2000, 0x1008: 0x3000, 0x1010: 0x2000, 0x1018: 0x4000}
    mod.ida_bytes.get_bytes = lambda ea, size: struct.pack("<Q", slots.get(ea, 0))
    mod.ida_bytes.is_loaded = lambda ea: ea != 0
    mod.idaapi.get_func = lambda ea: _func(ea, ea + 1)
    _wire_funcs(mod, mod.idaapi.get_func)
    mod.idc.get_name = lambda ea: f"f_{ea:x}"
    mod.idc.INF_SHORT_DN = 1
    mod.idc.get_inf_attr = lambda attr: 0
    mod.idc.demangle_name = lambda name, mask: None

    r = mod.types(action="vtable", addr="0x1000")
    assert r.get("ok") is True
    # 4 slots scanned, 3 unique targets; the repeated 0x2000 is skipped.
    assert r["count"] == 3
    assert [e["addr"] for e in r["entries"]] == ["0x2000", "0x3000", "0x4000"]


# ---------------------------------------------------------------------------
# types(vtable) — demangle uses portable idc API (IDA 9 has no
# ida_nalt.demangle_name)
# ---------------------------------------------------------------------------

def test_vtable_demangle_uses_portable_idc_api():
    mod = _load_types()
    slots = {0x1000: 0x2000}
    mod.ida_bytes.get_bytes = lambda ea, size: struct.pack("<Q", slots.get(ea, 0))
    mod.ida_bytes.is_loaded = lambda ea: ea != 0
    mod.idaapi.get_func = lambda ea: _func(ea, ea + 1)
    _wire_funcs(mod, mod.idaapi.get_func)
    mod.idc.get_name = lambda ea: "_ZN7android14KloProxy7methodEi"
    mod.idc.INF_SHORT_DN = 1
    mod.idc.get_inf_attr = lambda attr: 0
    mod.idc.demangle_name = lambda name, mask: (
        "KloProxy::method" if name.startswith("_Z") else None
    )
    # Simulate IDA 9: ida_nalt no longer exposes demangle_name at all. The old
    # call silently raised AttributeError and left names mangled.
    assert not hasattr(mod.ida_nalt, "demangle_name")

    r = mod.types(action="vtable", addr="0x1000")
    assert r.get("ok") is True
    assert r["entries"][0]["name"] == "KloProxy::method"
    assert r["entries"][0]["mangled"] == "_ZN7android14KloProxy7methodEi"


# ---------------------------------------------------------------------------
# types(apply) — kind validation: 'stack' / unknown kinds rejected
# ---------------------------------------------------------------------------

def _setup_apply(mod):
    # A plain callable class: ida_typeinf.tinfo_t() must hand back a fresh
    # instance each call.
    mod.ida_typeinf.tinfo_t = type("_Tif", (), {})
    mod.ida_typeinf.parse_decl = lambda *a, **k: True
    mod.ida_typeinf.PT_SIL = 0
    mod.ida_typeinf.TINFO_DEFINITE = 0
    mod.idaapi.get_func = lambda ea: None
    # compat.get_func_start resolves ida_funcs via sys.modules; mirror the
    # idaapi.get_func miss (no function at 0x1000 -> default kind "global").
    mod.ida_funcs.get_func = mod.idaapi.get_func
    mod.ida_funcs.ida_idaapi = types.SimpleNamespace(BADADDR=-1)
    mod.ida_funcs.func_entry_info_t = types.SimpleNamespace
    mod.ida_funcs.get_func_entry_info = lambda out, ea, flags=0: False


def test_apply_rejects_stack_kind():
    mod = _load_types()
    _setup_apply(mod)
    mod.ida_typeinf.apply_tinfo = lambda *a, **k: True
    r = mod.types(action="apply", addr="0x1000", decl="int", kind="stack")
    # Pre-fix this silently performed a GLOBAL apply and reported kind="stack".
    assert r.get("error") is True
    assert r["code"] == "INVALID_ARGS"
    assert "stack" in r["message"]


def test_apply_rejects_unknown_kind():
    mod = _load_types()
    _setup_apply(mod)
    r = mod.types(action="apply", addr="0x1000", decl="int", kind="bogus")
    assert r.get("error") is True
    assert r["code"] == "INVALID_ARGS"


def test_apply_global_kind_still_applies():
    mod = _load_types()
    _setup_apply(mod)
    calls = []
    mod.ida_typeinf.apply_tinfo = lambda *a, **k: calls.append(a) or True
    r = mod.types(action="apply", addr="0x1000", decl="int", kind="global")
    assert r.get("ok") is True
    assert r["kind"] == "global"
    assert len(calls) == 1


def test_apply_defaults_to_global_without_function():
    mod = _load_types()
    _setup_apply(mod)
    mod.ida_typeinf.apply_tinfo = lambda *a, **k: True
    r = mod.types(action="apply", addr="0x1000", decl="int")
    assert r.get("ok") is True
    assert r["kind"] == "global"


# ---------------------------------------------------------------------------
# modify(patch_bytes nop) — arch detection via _inf_procname (IDA 9 safe)
# ---------------------------------------------------------------------------

def _setup_patch_nop(mod, procname):
    mod._inf_procname = lambda: procname
    captured = {}

    def _patch(ea, data):
        captured["ea"] = ea
        captured["data"] = bytes(data)

    mod.ida_bytes.patch_bytes = _patch
    return captured


def test_patch_bytes_nop_uses_inf_procname_arm():
    mod = _load_modify()
    cap = _setup_patch_nop(mod, "ARM")
    r = mod.modify(action="patch_bytes", addr="0x401000", nop=True, count=4,
                   governed=False)
    assert r.get("ok") is True
    # ARM NOP (0xe320f000 little-endian), not x86 0x90.
    assert cap["data"] == b"\x00\xf0\x20\xe3"


def test_patch_bytes_nop_uses_inf_procname_riscv():
    mod = _load_modify()
    cap = _setup_patch_nop(mod, "riscv")
    r = mod.modify(action="patch_bytes", addr="0x401000", nop=True, count=4,
                   governed=False)
    assert r.get("ok") is True
    # RISC-V NOP = addi x0, x0, 0 = 0x00000013.
    assert cap["data"] == b"\x13\x00\x00\x00"


def test_patch_bytes_nop_x86_fallback():
    mod = _load_modify()
    cap = _setup_patch_nop(mod, "metapc")
    r = mod.modify(action="patch_bytes", addr="0x401000", nop=True, count=4,
                   governed=False)
    assert r.get("ok") is True
    assert cap["data"] == b"\x90\x90\x90\x90"


# ---------------------------------------------------------------------------
# Source-level guards — the broken call sites are gone
# ---------------------------------------------------------------------------

def _source(name: str) -> str:
    return (TOOLS / f"{name}.py").read_text(encoding="utf-8")


def test_types_no_ida_nalt_demangle_call():
    src = _source("types")
    # The old call site ida_nalt.demangle_name(...) / get_short_name_synonym()
    # is gone (it raises on IDA 9); demangling now goes through idc.
    assert "ida_nalt.demangle_name(" not in src
    assert "get_short_name_synonym(" not in src


def test_modify_no_get_inf_structure_procname_call():
    src = _source("modify")
    assert "get_inf_structure().procname" not in src
    assert "_inf_procname()" in src
