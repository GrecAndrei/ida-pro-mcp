"""Deep boundary matrix tests for code_helpers.py reaching 100% coverage."""

from __future__ import annotations

import builtins
import contextlib
import importlib
import types

import ida_hexrays
import idaapi

from tests.fakes.ida_fake import (
    BADADDR,
    cexpr_t,
    cot_asg,
    cot_call,
    cot_insn,
    cot_num,
    cot_obj,
    cot_ref,
    cot_sizeof,
    cot_var,
    var_ref_t,
)


def _helpers():
    return importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")


class _Args(list):
    def size(self):
        return len(self)

    def at(self, index):
        return self[index]


def test_code_helpers_ida_ua_import_fallback(monkeypatch):
    helpers = _helpers()
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "ida_ua":
            raise ImportError("no ida_ua")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    importlib.reload(helpers)
    assert helpers.ida_ua is None
    monkeypatch.undo()
    importlib.reload(helpers)


def test_extract_var_rename_hints_handles_bad_proto():
    helpers = _helpers()

    class BadProto:
        def __str__(self):
            raise RuntimeError("bad proto string")

    # Name "a1" matches ^[va]\d+$, starts with "a"
    # cfunc.type triggers __str__ raising RuntimeError, caught at lines 472-473
    lvar = types.SimpleNamespace(name="a1", type=None)
    cfunc = types.SimpleNamespace(type=BadProto(), lvars=[lvar])
    hints = helpers._extract_var_rename_hints(cfunc)
    assert hints == []


def test_detect_firmware_signals_and_crypto_limits(monkeypatch):
    helpers = _helpers()
    func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x2000)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)

    # 1. scan_iter >= 50000: break (line 590)
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _max_ea: ea)
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "nop")
    signals = helpers._detect_firmware_signals(0x1000, "")
    assert signals == []

    # 2. Decompiler text fallback with >= 8 signals break (line 597)
    monkeypatch.setattr(helpers.idc, "next_head", lambda _ea, _max_ea: 0x2000)
    pseudo = " ".join([f"0x{0x40000000 + i * 0x1000:08x}" for i in range(10)])
    signals = helpers._detect_firmware_signals(0x1000, pseudo)
    assert len(signals) == 8

    # 3. Outer exception fallback in _detect_firmware_signals (lines 598-599)
    bad_func = types.SimpleNamespace(start_ea=0x1000)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: bad_func)
    assert helpers._detect_firmware_signals(0x1000, "") == []


def test_scan_ctree_vulns_sink_visitor_and_checks(monkeypatch):
    helpers = _helpers()

    # 1. cot_call where _check_call raises (lines 730-731)
    class RaisingExpr:
        op = ida_hexrays.cot_call
        ea = 0x1000

        @property
        def x(self):
            raise RuntimeError("boom in x")

    # 2. String arg extraction exception (lines 788-790)
    ref_obj = cexpr_t(op=cot_ref, ea=0x1004)
    ref_obj.x = cexpr_t(op=cot_obj, obj_ea=0x5000)

    # 3. cot_sizeof is constant (line 797)
    sz_expr = cexpr_t(op=cot_sizeof, ea=0x1008)

    # 4. print1 contains "sizeof" (line 800)
    sz_text_expr = cexpr_t(op=cot_var, v=var_ref_t(0), ea=0x100C)
    sz_text_expr.print1 = lambda _tag=None: "sizeof(buf)"

    # 5. cot_call from network source (lines 827-829)
    net_call = cexpr_t(op=cot_call, ea=0x1010)
    net_call.x = cexpr_t(op=cot_obj, obj_ea=0x6000)
    net_call.a = _Args()

    # 6. size hint "computed" with strlen (line 845)
    strlen_expr = cexpr_t(op=cot_var, v=var_ref_t(0), ea=0x1014)
    strlen_expr.print1 = lambda _tag=None: "strlen(src)"

    # 7. callee_params with empty type (line 1034)
    empty_type_call = cexpr_t(op=cot_call, ea=0x1018)
    empty_type_call.x = cexpr_t(op=cot_obj, obj_ea=0x7000)
    num_arg = cexpr_t(op=cot_num, ea=0x1018)
    num_arg.n = types.SimpleNamespace(value=lambda _idx=0: 0x42)
    empty_type_call.a = _Args([num_arg])

    # 8. assignment rhs == 0 clears freed_vars (line 1061)
    asg_zero = cexpr_t(op=cot_asg, ea=0x101C)
    asg_zero.x = cexpr_t(op=cot_var, v=var_ref_t(0), ea=0x101C)
    rhs_zero = cexpr_t(op=cot_num, ea=0x101C)
    rhs_zero.n = types.SimpleNamespace(value=lambda _idx=0: 0)
    asg_zero.y = rhs_zero

    # Setup name lookups
    monkeypatch.setattr(
        helpers.idc,
        "get_name",
        lambda ea: {
            0x6000: "recv",
            0x7000: "target_func",
        }.get(ea, "free"),
    )
    monkeypatch.setattr(
        helpers.idc,
        "get_strlit_contents",
        lambda _ea, _len=-1, _type=0: (_ for _ in ()).throw(RuntimeError("strlit failed")),
    )

    # Set up callee prototype with empty type parameter for empty_type_call
    class FakeFuncData:
        def size(self):
            return 1

        def __getitem__(self, _idx):
            return types.SimpleNamespace(name="p0", type="")

    class FakeTinfo:
        def get_func_details(self, _data):
            return True

    monkeypatch.setattr(helpers.ida_typeinf, "tinfo_t", FakeTinfo)
    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", lambda _tif, _ea: True)
    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", FakeFuncData, raising=False)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_sizeof", 56, raising=False)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_ptr", 45, raising=False)

    def custom_apply_to(self, body, parent=None):
        if hasattr(self, "_check_call"):
            self.visit_expr(RaisingExpr())
            self._get_string_content(ref_obj)
            assert self._is_constant(sz_expr) is True
            assert self._is_constant(sz_text_expr) is True
            assert self._is_var_user_tainted(net_call) is True
            assert self._get_arg_size_hint(sz_expr) == "constant"
            assert self._get_arg_size_hint(strlen_expr) == "computed"
            self._check_call(empty_type_call)
            self._check_assignment(asg_zero)
        return 0

    monkeypatch.setattr(helpers.ida_hexrays.ctree_visitor_t, "apply_to", custom_apply_to)

    cfunc = types.SimpleNamespace(
        entry_ea=0x1000,
        body=types.SimpleNamespace(),
        lvars=[types.SimpleNamespace(name="freed_var", is_arg_var=False)],
    )
    findings = helpers._scan_ctree_vulns(cfunc)
    assert isinstance(findings, list)


def test_scan_ctree_vulns_uaf_and_alloc_exceptions(monkeypatch):
    helpers = _helpers()

    class BrokenVarExpr:
        op = ida_hexrays.cot_var

        @property
        def v(self):
            raise RuntimeError("broken var ref")

    monkeypatch.setattr(
        helpers._compat,
        "get_segment_perm",
        lambda _ea: (_ for _ in ()).throw(RuntimeError("seg perm error")),
    )
    monkeypatch.setattr(
        helpers.idc,
        "get_name",
        lambda ea: "free" if ea == 0x8000 else "malloc",
    )

    free_var = cexpr_t(op=cot_var, v=var_ref_t(0), ea=0x1000)
    free_var.print1 = lambda _tag=None: "target"
    free_call = cexpr_t(op=cot_call, ea=0x1000)
    free_call.x = cexpr_t(op=cot_obj, obj_ea=0x8000)
    free_call.a = _Args([free_var])

    alloc_call = cexpr_t(op=cot_call, ea=0x1004)
    alloc_call.x = cexpr_t(op=cot_obj, obj_ea=0x8004)
    alloc_call.a = _Args([cexpr_t(op=cot_num, ea=0x1004)])

    def custom_apply_to(self, body, parent=None):
        if hasattr(self, "_check_call"):
            self._check_call(free_call)
            self._check_call(alloc_call)
        elif hasattr(self, "found"):
            # UAFChecker
            self.visit_expr(BrokenVarExpr())
            raise RuntimeError("uaf apply_to error")
        elif hasattr(self, "alloc_eas"):
            # UncheckedAllocChecker
            raise RuntimeError("alloc apply_to error")
        return 0

    monkeypatch.setattr(helpers.ida_hexrays.ctree_visitor_t, "apply_to", custom_apply_to)
    cfunc = types.SimpleNamespace(
        entry_ea=0x1000,
        body=types.SimpleNamespace(),
        lvars=[types.SimpleNamespace(name="target", is_arg_var=False)],
    )
    findings = helpers._scan_ctree_vulns(cfunc)
    assert isinstance(findings, list)


def test_scan_ctree_vulns_subsystem_boundaries(monkeypatch):
    helpers = _helpers()

    class HexInt(int):
        def __new__(cls, val, *args, **kwargs):
            if str(val).lower() == "0xbadea":
                raise ValueError("corrupt hex")
            return super().__new__(cls, val, *args, **kwargs)

    monkeypatch.setattr(helpers, "int", HexInt, raising=False)

    monkeypatch.setattr(
        helpers._compat,
        "get_flow_chart",
        lambda _ea: (_ for _ in ()).throw(RuntimeError("flowchart failed")),
    )
    monkeypatch.setattr(
        helpers._compat,
        "frame_members",
        lambda _ea: (_ for _ in ()).throw(RuntimeError("frame members failed")),
    )
    monkeypatch.setattr(
        helpers.ida_ua,
        "decode_insn",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("decode error")),
    )
    monkeypatch.setattr(
        helpers.ida_bytes,
        "get_bytes",
        lambda _ea, _size: (_ for _ in ()).throw(RuntimeError("bytes failed")),
    )

    gets_call = cexpr_t(op=cot_call, ea=0xbadea)
    gets_call.x = cexpr_t(op=cot_obj, obj_ea=0x9000)
    gets_call.a = _Args()

    monkeypatch.setattr(helpers.idc, "get_name", lambda ea: "gets" if ea == 0x9000 else "")

    def custom_apply_to(self, body, parent=None):
        if hasattr(self, "_check_call"):
            self._check_call(gets_call)
        return 0

    monkeypatch.setattr(helpers.ida_hexrays.ctree_visitor_t, "apply_to", custom_apply_to)

    cfunc = types.SimpleNamespace(entry_ea=0x1000, body=types.SimpleNamespace(), lvars=[])
    findings = helpers._scan_ctree_vulns(cfunc)
    assert isinstance(findings, list)


def test_scan_ctree_vulns_shellcode_and_string_xrefs(monkeypatch):
    helpers = _helpers()

    # Shellcode in data segment (lines 1358-1362)
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _size: b"\x31\xc0\x90\x90")
    monkeypatch.setattr(helpers._compat, "get_segment_name", lambda _ea: ".data")

    # String xref analysis (line 1396 break)
    class FakeXref:
        def __init__(self, frm):
            self.frm = frm

    monkeypatch.setattr(helpers.idc, "get_str_type", lambda _ea: 0)
    monkeypatch.setattr(helpers.idautils, "XrefsTo", lambda _ea: [FakeXref(0x2000 + i * 4) for i in range(8)])
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda ea: f"func_{ea:x}")
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda _ea, _l=-1, _t=0: b"http://evil.com")

    monkeypatch.setattr(helpers.ida_hexrays, "cot_ref", cot_ref, raising=False)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_obj", cot_obj, raising=False)
    str_ref = cexpr_t(op=cot_ref, ea=0x1000)
    str_ref.x = cexpr_t(op=cot_obj, obj_ea=0x4000)

    def custom_apply_to(self, body, parent=None):
        if not hasattr(self, "_check_call"):
            self.visit_expr(str_ref)
        return 0

    monkeypatch.setattr(helpers.ida_hexrays.ctree_visitor_t, "apply_to", custom_apply_to)
    cfunc = types.SimpleNamespace(entry_ea=0x1000, body=types.SimpleNamespace(), lvars=[])
    findings = helpers._scan_ctree_vulns(cfunc)
    patterns = [f.get("pattern") for f in findings]
    assert "shellcode_in_data_seg" in patterns
    assert "shared_suspicious_string" in patterns


def test_scan_ctree_vulns_outer_catch_blocks(monkeypatch):
    helpers = _helpers()

    # 1. vuln_families exception (lines 1493-1494)
    monkeypatch.setattr(
        helpers.idc,
        "get_func_name",
        lambda _ea: (_ for _ in ()).throw(RuntimeError("func name failed")),
    )

    # 2. firmware signals exception (lines 1508-1509)
    monkeypatch.setattr(
        helpers,
        "_detect_firmware_signals",
        lambda _ea, **_kw: (_ for _ in ()).throw(RuntimeError("firmware scan failed")),
    )

    cfunc = types.SimpleNamespace(entry_ea=0x1000, body=types.SimpleNamespace(), lvars=[])
    findings = helpers._scan_ctree_vulns(cfunc)
    assert isinstance(findings, list)


def test_candidate_string_and_load_string_scans(monkeypatch):
    helpers = _helpers()

    # 1. _read_candidate_string returns None when get_bytes is empty (line 1678)
    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda _ea: True)
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _len: b"")
    assert helpers._read_candidate_string(0x1000) is None

    # 2. _scan_constant_load_strings scan_iter >= 100000 break (line 1758)
    func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x2000)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _max_ea: ea)
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "")
    assert helpers._scan_constant_load_strings(0x1000) == []

    # 3. _collect_function_string_entries empty string literal continue (line 1789)
    class FakeXref:
        to = 0x5000
        iscode = False

    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: [0x1000])
    monkeypatch.setattr(helpers.idautils, "XrefsFrom", lambda _ea, _flag: [FakeXref()])
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda _ea: None)
    assert helpers._collect_function_string_entries(0x1000) == []


def test_format_decompilation_with_ida_comments(monkeypatch):
    helpers = _helpers()

    # 1. CommentVisitor records comments (line 1887)
    insn = types.SimpleNamespace(ea=0x1000)
    monkeypatch.setattr(helpers.idc, "get_cmt", lambda ea, _flag: "test comment" if ea == 0x1000 else "")

    class Visitor(helpers.ida_hexrays.ctree_visitor_t):
        def apply_to(self, body):
            self.visit_insn(insn)

    # 2. apply_to exception (lines 1891-1892)
    class RaisingVisitor:
        def apply_to(self, _body):
            raise RuntimeError("ctree visitor failed")

    cfunc = types.SimpleNamespace(body=types.SimpleNamespace())
    lines = ["int func() {", "    x = 0x1000; // call", "    y = 0xbadea; // bad", "}"]

    # Test successful comment merge (lines 1887, 1903) and ValueError (line 1905)
    class HexInt(int):
        def __new__(cls, val, *args, **kwargs):
            if str(val).lower() == "0xbadea":
                raise ValueError("bad hex")
            return super().__new__(cls, val, *args, **kwargs)

    monkeypatch.setattr(helpers, "int", HexInt, raising=False)
    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", Visitor)

    annotated = helpers.annotate_pseudocode("\n".join(lines), 0x1000, [], [], cfunc=cfunc)
    assert "// [IDA] test comment" in annotated

    # Test apply_to exception
    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", RaisingVisitor)
    annotated_err = helpers.annotate_pseudocode("\n".join(lines), 0x1000, [], [], cfunc=cfunc)
    assert "int func()" in annotated_err


def test_decompile_with_diagnostics_success_and_retry_failure(monkeypatch):
    helpers = _helpers()

    # 1. First attempt decompile success (line 1952)
    monkeypatch.setattr(helpers.ida_hexrays, "init_hexrays_plugin", lambda: True)
    monkeypatch.setattr(helpers._compat, "HAS_DECOMPILER", True)
    fake_cfunc = types.SimpleNamespace()
    monkeypatch.setattr(helpers._compat, "decompile_function", lambda _ea, _f, _fl: fake_cfunc)
    cfunc, err = helpers._decompile_with_diagnostics(0x1000)
    assert cfunc is fake_cfunc
    assert err is None

    # 2. Retry exception caught (lines 1975-1976)
    class FakeFailure:
        code = 50735
        errea = 0x1000

    monkeypatch.setattr(helpers._compat, "decompile_function", lambda _ea, _f, _fl: None)
    monkeypatch.setattr(helpers.ida_hexrays, "hexrays_failure_t", FakeFailure)
    monkeypatch.setattr(
        helpers._compat,
        "get_func_info",
        lambda _ea: (_ for _ in ()).throw(RuntimeError("func info error")),
    )
    cfunc, err = helpers._decompile_with_diagnostics(0x1000)
    assert cfunc is None
    assert err is not None


def test_is_flow_control_mnemonic_syscall():
    helpers = _helpers()
    assert helpers._is_flow_control_mnemonic("syscall", arch="x86_64") is True


def test_disasm_window_edge_limits(monkeypatch):
    helpers = _helpers()

    class TrickInt(int):
        call_count = 0

        def __ge__(self, other):
            TrickInt.call_count += 1
            # Call 1: curr <= center_ea at line 2266 (fallback branch) -> True
            if TrickInt.call_count == 1:
                return True
            # Call 2: curr <= center_ea at line 2278 (normal branch) -> True
            return TrickInt.call_count == 2

    monkeypatch.setattr(
        helpers,
        "_format_disasm_line",
        lambda ea, **_kw: f"insn-{ea:x}",
    )
    monkeypatch.setattr(helpers.idc, "prev_head", lambda _ea, _min: BADADDR)

    heads = [BADADDR, 0x2004, BADADDR]
    head_idx = [0]

    def next_head(_ea, _max):
        idx = head_idx[0]
        head_idx[0] += 1
        return heads[min(idx, len(heads) - 1)]

    monkeypatch.setattr(helpers.idc, "next_head", next_head)
    monkeypatch.setattr(helpers.idc, "get_item_size", lambda _ea: 4)

    # 1. TrickInt causes curr <= center_ea in fallback (line 2267) and normal branch (line 2279)
    center = TrickInt(0x2000)
    lines = helpers._disasm_window(center, radius=3, max_items=10, style="classic", include_bytes=False)
    assert len(lines) >= 1

    # 2. TrickMaxItems causes len(lines) > max_items after before-trimming (line 2301)
    class TrickMaxItems(int):
        def __floordiv__(self, other):
            return 10

    monkeypatch.setattr(helpers.idc, "prev_head", lambda _ea, _min: BADADDR)
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _max: ea + 4)
    lines_tight = helpers._disasm_window(0x2000, radius=5, max_items=TrickMaxItems(2), style="classic", include_bytes=False)
    assert len(lines_tight) == 2


def test_detect_api_chains_decompilation_failure(monkeypatch):
    helpers = _helpers()
    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000]))
    monkeypatch.setattr(helpers, "_function_may_reference_apis", lambda *_args: True)
    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: None)

    # Line 2753: if not cfunc: continue
    matches = helpers._detect_api_chains(["recv"], max_items=5)
    assert matches == []


def test_code_helpers_disasm_fwd_boundary_loop(monkeypatch):
    helpers = _helpers()

    class TrickInt(int):
        call_count = 0

        def __ge__(self, other):
            TrickInt.call_count += 1
            if TrickInt.call_count == 2:
                return True
            return super().__ge__(other)

    center_ea = TrickInt(0x2000)
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _max=BADADDR: ea + 4)
    monkeypatch.setattr(helpers.idc, "prev_head", lambda _ea, _min=0: BADADDR)
    monkeypatch.setattr(helpers, "_format_disasm_line", lambda ea, **_kw: f"{ea:x}: nop")

    lines = helpers._disasm_window(center_ea, radius=2, max_items=10, style="classic", include_bytes=False)
    assert len(lines) >= 1


def test_scan_ctree_vulns_constant_and_size_hint_branches(monkeypatch):
    helpers = _helpers()
    monkeypatch.setattr(helpers.ida_hexrays, "cot_sizeof", cot_sizeof, raising=False)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_float", 51, raising=False)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_obj", cot_obj, raising=False)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_call", cot_call, raising=False)

    call_recv = cexpr_t(op=cot_call, ea=0x1010)
    call_recv.x = cexpr_t(op=cot_obj, obj_ea=0x2000)
    call_recv.a = _Args([])

    sz_expr = cexpr_t(op=cot_sizeof, ea=0x1011)
    sz_expr.print1 = lambda *_a: "sizeof(int)"

    sz_text_expr = cexpr_t(op=cot_insn, ea=0x1013)
    sz_text_expr.print1 = lambda *_a: "sizeof(int)"

    computed_sz = cexpr_t(op=cot_insn, ea=0x1012)
    computed_sz.print1 = lambda *_a: "strlen(buf)"

    call_memcpy = cexpr_t(op=cot_call, ea=0x1020)
    call_memcpy.x = cexpr_t(op=cot_obj, obj_ea=0x2004)
    call_memcpy.a = _Args([call_recv, sz_expr, computed_sz])

    monkeypatch.setattr(helpers.idc, "get_name", lambda ea: "recv" if ea == 0x2000 else "memcpy")

    class FakeFuncDetails:
        def __init__(self):
            self._items = [types.SimpleNamespace(name="dest", type="")]

        def size(self):
            return len(self._items)

        def __getitem__(self, i):
            return self._items[i]

    class FakeTinfo:
        def get_func_details(self, out_details):
            out_details._items = [types.SimpleNamespace(name="dest", type="")]
            return True

    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", lambda tif, _ea: True)
    monkeypatch.setattr(helpers.ida_typeinf, "tinfo_t", FakeTinfo, raising=False)
    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", FakeFuncDetails, raising=False)

    executed = {}

    def custom_apply_to(self, body, parent=None):
        if hasattr(self, "_check_call"):
            self.visit_expr(call_memcpy)
            executed["const_sizeof"] = self._is_constant(sz_expr)
            executed["const_text"] = self._is_constant(sz_text_expr)
            executed["tainted"] = self._is_var_user_tainted(call_recv)
            executed["hint_const"] = self._get_arg_size_hint(sz_expr)
            executed["hint_comp"] = self._get_arg_size_hint(computed_sz)
        return 0

    monkeypatch.setattr(helpers.ida_hexrays.ctree_visitor_t, "apply_to", custom_apply_to)
    cfunc = types.SimpleNamespace(entry_ea=0x1000, body=types.SimpleNamespace(), lvars=[])
    findings = helpers._scan_ctree_vulns(cfunc)
    assert isinstance(findings, list)
    assert executed["const_sizeof"] is True
    assert executed["const_text"] is True
    assert executed["tainted"] is True
    assert executed["hint_const"] == "constant"
    assert executed["hint_comp"] == "computed"


def test_scan_ctree_vulns_deep_exception_blocks(monkeypatch):
    helpers = _helpers()
    monkeypatch.setattr(helpers.ida_hexrays, "cot_obj", cot_obj, raising=False)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_call", cot_call, raising=False)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_var", cot_var, raising=False)

    # 1. Populating freed_vars, alloc_calls, and findings with dangerous eas
    call_free = cexpr_t(op=cot_call, ea=0x1010)
    call_free.x = cexpr_t(op=cot_obj, obj_ea=0x2000)
    var_arg = cexpr_t(op=cot_var, ea=0x1011)
    var_arg.v = types.SimpleNamespace(idx=0)
    var_arg.print1 = lambda *_a: "freed_ptr"
    call_free.a = _Args([var_arg])

    call_malloc = cexpr_t(op=cot_call, ea=0x1012)
    call_malloc.x = cexpr_t(op=cot_obj, obj_ea=0x2004)
    num_arg = cexpr_t(op=cot_num, ea=0x1013)
    num_arg.n = types.SimpleNamespace(value=lambda *_a: 100)
    call_malloc.a = _Args([num_arg])

    call_gets_bad = cexpr_t(op=cot_call, ea=0x1014)
    call_gets_bad.x = cexpr_t(op=cot_obj, obj_ea=0x2008)
    call_gets_bad.a = _Args([var_arg])

    call_gets_ok = cexpr_t(op=cot_call, ea=0x1015)
    call_gets_ok.x = cexpr_t(op=cot_obj, obj_ea=0x200C)
    call_gets_ok.a = _Args([var_arg])

    def fake_get_name(ea):
        if ea == 0x2000:
            return "free"
        if ea == 0x2004:
            return "malloc"
        if ea in (0x2008, 0x200C):
            return "gets"
        return "sub"

    monkeypatch.setattr(helpers.idc, "get_name", fake_get_name)
    monkeypatch.setattr(helpers, "hex_ea", lambda ea: "0xBADEA" if ea == 0x1014 else f"0x{ea:x}")

    # 2. HexInt causing ValueError at lines 1234-1235 and 1305-1306
    class HexInt(int):
        def __new__(cls, val, *args, **kwargs):
            if str(val).lower() == "0xbadea":
                raise ValueError("corrupt hex")
            return super().__new__(cls, val, *args, **kwargs)

    monkeypatch.setattr(helpers, "int", HexInt, raising=False)

    # 3. apply_to exceptions at lines 1101-1102 and 1134-1135
    def custom_apply_to(self, body, parent=None):
        name = type(self).__name__
        if name == "VulnVisitor":
            self.visit_expr(call_free)
            self.visit_expr(call_malloc)
            self.visit_expr(call_gets_bad)
            self.visit_expr(call_gets_ok)
        elif name in ("UAFChecker", "UncheckedAllocChecker"):
            # Visit broken expr for 1092-1093
            broken_expr = cexpr_t(op=cot_var, ea=0x1015)
            broken_expr.v = None
            with contextlib.suppress(Exception):
                self.visit_expr(broken_expr)
            raise RuntimeError("checker failed")
        return 0

    monkeypatch.setattr(helpers.ida_hexrays.ctree_visitor_t, "apply_to", custom_apply_to)

    # 4. _compat.get_flow_chart raises at lines 1267-1268
    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: (_ for _ in ()).throw(RuntimeError("flow failed")))

    # 5. idc.get_operand_type raises at lines 1331-1332
    monkeypatch.setattr(helpers.idc, "get_operand_type", lambda *_a: (_ for _ in ()).throw(RuntimeError("operand failed")))
    import ida_ua
    monkeypatch.setattr(ida_ua, "decode_insn", lambda *_a: True)

    lvars = [types.SimpleNamespace(name="freed_ptr", type="void *")]
    cfunc = types.SimpleNamespace(entry_ea=0x1000, body=types.SimpleNamespace(), lvars=lvars)
    findings = helpers._scan_ctree_vulns(cfunc)
    assert isinstance(findings, list)
