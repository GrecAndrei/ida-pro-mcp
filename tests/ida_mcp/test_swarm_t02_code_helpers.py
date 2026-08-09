"""Regression tests for ida_pro_mcp.ida_mcp.tools.code_helpers.

Covers the swarm/t02_code_helpers findings:
- UAF false positives: plain `v = 0` assignments must not mark a variable
  as freed; only free-family calls do, and a NULL-ing assignment clears the
  freed marker (free(p); p = NULL; is the safe idiom, not a UAF).
- fprintf/dprintf/syslog format string is args[1], not args[0].
- strcpy user-taint tests the source (args[1]), not the destination.
- Per-function ALLOC size-argument index (realloc/VirtualAlloc/HeapAlloc/mmap).
- snprintf zero-size check reads args[1], not the destination.
- lvar_t.type is a bound method in SWIG bindings: must be called, not str()'d,
  for type-based taint to work.
- CFG-reachability block no longer dies on a NameError (bb vs _bb).
- proc_name from get_inf_attr arrives as bytes and must be decoded before
  "in" membership checks.
- Stack frame analysis walks frame.members, not get_member(index).
- idc.parse_decl returns a (tinfo, name) tuple; _trace_argument_origin must
  unpack it instead of calling get_func_details on the tuple.
- Pure-helper coverage for the vuln-scanner supporting functions.

Host-side tests: ida_* modules are stubbed via tests._isolated_repo_loader;
no live IDA session is required.
"""

import sys
import types
import unittest

from tests._isolated_repo_loader import load_tool_module

# Hex-Rays ctree op constants (values only need to be unique within the test).
COT_CALL = 24
COT_OBJ = 28
COT_VAR = 21
COT_ASG = 8
COT_NUM = 22
COT_FLOAT = 25
COT_SIZE = 23
COT_STR = 27
COT_REF = 20

BADADDR = 0xFFFFFFFFFFFFFFFF

# Expression stream traversed by the mocked ctree visitors. Mutated in place
# per test so the visitor classes (which close over this list) see fresh data.
EXPR_STREAM: list = []


class _N:
    def __init__(self, val):
        self._val = val

    def value(self, _n):
        return self._val


class _V:
    def __init__(self, idx):
        self.idx = idx


class _Tinfo:
    def __init__(self, tstr):
        self._tstr = tstr

    def dstr(self):
        return self._tstr


class _LVar:
    """lvar_t stand-in whose .type mimics the SWIG bound-method shape."""

    def __init__(self, name, idx, type_str=None, is_arg_var=False, width=4):
        self.name = name
        self.idx = idx
        self.is_arg_var = is_arg_var
        self.width = width
        if type_str is not None:
            t = _Tinfo(type_str)
            self.type = (lambda t=t: t)
        else:
            self.type = None


class _Expr:
    def __init__(self, op, x=None, y=None, a=None, ea=0x1000, text="",
                 string=None, obj_ea=None, n=None, v=None):
        self.op = op
        self.x = x
        self.y = y
        self.a = a
        self.ea = ea
        self.text = text
        self.string = string
        self.obj_ea = obj_ea
        self.n = n
        self.v = v

    def print1(self, _tag=None):
        return self.text


class _Args:
    def __init__(self, args):
        self._args = args

    def size(self):
        return len(self._args)

    def at(self, i):
        return self._args[i]


class _Cfunc:
    def __init__(self, lvars=None, entry_ea=0):
        self.lvars = lvars or []
        self.entry_ea = entry_ea
        self.body = types.SimpleNamespace()
        self.type = None


class _Func:
    def __init__(self, start_ea, end_ea=0):
        self.start_ea = start_ea
        self.end_ea = end_ea


class _BB:
    def __init__(self, start_ea, end_ea, succs=None):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self._succs = succs or []

    def succs(self):
        return iter(self._succs)


class _Frame:
    def __init__(self, members, memqty):
        self.members = members
        self.memqty = memqty

    def get_member(self, offset):
        # Offset-based lookup — the old buggy path used a member index as
        # this offset, so only members at offsets 0..memqty were ever found.
        for m in self.members:
            if m.offset == offset:
                return m
        return None


class _Member:
    def __init__(self, mid, name, size, offset):
        self.id = mid
        self.name = name
        self.size = size
        self.offset = offset


class _FuncData:
    def __init__(self, items):
        self._items = items

    def size(self):
        return len(self._items)

    def __getitem__(self, i):
        return self._items[i]


# --- ctree shape builders ---
def _var_expr(idx, name, ea=0x1000):
    return _Expr(COT_VAR, v=_V(idx), text=name, ea=ea)


def _num_expr(val, ea=0x1000):
    return _Expr(COT_NUM, n=_N(val), text=str(val), ea=ea)


def _str_expr(s, ea=0x1000):
    return _Expr(COT_STR, string=s, text=f'"{s}"', ea=ea)


def _asg_expr(name_idx, name, rhs, ea=0x1000):
    return _Expr(COT_ASG, x=_var_expr(name_idx, name), y=rhs, ea=ea)


def _call_expr(name, args, ea=0x2000, name_ea=0x500):
    callee = _Expr(COT_OBJ, obj_ea=name_ea, text=name)
    return _Expr(COT_CALL, x=callee, a=_Args(args), ea=ea)


def _make_visitor_base():
    class FakeVisitor:
        def __init__(self, flags):
            pass

        def apply_to(self, body, item):
            for e in EXPR_STREAM:
                self.visit_expr(e)
            return 0

        def visit_expr(self, expr):
            return 0

    return FakeVisitor


def _patterns(findings):
    return [f["pattern"] for f in findings]


def _severities(findings):
    return {f["pattern"]: f.get("severity") for f in findings}


class ScanCtreeBase(unittest.TestCase):
    """Loads code_helpers and wires the IDA stubs for _scan_ctree_vulns."""

    def setUp(self):
        self.mod = load_tool_module("code_helpers")
        self._NAME_BY_EA = {}
        self._MEMBER_NAMES = {}
        self._configure_ida()

    def _configure_ida(self):
        hexrays = sys.modules["ida_hexrays"]
        for name, val in (("cot_call", COT_CALL), ("cot_obj", COT_OBJ),
                          ("cot_var", COT_VAR), ("cot_asg", COT_ASG),
                          ("cot_num", COT_NUM), ("cot_float", COT_FLOAT),
                          ("cot_sizeof", COT_SIZE), ("cot_str", COT_STR),
                          ("cot_ref", COT_REF), ("CV_FAST", 0)):
            setattr(hexrays, name, val)
        hexrays.ctree_visitor_t = _make_visitor_base()

        idaapi = sys.modules["idaapi"]
        idaapi.BADADDR = BADADDR
        idaapi.FUNC_LIB = 0x1
        idaapi.INF_PROCNAME = 0x1

        idc_ = sys.modules["idc"]
        idc_.get_name = lambda ea: self._NAME_BY_EA.get(ea, "")
        idc_.get_str_type = lambda ea: None
        idc_.get_strlit_contents = lambda ea, n, m: None
        idc_.get_func_name = lambda ea: ""
        idc_.get_func_attr = lambda ea, attr: None
        idc_.FUNCATTR_FLAGS = 0x1
        idc_.PT_SILENT = 0

        lines = sys.modules["ida_lines"]
        lines.tag_remove = lambda s: s if isinstance(s, str) else (str(s) if s is not None else "")

        funcs = sys.modules["ida_funcs"]
        funcs.get_func = lambda ea: None
        funcs.get_func_name = lambda ea: self._NAME_BY_EA.get(ea, "")
        funcs.get_frame = lambda f: None

        nalt = sys.modules["ida_nalt"]
        nalt.get_tinfo = lambda tif, ea: False

        tinf = sys.modules["ida_typeinf"]
        tinf.tinfo_t = types.SimpleNamespace
        tinf.func_type_data_t = lambda: _FuncData([])

        seg = sys.modules["ida_segment"]
        seg.getseg = lambda ea: None

        bytes_ = sys.modules["ida_bytes"]
        bytes_.get_bytes = lambda ea, n: None

        name_mod = sys.modules["ida_name"]
        name_mod.demangle_name = lambda name, flags: name

        autils = sys.modules["idautils"]
        autils.CodeRefsTo = lambda ea, flow: iter([])

        struct_ = sys.modules["ida_struct"]
        struct_.get_member_name = lambda mid: self._MEMBER_NAMES.get(mid, "")
        struct_.get_member_size = lambda m: int(getattr(m, "size", 0) or 0)

    def scan(self, lvars=None, entry_ea=0):
        cfunc = _Cfunc(lvars=lvars or [], entry_ea=entry_ea)
        return self.mod._scan_ctree_vulns(cfunc)

    def _with_callee(self, name, name_ea=0x500):
        """Map the callee obj_ea to its function name for idc.get_name."""
        self._NAME_BY_EA[name_ea] = name


# --- Finding 1: UAF false positives from `v = 0` assignments ---
class TestUAFDetection(ScanCtreeBase):
    def test_no_uaf_for_plain_zero_assignment(self):
        # `int i = 0; if (i) ...` must not be reported as use-after-free.
        EXPR_STREAM[:] = [
            _asg_expr(0, "i", _num_expr(0)),
            _var_expr(0, "i"),
        ]
        findings = self.scan(lvars=[_LVar("i", 0)])
        self.assertNotIn("use_after_free", _patterns(findings))

    def test_no_uaf_for_free_then_null_safe_idiom(self):
        # free(p); p = NULL; use(p) — the NULL-ing assignment clears the
        # freed marker, so the guarded use is not a UAF.
        self._with_callee("free")
        EXPR_STREAM[:] = [
            _call_expr("free", [_var_expr(0, "p")]),
            _asg_expr(0, "p", _num_expr(0)),
            _var_expr(0, "p"),
        ]
        findings = self.scan(lvars=[_LVar("p", 0)])
        self.assertNotIn("use_after_free", _patterns(findings))

    def test_uaf_detected_for_free_then_use(self):
        # free(p); use(p) without NULL-ing is a genuine use-after-free.
        self._with_callee("free")
        EXPR_STREAM[:] = [
            _call_expr("free", [_var_expr(0, "p")]),
            _var_expr(0, "p"),
        ]
        findings = self.scan(lvars=[_LVar("p", 0)])
        self.assertIn("use_after_free", _patterns(findings))
        uaf = [f for f in findings if f["pattern"] == "use_after_free"]
        self.assertTrue(uaf)
        self.assertEqual(uaf[0]["severity"], "critical")


# --- Finding 2: fprintf/dprintf/syslog format string is args[1] ---
class TestFormatStringIndex(ScanCtreeBase):
    def test_fprintf_literal_format_not_flagged(self):
        # fprintf(fp, "%s %s %s", x): fp (args[0]) is not a literal but is NOT
        # the format string; the literal at args[1] is. The format must be
        # read from args[1] (verified by the specifier mismatch firing).
        self._with_callee("fprintf")
        EXPR_STREAM[:] = [
            _call_expr("fprintf", [
                _var_expr(0, "fp"),
                _str_expr("%s %s %s"),
                _var_expr(1, "x"),
            ]),
        ]
        findings = self.scan(lvars=[_LVar("fp", 0), _LVar("x", 1)])
        self.assertNotIn("format_string_injection", _patterns(findings))
        self.assertIn("format_arg_mismatch", _patterns(findings))

    def test_fprintf_variable_format_flagged(self):
        self._with_callee("fprintf")
        EXPR_STREAM[:] = [
            _call_expr("fprintf", [
                _var_expr(0, "fp"),
                _var_expr(1, "fmt"),
            ]),
        ]
        findings = self.scan(lvars=[_LVar("fp", 0), _LVar("fmt", 1)])
        self.assertIn("format_string_injection", _patterns(findings))

    def test_fprintf_specifier_mismatch_uses_real_format(self):
        # fprintf(fp, "%s %d", x): 2 specifiers but only 1 arg after format.
        self._with_callee("fprintf")
        EXPR_STREAM[:] = [
            _call_expr("fprintf", [
                _var_expr(0, "fp"),
                _str_expr("%s %d"),
                _var_expr(1, "x"),
            ]),
        ]
        findings = self.scan(lvars=[_LVar("fp", 0), _LVar("x", 1)])
        self.assertIn("format_arg_mismatch", _patterns(findings))

    def test_syslog_format_is_arg1(self):
        # syslog(priority, fmt, ...) — format at args[1], not the priority.
        self._with_callee("syslog")
        EXPR_STREAM[:] = [
            _call_expr("syslog", [
                _num_expr(3),
                _var_expr(0, "fmt"),
            ]),
        ]
        findings = self.scan(lvars=[_LVar("fmt", 0)])
        self.assertIn("format_string_injection", _patterns(findings))

    def test_printf_format_is_arg0(self):
        self._with_callee("printf")
        EXPR_STREAM[:] = [
            _call_expr("printf", [_var_expr(0, "fmt")]),
        ]
        findings = self.scan(lvars=[_LVar("fmt", 0)])
        self.assertIn("format_string_injection", _patterns(findings))


# --- Finding 3: strcpy taint tests the source, not the destination ---
class TestStrcpyTaintSource(ScanCtreeBase):
    def test_strcpy_tainted_source_flagged(self):
        self._with_callee("strcpy")
        EXPR_STREAM[:] = [
            _call_expr("strcpy", [
                _var_expr(0, "dst"),
                _var_expr(1, "input_data"),
            ]),
        ]
        findings = self.scan(lvars=[_LVar("dst", 0), _LVar("input_data", 1)])
        self.assertIn("strcpy_user_input", _patterns(findings))

    def test_strcpy_tainted_dest_clean_source_not_flagged(self):
        self._with_callee("strcpy")
        EXPR_STREAM[:] = [
            _call_expr("strcpy", [
                _var_expr(0, "input_data"),
                _var_expr(1, "src"),
            ]),
        ]
        findings = self.scan(lvars=[_LVar("input_data", 0), _LVar("src", 1)])
        self.assertNotIn("strcpy_user_input", _patterns(findings))
        self.assertIn("strcpy_unbounded", _patterns(findings))


# --- Finding 4: per-function ALLOC size-argument index ---
class TestAllocSizeIndex(ScanCtreeBase):
    def test_realloc_size_at_arg1(self):
        # realloc(ptr, size) — the tainted size is args[1].
        self._with_callee("realloc")
        EXPR_STREAM[:] = [
            _call_expr("realloc", [
                _var_expr(0, "p"),
                _var_expr(1, "input_size"),
            ]),
        ]
        findings = self.scan(lvars=[_LVar("p", 0), _LVar("input_size", 1)])
        self.assertIn("user_controlled_alloc_size", _patterns(findings))

    def test_virtualalloc_zero_size_at_arg1(self):
        # VirtualAlloc(addr, 0, type, protect) — size is args[1].
        self._with_callee("VirtualAlloc")
        EXPR_STREAM[:] = [
            _call_expr("VirtualAlloc", [
                _num_expr(0, ea=0x1000),
                _num_expr(0, ea=0x1001),
                _num_expr(0x3000, ea=0x1002),
                _num_expr(0x40, ea=0x1003),
            ]),
        ]
        findings = self.scan()
        self.assertIn("zero_alloc", _patterns(findings))

    def test_malloc_size_at_arg0_still_works(self):
        self._with_callee("malloc")
        EXPR_STREAM[:] = [
            _call_expr("malloc", [_var_expr(0, "input_size")]),
        ]
        findings = self.scan(lvars=[_LVar("input_size", 0)])
        self.assertIn("user_controlled_alloc_size", _patterns(findings))


# --- Finding 5: snprintf zero-size reads args[1] ---
class TestSnprintfZeroSize(ScanCtreeBase):
    def test_snprintf_zero_size_at_arg1(self):
        # snprintf(dest, 0, fmt) — size is args[1], destination is args[0].
        self._with_callee("snprintf")
        EXPR_STREAM[:] = [
            _call_expr("snprintf", [
                _var_expr(0, "dest"),
                _num_expr(0),
                _str_expr("%s"),
            ]),
        ]
        findings = self.scan(lvars=[_LVar("dest", 0)])
        self.assertIn("snprintf_zero_size", _patterns(findings))


# --- Finding 8: lvar_t.type is a bound method; call it for type-based taint ---
class TestLvarTypeTaint(ScanCtreeBase):
    def test_memcpy_size_taint_from_lvar_type(self):
        # memcpy(dst, src, a3) where a3 is an argument with type "char *".
        # Type-based taint must survive the SWIG bound-method lvar.type.
        lvars = [
            _LVar("dst", 0, type_str=None),
            _LVar("src", 1, type_str=None),
            _LVar("a3", 2, type_str="char *", is_arg_var=True),
        ]
        self._with_callee("memcpy")
        EXPR_STREAM[:] = [
            _call_expr("memcpy", [
                _var_expr(0, "dst"),
                _var_expr(1, "src"),
                _var_expr(2, "a3"),
            ]),
        ]
        findings = self.scan(lvars=lvars)
        sev = _severities(findings)
        self.assertEqual(sev.get("user_controlled_copy_size"), "critical")


# --- Finding 6: CFG-reachability block must not NameError ---
class TestCfgReachability(ScanCtreeBase):
    def test_danger_in_loop_finding_produced(self):
        self._NAME_BY_EA = {0x500: "strcpy"}
        EXPR_STREAM[:] = [
            _call_expr("strcpy", [
                _var_expr(0, "dst"),
                _var_expr(1, "input_data"),
            ], ea=0x2000),
        ]

        def fake_get_func(ea):
            return _Func(ea, ea + 0x100)

        sys.modules["ida_funcs"].get_func = fake_get_func
        sys.modules["idaapi"].FlowChart = lambda func: [
            _BB(0x1000, 0x3000, succs=[_BB(0x500, 0x800)])
        ]
        # tainted src gives a critical strcpy_user_input; its EA (0x2000) is
        # inside the single BB whose successor starts earlier (back edge).
        findings = self.scan(
            lvars=[_LVar("dst", 0), _LVar("input_data", 1)], entry_ea=0x401000
        )
        self.assertIn("danger_in_loop", _patterns(findings))


# --- Finding 7: proc_name bytes decode enables arch checks ---
class TestProcNameBytes(ScanCtreeBase):
    def test_procname_bytes_decode_enables_arch_checks(self):
        self._NAME_BY_EA = {0x500: "strcpy"}
        idaapi = sys.modules["idaapi"]
        idaapi.get_inf_attr = lambda attr: b"metapc"
        idaapi.inf = types.SimpleNamespace(procname="")

        def fake_get_func(ea):
            return _Func(ea, ea + 0x100)

        sys.modules["ida_funcs"].get_func = fake_get_func
        sys.modules["idautils"].FuncItems = lambda ea: iter([0x1000])
        sys.modules["idc"].print_insn_mnem = lambda ea: "mov"
        sys.modules["idc"].print_operand = lambda ea, n: "fs:0x30" if n == 0 else ""

        EXPR_STREAM[:] = [
            _call_expr("strcpy", [
                _var_expr(0, "dst"),
                _var_expr(1, "input_data"),
            ]),
        ]
        findings = self.scan(lvars=[_LVar("dst", 0), _LVar("input_data", 1)])
        # A critical finding plus FS/GS access → seh_with_vuln. Reaching this
        # branch requires proc_name bytes to be decoded to a str first.
        self.assertIn("seh_with_vuln", _patterns(findings))


# --- Finding 9: stack-frame analysis walks frame.members ---
class TestStackFrameMembers(ScanCtreeBase):
    def test_stack_canary_found_via_members_iteration(self):
        self._MEMBER_NAMES = {1: "buf", 2: "canary"}
        frame = _Frame(members=[
            _Member(1, "buf", 512, offset=0),
            _Member(2, "canary", 8, offset=512),
        ], memqty=2)

        def fake_get_func(ea):
            return _Func(ea, ea + 0x100)

        sys.modules["ida_funcs"].get_func = fake_get_func
        sys.modules["ida_funcs"].get_frame = lambda f: frame
        # The canary lives at offset 512; get_member(0..memqty-1) would never
        # reach it, but walking frame.members does.
        findings = self.scan(entry_ea=0x401000)
        self.assertIn("stack_canary_present", _patterns(findings))
        self.assertIn("large_stack_buffer", _patterns(findings))


# --- Finding 10: idc.parse_decl returns a (tinfo, name) tuple ---
class TestTraceArgumentOriginParseDecl(unittest.TestCase):
    def setUp(self):
        # load_tool_module installs the stub ida_* modules; configure them
        # AFTER loading so the module's references see our mocks.
        self.mod = load_tool_module("code_helpers")

        idc_ = sys.modules["idc"]
        idc_.get_type = lambda ea: "int foo(char *buf, int len)"
        idc_.PT_SILENT = 0

        def fake_parse_decl(proto, flags):
            # Real IDA returns a (tinfo_t, name) tuple.
            class _ParsedType:
                def get_func_details(self, fd):
                    fd._items = [
                        types.SimpleNamespace(name="buf", type="char *"),
                        types.SimpleNamespace(name="len", type="int"),
                    ]
                    return True

            return _ParsedType(), "foo"

        idc_.parse_decl = fake_parse_decl

        tinf = sys.modules["ida_typeinf"]
        tinf.func_type_data_t = lambda: _FuncData([])

        idaapi = sys.modules["idaapi"]
        idaapi.BADADDR = BADADDR

        funcs = sys.modules["ida_funcs"]
        funcs.get_func_name = lambda ea: f"fn_{ea:x}"

        autils = sys.modules["idautils"]
        autils.XrefsTo = lambda ea, flow: iter([])

        hexrays = sys.modules["ida_hexrays"]
        hexrays.decompile = lambda ea: None

    def test_argument_name_from_parse_decl_tuple(self):
        func = _Func(0x401000, 0x401100)
        result = self.mod._trace_argument_origin(
            func, arg_index=0, max_depth=1, max_callers_per_level=10,
        )
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["argument_name"], "buf")
        self.assertEqual(result["prototype"], "int foo(char *buf, int len)")


# --- Finding 8: _lvar_type_str resolves the SWIG bound-method lvar.type ---
class TestLvarTypeStr(unittest.TestCase):
    def setUp(self):
        self.mod = load_tool_module("code_helpers")

    def test_bound_method_type_is_called(self):
        lv = _LVar("v1", 0, type_str="char *")
        self.assertEqual(self.mod._lvar_type_str(lv), "char *")

    def test_missing_type_returns_empty(self):
        self.assertEqual(self.mod._lvar_type_str(_LVar("v1", 0)), "")

    def test_plain_tinfo_attribute_is_used(self):
        lv = _LVar("v1", 0)
        lv.type = _Tinfo("int")
        self.assertEqual(self.mod._lvar_type_str(lv), "int")


# --- Finding 11: pure-helper coverage ---
class TestPureHelpers(unittest.TestCase):
    def setUp(self):
        self.mod = load_tool_module("code_helpers")

    def test_detect_api_calls(self):
        apis = self.mod._detect_api_calls("memcpy(dst, src, n); snprintf(buf, 64, \"%s\", x);")
        self.assertIn("memcpy", apis)
        self.assertIn("snprintf", apis)

    def test_detect_crypto_hints(self):
        hints, xor_count = self.mod._detect_crypto_hints("aes_encrypt(...); md5update(...)")
        self.assertIn("AES", hints)
        self.assertIn("MD5", hints)
        heavy, count = self.mod._detect_crypto_hints("a ^ b; c ^ d; e ^ f; g ^ h;")
        self.assertIn("XOR_heavy(4)", heavy)
        self.assertEqual(count, 4)

    def test_build_pseudocode_complexity(self):
        pseudo = "int f(int x) {\n  if (x) { for (;;) {} }\n  return x;\n}"
        c = self.mod._build_pseudocode_complexity(pseudo, include_switch_cases=True)
        self.assertGreaterEqual(c["lines"], 4)
        self.assertGreaterEqual(c["branches"], 1)
        self.assertGreaterEqual(c["loops"], 1)

    def test_semantic_pseudocode_summary(self):
        s = self.mod._semantic_pseudocode_summary(
            "int f(int x) {\n  if (x) return 1;\n  return 0;\n}"
        )
        self.assertGreaterEqual(s["line_count"], 3)
        self.assertGreaterEqual(s["if_count"], 1)
        self.assertGreaterEqual(s["return_count"], 2)

    def test_detect_dangerous_patterns_text_fallback(self):
        # cfunc=None forces the pure text-heuristic path.
        findings = self.mod._detect_dangerous_patterns(
            ["strcpy", "system"], "strcpy(dst, src); system(cmd);",
            detailed=True, cfunc=None,
        )
        patterns = _patterns(findings)
        self.assertIn("strcpy_unbounded", patterns)
        self.assertIn("command_injection", patterns)


if __name__ == "__main__":
    unittest.main()
