"""Regression tests for swarm q03_tools fixes (opaque RISC-V firmware support).

Each test maps to a confirmed finding in the q03 work order. All tests run
standalone with _FakeIda-style fakes — no live IDA, no MCP server. The central
scenario is a headerless RISC-V raw blob where IDA has no libc symbols, no
vector table, and no string items:

- code_helpers._is_flow_control_mnemonic / _flow_target_ea: branch-target
  annotation must work for RISC-V jal/jalr/beq/bne (target lives in the LAST
  operand), which the old substring scan missed.
- code_helpers._collect_function_string_entries: when a function has no strlit
  xrefs, fall back to resolving lui+addi / auipc+load constant materialization
  and reading the target bytes as a string.
- code_helpers._detect_firmware_signals: symbol-free firmware signals (ecall,
  CSR access, MMIO store) instead of an empty API report.
- code decompile_all: pagination via offset, fast disasm-only listing mode, and
  honest total_matched/returned/truncated counts.
- code xrefs_to_field: operand-displacement matching (member.offset // 8) with a
  bounded scan and a "no struct field xrefs found" note.
- code strings_in_func: RISC-V GP probe + read-cache invalidation on apply.
- code explain: "no libc APIs detected — bare-metal firmware?" note + purpose.
- ctree: CV_PARENTS-based visitors so nesting/depth tracking works, plus honest
  truncated/returned on dominance_map / get_logic_flow / get.
- types propagate: apply_tinfo only at genuine data items; code refs recorded
  as call_sites without mutation.
- stack_analysis uninitialized: arch-aware store-destination detection that
  recognizes RISC-V compressed stores (c.sw/c.swsp) and ARM64 store-pair.
"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import install_common_stub, load_ida_module, load_tool_module

BADADDR = 0xFFFFFFFFFFFFFFFF


# ---------------------------------------------------------------------------
# Shared fakes
# ---------------------------------------------------------------------------

def _blank_modules(names):
    for name in names:
        sys.modules.setdefault(name, types.ModuleType(name))


def _make_arch_common():
    """Stub overrides for the arch-aware helpers code_helpers relies on.

    Mirrors arch_utils semantics: RISC-V calls are NOT in CALL_MNEMONICS but
    jal/jalr live in UNCONDITIONAL_JUMP_MNEMONICS; beq/bne/blt/bge/bltu/bgeu
    are conditional branches; ecall is a syscall.
    """
    return {
        "get_arch": lambda: "riscv",
        "is_riscv_family": lambda arch=None: True,
        "is_x86_family": lambda arch=None: False,
        "is_arm_family": lambda arch=None: False,
        "is_mips_family": lambda arch=None: False,
        "is_ppc_family": lambda arch=None: False,
        "is_sparc_family": lambda arch=None: False,
        "is_call_mnemonic": lambda m, arch=None: (m or "").lower() in ("call", "bl", "blx", "blr", "bla"),
        "is_return_mnemonic": lambda m, text="", arch=None: (m or "").lower() in ("ret", "c.jr", "mret", "sret", "uret"),
        "is_syscall_mnemonic": lambda m, arch=None: (m or "").lower() in ("ecall", "syscall", "svc", "swi", "sc", "sysenter"),
        "CALL_MNEMONICS": {"call", "bl", "blx", "blr", "bla"},
        "RETURN_MNEMONICS": {"ret", "c.jr", "mret", "sret", "uret"},
        "SYSCALL_MNEMONICS": {"ecall", "syscall", "svc", "swi", "sc", "sysenter"},
        "CONDITIONAL_BRANCH_MNEMONICS": {
            "je", "jne", "beq", "bne", "blt", "bge", "bltu", "bgeu",
            "c.beqz", "c.bnez",
        },
        "UNCONDITIONAL_JUMP_MNEMONICS": {
            "jmp", "j", "jal", "jalr", "c.j", "c.jr", "c.jal", "c.jalr", "b",
        },
        "_inf_bitness": lambda: 32,
        "_inf_procname": lambda: "riscv",
    }


def _real_errors(module):
    """Rebind a tool module to the real IDA-side error contract."""
    err = load_ida_module("error_handling")
    module.make_error = err.make_error
    module.handle_error = err.handle_error
    module.MCPError = err.MCPError
    module.ERROR_HINTS = err.ERROR_HINTS
    return module


class _Op:
    def __init__(self, type_, addr=0, soff=None):
        self.type = type_
        self.addr = addr
        self.soff = soff


class _Insn:
    def __init__(self, ops):
        self.ops = ops


class _Func:
    def __init__(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea


# ---------------------------------------------------------------------------
# 1. RISC-V flow-control classification + branch-target resolution
# ---------------------------------------------------------------------------

class TestRiscVFlowControl(unittest.TestCase):
    """Direct branch targets: jal/jalr/beq/bne must be annotated, and the
    target operand (LAST on RISC-V) must be resolved via operand type."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load_tool_module("code_helpers", common_overrides=_make_arch_common())

    def setUp(self):
        idc = sys.modules["idc"]
        self._idc = idc
        self._idc.print_insn_mnem = lambda ea: "beq"
        self._idc.print_operand = lambda ea, i: ["a0", "a1", "loc_8008"][i] if i < 3 else ""
        self._idc.get_operand_type = lambda ea, i: (7 if i == 2 else 0)
        self._idc.get_operand_value = lambda ea, i: (0x8008 if i == 2 else 0)
        self._idc.get_name = lambda ea: ("firmware_handler" if ea == 0x8008 else "")
        self._idc.get_cmt = lambda ea, rpt: None
        self._idc.generate_disasm_line = lambda ea, flags: "beq a0, a1, loc_8008"
        self._idc.get_item_size = lambda ea: 4
        sys.modules["ida_lines"].tag_remove = lambda s: s
        sys.modules["ida_bytes"].get_byte = lambda ea: 0x90
        sys.modules["idaapi"].get_dref_cnt = lambda ea: 0
        sys.modules["idaapi"].get_dref = lambda ea, i: BADADDR

    def test_is_flow_control_recognizes_riscv_branches(self):
        fc = self.mod._is_flow_control_mnemonic
        self.assertTrue(fc("jal", "riscv"))
        self.assertTrue(fc("jalr", "riscv"))
        self.assertTrue(fc("beq", "riscv"))
        self.assertTrue(fc("bne", "riscv"))
        self.assertTrue(fc("blt", "riscv"))
        self.assertTrue(fc("c.jal", "riscv"))
        self.assertTrue(fc("ecall", "riscv"))
        self.assertFalse(fc("addi", "riscv"))
        self.assertFalse(fc("lui", "riscv"))
        self.assertFalse(fc("", "riscv"))

    def test_flow_target_resolves_last_operand_on_riscv(self):
        # beq rs1, rs2, off — the target is operand 2, not operand 0.
        self.assertEqual(self.mod._flow_target_ea(0x8000), 0x8008)

    def test_format_disasm_structured_annotates_riscv_branch(self):
        r = self.mod._format_disasm_structured(0x8000)
        self.assertEqual(r.get("branch_target"), "0x8008")
        self.assertEqual(r.get("branch_name"), "firmware_handler")

    def test_annotate_branch_target_returns_named_target(self):
        self.assertEqual(self.mod._annotate_branch_target(0x8000, ""),
                         "firmware_handler (0x8008)")


# ---------------------------------------------------------------------------
# 2. String fallback via constant loads (opaque RISC-V blob, no strlit items)
# ---------------------------------------------------------------------------

class TestStringConstantLoadFallback(unittest.TestCase):
    """A function with no strlit xrefs but a lui+addi constant load that points
    at printable bytes must still resolve its string."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load_tool_module("code_helpers", common_overrides=_make_arch_common())

    def setUp(self):
        sys.modules["ida_funcs"].get_func = lambda ea: _Func(0x8000, 0x800C)
        idc = sys.modules["idc"]
        idc.print_insn_mnem = lambda ea: {0x8000: "lui", 0x8004: "addi", 0x8008: "addi"}.get(ea, "")
        idc.print_operand = lambda ea, i: {
            0x8000: ("a0", "0x20", ""),
            0x8004: ("a0", "a0", "0x10"),
            0x8008: ("a0", "a0", "0x0"),
        }[ea][i]
        idc.get_operand_value = lambda ea, i: {
            0x8000: (0, 0x20, 0),
            0x8004: (0, 0, 0x10),
            0x8008: (0, 0, 0x0),
        }[ea][i]
        idc.next_head = lambda ea, end=None: ea + 4
        sys.modules["idautils"].FuncItems = lambda start: iter([0x8000, 0x8004, 0x8008])
        sys.modules["idautils"].XrefsFrom = lambda item, f: iter([])
        sys.modules["ida_bytes"].is_loaded = lambda ea: ea == 0x20010
        sys.modules["ida_bytes"].get_bytes = lambda ea, n: (
            b"Hello Firmware\x00" + b"\x00" * 80 if ea == 0x20010 else None
        )

    def test_falls_back_to_constant_load_strings(self):
        entries = self.mod._collect_function_string_entries(0x8000)
        self.assertEqual(len(entries), 1, entries)
        self.assertEqual(entries[0]["addr"], hex(0x20010))
        self.assertEqual(entries[0]["value"], "Hello Firmware")

    def test_collect_function_strings_returns_values_only(self):
        self.assertEqual(self.mod._collect_function_strings(0x8000), ["Hello Firmware"])


# ---------------------------------------------------------------------------
# 3. Symbol-free firmware signals
# ---------------------------------------------------------------------------

EXPR_STREAM = []  # emptied per-test; drives the t02-style ctree visitor base


def _make_ctree_visitor_base():
    """t02-style visitor base: replay EXPR_STREAM via visit_expr, ignore flags."""

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


class _FuncData:
    def __init__(self, items):
        self._items = items

    def size(self):
        return len(self._items)

    def __getitem__(self, i):
        return self._items[i]


def _load_code(common):
    """Load code.py with a fresh code_helpers.

    code.py does ``from .code_helpers import *`` after ``from ._common
    import *``, and code_helpers re-exports the ida_* module names. If a
    previous test class cached code_helpers in sys.modules, its stale ida_*
    bindings (e.g. a blank ida_typeinf without get_idati, a blank idautils
    without XrefsTo) would shadow the fresh modules this setUp just installed.
    Re-executing code_helpers against the current stub guarantees the bindings
    code.py sees are the fresh ones.
    """
    load_tool_module("code_helpers", common_overrides=common)
    return load_tool_module("code", common_overrides=common)


def _configure_ctree_scan_harness():
    """Install the t02-proven fake set that lets _scan_ctree_vulns run end to
    end with an empty expression stream (no UAF/format/taint findings)."""
    hexrays = sys.modules["ida_hexrays"]
    for name, val in (("cot_call", 101), ("cot_obj", 102), ("cot_var", 107),
                      ("cot_asg", 106), ("cot_num", 104), ("cot_float", 105),
                      ("cot_str", 109), ("cot_sizeof", 110), ("cot_ref", 111),
                      ("CV_FAST", 0)):
        setattr(hexrays, name, val)
    hexrays.ctree_visitor_t = _make_ctree_visitor_base()

    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = BADADDR
    idaapi.FUNC_LIB = 0x1
    idaapi.INF_PROCNAME = 0x1
    idaapi.get_inf_attr = lambda attr: 0
    idaapi.inf = types.SimpleNamespace(procname="")

    idc = sys.modules["idc"]
    idc.get_name = lambda ea: ""
    idc.get_str_type = lambda ea: None
    idc.get_strlit_contents = lambda ea, n, m: None
    idc.get_func_name = lambda ea: ""
    idc.get_func_attr = lambda ea, attr: None
    idc.FUNCATTR_FLAGS = 0x1
    idc.PT_SILENT = 0

    sys.modules["ida_lines"].tag_remove = lambda s: s if isinstance(s, str) else (str(s) if s is not None else "")

    funcs = sys.modules["ida_funcs"]
    funcs.get_func = lambda ea: _Func(0xA000, 0xA010)
    funcs.get_func_name = lambda ea: ""
    funcs.get_frame = lambda f: None

    sys.modules["ida_nalt"].get_tinfo = lambda tif, ea: False
    tinf = sys.modules["ida_typeinf"]
    tinf.tinfo_t = types.SimpleNamespace
    tinf.func_type_data_t = lambda: _FuncData([])
    sys.modules["ida_segment"].getseg = lambda ea: None
    sys.modules["ida_bytes"].get_bytes = lambda ea, n: None
    sys.modules["ida_name"].demangle_name = lambda name, flags: name
    sys.modules["idautils"].CodeRefsTo = lambda ea, flow: iter([])
    struct_ = sys.modules["ida_struct"]
    struct_.get_member_name = lambda mid: ""
    struct_.get_member_size = lambda m: 0


class TestFirmwareSignals(unittest.TestCase):
    """MMIO stores, traps (ecall), and RISC-V CSR access must surface as
    firmware signals even with no libc symbols present."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load_tool_module("code_helpers", common_overrides=_make_arch_common())

    def setUp(self):
        _configure_ctree_scan_harness()
        sys.modules["ida_funcs"].get_func = lambda ea: _Func(0xA000, 0xA010)
        idc = sys.modules["idc"]
        idc.print_insn_mnem = lambda ea: {0xA000: "ecall", 0xA004: "sw", 0xA008: "csrw"}.get(ea, "")
        idc.get_operand_value = lambda ea, i: 0
        idc.next_head = lambda ea, end=None: ea + 4
        ua = sys.modules["ida_ua"]
        ua.o_displ = 4
        ua.o_mem = 2
        ua.insn_t = lambda: _Insn([_Op(0), _Op(ua.o_displ, addr=0x40001000)])
        ua.decode_insn = lambda insn, ea: 1
        ua.get_operand_value = lambda insn, i: insn.ops[i].addr
        sys.modules["ida_bytes"].is_loaded = lambda ea: True

    def test_detects_ecall_csr_and_mmio(self):
        signals = self.mod._detect_firmware_signals(0xA000)
        self.assertIn("syscall:ecall", signals)
        self.assertIn("csr_access:csrw", signals)
        self.assertIn("mmio_store:0x40001000", signals)

    def test_firmware_signal_findings_in_ctree_scan(self):
        # Empty instruction stream: no UAF/format findings, but the firmware
        # block must still run. _detect_firmware_signals is unit-tested above;
        # here pin the wiring into _scan_ctree_vulns.
        EXPR_STREAM[:] = []
        original_detector = self.mod._detect_firmware_signals
        self.mod._detect_firmware_signals = (
            lambda ea, pseudo="": ["mmio_store:0x40001000"]
        )

        try:
            class _Cfunc:
                entry_ea = 0xA000
                type = None
                lvars = []
                body = types.SimpleNamespace()

            findings = self.mod._scan_ctree_vulns(_Cfunc())
            fw = [f for f in findings if f.get("pattern") == "firmware_signal"]
            self.assertTrue(fw, findings)
            self.assertIn("mmio_store:0x40001000", fw[0]["evidence"])
        finally:
            self.mod._detect_firmware_signals = original_detector


# ---------------------------------------------------------------------------
# 4. code decompile_all — pagination, listing mode, honest counts
# ---------------------------------------------------------------------------

class TestDecompileAllPagination(unittest.TestCase):
    """decompile_all must page via offset, offer a cheap listing mode, and
    report total_matched/returned/truncated honestly."""

    def setUp(self):
        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = BADADDR
        idaapi.get_func = lambda ea: _Func(ea, ea + 0x20)

        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func_name = lambda ea: f"firmware_{(ea - 0x8000) // 0x10}"
        # compat.get_func_info resolves ida_funcs via sys.modules; expose both
        # the legacy get_func (mirroring idaapi.get_func) and the 9.4 EA surface.
        ida_funcs.get_func = idaapi.get_func
        ida_funcs.ida_idaapi = types.SimpleNamespace(BADADDR=BADADDR)
        ida_funcs.func_entry_info_t = types.SimpleNamespace
        ida_funcs.get_func_entry_info = lambda out, ea, flags=0: False

        idautils = types.ModuleType("idautils")
        idautils.Functions = lambda: iter([0x8000 + i * 0x10 for i in range(5)])
        idautils.FuncItems = lambda start: iter([start])
        idautils.XrefsFrom = lambda item, f: iter([])

        _blank_modules(["ida_bytes", "ida_segment", "ida_name", "ida_typeinf",
                        "ida_nalt", "ida_hexrays", "ida_frame", "ida_struct",
                        "ida_lines", "ida_ua", "ida_kernwin", "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils

        common = {"idaapi": idaapi, "ida_funcs": ida_funcs, "idautils": idautils}
        install_common_stub(common)
        self.mod = _load_code(common)
        self.decomp_calls = []

        def fake_decompile(ea):
            self.decomp_calls.append(ea)
            cfunc = types.SimpleNamespace()
            cfunc.__str__ = lambda self, _ea=ea: f"/* {_ea} */"
            return cfunc, None

        self.mod._decompile_with_diagnostics = fake_decompile
        self.mod.get_prototype = lambda f: "int f();"

    def test_offset_pages_and_reports_honest_counts(self):
        result = self.mod.code(action="decompile_all", query="firmware", limit=2, offset=1)
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["total_functions"], 2, result)
        self.assertEqual(result["count"], 2, result)
        self.assertEqual(result["total_matched"], 5, result)
        self.assertEqual(result["offset"], 1, result)
        self.assertEqual(result["returned"], 2, result)
        self.assertTrue(result["truncated"], result)
        names = [r["name"] for r in result["results"]]
        self.assertEqual(names, ["firmware_1", "firmware_2"], names)

    def test_listing_mode_skips_decompile(self):
        result = self.mod.code(action="decompile_all", query="firmware", limit=2, mode="listing")
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["mode"], "listing")
        self.assertEqual(self.decomp_calls, [], "listing mode must not decompile")
        for r in result["results"]:
            self.assertEqual(r["mode"], "listing")
            self.assertNotIn("code", r)
            self.assertIn("size", r)

    def test_full_mode_still_decompiles(self):
        result = self.mod.code(action="decompile_all", query="firmware", limit=2)
        self.assertEqual(len(self.decomp_calls), 2, self.decomp_calls)
        self.assertIn("code", result["results"][0])

    def test_no_matches_reports_zero_page(self):
        result = self.mod.code(action="decompile_all", query="no_such", limit=2)
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["total_matched"], 0)
        self.assertEqual(result["truncated"], False)


# ---------------------------------------------------------------------------
# 5. code xrefs_to_field — operand-displacement matching + bounded scan
# ---------------------------------------------------------------------------

class TestXrefsToFieldOperandMatch(unittest.TestCase):
    """xrefs_to_field must resolve member.offset in bits (//8), match the
    decoded operand displacement exactly, and say so when nothing is found."""

    def setUp(self):
        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = BADADDR
        idaapi.get_func = lambda ea: _Func(0x9000, 0x9010)

        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func_name = lambda ea: "parse_pkt"

        idautils = types.ModuleType("idautils")
        idautils.Functions = lambda: iter([0x9000])
        idautils.FuncItems = lambda start: iter([0x9004, 0x9008])

        ida_typeinf = types.ModuleType("ida_typeinf")

        class _Member:
            name = "len"
            offset = 64  # bits -> 8 bytes after //8
            type = ""

        class _UDT:
            def __iter__(self):
                return iter([_Member()])

        class _TInfo:
            def get_named_type(self, til, name):
                return name == "pkt_hdr"

            def is_struct(self):
                return True

            def is_union(self):
                return False

            def get_udt_details(self, udt):
                return True

        ida_typeinf.get_idati = lambda: None
        ida_typeinf.get_ordinal_qty = lambda til: 0
        ida_typeinf.tinfo_t = _TInfo
        ida_typeinf.udt_type_data_t = _UDT

        _blank_modules(["ida_bytes", "ida_segment", "ida_name", "ida_nalt",
                        "ida_hexrays", "ida_frame", "ida_struct", "ida_lines",
                        "ida_ua", "ida_kernwin", "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils
        sys.modules["ida_typeinf"] = ida_typeinf
        sys.modules["idc"].print_insn_mnem = lambda ea: "lw"
        sys.modules["idc"].generate_disasm_line = lambda ea, flags: "lw a0, 8(a1)"
        sys.modules["ida_lines"].tag_remove = lambda s: s

        ua = sys.modules["ida_ua"]
        ua.o_displ = 4
        ua.o_phrase = 5
        ua.insn_t = lambda: _Insn([_Op(0), _Op(ua.o_displ, addr=8)])
        ua.decode_insn = lambda insn, ea: 1
        ua.get_operand_value = lambda insn, i: insn.ops[i].addr

        common = {"idaapi": idaapi, "ida_funcs": ida_funcs, "idautils": idautils,
                  "ida_typeinf": ida_typeinf}
        install_common_stub(common)
        self.mod = _load_code(common)

    def test_matches_operand_displacement(self):
        result = self.mod.code(action="xrefs_to_field", addrs="0x9000",
                               field_name="pkt_hdr.len")
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["struct"], "pkt_hdr")
        self.assertEqual(result["offset"], 8)
        self.assertEqual(result["offset_hex"], "0x8")
        self.assertEqual(result["count"], 2, result)
        self.assertEqual({x["func"] for x in result["xrefs"]}, {"0x9000"})

    def test_no_match_emits_explicit_note(self):
        # Point the operand at a different displacement: no instruction matches.
        sys.modules["ida_ua"].insn_t = lambda: _Insn([_Op(0), _Op(4, addr=16)])
        result = self.mod.code(action="xrefs_to_field", addrs="0x9000",
                               field_name="pkt_hdr.len")
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["count"], 0, result)
        self.assertIn("No struct field xrefs found", result["note"])


# ---------------------------------------------------------------------------
# 6. code strings_in_func — RISC-V GP probe + cache invalidation
# ---------------------------------------------------------------------------

class TestStringsInFuncRiscVGp(unittest.TestCase):
    """On RISC-V with no strings found, strings_in_func probes GP (x3) and
    drops the read cache when the GP value was applied + reanalysis queued."""

    def setUp(self):
        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = BADADDR
        idaapi.get_func = lambda ea: _Func(0xB000, 0xB020)

        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda ea: _Func(0xB000, 0xB020)
        ida_funcs.get_func_name = lambda ea: "firmware_init"

        idautils = types.ModuleType("idautils")
        idautils.FuncItems = lambda start: iter([])
        idautils.XrefsFrom = lambda item, f: iter([])

        _blank_modules(["ida_bytes", "ida_segment", "ida_name", "ida_typeinf",
                        "ida_nalt", "ida_hexrays", "ida_frame", "ida_struct",
                        "ida_lines", "ida_ua", "ida_kernwin", "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils
        sys.modules["idc"].print_insn_mnem = lambda ea: ""
        sys.modules["idc"].print_operand = lambda ea, i: ""
        sys.modules["idc"].get_operand_value = lambda ea, i: 0
        sys.modules["idc"].get_strlit_contents = lambda ea, n=0, m=0: None
        sys.modules["idc"].next_head = lambda ea, end=None: ea + 4

        common = {**_make_arch_common(), "idaapi": idaapi,
                  "ida_funcs": ida_funcs, "idautils": idautils}
        install_common_stub(common)
        self.mod = _load_code(common)
        self.cache_invalidated = 0
        self.mod._invalidate_tool_read_cache = self._spy_cache

    def _spy_cache(self):
        self.cache_invalidated += 1

    def test_unresolved_gp_note(self):
        self.mod._detect_riscv_gp = lambda: {"found": False, "applied": False,
                                             "note": "GP not resolvable"}
        result = self.mod.code(action="strings_in_func", addrs="0xB000")
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["count"], 0)
        self.assertIn("No string references found", result["note"])
        self.assertIn("GP (x3) unresolved", result["note"])
        self.assertNotIn("riscv_gp", result)
        self.assertEqual(self.cache_invalidated, 0)

    def test_applied_gp_records_note_and_invalidates_cache(self):
        self.mod._detect_riscv_gp = lambda: {"found": True, "applied": True,
                                             "gp": 0x3FC00,
                                             "reanalysis_queued": True}
        result = self.mod.code(action="strings_in_func", addrs="0xB000")
        self.assertTrue(result.get("ok"), result)
        self.assertIn("riscv_gp", result)
        self.assertTrue(result["riscv_gp"]["found"])
        self.assertEqual(self.cache_invalidated, 1)


# ---------------------------------------------------------------------------
# 7. code explain — bare-metal firmware signal
# ---------------------------------------------------------------------------

class TestExplainBareMetalFirmware(unittest.TestCase):
    """A symbol-poor function with no libc APIs must be described as
    bare-metal firmware, not 'internal computation'."""

    def setUp(self):
        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = BADADDR
        idaapi.get_func = lambda ea: _Func(0xC000, 0xC100)
        idaapi.FlowChart = lambda func: []

        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func_name = lambda ea: "soc_power_mgr"
        # code.py's explain action resolves get_func through _compat, which
        # reads sys.modules["ida_funcs"] at call time — expose the legacy
        # get_func there (mirrors idaapi.get_func).
        ida_funcs.get_func = idaapi.get_func

        idautils = types.ModuleType("idautils")
        idautils.XrefsTo = lambda ea, f: iter([])
        idautils.FuncItems = lambda start: iter([])
        idautils.XrefsFrom = lambda item, f: iter([])

        _blank_modules(["ida_bytes", "ida_segment", "ida_name", "ida_typeinf",
                        "ida_nalt", "ida_hexrays", "ida_frame", "ida_struct",
                        "ida_lines", "ida_ua", "ida_kernwin", "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils
        # idc previously leaked in from an earlier test; be self-sufficient.
        idc = sys.modules.get("idc") or types.ModuleType("idc")
        sys.modules["idc"] = idc
        idc.get_strlit_contents = lambda ea, n=0, m=0: None
        sys.modules["idc"].get_name = lambda ea: ""
        sys.modules["idc"].get_func_name = lambda ea: "soc_power_mgr"

        common = {"idaapi": idaapi, "ida_funcs": ida_funcs, "idautils": idautils}
        install_common_stub(common)
        self.mod = _load_code(common)

        pseudo = "void soc_power_mgr(){ *(volatile unsigned*)0x40001000 = 1u; }"
        cfunc = types.SimpleNamespace()
        cfunc.__str__ = lambda self, _p=pseudo: _p
        self.mod._decompile_with_diagnostics = lambda ea: (cfunc, None)
        self.mod._detect_firmware_signals = lambda ea, pseudo="": ["mmio_store:0x40001000"]

    def test_bare_metal_note_and_purpose(self):
        result = self.mod.code(action="explain", addrs="0xC000")
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["api_note"], "no libc APIs detected — bare-metal firmware?")
        self.assertIn("bare-metal/RTOS firmware operations", " ".join(result["purpose"]))
        self.assertEqual(result["firmware_signals"], ["mmio_store:0x40001000"])
        self.assertIn("bare-metal", result["summary"])


# ---------------------------------------------------------------------------
# 8. ctree — CV_PARENTS nesting + honest truncation
# ---------------------------------------------------------------------------

CIT = {"cit_if": 1, "cit_while": 2, "cit_for": 3, "cit_do": 4,
       "cit_switch": 5, "cit_return": 6}
COT = {"cot_call": 101, "cot_obj": 102, "cot_cmp": 103, "cot_num": 104,
       "cot_str": 109, "cot_asg": 106, "cot_var": 107}


class _CNode:
    def __init__(self, op, kind, children=(), ea=0x1000, text=None):
        self.op = op
        self._kind = kind
        self.ea = ea
        self._children = list(children)
        self._text = text

    def print1(self, _out=None):
        return self._text or f"<{self.op}>"


def _expr(op, ea=0x1000, children=(), text=None):
    return _CNode(op, "expr", children=children, ea=ea, text=text)


def _insn(op, ea=0x1000, children=(), text=None, **attrs):
    n = _CNode(op, "insn", children=children, ea=ea, text=text)
    for k, v in attrs.items():
        setattr(n, k, v)
    return n


class _FakeVisitorBase:
    """Replays a node tree in pre/post order — like a real CV_PARENTS walk:
    visit_insn/visit_expr fire on entry, children are walked, then
    leave_insn/leave_expr fire on exit."""

    def __init__(self, flags):
        self.flags = flags

    def apply_to(self, body, item=None):
        self._walk(body)
        return 0

    def _walk(self, node):
        if node is None:
            return
        if node._kind == "expr":
            if self.visit_expr(node):
                return
            for c in node._children:
                self._walk(c)
            self.leave_expr(node)
        else:
            if self.visit_insn(node):
                return
            for c in node._children:
                self._walk(c)
            self.leave_insn(node)

    def visit_expr(self, e):
        return 0

    def leave_expr(self, e):
        return 0

    def visit_insn(self, i):
        return 0

    def leave_insn(self, i):
        return 0


def _set_up_ctree(cfunc):
    _blank_modules(["ida_ida", "ida_entry", "ida_auto", "ida_segment",
                    "ida_loader", "ida_nalt", "ida_bytes", "ida_lines",
                    "idautils"])
    hexrays = sys.modules.setdefault("ida_hexrays", types.ModuleType("ida_hexrays"))
    hexrays.init_hexrays_plugin = lambda: True
    hexrays.decompile = lambda ea, hf=None: cfunc
    hexrays.ctree_visitor_t = _FakeVisitorBase
    hexrays.get_ctype_name = lambda op: f"op_{op}"
    hexrays.CV_FAST = 0
    hexrays.CV_PARENTS = 2
    hexrays.user_lvar_modifier_t = object
    for name, val in CIT.items():
        setattr(hexrays, name, val)
    for name, val in COT.items():
        setattr(hexrays, name, val)

    idaapi = sys.modules.setdefault("idaapi", types.ModuleType("idaapi"))
    idaapi.BADADDR = BADADDR
    idaapi.is_mapped = lambda ea: True

    idc = sys.modules.setdefault("idc", types.ModuleType("idc"))
    idc.get_func_name = lambda ea: "firmware_main"

    ida_funcs = sys.modules.setdefault("ida_funcs", types.ModuleType("ida_funcs"))
    ida_funcs.get_func = lambda ea: _Func(ea, ea + 0x100)

    ida_lines = sys.modules.setdefault("ida_lines", types.ModuleType("ida_lines"))
    ida_lines.tag_remove = lambda s: s if isinstance(s, str) else (str(s) if s is not None else "")


def _nested_if_call_tree():
    """if(A){ if(B){} call(after) } — the call closes INSIDE A but AFTER B."""
    root = _insn(CIT["cit_if"], ea=0x1000, children=(
        _expr(COT["cot_cmp"], ea=0x1001, text="a > 5"),
        _insn(CIT["cit_if"], ea=0x1004, children=(
            _expr(COT["cot_cmp"], ea=0x1005, text="b == 0"),
        )),
        _expr(COT["cot_call"], ea=0x1008, text="foo()"),
    ))
    root.cif = types.SimpleNamespace(expr=root._children[0])
    inner = root._children[1]
    inner.cif = types.SimpleNamespace(expr=inner._children[0])
    return root


class TestCtreeNestingAndTruncation(unittest.TestCase):
    """CV_FAST broke depth/control_stack tracking (leave_* never fired). The
    visitors must use CV_PARENTS so nesting resolves, and report truncation."""

    @classmethod
    def setUpClass(cls):
        _set_up_ctree(None)
        cls.mod = load_tool_module("ctree")

    def test_visitor_flags_use_cv_parents(self):
        flags = self.mod._ctree_visitor_flags()
        self.assertEqual(flags, sys.modules["ida_hexrays"].CV_PARENTS)
        self.assertNotEqual(flags, sys.modules["ida_hexrays"].CV_FAST)

    def test_logic_graph_nesting_resolves_call_parent(self):
        cfunc = types.SimpleNamespace(body=_nested_if_call_tree())
        graph = self.mod._ctree_build_logic_graph(cfunc, max_nodes=200)
        nodes = {n["ea"]: n for n in graph["nodes"]}
        call = nodes["0x1008"]
        # Depth must decrement after the inner if closes: call is at depth 1,
        # not 2 (which is what the CV_FAST no-leave bug produced).
        self.assertEqual(call["depth"], 1, graph["nodes"])
        edge = [e for e in graph["edges"]
                if e["to"] == call["id"] and e["relation"] == "contains_call"]
        self.assertEqual(len(edge), 1, graph["edges"])
        # The call's controller is the OUTER if (0x1000), not the inner one.
        self.assertEqual(edge[0]["from"], nodes["0x1000"]["id"], graph["edges"])

    def test_logic_graph_truncates_honestly(self):
        cfunc = types.SimpleNamespace(body=_nested_if_call_tree())
        graph = self.mod._ctree_build_logic_graph(cfunc, max_nodes=2)
        self.assertTrue(graph["truncated"])
        self.assertEqual(graph["node_count"], 2, graph)

    def test_dominance_map_truncates_honestly(self):
        cfunc = types.SimpleNamespace(body=_nested_if_call_tree())
        dom = self.mod._ctree_build_dominance_map(cfunc, max_nodes=1)
        self.assertTrue(dom["truncated"])
        self.assertEqual(dom["condition_count"], 1, dom)

    def test_get_logic_flow_action_returns_graph(self):
        cfunc = types.SimpleNamespace(body=_nested_if_call_tree())
        sys.modules["ida_hexrays"].decompile = lambda ea, hf=None: cfunc
        res = self.mod.ctree(action="get_logic_flow", addr="0x1000", depth=5)
        self.assertTrue(res.get("ok"), res)
        self.assertEqual(res["function"], "firmware_main")
        self.assertIn("0x1008", res["logic_flow"])


# ---------------------------------------------------------------------------
# 9. types propagate — apply only at data items, record code call-sites
# ---------------------------------------------------------------------------

class TestPropagateDataOnly(unittest.TestCase):
    """propagate must never apply_tinfo at a code address: code refs become
    call_sites, and only genuine data items receive the type."""

    def setUp(self):
        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = BADADDR
        idaapi.get_func = lambda ea: None

        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda ea: None
        ida_funcs.get_func_name = lambda ea: ""

        class _Xref:
            def __init__(self, frm, iscode):
                self.frm = frm
                self.iscode = iscode
                self.type = 0x10

        idautils = types.ModuleType("idautils")
        idautils.XrefsTo = lambda ea, f: iter([
            _Xref(0x4000, iscode=True),      # code call site
            _Xref(0x5000, iscode=False),     # data item -> applied
            _Xref(0x6000, iscode=False),     # not a data item -> skipped
        ])

        ida_bytes = types.ModuleType("ida_bytes")
        flags = {0x5000: 0xFF, 0x6000: 0x2}
        ida_bytes.get_flags = lambda ea: flags.get(ea, 0)
        ida_bytes.is_data = lambda fl: fl == 0xFF

        ida_typeinf = types.ModuleType("ida_typeinf")
        ida_typeinf.TINFO_DEFINITE = 1

        class _TInfo:
            def get_named_type(self, til, name):
                return name == "pkt_hdr"

            def get_size(self):
                return 8

        ida_typeinf.tinfo_t = _TInfo
        ida_typeinf.get_named_type_tid = lambda name: 0xABC
        applied = []
        ida_typeinf.apply_tinfo = lambda frm, tif, flags: (applied.append(frm), True)[1]

        _blank_modules(["ida_segment", "ida_name", "ida_nalt", "ida_hexrays",
                        "ida_frame", "ida_struct", "ida_lines", "ida_ua",
                        "ida_kernwin", "ida_loader", "ida_dbg", "ida_ida",
                        "ida_entry", "ida_auto"])
        sys.modules["idaapi"] = idaapi
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils
        sys.modules["ida_bytes"] = ida_bytes
        sys.modules["ida_typeinf"] = ida_typeinf

        common = {"idaapi": idaapi, "ida_funcs": ida_funcs,
                  "idautils": idautils, "ida_bytes": ida_bytes,
                  "ida_typeinf": ida_typeinf}
        install_common_stub(common)
        self.mod = load_tool_module("types")
        _real_errors(self.mod)
        self.mod._inf_is_64bit = lambda: True
        self.mod._inf_is_be = lambda: False
        self.applied = applied

    def test_code_xrefs_become_call_sites_not_mutations(self):
        result = self.mod.types(action="propagate", seed_addr="0x4000",
                                type_name="pkt_hdr")
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(self.applied, [0x5000], self.applied)
        self.assertEqual(result["propagated_to"], ["0x5000"])
        self.assertEqual(result["total_xrefs"], 3, result)
        # Code xref recorded as a call site, not a mutation.
        self.assertEqual(len(result["call_sites"]), 1, result)
        self.assertEqual(result["call_sites"][0]["from_hex"], "0x4000")
        self.assertEqual(result["call_sites"][0]["status"], "referenced")
        self.assertEqual(result["call_sites"][0]["xref_kind"], "code")
        # Non-data origin skipped without applying.
        skipped = [loc for loc in result["locations"] if loc.get("status") == "skipped"]
        self.assertEqual(len(skipped), 1, result)
        self.assertEqual(skipped[0]["from_hex"], "0x6000")
        self.assertIn("not a data item", skipped[0]["reason"])
        self.assertIn("without mutation", result["note"])


# ---------------------------------------------------------------------------
# 10. stack_analysis uninitialized — arch-aware store destinations
# ---------------------------------------------------------------------------

class TestUninitializedRiscVStores(unittest.TestCase):
    """RISC-V compressed stores (c.swsp) must be recognized as writes, so an
    initialized local is excluded and an unwritten local is reported."""

    def setUp(self):
        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = BADADDR
        idaapi.get_func = lambda ea: _Func(0xD000, 0xD020)

        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func_name = lambda ea: "rtos_task"
        # _compat resolves get_func through sys.modules["ida_funcs"] (mirrors
        # idaapi.get_func); same alias pattern as the other q03 fixtures.
        ida_funcs.get_func = idaapi.get_func

        ida_frame = types.ModuleType("ida_frame")

        class _FMember:
            def __init__(self, idx, soff, eoff):
                self.id = idx
                self.soff = soff
                self.eoff = eoff

        class _FFrame:
            members = [_FMember(0, 0x0, 0x4),   # arg_0
                       _FMember(1, 0x4, 0x8),   #  r1 (saved)
                       _FMember(2, 0x10, 0x14),  # var_0 — written by c.swsp
                       _FMember(3, 0x20, 0x24)]  # var_1 — never written

            def __init__(self):
                self.memqty = len(self.members)

            def get_member(self, i):
                return self.members[i] if i < self.memqty else None

        frame = _FFrame()
        ida_frame.get_frame = lambda func: frame
        # _member_name consults ida_frame.get_member_name(member.id); without it
        # the fallback names every member var_<idx>, which would move var_0 to
        # offset 0x0 (the arg) and defeat the write-tracking assertions.
        ida_frame.get_member_name = lambda mid: {0: "arg_0", 1: "r1",
                                                 2: "var_0", 3: "var_1"}[mid]

        _blank_modules(["idc", "ida_bytes", "ida_segment", "ida_name", "ida_typeinf",
                        "ida_nalt", "ida_hexrays", "ida_struct", "ida_lines",
                        "ida_ua", "ida_kernwin", "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["ida_frame"] = ida_frame
        sys.modules["ida_typeinf"].tinfo_t = types.SimpleNamespace

        ua = sys.modules["ida_ua"]
        ua.o_displ = 4
        ua.o_phrase = 5
        ua.insn_t = lambda: _Insn([_Op(0), _Op(ua.o_displ, soff=0x10)])
        ua.decode_insn = lambda insn, ea: 1
        ida_frame.get_stkvar = lambda insn, op: (
            (_FMember(0, op.soff, op.soff + 4), 0) if op.soff is not None else (None, 0)
        )

        common = {**_make_arch_common(), "idaapi": idaapi,
                  "ida_funcs": ida_funcs, "ida_frame": ida_frame}
        install_common_stub(common)
        self.mod = load_tool_module("stack_analysis", common_overrides=common)
        # `from ._common import *` skips underscore-prefixed names (the real
        # _common.__all__ lists them explicitly, the loader stub does not), so
        # the arch info helpers are not in the module namespace — patch them.
        self.mod._inf_bitness = lambda: 32
        self.mod._inf_procname = lambda: "riscv"
        # install_common_stub resets idc.next_head to the two-required-arg base
        # lambda on every call, and the uninitialized scan walks with
        # idc.next_head(ea) (one arg) — re-apply the firmware disasm fakes after
        # the module is loaded so the scan actually advances.
        idc = self.mod.idc
        idc.print_insn_mnem = lambda ea: {0xD000: "c.swsp", 0xD004: "addi",
                                          0xD008: "lw"}.get(ea, "")
        idc.next_head = lambda ea, end=None: ea + 4

    def test_compressed_store_marks_initialized_and_reports_unwritten(self):
        result = self.mod.stack_analysis(action="uninitialized", addr="0xD000")
        self.assertTrue(result.get("ok"), result)
        uninit = result["uninitialized"]
        self.assertIn("var_1", uninit, result)
        self.assertIn("0x20", uninit, result)
        self.assertNotIn("var_0", uninit, result)

    def test_store_whitelist_excludes_reads(self):
        # 'lw' (a load) must not mark a local initialized even with a
        # displacement operand in position 1.
        sys.modules["ida_ua"].insn_t = lambda: _Insn([_Op(0), _Op(4, soff=0x10)])
        sys.modules["idc"].print_insn_mnem = lambda ea: {0xD000: "lw", 0xD004: "lw",
                                                         0xD008: "lw"}.get(ea, "")
        result = self.mod.stack_analysis(action="uninitialized", addr="0xD000")
        self.assertTrue(result.get("ok"), result)
        self.assertIn("var_0", result["uninitialized"], result)


if __name__ == "__main__":
    unittest.main()
