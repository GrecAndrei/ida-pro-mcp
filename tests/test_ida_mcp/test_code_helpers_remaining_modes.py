"""Cross-mode coverage for the composed code-helper analysis surface."""

from __future__ import annotations

import importlib
import types

from tests.fakes.ida_fake import BADADDR

helpers = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")


def test_cfg_dataflow_and_call_context_modes(monkeypatch):
    class Block:
        def __init__(self, start, end, successors=()):
            self.start_ea = start
            self.end_ea = end
            self._successors = list(successors)

        def succs(self):
            return list(self._successors)

    first = Block(0x1000, 0x1004)
    second = Block(0x1004, 0x1008)
    loop = Block(0x1008, 0x100C, [second])
    first._successors = [second]
    second._successors = [loop]
    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: [first, second, loop])
    cfg = helpers._compute_cfg_semantics(types.SimpleNamespace(start_ea=0x1000))
    assert cfg["nodes"] == 3 and cfg["edges"] == 3 and cfg["back_edges"] == 1
    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: None)
    assert helpers._compute_cfg_semantics(types.SimpleNamespace(start_ea=0x1000))["nodes"] == 0

    cfunc = types.SimpleNamespace(
        entry_ea=BADADDR,
        lvars=[types.SimpleNamespace(name="dst", is_arg_var=False), types.SimpleNamespace(name="src", is_arg_var=True)],
    )
    monkeypatch.setattr(helpers, "_collect_expr_rows_from_cfunc", lambda *_a, **_k: [
        (BADADDR, "dst = src"),
        (0x1004, "send(dst, src)"),
        (0x1008, "dst = dst"),
        (0x100C, ""),
    ])
    flow = helpers._build_decompiler_dataflow(cfunc, max_items=20)
    assert flow["assignment_edges"] == 1
    assert flow["call_edges"] == 2
    assert flow["argument_variables"] == ["src"]
    assert any(edge["ea"] is None for edge in flow["edges"])
    assert helpers._build_decompiler_dataflow(types.SimpleNamespace(lvars=[]))["nodes"] == []

    microcode = importlib.import_module("ida_pro_mcp.ida_mcp.support.microcode_engine")
    monkeypatch.setattr(microcode, "build_microcode_ssa_graph", lambda *_a, **_k: {
        "edge_count": 2,
        "nodes": ["src", "dst"],
        "edges": [{"from": "src", "to": "dst"}],
        "phi_like_merges": [{"var": "dst"}],
    })
    ssa = helpers._build_decompiler_dataflow(
        types.SimpleNamespace(entry_ea=0x1000, lvars=[types.SimpleNamespace(name="src", is_arg_var=True)])
    )
    assert ssa["engine"] == "hexrays_microcode_ssa" and ssa["top_hubs"] == ["dst"]

    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([0x1000]))
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda _ea, _flow: iter([0x2000, 0x1000]))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda ea: "callee" if ea == 0x2000 else "self")
    summary = helpers._build_function_structure_summary(
        types.SimpleNamespace(start_ea=0x1000), cfunc=None, max_items=4
    )
    assert summary["call_targets"] == ["callee"]

    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda _ea, _flow: iter([0x3000, 0x3000, 0x4000]))
    assert len(helpers._collect_compact_callers(0x2000)) == 2
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda _ea, _flow: iter([0x5000, 0x5000]))
    assert len(helpers._collect_compact_callees(0x1000)) == 1


def test_firmware_signals_and_rename_heuristics(monkeypatch):
    class Insn:
        def __init__(self):
            self.ops = []
            self.ea = 0

    class UA:
        o_displ = 4
        o_mem = 2

        @staticmethod
        def insn_t():
            return Insn()

        @staticmethod
        def decode_insn(insn, ea):
            insn.ea = ea
            insn.ops = [types.SimpleNamespace(type=4 if ea == 0x1008 else 0)]
            return 1

        @staticmethod
        def get_operand_value(insn, _idx):
            return 0x40001000 if insn.ea == 0x1008 else 0

    monkeypatch.setattr(helpers, "ida_ua", UA)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1014))
    mnems = {0x1000: "ecall", 0x1004: "csrrw", 0x1008: "sw", 0x100C: "lui", 0x1010: "addi"}
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda ea: mnems.get(ea, "nop"))
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea + 4 if ea < 0x1010 else BADADDR)
    monkeypatch.setattr(helpers, "is_riscv_family", lambda: True)
    monkeypatch.setattr(helpers, "is_syscall_mnemonic", lambda mnem: mnem == "ecall")
    monkeypatch.setattr(helpers, "_FIRMWARE_STORE_MNEMONICS", {"sw"})
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda ea, _idx: 0x5000 if ea == 0x100C else 0)
    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda ea: ea == 0x5000)
    signals = helpers._detect_firmware_signals(0x1000)
    assert "syscall:ecall" in signals
    assert "csr_access:csrrw" in signals
    assert "mmio_store:0x40001000" in signals
    assert "large_constant_load:0x5000" in signals

    class TypeInfo:
        def dstr(self):
            return "plain_record_t *"

    names = ["v1", "v2", "v3", "v4", "v5", "a1", "a2"]
    pseudo = "v1 = fopen(x); v2 = ioctl(fd); v3->size; v4 = 0; v5 = mmap(p); a1; a2"
    lvars = [types.SimpleNamespace(name=name, type=TypeInfo() if name == "v5" else None, is_arg_var=False) for name in names]
    class Decompiled:
        def __init__(self):
            self.lvars = lvars
            self.type = "int socket(int fd, int size)"

        def __str__(self):
            return pseudo

    cfunc = Decompiled()
    hints = helpers._extract_var_rename_hints(cfunc)
    suggestions = {row["suggested"] for row in hints}
    assert {"fp", "fd", "size", "result"} <= suggestions


def test_text_detectors_and_custom_detector_dispatch(monkeypatch):
    pseudo = (
        'gets(buf); system(cmd); malloc(n * 4); recv(fd, buf, n); '
        'memcpy(dst, buf, n); access(path, 0); open(path, 0); '
        'password = "secret"; VirtualAlloc(x); WriteProcessMemory(p); CreateRemoteThread(p);'
    )
    detailed = helpers._detect_dangerous_patterns(
        ["access", "open", "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"], pseudo, detailed=True
    )
    patterns = {row["pattern"] for row in detailed}
    assert {"command_injection", "integer_overflow_alloc", "source_to_sink_flow", "toctou_race", "hardcoded_secret", "process_injection", "remote_thread_injection"} <= patterns
    assert helpers._detect_dangerous_patterns([], "strcpy(dst, src);", detailed=False)

    helpers._CUSTOM_DETECTORS.clear()
    assert helpers._run_custom_detector({"register": True, "name": "one", "rule": {"type": "xor_threshold"}}, 3)["ok"] is True
    assert helpers._run_custom_detector({"list_detectors": True}, 3)["detectors"]
    assert helpers._run_custom_detector({"delete_detector": True, "name": "one"}, 3)["deleted"] is True
    assert helpers._run_custom_detector({"rule_type": "xor_threshold", "threshold": 2}, 3)["ok"] is True
    assert helpers._run_custom_detector({"rule_type": "string_ref"}, 3)["error"] is True
    assert helpers._run_custom_detector({"rule_type": "other"}, 3)["error"] is True

    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000]))
    monkeypatch.setattr(helpers.idc, "get_name_ea_simple", lambda name: 0x2000 if name == "_target" else BADADDR)
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([0x1000]))
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda _ea, _flow: iter([0x3000]))
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda _ea, _flow: iter([0x4000]))
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda ea: f"fn_{ea:x}")
    assert helpers._detect_callers_of("target")
    assert helpers._detect_callees_of("target")

    class StringObject:
        ea = 0x5000

        def __str__(self):
            return "http://host"

    monkeypatch.setattr(helpers.idautils, "Strings", lambda: [StringObject()], raising=False)
    monkeypatch.setattr(helpers.idautils, "XrefsTo", lambda _ea: [types.SimpleNamespace(frm=0x1001)])
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda *_args: b"http://host")
    assert helpers._detect_string_refs("[") == []
    assert helpers._detect_string_refs("http")[0]["string"] == "http://host"


def test_disassembly_argument_trace_and_decompiler_error_modes(monkeypatch):
    monkeypatch.setattr(helpers.idc, "generate_disasm_line", lambda _ea, _flags: "mov rax, rbx")
    monkeypatch.setattr(helpers.idc, "get_cmt", lambda ea, repeat: "comment" if ea == 0x1000 and repeat == 0 else "")
    monkeypatch.setattr(helpers.idc, "get_item_size", lambda _ea: 2)
    monkeypatch.setattr(helpers.ida_bytes, "get_byte", lambda ea: ea & 0xFF)
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "mov")
    monkeypatch.setattr(helpers.idc, "print_operand", lambda _ea, _idx: "rax" if _idx == 0 else "")
    monkeypatch.setattr(helpers.idaapi, "get_dref_cnt", lambda _ea: 0, raising=False)
    line = helpers._format_disasm_line(0x1000, style="classic", include_bytes=True, include_comments=True, mark_all=False)
    assert "bytes=" in line and "comment" in line and line.startswith("0x1000")
    structured = helpers._format_disasm_structured(0x1000)
    assert structured["bytes"] == "00 01"
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea if ea == 0x1000 else BADADDR)
    assert helpers._disasm_range(0x1000, 0x1004, max_items=2, style="annotated", include_bytes=False)
    monkeypatch.setattr(helpers.idc, "prev_head", lambda ea, _min: ea - 1 if ea > 0x0FFE else BADADDR)
    assert len(helpers._disasm_window(0x1000, radius=3, max_items=3, style="csmini", include_bytes=False)) >= 1

    assert helpers._extract_arg_from_decompiled("target(a, nested(b, c), &d)", "target", 1) == "nested(b, c)"
    assert helpers._extract_arg_from_decompiled("target(a)", "target", 4) is None
    func = types.SimpleNamespace(start_ea=0x2000)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda _ea: "target")
    monkeypatch.setattr(helpers.idc, "get_type", lambda _ea: "int target(char *buf)")
    monkeypatch.setattr(helpers.idc, "parse_decl", lambda *_args: None)
    monkeypatch.setattr(helpers.idautils, "XrefsTo", lambda _ea, _flow: iter(()))
    assert helpers._trace_argument_origin(func, 3, 1, 2)["trace_tree"] == []

    monkeypatch.setattr(helpers.ida_hexrays, "init_hexrays_plugin", lambda: False)
    unavailable = helpers._decompile_with_diagnostics(0x1000)
    assert unavailable[1]["error"] is True
    monkeypatch.setattr(helpers.ida_hexrays, "init_hexrays_plugin", lambda: (_ for _ in ()).throw(RuntimeError("init")))
    assert helpers._decompile_with_diagnostics(0x1000)[1]["error"] is True


def test_ctree_vulnerability_matrix_uses_ast_and_runtime_metadata(monkeypatch):
    """Exercise the scanner's composed evidence paths with one fake IDB."""
    from tests.fakes.ida_fake import (
        cexpr_t,
        cinsn_t,
        cnumber_t,
        ctree_visitor_t,
        lvar_t,
        var_ref_t,
    )

    hx = helpers.ida_hexrays
    constants = {
        "cot_asg": 2,
        "cot_eq": 16,
        "cot_ne": 17,
        "cot_sle": 20,
        "cot_ule": 21,
        "cot_ptr": 45,
        "cot_ref": 46,
        "cot_num": 50,
        "cot_str": 52,
        "cot_obj": 53,
        "cot_var": 54,
        "cot_call": 59,
        "cot_float": 51,
        "cot_sizeof": 56,
    }
    for name, value in constants.items():
        monkeypatch.setattr(hx, name, value, raising=False)
    monkeypatch.setattr(hx, "ctree_visitor_t", ctree_visitor_t, raising=False)

    class Args(list):
        def size(self):
            return len(self)

        def at(self, index):
            return self[index]

    def expr(op, ea, *, text="", x=None, y=None, string="", obj_ea=BADADDR, value=0, idx=0, args=()):
        node = cexpr_t(
            op=op,
            ea=ea,
            x=x,
            y=y,
            v=var_ref_t(idx),
            n=cnumber_t(value),
            string=string,
            obj_ea=obj_ea,
        )
        node.a = Args(args)
        node.n.value = lambda _index=0, stored=value: stored
        node.print1 = lambda _tag=None, rendered=text: rendered
        return node

    names = {
        0x2000: "memcpy",
        0x2001: "malloc",
        0x2002: "free",
        0x2003: "fprintf",
        0x2004: "system",
        0x2005: "HeapAlloc",
        0x2006: "strcpy",
        0x2007: "CreateRemoteThread",
        0x2008: "WriteProcessMemory",
        0x2009: "LocalAlloc",
    }

    def var(idx, name, ea):
        return expr(hx.cot_var, ea, text=name, idx=idx)

    def num(value, ea):
        return expr(hx.cot_num, ea, text=str(value), value=value)

    def string(value, ea):
        return expr(hx.cot_str, ea, text=repr(value), string=value)

    def call(name, args, ea, target):
        return expr(
            hx.cot_call,
            ea,
            text=f"{name}()",
            x=expr(hx.cot_obj, ea + 1, text=name, obj_ea=target),
            args=args,
        )

    alloc = call("malloc", [var(1, "input_buf", 0x1100)], 0x1200, 0x2001)
    checked_alloc = call("malloc", [num(8, 0x1201)], 0x1201, 0x2001)
    check = expr(hx.cot_eq, 0x1202, x=checked_alloc, y=num(0, 0x1203), text="malloc(8) == 0")
    free = call("free", [var(0, "heap_buf", 0x1300)], 0x1300, 0x2002)
    use_after_free = var(0, "heap_buf", 0x1301)
    copy = call(
        "memcpy",
        [var(2, "dst", 0x1400), var(1, "input_buf", 0x1401), var(1, "input_buf", 0x1402)],
        0x1400,
        0x2000,
    )
    format_call = call(
        "fprintf",
        [var(2, "stream", 0x1500), var(3, "fmt", 0x1501)],
        0x1500,
        0x2003,
    )
    command = call("system", [var(3, "cmd", 0x1600)], 0x1600, 0x2004)
    heap_alloc = call(
        "HeapAlloc",
        [var(2, "heap", 0x1700), num(0, 0x1701), var(1, "input_buf", 0x1702)],
        0x1700,
        0x2005,
    )
    zero_alloc = call("LocalAlloc", [num(0, 0x1750), num(0, 0x1751)], 0x1750, 0x2009)
    strcpy = call("strcpy", [var(2, "dst", 0x1800), var(1, "input_buf", 0x1801)], 0x1800, 0x2006)
    remote_thread = call("CreateRemoteThread", [var(2, "dst", 0x1900)], 0x1900, 0x2007)
    process_write = call("WriteProcessMemory", [var(2, "dst", 0x1901)], 0x1901, 0x2008)
    suspicious = string("https://10.1.2.3/cmd.exe", 0x1A00)
    ref_obj = expr(hx.cot_obj, 0x1A01, obj_ea=0x5000, text="c2")
    suspicious_ref = expr(hx.cot_ref, 0x1A02, x=ref_obj, text="&c2")

    statements = [
        alloc, checked_alloc, check, free, use_after_free, copy, format_call,
        command, heap_alloc, zero_alloc, strcpy, remote_thread, process_write, suspicious, suspicious_ref,
    ]
    body = cinsn_t(
        op=getattr(hx, "cit_block", 1),
        ea=0x1000,
        cblock=[cinsn_t(op=getattr(hx, "cit_expr", 2), cexpr=item, ea=item.ea) for item in statements],
    )

    class FunctionType:
        def get_func_details(self, data):
            data._items = [
                types.SimpleNamespace(name="dst", type="char *"),
                types.SimpleNamespace(name="src", type="int *"),
            ]
            return True

    class CFuncType:
        def get_func_details(self, data):
            data._items = [types.SimpleNamespace(name="arg0", type="char *")]
            return True

    class FuncData:
        def __init__(self):
            self._items = []

        def size(self):
            return len(self._items)

        def __getitem__(self, index):
            return self._items[index]

    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", FuncData, raising=False)
    monkeypatch.setattr(helpers.ida_typeinf, "tinfo_t", CFuncType, raising=False)
    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", lambda _tinfo, _ea: True)
    monkeypatch.setattr(helpers.idc, "get_name", lambda ea: names.get(ea, ""))
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda _ea: "strcpy_network_handler")
    monkeypatch.setattr(helpers.idc, "get_func_attr", lambda *_args: 4, raising=False)
    monkeypatch.setattr(helpers.idaapi, "FUNC_LIB", 4, raising=False)
    monkeypatch.setattr(helpers.idaapi, "SEGPERM_WRITE", 2, raising=False)
    monkeypatch.setattr(helpers.idaapi, "SEGPERM_EXEC", 4, raising=False)
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda _ea, _flow: iter([0x3000]))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: 0x3000 if ea == 0x3000 else ea)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda _ea: "network_dispatch")
    monkeypatch.setattr(helpers._compat, "get_segment_perm", lambda _ea: 2 | 4)
    monkeypatch.setattr(helpers._compat, "get_segment_name", lambda _ea: "payload")
    monkeypatch.setattr(helpers._compat, "frame_members", lambda _ea: [
        (0, "buffer", 0, 512, "char[512]"),
        (1, "password", 0, 8, "char *"),
        (2, "__stack_chk_guard", 0, 8, "uint64_t"),
    ])
    monkeypatch.setattr(helpers.idc, "get_str_type", lambda ea: 0 if ea == 0x5000 else None)
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda *_args: b"http://10.1.2.3/cmd.exe")
    monkeypatch.setattr(helpers.idautils, "XrefsTo", lambda _ea: [types.SimpleNamespace(frm=0x3000)])
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _size: b"\x90\x90\x90\x90" + b"\x00" * 12)
    monkeypatch.setattr(helpers.idaapi, "get_inf_attr", lambda _attr: b"metapc", raising=False)
    monkeypatch.setattr(helpers.idaapi, "INF_PROCNAME", 1, raising=False)
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([0x1800]))
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "mov")
    monkeypatch.setattr(helpers.idc, "print_operand", lambda _ea, _idx: "fs:[0x30]")
    monkeypatch.setattr(helpers, "_detect_firmware_signals", lambda *_args, **_kwargs: [])

    class Block:
        start_ea = 0x1000
        end_ea = 0x2000

        def succs(self):
            return [self]

    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: [Block()])

    class UA:
        o_displ = 4
        o_mem = 2

        class insn_t:
            pass

        @staticmethod
        def decode_insn(_insn, _ea):
            return 1

    monkeypatch.setattr(helpers.ida_ua, "insn_t", UA.insn_t, raising=False)
    monkeypatch.setattr(helpers.ida_ua, "decode_insn", UA.decode_insn, raising=False)
    monkeypatch.setattr(helpers.ida_ua, "o_displ", UA.o_displ, raising=False)
    monkeypatch.setattr(helpers.ida_ua, "o_mem", UA.o_mem, raising=False)
    monkeypatch.setattr(helpers.idc, "get_operand_type", lambda _ea, index: 2 if index == 0 else 0, raising=False)
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda _ea, _idx: 0x6000, raising=False)

    lvars = [
        lvar_t("heap_buf", is_arg_var=False),
        lvar_t("input_buf", is_arg_var=True, type_=types.SimpleNamespace(dstr=lambda: "char *")),
        lvar_t("dst", is_arg_var=False),
        lvar_t("fmt", is_arg_var=True, type_=types.SimpleNamespace(dstr=lambda: "char *")),
    ]
    cfunc = types.SimpleNamespace(entry_ea=0x1000, body=body, lvars=lvars, type=FunctionType())
    findings = helpers._scan_ctree_vulns(cfunc)
    patterns = {row["pattern"] for row in findings}
    assert {
        "unchecked_malloc",
        "user_controlled_alloc_size",
        "use_after_free",
        "user_controlled_copy_size",
        "format_string_injection",
        "command_injection",
        "process_injection_write",
        "remote_thread_injection",
        "network_reachable_vuln",
        "library_func_with_vuln",
        "writable_executable_segment",
        "hardcoded_url",
        "hardcoded_ip",
        "shell_command_string",
        "danger_in_loop",
        "large_stack_buffer",
        "stack_canary_present",
        "sensitive_stack_var",
        "global_writable_ref",
        "nop_sled",
        "seh_with_vuln",
        "vulnerable_function_name",
    } <= patterns
    assert "zero_alloc" in patterns


def test_detector_positive_modes_and_resilient_iteration(monkeypatch):
    monkeypatch.setattr(helpers.ida_hexrays, "cot_call", 59, raising=False)
    monkeypatch.setattr(helpers.ida_hexrays, "cot_obj", 53, raising=False)
    class StringObject:
        ea = 0x5000

        def __str__(self):
            return "password reset"

    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000, 0x2000]))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(helpers.idc, "get_name_ea_simple", lambda name: 0x9000 if name in {"target", "_target"} else BADADDR)
    monkeypatch.setattr(helpers.idc, "get_name", lambda ea: {0x3000: "recv", 0x3001: "memcpy"}.get(ea, ""))
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda ea: f"fn_{ea:x}")
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "xor")
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([0x1000, 0x1004, 0x1008, 0x100C, 0x1010]))
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda _ea, _flow: iter([0x3000, 0x3001]))
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda _ea, _flow: iter([0x4000]))
    monkeypatch.setattr(helpers.idautils, "Strings", lambda: [StringObject()], raising=False)
    monkeypatch.setattr(helpers.idautils, "XrefsTo", lambda _ea: [types.SimpleNamespace(frm=0x1001)])
    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", lambda _tinfo, _ea: True)

    class Visitor(helpers.ida_hexrays.ctree_visitor_t):
        def apply_to(self, _body, _parent=None):
            for target in (0x3000, 0x3001):
                self.visit_expr(types.SimpleNamespace(
                    op=helpers.ida_hexrays.cot_call,
                    x=types.SimpleNamespace(op=helpers.ida_hexrays.cot_obj, obj_ea=target),
                ))

    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", Visitor)
    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: types.SimpleNamespace(body=types.SimpleNamespace()))
    assert helpers._detect_api_chains(["recv", "memcpy"], strict_order=True, max_items=5)
    assert helpers._detect_api_chains(["memcpy", "recv"], strict_order=False, max_items=5)

    class ParamData:
        def __init__(self):
            self._items = [types.SimpleNamespace(name="sock", type="SOCKET")]

        def size(self):
            return len(self._items)

        def __getitem__(self, index):
            return self._items[index]

    class Tinfo:
        def get_func_details(self, data):
            data._items = [types.SimpleNamespace(name="sock", type="SOCKET")]
            return True

    monkeypatch.setattr(helpers.ida_typeinf, "tinfo_t", Tinfo)
    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", ParamData, raising=False)
    assert helpers._detect_type_matches("[", max_items=5) == []
    assert helpers._detect_type_matches("SOCKET", max_items=5)
    assert helpers._detect_xor_heavy(threshold=2, max_items=5)


def test_constant_materialization_fallback_and_processor_specific_modes(monkeypatch):
    """Exercise raw-firmware string recovery alongside architecture checks."""
    class EmptyVisitor:
        def __init__(self, *_args):
            pass

        def apply_to(self, *_args):
            return None

    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", EmptyVisitor)
    monkeypatch.setattr(helpers.ida_hexrays, "CV_FAST", 0, raising=False)
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda *_args: None)
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda _ea: "safe_handler")
    monkeypatch.setattr(helpers.idaapi, "get_inf_attr", lambda _attr: b"arm", raising=False)
    monkeypatch.setattr(helpers.idaapi, "INF_PROCNAME", 1, raising=False)
    monkeypatch.setattr(helpers.idaapi, "SEGPERM_WRITE", 2, raising=False)
    monkeypatch.setattr(helpers, "_compat", helpers._compat)

    class Block:
        start_ea = 0x1000
        end_ea = 0x1008

        def succs(self):
            return []

    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: [Block()])
    monkeypatch.setattr(helpers._compat, "get_segment_perm", lambda _ea: 2)
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "BX")
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda _ea, _idx: 0x6000)
    cfunc = types.SimpleNamespace(entry_ea=0x1000, body=types.SimpleNamespace(), lvars=[], type=None)
    arm_findings = helpers._scan_ctree_vulns(cfunc)
    assert any(row["pattern"] == "arm_branch_to_writable" for row in arm_findings)

    monkeypatch.setattr(helpers.idaapi, "get_inf_attr", lambda _attr: b"mips", raising=False)
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([0x1000]))
    monkeypatch.setattr(
        helpers.idc,
        "print_insn_mnem",
        lambda ea: "JAL" if ea == 0x1000 else "LW",
    )
    monkeypatch.setattr(helpers.idc, "next_head", lambda _ea, _end: 0x1004)
    assert not any(row["pattern"] == "arm_branch_to_writable" for row in helpers._scan_ctree_vulns(cfunc))

    monkeypatch.setattr(helpers.idaapi, "get_inf_attr", lambda _attr: b"metapc", raising=False)
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "mov")
    monkeypatch.setattr(helpers.idc, "print_operand", lambda _ea, _idx: "fs:[0x30]")
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda _ea: "strcpy_handler")
    x86_findings = helpers._scan_ctree_vulns(cfunc)
    assert any(row["pattern"] == "vulnerable_function_name" for row in x86_findings)

    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: types.SimpleNamespace(start_ea=0x2000, end_ea=0x200C))
    mnem = {0x2000: "lui", 0x2004: "addi", 0x2008: "mov"}
    operands = {
        (0x2000, 0): "a0", (0x2000, 1): "0x500",
        (0x2004, 0): "a0", (0x2004, 1): "a0", (0x2004, 2): "0x10",
        (0x2008, 0): "a1", (0x2008, 1): "0",
    }
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda ea: mnem.get(ea, "nop"))
    monkeypatch.setattr(helpers.idc, "print_operand", lambda ea, idx: operands.get((ea, idx), ""))
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda ea, idx: 0x500 if ea == 0x2000 else (0x10 if idx == 2 else 0))
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea + 4 if ea < 0x2008 else BADADDR)
    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda ea: ea == 0x500010)
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda _ea, _size: b"config-key\x00")
    entries = helpers._scan_constant_load_strings(0x2000)
    assert entries == [{"addr": 0x500010, "value": "config-key"}]
    assert helpers._read_candidate_string(BADADDR) is None
    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda _ea: False)
    assert helpers._read_candidate_string(0x500010) is None


def test_vulnerability_call_variants_cover_format_prototype_and_taint_modes(monkeypatch):
    from tests.fakes.ida_fake import cexpr_t, cinsn_t, cnumber_t, ctree_visitor_t, var_ref_t

    hx = helpers.ida_hexrays
    for name, value in {
        "cot_eq": 16, "cot_num": 50, "cot_var": 54, "cot_obj": 53,
        "cot_call": 59, "cot_str": 52, "cot_ref": 46, "cot_ptr": 45,
        "cot_sizeof": 56, "CV_FAST": 0,
    }.items():
        monkeypatch.setattr(hx, name, value, raising=False)
    monkeypatch.setattr(hx, "ctree_visitor_t", ctree_visitor_t, raising=False)

    class Args(list):
        def size(self):
            return len(self)

        def at(self, index):
            return self[index]

    def expr(op, ea, *, text="", x=None, string="", value=0, idx=0, args=(), obj_ea=BADADDR):
        node = cexpr_t(op=op, ea=ea, x=x, v=var_ref_t(idx), n=cnumber_t(value), string=string, obj_ea=obj_ea)
        node.a = Args(args)
        node.n.value = lambda _index=0, stored=value: stored
        node.print1 = lambda _tag=None, rendered=text: rendered
        return node

    def obj(name, ea):
        return expr(hx.cot_obj, ea + 1, text=name, obj_ea=ea)

    names = {
        0x2100: "strcat", 0x2101: "strcpy", 0x2102: "memcpy",
        0x2103: "printf", 0x2104: "snprintf", 0x2105: "system",
    }
    monkeypatch.setattr(helpers.idc, "get_name", lambda ea: names.get(ea, ""))
    monkeypatch.setattr(helpers.idc, "get_func_name", lambda _ea: "safe_wrapper")
    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", lambda _tinfo, _ea: True)
    monkeypatch.setattr(helpers.idaapi, "get_inf_attr", lambda _attr: "", raising=False)
    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: [])
    monkeypatch.setattr(helpers._compat, "frame_members", lambda _ea: [])
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda *_args: None)
    monkeypatch.setattr(helpers.idautils, "CodeRefsTo", lambda *_args: iter(()))
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda *_args: iter(()))
    monkeypatch.setattr(helpers.idc, "get_str_type", lambda _ea: None)
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda *_args: b"%n %s")

    class FuncData:
        def __init__(self):
            self.items = [types.SimpleNamespace(name="dst", type="char *"), types.SimpleNamespace(name="src", type="int *")]

        def size(self):
            return len(self.items)

        def __getitem__(self, index):
            return self.items[index]

    class Tinfo:
        def get_func_details(self, data):
            data.items = [types.SimpleNamespace(name="dst", type="char *"), types.SimpleNamespace(name="src", type="int *")]
            return True

    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", FuncData, raising=False)
    monkeypatch.setattr(helpers.ida_typeinf, "tinfo_t", Tinfo, raising=False)

    def call(name, ea, args, target):
        return expr(hx.cot_call, ea, text=f"{name}()", x=obj(name, target), args=args)

    generic = expr(hx.cot_var, 0x3000, text="source", idx=0)
    tainted = expr(hx.cot_var, 0x3001, text="input_buf", idx=1)
    size = expr(hx.cot_var, 0x3002, text="size", idx=2)
    literal = expr(hx.cot_str, 0x3003, text="%n %s", string="%n %s")
    calls = [
        call("strcat", 0x3100, [generic, generic], 0x2100),
        call("strcpy", 0x3101, [generic, generic], 0x2101),
        call("memcpy", 0x3102, [expr(hx.cot_num, 0x3006, text="4", value=4), tainted, tainted], 0x2102),
        call("memcpy", 0x3103, [generic, generic, size], 0x2102),
        call("printf", 0x3104, [literal], 0x2103),
        call("snprintf", 0x3105, [generic, expr(hx.cot_num, 0x3004, text="0", value=0), literal], 0x2104),
        call("system", 0x3106, [literal], 0x2105),
    ]
    variable_callee = expr(hx.cot_call, 0x3107, x=expr(hx.cot_var, 0x3005, text="callback", idx=3), args=Args())
    calls.append(variable_callee)
    body = cinsn_t(
        op=getattr(hx, "cit_block", 1),
        ea=0x3000,
        cblock=[cinsn_t(op=getattr(hx, "cit_expr", 2), cexpr=item, ea=item.ea) for item in calls],
    )
    cfunc = types.SimpleNamespace(
        entry_ea=0x3000,
        body=body,
        lvars=[
            types.SimpleNamespace(name="source", is_arg_var=False),
            types.SimpleNamespace(name="input_buf", is_arg_var=True, type=types.SimpleNamespace(dstr=lambda: "char *")),
            types.SimpleNamespace(name="size", is_arg_var=False),
            types.SimpleNamespace(name="callback", is_arg_var=False),
        ],
        type=None,
    )
    findings = helpers._scan_ctree_vulns(cfunc)
    patterns = {row["pattern"] for row in findings}
    assert {
        "strcat_unbounded", "strcpy_unbounded", "user_controlled_copy_size",
        "type_mismatch_copy", "format_arg_mismatch", "format_string_write",
        "snprintf_zero_size", "int_as_pointer",
    } <= patterns
