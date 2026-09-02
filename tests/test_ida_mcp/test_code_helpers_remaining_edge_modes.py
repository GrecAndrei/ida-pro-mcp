"""Exercise code-helper fallbacks and cross-architecture edge modes."""

from __future__ import annotations

import importlib
import types

from tests.fakes.ida_fake import BADADDR

helpers = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")


def test_expr_and_dataflow_fallback_survives_sdk_failures(monkeypatch):
    class VisitorBase:
        def __init__(self, *_args):
            pass

        def apply_to(self, body, _parent=None):
            for expr in getattr(body, "exprs", ()):
                self.visit_expr(expr)

    class BrokenExpr:
        ea = BADADDR

        def print1(self, _tag):
            raise RuntimeError("printer unavailable")

    class Expr:
        def __init__(self, ea, text):
            self.ea = ea
            self.text = text

        def print1(self, _tag):
            return self.text

    monkeypatch.setattr(helpers.ida_hexrays, "ctree_visitor_t", VisitorBase)
    rows = helpers._collect_expr_rows_from_cfunc(
        types.SimpleNamespace(body=types.SimpleNamespace(exprs=[BrokenExpr(), Expr(0x1000, "dst = src")])),
        max_items=8,
    )
    assert rows == [(BADADDR, ""), (0x1000, "dst = src")]

    monkeypatch.setattr(
        importlib.import_module("ida_pro_mcp.ida_mcp.support.microcode_engine"),
        "build_microcode_ssa_graph",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("no microcode")),
    )
    cfunc = types.SimpleNamespace(
        entry_ea=0x1000,
        lvars=[
            types.SimpleNamespace(name="dst", is_arg_var=False),
            types.SimpleNamespace(name="src", is_arg_var=True),
        ],
        body=types.SimpleNamespace(
            exprs=[
                Expr(0x1000, "dst = src"),
                Expr(BADADDR, "send(dst, src)"),
                Expr(0x1004, "dst = dst"),
                Expr(0x1008, ""),
            ]
        ),
    )
    dataflow = helpers._build_decompiler_dataflow(cfunc, max_items=20)
    assert dataflow["assignment_edges"] == 1
    assert dataflow["call_edges"] == 2
    assert dataflow["edges"][0]["ea"] == "0x1000"
    assert dataflow["edges"][1]["ea"] is None


def test_structure_summary_control_points_details_and_failure_modes(monkeypatch):
    class VisitorBase:
        def __init__(self, *_args):
            pass

        def apply_to(self, body, _parent=None):
            for insn in getattr(body, "insns", ()):
                self.visit_insn(insn)

    class Flow:
        def __init__(self, start, end, succs=()):
            self.start_ea = start
            self.end_ea = end
            self._succs = list(succs)

        def succs(self):
            return self._succs

    def point(op, ea, container, field, text):
        expr = types.SimpleNamespace(print1=lambda _tag: text)
        return types.SimpleNamespace(op=op, ea=ea, **{container: types.SimpleNamespace(**{field: expr})})

    hx = helpers.ida_hexrays
    monkeypatch.setattr(hx, "ctree_visitor_t", VisitorBase)
    monkeypatch.setattr(hx, "CV_FAST", 0, raising=False)
    monkeypatch.setattr(hx, "cit_if", 1, raising=False)
    monkeypatch.setattr(hx, "cit_while", 2, raising=False)
    monkeypatch.setattr(hx, "cit_for", 3, raising=False)
    monkeypatch.setattr(hx, "cit_switch", 4, raising=False)
    first = Flow(0x1000, 0x1004)
    second = Flow(0x1004, 0x1008)
    first._succs = [second]
    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: [first, second])
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([0x1000]))
    monkeypatch.setattr(helpers.idautils, "CodeRefsFrom", lambda *_args: iter([0x2000]))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda _ea: "callee")
    monkeypatch.setattr(
        helpers,
        "_build_decompiler_dataflow",
        lambda *_args, **_kwargs: {
            "argument_variables": ["input"],
            "top_hubs": [{"node": "input", "degree": 2}],
            "assignment_edges": 1,
            "call_edges": 2,
        },
    )
    cfunc = types.SimpleNamespace(
        body=types.SimpleNamespace(
            insns=[
                point(hx.cit_if, 0x1010, "cif", "expr", "x > 0"),
                point(hx.cit_while, BADADDR, "cwhile", "expr", ""),
                point(hx.cit_for, 0x1014, "cfor", "cond", "i < n"),
                types.SimpleNamespace(op=99, ea=0x1018),
            ]
        ),
    )
    summary = helpers._build_function_structure_summary(
        types.SimpleNamespace(start_ea=0x1000), cfunc=cfunc, max_items=8, details=True
    )
    assert summary["call_targets"] == ["callee"]
    assert [p["kind"] for p in summary["control_points"]] == ["if", "while", "for"]
    assert summary["control_points"][1]["ea"] == ""
    assert summary["dataflow"]["top_hubs"]
    assert "control: if(x > 0); while; for(i < n)" in summary["evidence"]

    monkeypatch.setattr(helpers._compat, "get_flow_chart", lambda _ea: (_ for _ in ()).throw(RuntimeError("bad cfg")))
    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: (_ for _ in ()).throw(RuntimeError("bad refs")))
    failed = helpers._build_function_structure_summary(types.SimpleNamespace(start_ea=0x1000))
    assert failed["cfg"]["nodes"] == 0


def test_variable_names_cover_usage_type_and_argument_modes():
    class TypeInfo:
        def __init__(self, value):
            self.value = value

        def dstr(self):
            return self.value

    variables = [
        types.SimpleNamespace(name="v1", type=None),
        types.SimpleNamespace(name="v2", type=None),
        types.SimpleNamespace(name="v3", type=None),
        types.SimpleNamespace(name="v4", type=None),
        types.SimpleNamespace(name="v5", type=None),
        types.SimpleNamespace(name="v6", type=None),
        types.SimpleNamespace(name="v7", type=None),
        types.SimpleNamespace(name="v8", type=None),
        types.SimpleNamespace(name="v9", type=None),
        types.SimpleNamespace(name="v10", type=None),
        types.SimpleNamespace(name="v11", type=None),
        types.SimpleNamespace(name="v12", type=None),
    ]
    pseudo = (
        "v1 = recv(fd, v1); v2 = send(fd, v2); v3 = socket(AF_INET); "
        "v4 = malloc(n); v5 = key_material; v6 = packet; v7 = strlen(v7); "
        "v8->next = v8; v9->size = n; v10 = fopen(path); "
        "v11 = ioctl(fd, req); v12 = 0;"
    )
    class DecompiledVars:
        def __init__(self, lvars, proto, text):
            self.lvars = lvars
            self.type = proto
            self._text = text

        def __str__(self):
            return self._text

    hints = helpers._extract_var_rename_hints(DecompiledVars(variables, "", pseudo))
    suggestions = {row["var"]: row["suggested"] for row in hints}
    assert suggestions["v1"] == "recv_buf"
    assert suggestions["v2"] == "send_buf"
    assert suggestions["v3"] == "sock_fd"
    assert suggestions["v4"] == "heap_buf"
    assert suggestions["v5"] == "key_buf"
    assert suggestions["v6"] == "pkt_buf"
    assert suggestions["v7"] == "str_buf"
    assert suggestions["v8"] == "node"
    assert suggestions["v9"] == "size"
    assert suggestions["v10"] == "fp"

    class BadType:
        def __call__(self):
            raise RuntimeError("type unavailable")

    typed = DecompiledVars(
        [
                types.SimpleNamespace(name="v1", type=lambda: TypeInfo("wifi_frame_t *")),
                types.SimpleNamespace(name="v2", type=BadType()),
                types.SimpleNamespace(name="v3", type=types.SimpleNamespace(dstr=lambda: "int")),
                types.SimpleNamespace(name="a1", type=None),
                types.SimpleNamespace(name="a2", type=None),
                types.SimpleNamespace(name="not_a_lvar", type=None),
        ],
        "int socket(int fd, void *buf, int size)",
        "v2 = recv(fd, v2);",
    )
    typed_hints = helpers._extract_var_rename_hints(typed)
    typed_suggestions = {row["var"]: row["suggested"] for row in typed_hints}
    assert typed_suggestions["v1"] == "frame"
    assert typed_suggestions["a1"] == "fd"
    assert typed_suggestions["a2"] == "size"


def test_firmware_signal_fallbacks_store_decoder_and_crypto_modes(monkeypatch):
    class UA:
        o_displ = 4
        o_mem = 2

        def __init__(self, ops, decoded=1, value=0):
            self.ops = ops
            self.decoded = decoded
            self.value = value

        def insn_t(self):
            return types.SimpleNamespace(ops=self.ops)

        def decode_insn(self, _insn, _ea):
            return self.decoded

        def get_operand_value(self, _insn, _idx):
            return self.value

    monkeypatch.setattr(helpers, "ida_ua", None)
    assert helpers._store_memory_target(0x1000) is None

    monkeypatch.setattr(
        helpers,
        "ida_ua",
        types.SimpleNamespace(
            o_displ=4,
            o_mem=2,
            insn_t=lambda: types.SimpleNamespace(ops=[types.SimpleNamespace(type=0)]),
            decode_insn=lambda *_args: 1,
            get_operand_value=lambda *_args: 0,
        ),
    )
    assert helpers._store_memory_target(0x1000) is None
    monkeypatch.setattr(helpers.ida_ua, "decode_insn", lambda *_args: 0)
    assert helpers._store_memory_target(0x1000) is None

    monkeypatch.setattr(
        helpers,
        "ida_ua",
        types.SimpleNamespace(
            o_displ=4,
            o_mem=2,
            insn_t=lambda: types.SimpleNamespace(ops=[types.SimpleNamespace(type=4)]),
            decode_insn=lambda *_args: 1,
            get_operand_value=lambda *_args: 0x40001000,
        ),
    )
    assert helpers._store_memory_target(0x1000) == 0x40001000

    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1000))
    monkeypatch.setattr(helpers, "is_riscv_family", lambda: False)
    assert helpers._detect_firmware_signals(0x1000, "table at 0x40000000 and 0x50000000") == [
        "constant_ref:0x40000000",
        "constant_ref:0x50000000",
    ]
    assert helpers._detect_firmware_signals(0x1000) == []

    assert helpers._detect_api_calls("malloc(x); recv(fd); close(fd)", limit=2) == ["malloc", "recv"]
    crypto, xor_count = helpers._detect_crypto_hints("AES_encrypt(x); a ^ b ^ c ^ d ^ e", xor_threshold=4)
    assert "AES" in crypto and "XOR_heavy(4)" in crypto and xor_count == 4
    complexity = helpers._build_pseudocode_complexity(
        "switch (x) { case 1: if (y) { a ^= b; } }", include_switch_cases=True, xor_count=4
    )
    assert complexity["switch_cases"] == 1 and complexity["xor_ops"] == 4


def test_disassembly_context_and_argument_trace_modes(monkeypatch):
    monkeypatch.setattr(helpers.idc, "generate_disasm_line", lambda ea, _flags: "bne a0, a1, loc" if ea == 0x1000 else "")
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "bne")
    monkeypatch.setattr(helpers.idc, "print_operand", lambda _ea, index: ["a0", "a1", "loc"][index] if index < 3 else "")
    monkeypatch.setattr(helpers.idc, "get_operand_type", lambda _ea, index: 7 if index == 2 else 0)
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda *_args: 0x2000)
    monkeypatch.setattr(helpers.idc, "get_name", lambda ea: "target_fn" if ea == 0x2000 else "")
    monkeypatch.setattr(helpers.idc, "get_cmt", lambda _ea, repeat: "repeat" if repeat else "")
    monkeypatch.setattr(helpers.idc, "get_item_size", lambda _ea: 2)
    monkeypatch.setattr(helpers.ida_bytes, "get_byte", lambda ea: ea & 0xFF)
    monkeypatch.setattr(helpers.idaapi, "get_dref_cnt", lambda _ea: 2, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_dref", lambda _ea, index: 0x3000 if index == 0 else BADADDR, raising=False)
    structured = helpers._format_disasm_structured(0x1000)
    assert structured["branch_target"] == "0x2000"
    assert structured["branch_name"] == "target_fn"
    assert structured["comment"] == "repeat"
    assert structured["data_refs"] == [{"addr": "0x3000"}]
    assert "target_fn" in helpers._format_disasm_line(0x1000, style="annotated", annotate_branches=True)

    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: BADADDR if ea >= 0x1000 else ea + 1)
    monkeypatch.setattr(helpers.idc, "prev_head", lambda ea, _min: BADADDR)
    assert len(helpers._disasm_range_structured(0x1000, 0x1002, 2)) == 1
    assert len(helpers._disasm_window(0x1000, radius=3, max_items=3, style="classic", include_bytes=False)) == 1

    class FuncData:
        def __init__(self):
            self.items = [types.SimpleNamespace(name="value")]

        def size(self):
            return len(self.items)

        def __getitem__(self, index):
            return self.items[index]

    class Tinfo:
        def get_func_details(self, data):
            data.items = [types.SimpleNamespace(name="value")]
            return True

    monkeypatch.setattr(helpers.idc, "get_type", lambda _ea: "int target(int value)")
    monkeypatch.setattr(helpers.idc, "parse_decl", lambda *_args: (Tinfo(), "target"))
    monkeypatch.setattr(helpers.ida_typeinf, "func_type_data_t", FuncData, raising=False)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda ea: {0x4000: "target", 0x5000: "caller"}.get(ea, ""))
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(
        helpers.idautils,
        "XrefsTo",
        lambda ea, _flow: [types.SimpleNamespace(frm=0x5000, iscode=True)] if ea == 0x4000 else [],
    )
    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: types.SimpleNamespace(__str__=lambda self: "target(0x1234)"))
    # A plain object with a custom __str__ is more reliable than assigning the
    # special method on an instance.
    class Decompiled:
        def __str__(self):
            return "target(0x1234)"

    monkeypatch.setattr(helpers.ida_hexrays, "decompile", lambda _ea: Decompiled())
    traced = helpers._trace_argument_origin(types.SimpleNamespace(start_ea=0x4000), 0, 0, 4)
    assert traced["trace_tree"][0]["arg_type"] == "constant"
    assert traced["trace_tree"][0]["arg_source"] == "0x1234"


def test_gather_function_context_collects_callers_callees_strings_and_cfg(monkeypatch):
    func = types.SimpleNamespace(start_ea=0x1000)

    class Iterator:
        def __init__(self, _func):
            self.ea = 0x1000

        def current(self):
            return self.ea

        def next_code(self):
            self.ea = BADADDR
            return False

    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: 0x1000 if ea == 0x1000 else ea)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(helpers.idaapi, "get_first_cref_to", lambda _ea: 0x2000, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_next_cref_to", lambda *_args: BADADDR, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_first_cref_from", lambda _ea: 0x3000, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_next_cref_from", lambda *_args: BADADDR, raising=False)
    monkeypatch.setattr(helpers.idaapi, "func_item_iterator_t", Iterator, raising=False)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda ea: {0x2000: "caller", 0x3000: "callee"}.get(ea, ""))
    monkeypatch.setattr(helpers.idaapi, "get_first_dref_from", lambda _ea: 0x5000, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_next_dref_from", lambda *_args: BADADDR, raising=False)
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda *_args: b"hello")
    monkeypatch.setattr(helpers, "_compute_cfg_semantics", lambda _func: {"nodes": 1, "edges": 0})
    context = helpers.gather_function_context(0x1000, max_refs=4)
    assert context["callers"] == ["caller"]
    assert context["callees"] == ["callee"]
    assert context["strings"] == ["hello"]
    assert context["complexity"]["nodes"] == 1
