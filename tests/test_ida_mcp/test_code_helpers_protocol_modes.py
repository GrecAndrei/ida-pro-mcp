"""Protocol and fallback coverage for code-helper paths across IDA modes."""

from __future__ import annotations

import importlib
import types

from tests.fakes.ida_fake import BADADDR


def _helpers():
    return importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")


def test_store_and_firmware_signals_cover_instruction_fallbacks(monkeypatch, fresh_fake_idb):
    helpers = _helpers()

    class _UA:
        o_displ = 4
        o_mem = 2

        class insn_t:
            def __init__(self):
                self.ops = []

        @staticmethod
        def decode_insn(insn, ea):
            if ea == 0x1000:
                return 0
            insn.ops = [types.SimpleNamespace(type=4)] if ea in {0x1004, 0x1008} else []
            return 1

        @staticmethod
        def get_operand_value(_insn, _index):
            return 0x40001000

    monkeypatch.setattr(helpers, "ida_ua", _UA)
    assert helpers._store_memory_target(0x1000) is None
    assert helpers._store_memory_target(0x1008) == 0x40001000
    assert helpers._store_memory_target(0x1004) == 0x40001000
    monkeypatch.setattr(helpers, "ida_ua", None)
    assert helpers._store_memory_target(0x1004) is None

    func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1014)
    mnems = {0x1000: "ecall", 0x1004: "csrrw", 0x1008: "sw", 0x100C: "lui", 0x1010: ""}
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(helpers, "is_riscv_family", lambda: True)
    monkeypatch.setattr(helpers, "is_syscall_mnemonic", lambda value: value == "ecall")
    monkeypatch.setattr(helpers, "_FIRMWARE_STORE_MNEMONICS", {"sw"})
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda ea: mnems.get(ea, "nop"))
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda _ea, _idx: 0x5000)
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea + 4 if ea < 0x1010 else BADADDR)
    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda ea: ea in {0x5000})
    monkeypatch.setattr(helpers, "ida_ua", _UA)
    signals = helpers._detect_firmware_signals(0x1000)
    assert "syscall:ecall" in signals
    assert "csr_access:csrrw" in signals
    assert "mmio_store:0x40001000" in signals
    assert "large_constant_load:0x5000" in signals


def test_constant_strings_and_function_string_collection_use_both_modes(monkeypatch, fresh_fake_idb):
    helpers = _helpers()
    func = types.SimpleNamespace(start_ea=0x2000, end_ea=0x2018)
    mnems = {0x2000: "lui", 0x2004: "addi", 0x2008: "auipc", 0x200C: "ld", 0x2010: "mov", 0x2014: "li"}
    operands = {
        (0x2000, 0): "a0", (0x2000, 1): "0x500",
        (0x2004, 0): "a0", (0x2004, 1): "a0", (0x2004, 2): "0x10",
        (0x2008, 0): "a1", (0x2008, 1): "0x500",
        (0x200C, 0): "a2", (0x200C, 1): "0(a1)", (0x200C, 2): "0x10",
        (0x2010, 0): "a3", (0x2010, 1): "0x6000",
        (0x2014, 0): "a4", (0x2014, 1): "0x6000",
    }
    values = {(0x2000, 1): 0x500, (0x2004, 2): 0x10, (0x2008, 1): 0x500,
              (0x200C, 2): 0x10, (0x2010, 1): 0x6000, (0x2014, 1): 0x6000}
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda ea: mnems.get(ea, "nop"))
    monkeypatch.setattr(helpers.idc, "print_operand", lambda ea, idx: operands.get((ea, idx), ""))
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda ea, idx: values.get((ea, idx), 0))
    monkeypatch.setattr(helpers.idc, "next_head", lambda ea, _end: ea + 4 if ea < 0x2014 else BADADDR)
    loaded = {0x500010, 0x6000}
    monkeypatch.setattr(helpers.ida_bytes, "is_loaded", lambda ea: ea in loaded)
    monkeypatch.setattr(helpers.ida_bytes, "get_bytes", lambda ea, _size: {0x500010: b"config-key\x00", 0x6000: b"hello\x00"}.get(ea, b""))
    entries = helpers._scan_constant_load_strings(0x2000, result_limit=4)
    assert {row["value"] for row in entries} == {"config-key", "hello"}

    class _Xref:
        iscode = False
        to = 0x7000

    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _ea: iter([0x2000]))
    monkeypatch.setattr(helpers.idautils, "XrefsFrom", lambda *_args: iter([types.SimpleNamespace(iscode=True), _Xref()]))
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda *_args: b"primary")
    assert helpers._collect_function_strings(0x2000) == ["primary"]
    monkeypatch.setattr(helpers.idautils, "XrefsFrom", lambda *_args: iter(()))
    monkeypatch.setattr(helpers, "_scan_constant_load_strings", lambda *_args: [{"addr": 0x7000, "value": "fallback"}])
    assert helpers._collect_function_string_entries(0x2000) == [{"addr": "0x7000", "value": "fallback"}]


def test_flow_and_disassembly_helpers_cover_sparse_head_and_reference_modes(monkeypatch, fresh_fake_idb):
    helpers = _helpers()
    monkeypatch.setattr(helpers, "get_arch", lambda: "arm64")
    assert helpers._is_flow_control_mnemonic("b.eq") is True
    assert helpers._is_flow_control_mnemonic("") is False
    assert helpers._is_flow_control_mnemonic("jal", arch="unknown") is True
    monkeypatch.setattr(helpers.idc, "print_insn_mnem", lambda _ea: "beq")
    monkeypatch.setattr(helpers.idc, "get_operand_type", lambda _ea, idx: 7 if idx == 2 else 0)
    monkeypatch.setattr(helpers.idc, "get_operand_value", lambda _ea, _idx: 0x140001040)
    monkeypatch.setattr(helpers.idc, "get_name", lambda ea: "target" if ea == 0x140001040 else "")
    assert helpers._flow_target_ea(0x140001000) == 0x140001040
    assert helpers._annotate_branch_target(0x140001000, "beq").startswith("target")
    monkeypatch.setattr(helpers.idc, "get_operand_type", lambda *_args: 0)
    assert helpers._flow_target_ea(0x140001000) is None

    monkeypatch.setattr(helpers.idc, "generate_disasm_line", lambda _ea, _flags: "")
    monkeypatch.setattr(helpers.idc, "print_operand", lambda *_args: "")
    monkeypatch.setattr(helpers.idc, "get_cmt", lambda *_args: "")
    monkeypatch.setattr(helpers.idc, "get_item_size", lambda _ea: 0)
    monkeypatch.setattr(helpers.idaapi, "get_dref_cnt", lambda _ea: 2, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_dref", lambda _ea, idx: 0x5000 if idx == 0 else BADADDR, raising=False)
    structured = helpers._format_disasm_structured(0x140001000)
    assert structured["text"] == "<data>" and structured["data_refs"] == [{"addr": "0x5000"}]
    monkeypatch.setattr(helpers.idc, "next_head", lambda *_args: BADADDR)
    monkeypatch.setattr(helpers.idc, "get_item_size", lambda _ea: 2)
    assert len(helpers._disasm_range_structured(0x1000, 0x1001, 3)) == 1
    monkeypatch.setattr(helpers.idc, "prev_head", lambda *_args: BADADDR)
    assert len(helpers._disasm_window(0x1000, radius=3, max_items=3, style="csmini", include_bytes=False)) == 1


def test_gather_context_and_detector_helpers_handle_missing_and_duplicate_modes(monkeypatch, fresh_fake_idb):
    helpers = _helpers()
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda _ea: None)
    assert helpers.gather_function_context(0x1000) == {}
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: None)
    assert helpers.gather_function_context(0x1000) == {}

    func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1008)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(helpers.idaapi, "get_first_cref_to", lambda _ea: 0x2000, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_next_cref_to", lambda *_args: BADADDR, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_first_cref_from", lambda _ea: 0x3000, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_next_cref_from", lambda *_args: BADADDR, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_first_dref_from", lambda _ea: 0x4000, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_next_dref_from", lambda *_args: BADADDR, raising=False)
    monkeypatch.setattr(helpers.idaapi, "func_item_iterator_t", lambda _func: types.SimpleNamespace(current=lambda: 0x1000, next_code=lambda: False), raising=False)
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: {0x2000: 0x2000, 0x3000: 0x3000}.get(ea, ea))
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda ea: {0x2000: "caller", 0x3000: "callee"}.get(ea, ""))
    monkeypatch.setattr(helpers.idc, "get_strlit_contents", lambda *_args: b"url")
    monkeypatch.setattr(helpers, "_compute_cfg_semantics", lambda _func: {"nodes": 1})
    context = helpers.gather_function_context(0x1000)
    assert context["callers"] == ["caller"] and context["callees"] == ["callee"]
    assert context["strings"] == ["url"] and context["complexity"] == {"nodes": 1}
