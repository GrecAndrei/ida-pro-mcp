"""Exercise gadget scanner boundaries that are easy to miss in one mode."""

from __future__ import annotations

import importlib
import sys
import types

module = importlib.import_module("ida_pro_mcp.ida_mcp.tools.gadgets")
from ida_pro_mcp.ida_mcp.tools.gadgets import (
    _decode_backward,
    _find_stack_pivot,
    _find_write_what_where,
    _get_exec_segments,
    _is_cop_terminator,
    _is_jop_terminator,
    _is_syscall_terminator,
    _raw_decode_insn,
    _scan_region_terminators,
    _suggest_pivot_chains,
    _sweep_region_terminators,
    gadgets as gadget_tool,
)
from tests.test_ida_mcp.test_gadgets_mode_matrix import _install_instruction_map


def test_exec_segment_selection_and_backward_decode_failures(monkeypatch):
    import idc

    segments = {
        1: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010),
        2: types.SimpleNamespace(start_ea=0x2000, end_ea=0x2010),
        3: None,
    }
    monkeypatch.setattr(module, "validate_addr", lambda _value: (0x1004, None))
    def get_segment(ea):
        return segments.get(ea) or segments[1]

    monkeypatch.setattr(module._compat, "get_segment", get_segment)
    monkeypatch.setattr(module._compat, "get_segment_perm", lambda _ea: 4)
    monkeypatch.setattr(module._compat, "get_segment_type", lambda ea: 2 if ea == 2 else 0)
    monkeypatch.setattr(idc, "o_near", 7, raising=False)
    monkeypatch.setattr(module.idaapi, "SEGPERM_EXEC", 4, raising=False)
    monkeypatch.setattr(module.idaapi, "SEG_CODE", 2, raising=False)
    assert list(_get_exec_segments("0x1004")) == [(0x1000, 0x1010)]

    monkeypatch.setattr(module, "validate_addr", lambda _value: (0x1004, {"error": True}))
    assert list(_get_exec_segments("bad")) == []
    monkeypatch.setattr(module, "validate_addr", lambda _value: (0x1004, None))
    monkeypatch.setattr(module._compat, "get_segment_perm", lambda _ea: 0)
    assert list(_get_exec_segments("0x1004")) == []

    monkeypatch.setattr(module.idautils, "Segments", lambda: iter((1, 2, 3)))
    monkeypatch.setattr(module._compat, "get_segment_perm", lambda ea: 4 if ea == 1 else 0)
    assert list(_get_exec_segments(None)) == [(0x1000, 0x1010), (0x2000, 0x2010)]

    entries = {
        0x3000: {"mnem": "nop", "disasm": "nop", "size": 2},
        0x3002: {"mnem": "ret", "disasm": "ret", "size": 1},
    }
    _install_instruction_map(monkeypatch, entries)
    assert _decode_backward(0x3002, 3)[0][1] == "nop"
    monkeypatch.setattr(idc, "prev_head", lambda _ea, _start=0: 0x2FFF, raising=False)
    monkeypatch.setattr(idc, "get_item_size", lambda _ea: 1, raising=False)
    assert len(_decode_backward(0x3002, 3)) == 1


def test_terminators_and_raw_decoder_cover_unparseable_arch_paths(monkeypatch):
    import ida_ua
    import idc

    monkeypatch.setattr(idc, "get_operand_type", lambda *_args: idc.o_reg, raising=False)
    assert _is_jop_terminator(1, "bx", "bx lr", "arm") is False
    assert _is_cop_terminator(1, "blx", "blx lr", "arm") is False
    assert _is_syscall_terminator(1, "int", "int 3", "x86") is False
    assert _is_syscall_terminator(1, "trap", "trap", "unknown") is False

    class NoMnemonic:
        size = 4

        def get_canon_mnem(self):
            return ""

    monkeypatch.setattr(ida_ua, "insn_t", NoMnemonic, raising=False)
    monkeypatch.setattr(ida_ua, "decode_insn", lambda *_args: 1, raising=False)
    assert _raw_decode_insn(0x1000) is None

    class NoSize:
        size = 0

        def get_canon_mnem(self):
            return "nop"

    monkeypatch.setattr(ida_ua, "insn_t", NoSize, raising=False)
    assert _raw_decode_insn(0x1000) is None


def test_head_and_raw_scans_handle_gaps_duplicates_and_limits(monkeypatch):
    entries = {
        0x1000: {"mnem": "", "disasm": "", "size": 1},
        0x1001: {"mnem": "nop", "disasm": "nop", "size": 1},
        0x1002: {"mnem": "ret", "disasm": "ret", "size": 1},
    }
    _install_instruction_map(monkeypatch, entries)
    found = _scan_region_terminators(
        0x1000,
        0x1003,
        2,
        3,
        "ret",
        "x64",
        lambda _ea, mnem, _text: mnem == "ret",
        set(),
    )
    assert found and found[0]["insns"] == 2
    assert _scan_region_terminators(
        0x1001,
        0x1003,
        2,
        3,
        "never-matches",
        "x64",
        lambda *_args: True,
        set(),
    ) == []

    decoded = {
        0x2000: (0x2000, "nop", "nop", 1),
        0x2001: (0x2001, "ret", "ret", 1),
    }
    monkeypatch.setattr(module, "_raw_decode_insn", decoded.get)
    output = _sweep_region_terminators(
        0x2000,
        0x2003,
        2,
        3,
        None,
        "x64",
        lambda _ea, mnem, _text: mnem == "ret",
        set(),
    )
    assert output and output[0]["insns"] == 2


def test_write_where_and_stack_pivot_scans_cover_positive_and_rejected_shapes(monkeypatch):
    import idc

    entries = {
        0x1000: {
            "mnem": "mov",
            "disasm": "mov [rax], rbx",
            "size": 1,
            "types": {0: idc.o_phrase, 1: idc.o_reg},
        },
        0x1001: {"mnem": "ret", "disasm": "ret", "size": 1},
        0x1010: {"mnem": "leave", "disasm": "leave", "size": 1},
        0x1011: {"mnem": "ret", "disasm": "ret", "size": 1},
        0x1020: {"mnem": "pop", "disasm": "pop rsp", "size": 1},
        0x1021: {"mnem": "ret", "disasm": "ret", "size": 1},
    }
    _install_instruction_map(monkeypatch, entries)
    monkeypatch.setattr(module, "_get_arch", lambda: "x64")
    monkeypatch.setattr(module, "_get_exec_segments", lambda _addr: iter([(0x1000, 0x1022)]))
    monkeypatch.setattr(module, "_prepare_exec_region", lambda *_args: False)
    www = _find_write_what_where(None, 10, 3, None)
    pivots = _find_stack_pivot(None, 10, 3, None)
    assert any("mov [rax]" in row["gadget"] for row in www)
    assert any("leave" in row["gadget"] for row in pivots)
    assert any("pop rsp" in row["gadget"] for row in pivots)

    riscv = {
        0x2000: {"mnem": "sw", "disasm": "sw a0, 0(sp)", "size": 1},
        0x2001: {"mnem": "sw", "disasm": "sw a0, 0(a1)", "size": 1},
        0x2002: {"mnem": "ret", "disasm": "ret", "size": 1},
    }
    _install_instruction_map(monkeypatch, riscv)
    monkeypatch.setattr(module, "_get_arch", lambda: "riscv64")
    monkeypatch.setattr(module, "_get_exec_segments", lambda _addr: iter([(0x2000, 0x2003)]))
    assert any("sw a0, 0(a1)" in row["gadget"] for row in _find_write_what_where(None, 5, 3, None))


def test_pivot_chains_cover_arch_fallbacks_and_public_empty_notes(monkeypatch):
    entries = {
        0x1000: {"mnem": "mov", "disasm": "mov rax, rbx", "size": 1},
        0x1001: {"mnem": "ret", "disasm": "ret", "size": 1},
    }
    _install_instruction_map(monkeypatch, entries)
    monkeypatch.setattr(module, "_get_exec_segments", lambda _addr: iter([(0x1000, 0x1002)]))
    monkeypatch.setattr(module, "_get_arch", lambda: "unknown")
    assert _suggest_pivot_chains(None, 10, 3, None)
    for arch in ("arm64", "mips", "ppc", "riscv64"):
        monkeypatch.setattr(module, "_get_arch", lambda arch=arch: arch)
        assert isinstance(_suggest_pivot_chains(None, 10, 3, None), dict)

    monkeypatch.setattr(module, "_exec_region_has_heads", lambda _addr: True)
    monkeypatch.setattr(module, "_ACTIONS", {"rop": lambda *_args, **_kwargs: []})
    monkeypatch.setattr(module, "_score_gadgets_behavior", lambda *_args: None)
    monkeypatch.setattr(module, "_get_arch", lambda: "x64")
    forced = gadget_tool(action="rop", raw=True)
    assert forced["note"].startswith("raw=True forced")
    monkeypatch.setattr(module, "_exec_region_has_heads", lambda _addr: False)
    automatic = gadget_tool(action="rop")
    assert "never disassembled" in automatic["note"]


def test_chain_assessment_covers_minimal_low_medium_and_high(monkeypatch):
    class FakeClassifier:
        ANCHORS = {"memory_manipulation": "memory"}

        def clear_cache(self):
            return None

        def classify(self, *_args, **_kwargs):
            return []

    classifier = FakeClassifier()

    class Behavior:
        ANCHORS = classifier.ANCHORS

        @classmethod
        def instance(cls, _embedder):
            return classifier

    services = types.ModuleType("ida_pro_mcp.services")
    services.BehaviorClassifier = Behavior
    services.BgeCodeEmbedder = lambda: types.SimpleNamespace(backend="offline")
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    monkeypatch.setattr(module, "_get_arch", lambda: "x64")

    def assess(handlers):
        monkeypatch.setattr(module, "_ACTIONS", handlers)
        return module._classify_gadget_chain(None, 10, 3, None)

    assert assess({"stack_pivot": lambda *_args: [{"gadget": "leave ; ret"}]})["exploit_assessment"].startswith("MINIMAL")
    assert assess({"rop": lambda *_args: [{"gadget": "pop rdi ; ret"}]})["exploit_assessment"].startswith("LOW")
    medium = assess({
        "rop": lambda *_args: [{"gadget": "pop rdi ; ret"}],
        "stack_pivot": lambda *_args: [{"gadget": "leave ; ret"}],
    })
    assert medium["exploit_assessment"].startswith("MEDIUM")
    high = assess({
        "rop": lambda *_args: [{"gadget": "pop rdi ; ret"}],
        "stack_pivot": lambda *_args: [{"gadget": "leave ; ret"}],
        "write_what_where": lambda *_args: [{"gadget": "mov [rax], rbx ; ret"}],
        "syscall": lambda *_args: [{"gadget": "syscall"}],
    })
    assert high["exploit_assessment"].startswith("HIGH")
    assert high["behavior_classifications"] == []
