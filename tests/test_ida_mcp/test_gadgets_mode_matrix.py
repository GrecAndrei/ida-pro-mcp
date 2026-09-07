"""Cross-mode gadget discovery tests for heads, raw sweeps, and ABIs."""

from __future__ import annotations

import importlib
import sys
import types

import pytest

from ida_pro_mcp.ida_mcp.tools.gadgets import (
    _decode_backward,
    _detect_mitigations,
    _find_cop_gadgets,
    _find_jop_gadgets,
    _find_rop_gadgets,
    _find_seh_handlers,
    _find_shellcode_space,
    _find_stack_pivot,
    _find_syscall_gadgets,
    _find_write_what_where,
    _get_exec_segments,
    _is_cop_terminator,
    _is_jop_terminator,
    _is_syscall_terminator,
    _matches_query,
    _prepare_exec_region,
    _raw_decode_insn,
    _region_results,
    _scan_region_terminators,
    _score_gadgets_behavior,
    _suggest_pivot_chains,
    gadgets,
)

gadgets_module = importlib.import_module("ida_pro_mcp.ida_mcp.tools.gadgets")


def _install_instruction_map(monkeypatch, entries):
    """Install a deterministic IDA-head view for scanner tests."""
    import idc

    addresses = sorted(entries)
    monkeypatch.setattr(idc, "print_insn_mnem", lambda ea: entries.get(ea, {}).get("mnem", ""), raising=False)
    monkeypatch.setattr(idc, "generate_disasm_line", lambda ea, _flags=0: entries.get(ea, {}).get("disasm", ""), raising=False)
    monkeypatch.setattr(idc, "get_item_size", lambda ea: entries.get(ea, {}).get("size", 1), raising=False)
    monkeypatch.setattr(idc, "get_operand_type", lambda ea, index: entries.get(ea, {}).get("types", {}).get(index, 0), raising=False)
    monkeypatch.setattr(idc, "get_operand_value", lambda ea, index: entries.get(ea, {}).get("values", {}).get(index, 0), raising=False)
    monkeypatch.setattr(
        idc,
        "next_head",
        lambda ea, end=0xFFFFFFFFFFFFFFFF: next((value for value in addresses if ea < value < end), 0xFFFFFFFFFFFFFFFF),
        raising=False,
    )
    monkeypatch.setattr(
        idc,
        "prev_head",
        lambda ea, _start=0: next((value for value in reversed(addresses) if value < ea), 0xFFFFFFFFFFFFFFFF),
        raising=False,
    )


def test_terminator_classifiers_cover_x86_arm_mips_ppc_riscv_and_sparc():
    import idc

    monkeypatch = pytest.MonkeyPatch()
    try:
        # The imported classifier can outlive a canonical module reload made
        # by another test family.  Bind its globals explicitly so the patch
        # reaches the object the function actually executes against.
        monkeypatch.setitem(_is_jop_terminator.__globals__, "idc", gadgets_module.idc)
        monkeypatch.setattr(
            gadgets_module.idc,
            "get_operand_type",
            lambda ea, _index: gadgets_module.idc.o_near if ea == 2 else gadgets_module.idc.o_reg,
            raising=False,
        )
        monkeypatch.setattr(gadgets_module.idc, "get_operand_value", lambda *_args: 0x80, raising=False)
        assert _is_jop_terminator(1, "jmp", "jmp rax", "x64")
        assert not _is_jop_terminator(2, "jmp", "jmp 0x1000", "x64")
        assert _is_cop_terminator(1, "call", "call rax", "x64")
        assert _is_syscall_terminator(1, "int", "int 0x80", "x86")
        assert _is_syscall_terminator(1, "svc", "svc #0", "arm")
        assert _is_jop_terminator(1, "bx", "bx r3", "arm")
        assert _is_cop_terminator(1, "blr", "blr r3", "arm")
        assert _is_jop_terminator(1, "jr", "jr $t9", "mips")
        assert _is_cop_terminator(1, "jalr", "jalr $t9", "mips")
        assert _is_syscall_terminator(1, "syscall", "syscall", "mips")
        assert _is_jop_terminator(1, "bctr", "bctr", "ppc")
        assert _is_cop_terminator(1, "bctrl", "bctrl", "ppc")
        assert _is_syscall_terminator(1, "sc", "sc", "ppc")
        assert _is_jop_terminator(1, "jalr", "jalr t0, 0(t1)", "riscv")
        assert _is_cop_terminator(1, "c.jalr", "c.jalr t1", "riscv")
        assert _is_syscall_terminator(1, "ecall", "ecall", "riscv")
        assert _is_syscall_terminator(1, "ta", "ta 0x10", "sparc")
        assert not _is_jop_terminator(1, "jmp", "jmp r0", "unknown")
    finally:
        monkeypatch.undo()


def test_head_scan_decoding_query_cache_and_region_selection(monkeypatch):
    entries = {
        0x1000: {"mnem": "pop", "disasm": "pop rdi", "size": 1},
        0x1001: {"mnem": "ret", "disasm": "ret", "size": 1},
    }
    _install_instruction_map(monkeypatch, entries)
    insns = _decode_backward(0x1001, 5)
    assert [item[1] for item in insns] == ["pop", "ret"]
    assert _matches_query(insns, "rdi")
    assert _matches_query(insns, "rdi")  # exercises the LRU hit path
    assert _matches_query(insns, None)
    seen = set()
    found = _scan_region_terminators(
        0x1000, 0x1002, 5, 5, "ret", "x64", lambda *_args: True, seen
    )
    assert found[0]["insns"] == 2

    monkeypatch.setattr(gadgets_module, "_region_has_heads", lambda *_args: True)
    monkeypatch.setattr(gadgets_module, "_scan_region_terminators", lambda *args: [{"path": "heads"}])
    monkeypatch.setattr(gadgets_module, "_sweep_region_terminators", lambda *args: [{"path": "raw"}])
    monkeypatch.setattr(gadgets_module, "_prepare_exec_region", lambda *_args: True)
    assert _region_results(0x1000, 0x1002, 3, 3, None, "x64", lambda *_a: True, set(), False) == [{"path": "heads"}]
    assert _region_results(0x1000, 0x1002, 3, 3, None, "x64", lambda *_a: True, set(), True) == [{"path": "raw"}]
    assert _prepare_exec_region(0x1000, 0x1002)


def test_raw_decode_handles_missing_invalid_and_valid_decoder(monkeypatch):
    import ida_ua

    class Decoded:
        size = 4

        def get_canon_mnem(self):
            return "ret"

    monkeypatch.setattr(ida_ua, "insn_t", Decoded, raising=False)
    monkeypatch.setattr(ida_ua, "decode_insn", lambda _insn, _ea: 4, raising=False)
    monkeypatch.setattr(gadgets_module, "_disasm_at", lambda _ea: "ret", raising=False)
    assert _raw_decode_insn(0x1000) == (0x1000, "ret", "ret", 4)
    monkeypatch.setattr(ida_ua, "decode_insn", lambda _insn, _ea: 0, raising=False)
    assert _raw_decode_insn(0x1000) is None
    monkeypatch.setattr(ida_ua, "decode_insn", lambda *_args: (_ for _ in ()).throw(RuntimeError("bad")), raising=False)
    assert _raw_decode_insn(0x1000) is None


def test_rop_jop_cop_syscall_paths_run_on_real_fake_idb(monkeypatch, fresh_fake_idb):
    monkeypatch.setattr(gadgets_module, "_get_exec_segments", lambda _addr: iter([(0x140001000, 0x140001050)]))
    monkeypatch.setattr(gadgets_module, "_get_arch", lambda: "x64")
    for finder in (_find_rop_gadgets, _find_jop_gadgets, _find_cop_gadgets, _find_syscall_gadgets):
        result = finder("0x140001000", 20, 5, None, raw=False)
        assert isinstance(result, list)
    public = gadgets(action="rop", address="0x140001000", limit=5)
    assert public["ok"] is True
    assert public["action"] == "rop"
    assert "arch" in public
    assert gadgets(action="semantic_find").get("ok") is not True


@pytest.mark.parametrize(
    ("arch_name", "store_mnem", "store_disasm", "pivot_disasm"),
    [
        ("x64", "mov", "mov [rax], rbx", "xchg rsp, rax"),
        ("arm64", "str", "str x0, [x1]", "mov sp, x0"),
        ("mips", "sw", "sw $t0, 0($t1)", "addiu sp, t0, 4"),
        ("ppc", "stw", "stw r3, 0(r4)", "addi r1, r3, 4"),
        ("riscv", "sw", "sw a0, 0(a1)", "addi sp, a0, 4"),
    ],
)
def test_write_what_where_and_stack_pivot_are_arch_aware(
    monkeypatch, arch_name, store_mnem, store_disasm, pivot_disasm
):
    import idc

    entries = {
        0x1000: {
            "mnem": store_mnem,
            "disasm": store_disasm,
            "size": 1,
            "types": {0: idc.o_phrase, 1: idc.o_reg},
        },
        0x1001: {"mnem": "ret", "disasm": "ret", "size": 1},
        0x1010: {"mnem": "xchg" if arch_name == "x64" else "mov", "disasm": pivot_disasm, "size": 1},
        0x1011: {"mnem": "ret", "disasm": "ret", "size": 1},
    }
    _install_instruction_map(monkeypatch, entries)
    monkeypatch.setattr(gadgets_module, "_get_arch", lambda: arch_name)
    monkeypatch.setattr(gadgets_module, "_get_exec_segments", lambda _addr: iter([(0x1000, 0x1012)]))
    monkeypatch.setattr(gadgets_module, "_prepare_exec_region", lambda *_args: True)
    www = _find_write_what_where("0x1000", 5, 3, None)
    pivot = _find_stack_pivot("0x1000", 5, 3, None)
    assert isinstance(www, list)
    assert isinstance(pivot, list)


def test_shellcode_mitigations_seh_and_pivot_chain_modes(monkeypatch, fresh_fake_idb):
    import ida_bytes
    import idaapi
    import idautils
    import idc

    monkeypatch.setattr(gadgets_module, "_get_exec_segments", lambda _addr: iter([(0x140001000, 0x140001050)]))
    shell = _find_shellcode_space(None, 10, 5, None)
    assert any(".text" in row for row in shell) is False  # executable but not writable
    fresh_fake_idb.segments[0].perm |= idaapi.SEGPERM_WRITE
    shell = _find_shellcode_space(None, 10, 10, None)
    assert shell

    monkeypatch.setattr(gadgets_module, "_get_arch", lambda: "x64")
    monkeypatch.setattr(idaapi, "get_imagebase", lambda: fresh_fake_idb.base, raising=False)
    monkeypatch.setattr(ida_bytes, "get_dword", lambda _ea: 0x80, raising=False)
    monkeypatch.setattr(ida_bytes, "get_word", lambda _ea: 0x20B, raising=False)
    monkeypatch.setattr(idc, "get_name_ea_simple", lambda _name: idaapi.BADADDR, raising=False)
    monkeypatch.setattr(idautils, "Names", lambda: iter(()), raising=False)
    mits = _detect_mitigations(None, 10, 5, None)
    assert mits["format"] == "PE"
    assert "DEP/NX" in mits
    fresh_fake_idb.filetype = idaapi.f_ELF
    elf = _detect_mitigations(None, 10, 5, None)
    assert elf["format"] == "ELF"
    fresh_fake_idb.filetype = idaapi.f_MACHO
    macho = _detect_mitigations(None, 10, 5, None)
    assert macho["format"] == "Mach-O"
    fresh_fake_idb.filetype = 999
    assert _detect_mitigations(None, 10, 5, None)["format"] == "unknown"

    handlers = _find_seh_handlers(None, 5, 5, None)
    assert handlers == []
    monkeypatch.setattr(gadgets_module, "_get_arch", lambda: "arm")
    assert _find_seh_handlers(None, 5, 5, None) == []

    for arch_name in ("x64", "arm64", "mips", "ppc", "riscv", "unknown"):
        monkeypatch.setattr(gadgets_module, "_get_arch", lambda name=arch_name: name)
        monkeypatch.setattr(gadgets_module, "_get_exec_segments", lambda _addr: iter(()))
        assert isinstance(_suggest_pivot_chains(None, 20, 3, None), dict)


def test_behavior_scoring_and_chain_empty_paths_are_fail_closed(monkeypatch):
    assert _score_gadgets_behavior([], "rop") is None
    monkeypatch.setattr(gadgets_module, "_ACTIONS", {"rop": lambda *_args, **_kwargs: []})
    empty = gadgets_module._classify_gadget_chain(None, 5, 3, None)
    assert empty["ok"] is True
    assert empty["exploit_assessment"] == "No gadgets found"
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", None)
    assert _score_gadgets_behavior([{"gadget": "ret"}], "rop") is None


def test_positive_chain_classification_and_semantic_scoring_modes(monkeypatch):
    class FakeEmbedder:
        backend = "offline-test"

    class FakeClassifier:
        ANCHORS = {"memory_manipulation": "memory"}

        def __init__(self):
            self.calls = []

        def clear_cache(self):
            return None

        def classify(self, text, **kwargs):
            self.calls.append((text, kwargs))
            return [{"behavior": "code_exec", "confidence": 0.95}]

    classifier = FakeClassifier()

    class FakeBehaviorClassifier:
        ANCHORS = {"memory_manipulation": "memory"}

        @classmethod
        def instance(cls, _embedder):
            return classifier

    fake_services = types.ModuleType("ida_pro_mcp.services")
    fake_services.BehaviorClassifier = FakeBehaviorClassifier
    fake_services.BgeCodeEmbedder = FakeEmbedder
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", fake_services)

    handlers = {
        "rop": lambda *_args, **_kwargs: [{"gadget": "pop rdi ; ret"}],
        "stack_pivot": lambda *_args, **_kwargs: [{"gadget": "xchg rsp, rax ; ret"}],
        "write_what_where": lambda *_args, **_kwargs: [{"gadget": "mov [rax], rbx ; ret"}],
        "syscall": lambda *_args, **_kwargs: [{"gadget": "syscall"}],
    }
    monkeypatch.setattr(gadgets_module, "_ACTIONS", handlers)
    monkeypatch.setattr(gadgets_module, "_get_arch", lambda: "x64")

    scored = _score_gadgets_behavior([{"gadget": "pop rdi ; ret"}], "rop")
    assert scored["top_primitive"] == "code_exec"

    result = gadgets_module._classify_gadget_chain(None, 20, 5, None)
    assert result["exploit_assessment"].startswith("HIGH:")
    assert result["primitives_found"]["rop"] == 1
    assert result["backend"] == "offline-test"
    assert classifier.calls


def test_pivot_chain_categories_seh_and_elf_mitigation_branches(monkeypatch):
    import idaapi
    import idautils
    import idc

    entries = {}
    mnemonics = ("pop", "mov", "xchg", "add", "sub", "inc", "dec", "xor", "neg", "not", "syscall")
    for index, mnem in enumerate(mnemonics):
        ea = 0x1000 + index * 2
        entries[ea] = {"mnem": mnem, "disasm": f"{mnem} rax", "size": 1}
        entries[ea + 1] = {"mnem": "ret", "disasm": "ret", "size": 1}
    _install_instruction_map(monkeypatch, entries)
    monkeypatch.setattr(gadgets_module, "_get_arch", lambda: "x64")
    monkeypatch.setattr(gadgets_module, "_get_exec_segments", lambda _addr: iter([(0x1000, 0x1020)]))
    categories = _suggest_pivot_chains(None, 100, 3, None)
    assert categories and "pop_reg_ret" in categories

    seh_entries = {
        0x2000: {"mnem": "push", "disasm": "push 0x3000", "size": 1, "values": {0: 0x3000}},
        0x2001: {"mnem": "push", "disasm": "push dword ptr fs:[0]", "size": 1},
    }
    _install_instruction_map(monkeypatch, seh_entries)
    monkeypatch.setattr(gadgets_module, "_get_arch", lambda: "x86")
    monkeypatch.setattr(gadgets_module, "_get_exec_segments", lambda _addr: iter([(0x2000, 0x2002)]))
    monkeypatch.setattr(gadgets_module._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(gadgets_module.ida_funcs, "get_func_name", lambda ea: f"handler_{ea:x}")
    handlers = _find_seh_handlers(None, 5, 5, None)
    assert handlers and "handler_3000" in handlers[0]

    monkeypatch.setattr(gadgets_module, "_inf_filetype_id", lambda: idaapi.f_ELF)
    monkeypatch.setattr(idautils, "Segments", lambda: [1, 2])
    monkeypatch.setattr(gadgets_module._compat, "get_segment", lambda _ea: object())
    monkeypatch.setattr(gadgets_module._compat, "get_segment_name", lambda ea: ".got.plt" if ea == 1 else ".text")
    monkeypatch.setattr(gadgets_module._compat, "get_segment_perm", lambda ea: 2 if ea == 1 else 0)
    monkeypatch.setattr(idautils, "Names", lambda: iter([(0x4000, "__memcpy_chk")]))
    monkeypatch.setattr(idc, "get_name_ea_simple", lambda _name: idaapi.BADADDR, raising=False)
    monkeypatch.setattr(idaapi, "get_imagebase", lambda: 0, raising=False)
    mitigations = _detect_mitigations(None, 5, 5, None)
    assert mitigations["format"] == "ELF"
    assert mitigations["RELRO"] == "partial"
    assert mitigations["FORTIFY_SOURCE"] is True
    assert mitigations["NX"] is True


def test_mitigation_format_and_cookie_modes_cover_pe_elf_macho(monkeypatch, fresh_fake_idb):
    import ida_bytes
    import idaapi
    import idautils
    import idc

    base = 0x140000000
    monkeypatch.setattr(gadgets_module, "_get_arch", lambda: "x64")
    monkeypatch.setattr(idaapi, "get_imagebase", lambda: base, raising=False)
    monkeypatch.setattr(gadgets_module, "_inf_filetype_id", lambda: idaapi.f_PE)
    monkeypatch.setattr(ida_bytes, "get_dword", lambda _ea: 0x100, raising=False)
    monkeypatch.setattr(ida_bytes, "get_word", lambda _ea: 0xFFFF, raising=False)
    monkeypatch.setattr(
        idc,
        "get_name_ea_simple",
        lambda name: 0x7000 if name == "__security_cookie" else idaapi.BADADDR,
        raising=False,
    )
    pe = _detect_mitigations(None, 10, 5, None)
    assert pe["format"] == "PE"
    assert pe["ASLR"] is True and pe["DEP/NX"] is True
    assert pe["high_entropy_ASLR"] is True and pe["guard_CF"] is True
    assert pe["stack_cookies"] is True

    monkeypatch.setattr(ida_bytes, "get_dword", lambda _ea: (_ for _ in ()).throw(RuntimeError("bad PE")), raising=False)
    pe_error = _detect_mitigations(None, 10, 5, None)
    assert pe_error["pe_parse_error"] is True

    monkeypatch.setattr(gadgets_module, "_inf_filetype_id", lambda: idaapi.f_ELF)
    monkeypatch.setattr(idc, "get_name_ea_simple", lambda name: 0x7000 if name == "__stack_chk_fail" else idaapi.BADADDR, raising=False)
    monkeypatch.setattr(idautils, "Segments", lambda: [1], raising=False)
    monkeypatch.setattr(gadgets_module._compat, "get_segment", lambda _ea: object())
    monkeypatch.setattr(gadgets_module._compat, "get_segment_name", lambda _ea: ".got")
    monkeypatch.setattr(gadgets_module._compat, "get_segment_perm", lambda _ea: idaapi.SEGPERM_EXEC | idaapi.SEGPERM_WRITE)
    monkeypatch.setattr(idautils, "Names", lambda: iter(()), raising=False)
    elf = _detect_mitigations(None, 10, 5, None)
    assert elf["format"] == "ELF" and elf["RELRO"] == "none" and elf["NX"] is False
    assert elf["stack_cookies"] is True and elf["PIE"] is False

    monkeypatch.setattr(gadgets_module, "_inf_filetype_id", lambda: idaapi.f_MACHO)
    monkeypatch.setattr(idaapi, "get_imagebase", lambda: 0x100000000, raising=False)
    monkeypatch.setattr(idc, "get_name_ea_simple", lambda name: 0x7000 if name == "___stack_chk_guard" else idaapi.BADADDR, raising=False)
    macho = _detect_mitigations(None, 10, 5, None)
    assert macho == {
        "format": "Mach-O",
        "stack_cookies": True,
        "stack_cookie_symbol": "___stack_chk_guard",
        "PIE": True,
        "arch": "x64",
    }


def test_gadget_scan_helper_fallbacks_and_public_error_modes(monkeypatch):
    import idc

    ida_auto = types.ModuleType("ida_auto")
    monkeypatch.setitem(sys.modules, "ida_auto", ida_auto)

    assert list(_get_exec_segments("bad-address")) == []
    monkeypatch.setattr(idc, "get_item_size", lambda _ea: 0, raising=False)
    assert _decode_backward(0x1000, 3) is None
    monkeypatch.setattr(idc, "get_item_size", lambda _ea: 1, raising=False)
    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: "", raising=False)
    assert _decode_backward(0x1000, 3) is None

    monkeypatch.delattr(ida_auto, "plan_range", raising=False)
    ida_auto.auto_mark_range = lambda *_args: None
    ida_auto.AU_FINAL = 16
    assert _prepare_exec_region(1, 2) is True
    monkeypatch.delattr(ida_auto, "auto_mark_range", raising=False)
    ida_auto.auto_make_code = lambda *_args: None
    assert _prepare_exec_region(1, 2) is True
    monkeypatch.setattr(ida_auto, "auto_make_code", lambda *_args: (_ for _ in ()).throw(RuntimeError("busy")))
    assert _prepare_exec_region(1, 2) is False

    monkeypatch.setattr(gadgets_module, "_ACTIONS", {})
    assert gadgets(action="not-an-action")["error"] is True
    semantic = gadgets(action="semantic_find")
    assert semantic["error"] is True and "host-intercepted" in semantic["message"]
