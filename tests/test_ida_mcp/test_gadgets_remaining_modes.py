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


def test_gadget_parser_classifier_and_import_fallback_modes(monkeypatch):
    import ida_ua
    import idautils

    # A segment can disappear between enumeration and lookup.  The scanner
    # should skip it instead of dereferencing a stale segment object.
    monkeypatch.setattr(idautils, "Segments", lambda: iter((1, 2)))
    monkeypatch.setattr(
        module._compat,
        "get_segment",
        lambda ea: None if ea == 1 else types.SimpleNamespace(start_ea=0x2000, end_ea=0x2010),
    )
    monkeypatch.setattr(module._compat, "get_segment_perm", lambda _ea: 4)
    monkeypatch.setattr(module._compat, "get_segment_type", lambda _ea: 0)
    monkeypatch.setattr(module.idaapi, "SEGPERM_EXEC", 4, raising=False)
    assert list(_get_exec_segments(None)) == [(0x2000, 0x2010)]

    # Exercise the bounded query cache, including its eviction and hit paths.
    module._QUERY_MATCHER_CACHE.clear()
    insns = [(0x1000, "mov", "mov rax, rbx")]
    for index in range(module._MAX_MATCHER_CACHE_SIZE + 1):
        assert module._matches_query(insns, f"query-{index}") is False
    assert len(module._QUERY_MATCHER_CACHE) == module._MAX_MATCHER_CACHE_SIZE
    assert module._matches_query(insns, "query-64") is False

    assert module._riscv_branch_kind("c.jalr", "c.jalr t0", "riscv64") == "call"
    assert module._riscv_branch_kind("c.jr", "c.jr ra", "riscv64") == "return"
    assert module._riscv_branch_kind("c.jr", "c.jr t0", "riscv64") == "jump"
    assert module._riscv_branch_kind("jalr", "jalr x0, 0(ra)", "riscv64") == "return"
    assert module._riscv_branch_kind("jalr", "jalr x1, 0(t0)", "riscv64") == "call"
    assert module._riscv_branch_kind("jalr", "jalr x0, 0(t0)", "riscv64") == "jump"
    assert module._riscv_branch_kind("jalr", "jalr", "riscv64") == "call"
    assert module._riscv_branch_kind("add", "add a0, a1, a2", "riscv64") == "other"
    assert module._riscv_store_base("sw a0, 8(a1)", "sw") == "a1"
    assert module._riscv_store_base("sw a0, a1", "sw") is None

    # The helpers also have explicit graceful-degradation branches when the
    # support parser or IDA's raw decoder is unavailable.
    monkeypatch.setattr(module, "_riscv_operand_parts", None)
    assert module._riscv_branch_kind("jalr", "jalr x0, 0(t0)", "riscv64") == "call"
    assert module._riscv_store_base("sw a0, 8(a1)", "sw") is None
    monkeypatch.setattr(module, "_riscv_operand_parts", lambda *_args: ["a0", "8(a1)"])
    monkeypatch.setattr(module, "_riscv_reg_name", None)
    assert module._riscv_store_base("sw a0, 8(a1)", "sw") == "a1"
    monkeypatch.setattr(module, "_riscv_operand_parts", lambda *_args: [])
    assert module._riscv_store_base("sw a0, 8(a1)", "sw") is None

    monkeypatch.delattr(module, "TERMINATOR_MNEMONICS")
    assert module._sweep_stop_set() == frozenset()
    monkeypatch.setitem(sys.modules, "ida_auto", None)
    assert module._prepare_exec_region(1, 2) is False
    monkeypatch.setitem(sys.modules, "ida_ua", None)
    assert _raw_decode_insn(0x1000) is None


def test_pivot_chain_catalogs_cover_every_supported_architecture(monkeypatch):
    catalog = {
        "x86": ("pop", "mov", "xchg", "add", "sub", "inc", "dec", "xor", "neg", "not", "pushad", "syscall"),
        "arm64": ("pop", "mov", "add", "sub", "str", "ldr", "svc"),
        "mips": ("lw", "move", "addu", "sw", "syscall"),
        "ppc": ("lwz", "mr", "addi", "stw", "sc"),
        "riscv64": ("lw", "mv", "addi", "sw", "ecall"),
        "unknown": ("mov", "add"),
    }
    for arch, mnemonics in catalog.items():
        entries = {}
        for index, mnem in enumerate(mnemonics):
            ea = 0x4000 + index * 2
            entries[ea] = {"mnem": mnem, "disasm": f"{mnem} r0", "size": 1}
            entries[ea + 1] = {"mnem": "ret", "disasm": "ret", "size": 1}
        _install_instruction_map(monkeypatch, entries)
        monkeypatch.setattr(module, "_get_arch", lambda arch=arch: arch)
        end = 0x4000 + len(mnemonics) * 2
        monkeypatch.setattr(
            module,
            "_get_exec_segments",
            lambda _addr, end=end: iter([(0x4000, end)]),
        )
        categories = _suggest_pivot_chains(None, 100, 3, None)
        assert categories, arch


def test_gadget_public_dispatch_and_blackboard_opt_in_modes(monkeypatch):
    import builtins

    monkeypatch.setattr(module, "_get_arch", lambda: "x64")
    real_classify = module._classify_gadget_chain
    assert module._score_gadgets_behavior([{"gadget": ""}], "rop") is None
    monkeypatch.setattr(module, "_find_shellcode_space", lambda *args: ["RWX region"])
    shell = gadget_tool(action="shellcode_space", address="0x1000")
    assert shell == {
        "ok": True,
        "action": "shellcode_space",
        "regions": "RWX region",
        "count": 1,
        "arch": "x64",
    }

    monkeypatch.setattr(module, "_find_seh_handlers", lambda *args: ["handler"])
    assert gadget_tool(action="seh_handlers")["count"] == 1
    monkeypatch.setattr(module, "_suggest_pivot_chains", lambda *args: {"rop": {"count": 2}})
    assert gadget_tool(action="pivot_chains")["total_gadgets"] == 2
    monkeypatch.setattr(module, "_classify_gadget_chain", lambda *args: {"ok": True, "chain": 1})
    assert gadget_tool(action="classify_chain")["chain"] == 1

    writes = []

    class EmptyStore:
        def list(self, **_kwargs):
            return []

        def write(self, **kwargs):
            writes.append(kwargs)

    blackboard = types.ModuleType("blackboard")
    blackboard.BlackboardStore = EmptyStore
    monkeypatch.setitem(sys.modules, "blackboard", blackboard)
    monkeypatch.setattr(module, "_detect_mitigations", lambda *args: {"ASLR": False, "DEP/NX": True})
    mitigation = gadget_tool(action="mitigations", auto_blackboard=True)
    assert mitigation["ok"] is True and writes[0]["category"] == "mitigation_gap"

    class ExistingStore(EmptyStore):
        def list(self, **_kwargs):
            return [{"title": "Existing mitigation gap"}]

    blackboard.BlackboardStore = ExistingStore
    assert gadget_tool(action="mitigations", auto_blackboard=True)["ok"] is True

    class BrokenStore:
        def __init__(self):
            raise RuntimeError("store unavailable")

    blackboard.BlackboardStore = BrokenStore
    assert gadget_tool(action="mitigations", auto_blackboard=True)["ok"] is True

    calls = []

    def handler(*args, **kwargs):
        calls.append((args, kwargs))
        return [{"gadget": "pop rdi ; ret"}]

    real_score = module._score_gadgets_behavior
    monkeypatch.setattr(module, "_ACTIONS", {"rop": handler})
    monkeypatch.setattr(module, "_exec_region_has_heads", lambda _addr: True)
    monkeypatch.setattr(module, "_score_gadgets_behavior", lambda *_args: {"confidence": 0.9})
    normal = gadget_tool(action="rop", limit=1)
    assert normal["count"] == 1 and normal["truncated"] is True
    assert "exploit_potential" in normal and calls[0][1]["raw"] is False

    monkeypatch.setattr(module, "_ACTIONS", {"rop": lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom"))})
    assert gadget_tool(action="rop")["error"] is True

    class ExplodingBehavior:
        ANCHORS = {}

        @classmethod
        def instance(cls, _embedder):
            raise RuntimeError("classifier unavailable")

    services = types.ModuleType("ida_pro_mcp.services")
    services.BehaviorClassifier = ExplodingBehavior

    def make_embedder():
        return object()

    services.BgeCodeEmbedder = make_embedder
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    monkeypatch.setattr(module, "_score_gadgets_behavior", real_score)
    assert module._score_gadgets_behavior([{"gadget": "ret"}], "rop") is None

    real_import = builtins.__import__

    def refuse_intelligence(name, *args, **kwargs):
        if name in ("ida_pro_mcp.services", "host.intelligence.core"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    for name in ("ida_pro_mcp.services", "host", "host.intelligence", "host.intelligence.core"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setattr(builtins, "__import__", refuse_intelligence)
    assert real_classify(None, 1, 1, None)["error"] is True


def test_gadget_chain_blackboard_and_handler_failure_modes(monkeypatch):
    classifier = types.SimpleNamespace(
        ANCHORS={"memory_manipulation": "memory"},
        clear_cache=lambda: None,
        classify=lambda *_args, **_kwargs: [],
    )

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

    def broken(*_args, **_kwargs):
        raise RuntimeError("primitive failed")

    handlers = {
        "broken": broken,
        "rop": lambda *_args, **_kwargs: [{"gadget": "pop rdi ; ret"}],
        "stack_pivot": lambda *_args, **_kwargs: [{"gadget": "leave ; ret"}],
        "write_what_where": lambda *_args, **_kwargs: [{"gadget": "mov [rax], rbx ; ret"}],
        "syscall": lambda *_args, **_kwargs: [{"gadget": "syscall"}],
    }
    monkeypatch.setattr(module, "_ACTIONS", handlers)
    writes = []

    class Store:
        def list(self, **_kwargs):
            return []

        def write(self, **kwargs):
            writes.append(kwargs)

    blackboard = types.ModuleType("blackboard")
    blackboard.BlackboardStore = Store
    monkeypatch.setitem(sys.modules, "blackboard", blackboard)
    result = module._classify_gadget_chain(None, 20, 3, None, auto_blackboard=True)
    assert result["exploit_assessment"].startswith("HIGH:")
    assert writes and writes[0]["category"] == "exploit"

    class ExistingStore(Store):
        def list(self, **_kwargs):
            return [{"title": "Existing gadget finding"}]

    blackboard.BlackboardStore = ExistingStore
    result = module._classify_gadget_chain(None, 20, 3, None, auto_blackboard=True)
    assert result["ok"] is True
