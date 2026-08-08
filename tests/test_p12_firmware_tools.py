"""Regression tests for p12_firmware_tools (firmware_view / gadgets / stack_analysis).

These exercise the IDA-bound heuristic paths with mocked ``ida_*`` modules via
``tests._isolated_repo_loader`` (the same harness the rest of the tool tests
use). They pin the bug fixes shipped in this package:

- detect_vector_table must skip zero/unused IVT entries (no handler at 0x0)
- detect_vector_table / detect_mmio must honor auto_blackboard=False (no writes)
- smart_carve string pass must not span runs into defined code
- stack_analysis uninitialized must treat reads as reads and resolve RSP/RBP
  stack offsets through get_stkvar
- stack_analysis buffers/summary/arrays must agree on the same frame
- gadgets stack_pivot must catch `leave; ret` and `pop rsp; ret`
- gadgets mitigations/classify_chain blackboard writes are opt-in
"""

from __future__ import annotations

import sys
import types

from tests._isolated_repo_loader import load_tool_module


def _set(module, **attrs):
    for key, value in attrs.items():
        setattr(module, key, value)


def _mock(monkeypatch, module, name, value):
    """Set an attribute on an ida stub module (which may not have the attr yet)."""
    monkeypatch.setattr(module, name, value, raising=False)


def _fake_blackboard(writes):
    """Install a top-level `blackboard` module whose store records writes."""
    bb = types.ModuleType("blackboard")

    class _FakeStore:
        def __init__(self, *args, **kwargs):
            pass

        def write(self, **kwargs):
            writes.append(kwargs)
            return "entry-1"

        def list(self, **kwargs):
            return []

    bb.BlackboardStore = _FakeStore
    sys.modules["blackboard"] = bb
    return bb


# ---------------------------------------------------------------------------
# firmware_view: detect_vector_table
# ---------------------------------------------------------------------------


def _set_fw_bounds(monkeypatch, mod, min_ea, max_ea):
    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    _set(
        mod,
        _safe_idb_bounds=lambda: (min_ea, max_ea),
        _is_64bit=lambda: False,
        _inf_procname=lambda: "metapc",
        _inf_filetype_id=lambda: 0,
    )


def _arm_ivt_chunk(sz=0x200):
    """Cortex-M vector table: plausible SP, thumb reset, one zero slot."""
    chunk = bytearray(sz)

    def put(off, val):
        chunk[off : off + 4] = val.to_bytes(4, "little")

    put(0, 0x20001000)  # Initial_SP (plausible SRAM)
    put(4, 0x08000101)  # Reset_Handler (Thumb bit set)
    # entry index 2 stays 0 -> unused/reserved vector slot
    for i, val in enumerate([0x08000201, 0x08000301, 0x08000401, 0x08000501], start=3):
        put(i * 4, val)
    return bytes(chunk)


def test_detect_vector_table_skips_zero_entries(monkeypatch):
    mod = load_tool_module("firmware_view")
    ida_bytes = sys.modules["ida_bytes"]
    _set_fw_bounds(monkeypatch, mod, 0x0, 0x200)
    _mock(monkeypatch, ida_bytes, "get_bytes", lambda ea, size: _arm_ivt_chunk()[:size])

    res = mod.firmware_view(action="detect_vector_table", auto_blackboard=False)
    assert res.get("ok") is True, res
    # The zero (unused) slot must not become a handler at address 0 / image base
    handlers = [v.get("handler") for v in res.get("vectors", []) if "handler" in v]
    assert "0x0" not in handlers, f"zero entry mapped to a handler: {handlers}"
    assert "0x0" not in res.get("entry_points", []), res.get("entry_points")
    zero_recs = [v for v in res.get("vectors", []) if str(v.get("value")) == "0x0"]
    assert zero_recs == [], f"zero entry still recorded: {zero_recs}"
    # The real Reset_Handler entry is still found
    assert "0x100" in res.get("entry_points", []), res.get("entry_points")


def test_detect_vector_table_blackboard_is_opt_in(monkeypatch):
    mod = load_tool_module("firmware_view")
    ida_bytes = sys.modules["ida_bytes"]
    _set_fw_bounds(monkeypatch, mod, 0x0, 0x200)
    _mock(monkeypatch, ida_bytes, "get_bytes", lambda ea, size: _arm_ivt_chunk()[:size])

    writes = []
    _fake_blackboard(writes)
    res = mod.firmware_view(action="detect_vector_table", auto_blackboard=False)
    assert res.get("ok") is True, res
    assert writes == [], "auto_blackboard=False must not write entry points"

    res = mod.firmware_view(action="detect_vector_table", auto_blackboard=True)
    assert res.get("ok") is True, res
    assert writes, "auto_blackboard=True should write entry points"


# ---------------------------------------------------------------------------
# firmware_view: detect_mmio
# ---------------------------------------------------------------------------


def test_detect_mmio_blackboard_is_opt_in(monkeypatch):
    mod = load_tool_module("firmware_view")
    idaapi = sys.modules["idaapi"]
    ida_bytes = sys.modules["ida_bytes"]
    idautils = sys.modules["idautils"]
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF

    _set(mod, _safe_idb_bounds=lambda: (0x0, 0x1000), _is_64bit=lambda: False)
    _mock(monkeypatch, idautils, "Segments", lambda: [0x0])
    _mock(
        monkeypatch, idaapi, "getseg",
        lambda ea: types.SimpleNamespace(start_ea=0x0, end_ea=0x1000),
    )
    _mock(monkeypatch, idaapi, "get_func", lambda ea: None)
    _mock(monkeypatch, ida_bytes, "get_flags", lambda ea: 0)
    _mock(monkeypatch, ida_bytes, "is_code", lambda f: False)
    raw = bytearray(0x1000)
    raw[0:4] = (0x40000000).to_bytes(4, "little")  # STM32_APB1 peripheral address
    _mock(monkeypatch, ida_bytes, "get_bytes", lambda ea, size: bytes(raw[:size]))

    writes = []
    _fake_blackboard(writes)
    res = mod.firmware_view(action="detect_mmio", auto_blackboard=False)
    assert res.get("ok") is True, res
    assert res["peripheral_count"] >= 1, res
    assert writes == [], "auto_blackboard=False must not write IOC entries"

    res = mod.firmware_view(action="detect_mmio", auto_blackboard=True)
    assert res.get("ok") is True, res
    assert writes, "auto_blackboard=True should write IOC entries"


# ---------------------------------------------------------------------------
# firmware_view: smart_carve string pass
# ---------------------------------------------------------------------------


def _set_carve_idb(monkeypatch, mod, code_start):
    idaapi = sys.modules["idaapi"]
    ida_bytes = sys.modules["ida_bytes"]
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    _set(mod, _is_64bit=lambda: False, validate_range=lambda s, e: (0x100, 0x200, None))
    _mock(monkeypatch, idaapi, "getseg", lambda ea: None)  # no pointer hits
    _mock(monkeypatch, ida_bytes, "get_flags", lambda ea: 1 if ea >= code_start else 0)
    _mock(monkeypatch, ida_bytes, "is_code", lambda f: f == 1)
    _mock(monkeypatch, ida_bytes, "is_data", lambda f: False)
    _mock(monkeypatch, ida_bytes, "is_strlit", lambda f: False)
    _mock(monkeypatch, ida_bytes, "get_dword", lambda ea: 0)
    _mock(monkeypatch, ida_bytes, "get_qword", lambda ea: 0)


def test_smart_carve_does_not_span_code(monkeypatch):
    mod = load_tool_module("firmware_view")
    ida_bytes = sys.modules["ida_bytes"]
    _set_carve_idb(monkeypatch, mod, code_start=0x150)

    # printable run 0x100-0x14f whose NUL terminator lands on code (0x150)
    def get_byte(ea):
        if 0x100 <= ea < 0x150:
            return 0x41  # 'A'
        return 0

    _mock(monkeypatch, ida_bytes, "get_byte", get_byte)
    res = mod.firmware_view(action="smart_carve", start="0x100", end="0x200", apply=False)
    assert res.get("ok") is True, res
    assert res["type_totals"]["make_string"] == 0, res["items"]


def test_bootstrap_define_strings_creates_strings(monkeypatch):
    """_fwb_define_ascii_strings must actually create string literals."""
    mod = load_tool_module("firmware_view")
    ida_bytes = sys.modules["ida_bytes"]
    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    _set(mod, _fwb_safe_bounds=lambda: (0x100, 0x200))
    _mock(monkeypatch, ida_bytes, "get_flags", lambda ea: 0)  # everything unknown
    _mock(monkeypatch, ida_bytes, "is_code", lambda f: False)
    _mock(monkeypatch, ida_bytes, "is_data", lambda f: False)
    _mock(monkeypatch, ida_bytes, "is_strlit", lambda f: False)

    def get_byte(ea):
        if 0x100 <= ea < 0x120:
            return 0x41  # 'A'
        return 0

    _mock(monkeypatch, ida_bytes, "get_byte", get_byte)

    created = []
    _mock(monkeypatch, mod, "_create_ascii_string",
          lambda ea, length: created.append((ea, length)) or True)

    res = mod._fwb_define_ascii_strings(limit=256)
    assert res.get("strings_defined") == 1, res
    assert res.get("skipped") == 0, res
    assert (0x100, 33) in created, created


def test_scan_region_bounds_byte_scan(monkeypatch):
    """scan_region must cap its per-byte item-kind scan to the 1MiB budget."""
    mod = load_tool_module("firmware_view")
    ida_bytes = sys.modules["ida_bytes"]
    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    _set(mod, _is_64bit=lambda: False, validate_range=lambda s, e: (0x100, 0x1000000, None))
    _mock(monkeypatch, ida_bytes, "get_flags", lambda ea: 0)  # all unknown
    _mock(monkeypatch, ida_bytes, "is_code", lambda f: False)
    _mock(monkeypatch, ida_bytes, "is_data", lambda f: False)
    _mock(monkeypatch, ida_bytes, "is_strlit", lambda f: False)

    res = mod.firmware_view(action="scan_region", start="0x100", end="0x1000000")
    assert res.get("ok") is True, res
    assert res["stats"]["scanned_bytes"] == (1 << 20), res["stats"]
    # The range is far larger than the budget, proving the cap engaged.
    assert res["stats"]["scanned_bytes"] < (0x1000000 - 0x100)


def test_detect_mmio_reports_actual_scanned_code_bytes(monkeypatch):
    """detect_mmio must report bytes actually scanned, not the whole image."""
    mod = load_tool_module("firmware_view")
    idaapi = sys.modules["idaapi"]
    ida_bytes = sys.modules["ida_bytes"]
    idc = sys.modules["idc"]
    idautils = sys.modules["idautils"]
    ida_ua = sys.modules["ida_ua"]
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    _set(mod, _safe_idb_bounds=lambda: (0x0, 0x1000), _is_64bit=lambda: False)
    _mock(monkeypatch, idautils, "Segments", lambda: [0x0])
    _mock(monkeypatch, idaapi, "getseg",
          lambda ea: types.SimpleNamespace(start_ea=0x0, end_ea=0x1000))
    _mock(monkeypatch, idaapi, "get_func", lambda ea: None)
    # exactly one defined instruction at 0x0
    _mock(monkeypatch, ida_bytes, "get_flags", lambda ea: 1 if ea == 0x0 else 0)
    _mock(monkeypatch, ida_bytes, "is_code", lambda f: f == 1)
    _mock(monkeypatch, idc, "get_item_size", lambda ea: 4)
    _mock(monkeypatch, idc, "next_head", lambda ea, end: ea + 4 if ea == 0x0 else ea + 1)
    _mock(monkeypatch, ida_ua, "o_imm", 1)
    _mock(monkeypatch, ida_ua, "o_mem", 2)
    _mock(monkeypatch, ida_ua, "o_displ", 3)
    _mock(monkeypatch, ida_ua, "insn_t", lambda: types.SimpleNamespace(ops=[]))

    def decode(insn, ea):
        # o_imm with value 0 -> no MMIO hit, but the operand decode path runs
        insn.ops = [types.SimpleNamespace(type=ida_ua.o_imm, value=0)]
        return 1

    _mock(monkeypatch, ida_ua, "decode_insn", decode)
    _mock(monkeypatch, ida_bytes, "get_bytes", lambda ea, size: b"\x00" * size)

    res = mod.firmware_view(action="detect_mmio", auto_blackboard=False)
    assert res.get("ok") is True, res
    cov = res["scan_coverage"]
    assert cov["mode"] == "decoded_operands", cov
    assert cov["bytes_scanned"] == 4, cov  # one 4-byte instruction, not 0x1000
    assert cov["instructions_decoded"] == 1, cov


def test_smart_carve_keeps_fully_unknown_run(monkeypatch):
    mod = load_tool_module("firmware_view")
    ida_bytes = sys.modules["ida_bytes"]
    _set_carve_idb(monkeypatch, mod, code_start=0x121)

    # printable run 0x100-0x11f, NUL at 0x120 (still unknown) -> valid string
    def get_byte(ea):
        if 0x100 <= ea < 0x120:
            return 0x42  # 'B'
        return 0

    _mock(monkeypatch, ida_bytes, "get_byte", get_byte)
    res = mod.firmware_view(action="smart_carve", start="0x100", end="0x200", apply=False)
    assert res.get("ok") is True, res
    assert res["type_totals"]["make_string"] == 1, res["items"]


# ---------------------------------------------------------------------------
# stack_analysis: uninitialized heuristic
# ---------------------------------------------------------------------------


def _load_stack_analysis():
    overrides = {
        "get_arch": lambda: "x86",
        "is_x86_family": lambda arch: arch == "x86",
    }
    return load_tool_module("stack_analysis", common_overrides=overrides)


def _set_stack_frame(monkeypatch, mod, members):
    """Install a function + frame with the given member tuples (name, soff, eoff)."""
    idaapi = sys.modules["idaapi"]
    idc = sys.modules["idc"]
    ida_funcs = sys.modules["ida_funcs"]
    ida_frame = sys.modules["ida_frame"]
    ida_typeinf = sys.modules["ida_typeinf"]
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    _set(mod, _inf_bitness=lambda: 32, _inf_procname=lambda: "metapc")

    class FakeFunc:
        start_ea = 0x1000
        end_ea = 0x1100

    _mock(monkeypatch, idaapi, "get_func", lambda ea: FakeFunc())
    _mock(monkeypatch, ida_funcs, "get_func_name", lambda ea: "test_func")

    class FakeMember:
        def __init__(self, idx, soff, eoff, name):
            self.id = idx
            self.soff = soff
            self.eoff = eoff
            self._name = name

    class FakeFrame:
        memqty = len(members)

        def get_member(self, i):
            return FakeMember(i, members[i][1], members[i][2], members[i][0])

    _mock(monkeypatch, ida_frame, "get_frame", lambda func: FakeFrame())
    _mock(
        monkeypatch, ida_frame, "get_member_name",
        lambda mid: members[mid][0] if 0 <= mid < len(members) else None,
    )
    _mock(monkeypatch, ida_frame, "get_struc_size", lambda frame: 64)
    _mock(monkeypatch, ida_typeinf, "tinfo_t", object)
    _mock(monkeypatch, idc, "get_name_ea_simple", lambda name: idaapi.BADADDR)
    ida_ua = sys.modules["ida_ua"]
    _mock(monkeypatch, ida_ua, "o_displ", 2)
    _mock(monkeypatch, ida_ua, "o_phrase", 3)
    _mock(monkeypatch, ida_ua, "o_reg", 1)
    _mock(monkeypatch, ida_ua, "insn_t", lambda: types.SimpleNamespace(ops=[]))
    return ida_ua


def test_uninitialized_does_not_count_reads(monkeypatch):
    mod = _load_stack_analysis()
    ida_ua = _set_stack_frame(
        monkeypatch, mod,
        [("v1", -8, 0), ("v2", -16, -8)],
    )
    ida_frame = sys.modules["ida_frame"]
    idc = sys.modules["idc"]

    # 0x1000: mov [rsp+0x10], rax  -> write, resolves to local v1 (soff -8)
    # 0x1010: cmp [rbp-16], 0      -> READ, must not count as a write
    _mock(monkeypatch, idc, "print_insn_mnem", {0x1000: "mov", 0x1010: "cmp"}.get)
    _mock(monkeypatch, idc, "next_head", lambda ea: 0x1010 if ea == 0x1000 else 0x1100)

    def decode(insn, ea):
        if ea == 0x1000:
            insn.ops = [
                types.SimpleNamespace(type=ida_ua.o_displ),
                types.SimpleNamespace(type=ida_ua.o_reg),
            ]
        return 1

    _mock(monkeypatch, ida_ua, "decode_insn", decode)
    _mock(
        monkeypatch, ida_frame, "get_stkvar",
        lambda insn, op: (types.SimpleNamespace(soff=-8), 0),
    )

    res = mod.stack_analysis(action="uninitialized", addr="0x1000")
    assert res.get("ok") is True, res
    assert res["count"] == 1, res
    assert "v2" in res["uninitialized"], res
    assert "v1" not in res["uninitialized"], res


def test_uninitialized_resolves_rsp_relative_write(monkeypatch):
    """A write like mov [rsp+0x10], rax must map to the right frame member."""
    mod = _load_stack_analysis()
    ida_ua = _set_stack_frame(
        monkeypatch, mod,
        [("v1", -8, 0), ("v2", -16, -8)],
    )
    ida_frame = sys.modules["ida_frame"]
    idc = sys.modules["idc"]

    _mock(monkeypatch, idc, "print_insn_mnem", {0x1000: "mov"}.get)
    _mock(monkeypatch, idc, "next_head", lambda ea: 0x1100)

    def decode(insn, ea):
        insn.ops = [
            types.SimpleNamespace(type=ida_ua.o_displ),
            types.SimpleNamespace(type=ida_ua.o_reg),
        ]
        return 1

    _mock(monkeypatch, ida_ua, "decode_insn", decode)
    # raw displacement +0x10 is mapped by get_stkvar to the local at soff -8
    _mock(
        monkeypatch, ida_frame, "get_stkvar",
        lambda insn, op: (types.SimpleNamespace(soff=-8), 0),
    )

    res = mod.stack_analysis(action="uninitialized", addr="0x1000")
    assert res.get("ok") is True, res
    assert res["count"] == 1, res
    assert "v1" not in res["uninitialized"], res


# ---------------------------------------------------------------------------
# stack_analysis: buffer thresholds agree
# ---------------------------------------------------------------------------


def test_stack_analysis_buffer_actions_agree(monkeypatch):
    mod = _load_stack_analysis()
    _set_stack_frame(
        monkeypatch, mod,
        [
            ("buf", -32, -16),  # 16-byte non-pointer block
            ("ptr", -16, -12),  # 4-byte pointer
            ("big", -48, -32),  # 16-byte non-pointer block
        ],
    )
    idc = sys.modules["idc"]

    # no code scanned: only the frame action paths run
    _mock(monkeypatch, idc, "print_insn_mnem", lambda ea: None)
    _mock(monkeypatch, idc, "next_head", lambda ea: 0x1100)

    res_buf = mod.stack_analysis(action="buffers", addr="0x1000")
    assert res_buf.get("ok") is True, res_buf
    assert "buf" in res_buf["buffers"], res_buf["buffers"]

    res_sum = mod.stack_analysis(action="summary", addr="0x1000")
    assert res_sum.get("ok") is True, res_sum
    assert res_sum["buffer_count"] == 2, res_sum  # buf + big, ptr excluded

    res_arr = mod.stack_analysis(action="arrays", addr="0x1000")
    assert res_arr.get("ok") is True, res_arr
    assert "buf" in res_arr["arrays"], res_arr["arrays"]


# ---------------------------------------------------------------------------
# gadgets: stack_pivot idioms
# ---------------------------------------------------------------------------


def _load_gadgets():
    overrides = {
        "get_arch": lambda: "x64",
        "is_x86_family": lambda arch: arch in ("x86", "x64"),
        "is_arm_family": lambda arch: False,
        "is_mips_family": lambda arch: False,
        "is_ppc_family": lambda arch: False,
        "is_riscv_family": lambda arch: False,
        "is_sparc_family": lambda arch: False,
        "get_stack_pointer_names": lambda arch: {"rsp"},
        "is_return_mnemonic": lambda m, d="", a=None: m in ("ret", "retn", "retl", "rts", "rte", "rtd"),
        "is_syscall_mnemonic": lambda m, a=None: m in ("syscall", "sysenter", "svc", "swi", "ecall", "sc", "ta"),
        "CALL_MNEMONICS": frozenset({"call", "bl", "blx"}),
        "UNCONDITIONAL_JUMP_MNEMONICS": frozenset({"jmp", "b", "br"}),
        "SYSCALL_MNEMONICS": frozenset({"syscall", "sysenter", "svc", "ecall"}),
        "TERMINATOR_MNEMONICS": frozenset({"ret", "jmp"}),
    }
    return load_tool_module("gadgets", common_overrides=overrides)


def _set_gadget_segment(monkeypatch, disasm_map):
    mod = _load_gadgets()
    idaapi = sys.modules["idaapi"]
    idc = sys.modules["idc"]
    idautils = sys.modules["idautils"]
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi.SEGPERM_EXEC = 4
    idaapi.SEG_CODE = 2
    _mock(monkeypatch, idautils, "Segments", lambda: [0x1000])
    _mock(
        monkeypatch, idaapi, "getseg",
        lambda ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010, perm=4, type=2),
    )
    # IDA's print_insn_mnem returns only the mnemonic (e.g. "pop"), while the
    # disassembly line carries the full text (e.g. "pop rsp").
    _mock(
        monkeypatch, idc, "print_insn_mnem",
        lambda ea: disasm_map.get(ea, "").split(" ", 1)[0] or None,
    )
    _mock(monkeypatch, idc, "next_head", lambda ea: 0x1008 if ea == 0x1000 else 0x1010)
    _mock(monkeypatch, idc, "generate_disasm_line", lambda ea, flags: disasm_map.get(ea, ""))
    _mock(monkeypatch, mod, "_disasm_at", lambda ea: disasm_map.get(ea, ""))
    return mod


def test_stack_pivot_matches_leave_ret(monkeypatch):
    mod = _set_gadget_segment(monkeypatch, {0x1000: "leave", 0x1008: "ret"})
    res = mod._find_stack_pivot(None, 10, 5, None)
    assert len(res) == 1, res
    assert "leave" in res[0]["gadget"] and "ret" in res[0]["gadget"]


def test_stack_pivot_matches_pop_rsp_ret(monkeypatch):
    mod = _set_gadget_segment(monkeypatch, {0x1000: "pop rsp", 0x1008: "ret"})
    res = mod._find_stack_pivot(None, 10, 5, None)
    assert len(res) == 1, res
    assert "pop rsp" in res[0]["gadget"] and "ret" in res[0]["gadget"]


# ---------------------------------------------------------------------------
# gadgets: blackboard writes are opt-in
# ---------------------------------------------------------------------------


def test_gadgets_mitigations_blackboard_is_opt_in(monkeypatch):
    mod = _load_gadgets()
    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    _mock(
        monkeypatch, mod, "_detect_mitigations",
        lambda *a, **kw: {"format": "ELF", "ASLR": False, "DEP/NX": False},
    )
    writes = []
    _fake_blackboard(writes)

    res = mod.gadgets(action="mitigations")
    assert res.get("ok") is True, res
    assert writes == [], "mitigations must not write by default"

    res = mod.gadgets(action="mitigations", auto_blackboard=True)
    assert res.get("ok") is True, res
    assert writes, "auto_blackboard=True should write the mitigation_gap finding"


def test_gadgets_classify_chain_blackboard_is_opt_in(monkeypatch):
    mod = _load_gadgets()
    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    # only a ROP primitive is discovered -> has_rop True, write gate reachable
    _mock(
        monkeypatch, mod, "_ACTIONS",
        {"rop": lambda addr, limit, max_insns, query: [{"gadget": "pop rdi ; ret"}]},
    )

    class FakeEmbedder:
        backend = "fake"

    class FakeClassifier:
        ANCHORS = {}

        @classmethod
        def instance(cls, embedder):
            return cls()

        def clear_cache(self):
            pass

        def classify(self, text, **kwargs):
            return []

    # Inject a fake ida_pro_mcp.services so the intelligence imports inside
    # _classify_gadget_chain resolve without pulling in the real llama backend.
    services_mod = types.ModuleType("ida_pro_mcp.services")
    services_mod.BgeCodeEmbedder = FakeEmbedder
    services_mod.BehaviorClassifier = FakeClassifier
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services_mod)

    writes = []
    _fake_blackboard(writes)

    res = mod.gadgets(action="classify_chain")
    assert res.get("ok") is True, res
    assert writes == [], "classify_chain must not write by default"

    res = mod.gadgets(action="classify_chain", auto_blackboard=True)
    assert res.get("ok") is True, res
    assert writes, "auto_blackboard=True should write the exploit finding"
