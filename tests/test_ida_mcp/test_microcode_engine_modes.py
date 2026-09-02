"""Offline fake-ABI coverage for the microcode and SSA adapter."""

from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.ida_mcp.support import microcode_engine as engine


class _Operand:
    def __init__(self, kind, text, *, value=0, reg=0, ea=0, off=0, size=4):
        self.t = kind
        self.size = size
        self.nnn = value
        self.value = value
        self.r = reg
        self.g = ea
        self.s = off
        self._text = text

    def dstr(self):
        return self._text


class _Insn:
    def __init__(self, ea, opcode, left, right, destination):
        self.ea = ea
        self.opcode = opcode
        self.l = left
        self.r = right
        self.d = destination
        self.next = None

    def dstr(self):
        return f"m{self.opcode}"


def test_operand_and_instruction_shapes_cover_each_operand_kind(monkeypatch):
    monkeypatch.setattr(engine.ida_hexrays, "mop_r", 1, raising=False)
    monkeypatch.setattr(engine.ida_hexrays, "mop_n", 2, raising=False)
    monkeypatch.setattr(engine.ida_hexrays, "mop_v", 3, raising=False)
    monkeypatch.setattr(engine.ida_hexrays, "mop_S", 4, raising=False)
    monkeypatch.setattr(engine.ida_hexrays, "mop_d", 5, raising=False)
    monkeypatch.setattr(engine.ida_hexrays, "mop_z", 0, raising=False)
    monkeypatch.setattr(engine.ida_hexrays, "m_42", "m_add", raising=False)
    monkeypatch.setattr(engine.ida_hexrays, "get_mcode_name", lambda _op: "add", raising=False)
    monkeypatch.setattr(engine.ida_lines, "tag_remove", lambda text: str(text).replace("<tag>", ""), raising=False)

    assert engine.extract_operand_repr(None) == {"type": "none", "text": ""}
    assert engine.extract_operand_repr(_Operand(1, "<tag>r1", reg=1)) == {
        "type_id": 1, "size": 4, "type": "reg", "reg": 1, "text": "r1"
    }
    assert engine.extract_operand_repr(_Operand(2, "7", value=7))["type"] == "imm"
    assert engine.extract_operand_repr(_Operand(2, "7", value=7))["val"] == "0x7"
    assert engine.extract_operand_repr(_Operand(3, "g", ea=0x401000))["ea"] == "0x401000"
    assert engine.extract_operand_repr(_Operand(3, "bad", ea=engine.idaapi.BADADDR))["ea"] == "?"
    assert engine.extract_operand_repr(_Operand(4, "stack", off=-8))["off"] == -8
    assert engine.extract_operand_repr(_Operand(5, "sub"))["type"] == "sub_insn"
    assert engine.extract_operand_repr(_Operand(99, "other"))["type"] == "mop_99"

    insn = _Insn(
        0x401000,
        42,
        _Operand(1, "r1", reg=1),
        _Operand(2, "4", value=4),
        _Operand(3, "global", ea=0x402000),
    )
    record = engine.extract_instruction_repr(insn)
    assert record["ea"] == "0x401000"
    assert record["opcode"] == "add"
    assert record["l"]["type"] == "reg"
    assert record["r"]["type"] == "imm"
    assert record["d"]["type"] == "global"


def test_ssa_graph_extracts_def_use_edges_and_phi_like_merges(monkeypatch):
    monkeypatch.setattr(engine.ida_hexrays, "mop_z", 0, raising=False)
    monkeypatch.setattr(engine.ida_hexrays, "gen_microcode", lambda *_args: _Mba(), raising=False)
    monkeypatch.setattr(engine.ida_hexrays, "mba_ranges_t", lambda func: (func.start_ea, func.end_ea), raising=False)
    monkeypatch.setattr(engine.ida_funcs, "get_func", lambda _ea: SimpleNamespace(start_ea=0x401000, end_ea=0x401020), raising=False)
    def tag_remove(text):
        return str(text)

    monkeypatch.setattr(engine.ida_lines, "tag_remove", tag_remove, raising=False)

    result = engine.build_microcode_ssa_graph(0x401000, max_edges=20)

    assert result["source"] == "hexrays_microcode_ssa"
    assert result["edge_count"] == 5
    assert {edge["kind"] for edge in result["edges"]} == {"ssa_def_use"}
    assert {edge["from"] for edge in result["edges"]} == {"arg0", "arg1", "tmp"}
    assert result["phi_like_merges"] == [{
        "var": "out",
        "incoming_sources": ["arg0", "arg1", "tmp"],
        "source_count": 3,
    }]


def test_ssa_graph_reports_unavailable_and_unlinked_modes(monkeypatch):
    monkeypatch.setattr(engine.ida_hexrays, "gen_microcode", lambda *_args: None, raising=False)
    monkeypatch.setattr(engine.ida_funcs, "get_func", lambda _ea: None, raising=False)
    missing = engine.build_microcode_ssa_graph(0x401000)
    assert missing["source"] == "not_found"

    monkeypatch.setattr(engine.ida_funcs, "get_func", lambda _ea: SimpleNamespace(start_ea=1, end_ea=2), raising=False)
    monkeypatch.setattr(engine.ida_hexrays, "gen_microcode", lambda *_args: None, raising=False)
    unlinked = engine.build_microcode_ssa_graph(1)
    assert unlinked["source"] == "unlinked"

    monkeypatch.delattr(engine.ida_hexrays, "gen_microcode", raising=False)
    fallback = engine.build_microcode_ssa_graph(1)
    assert fallback["source"] == "fallback"


class _Mba:
    qty = 1

    def get_mblock(self, _index):
        first = _Insn(
            0x401000,
            1,
            _Operand(1, "arg0"),
            _Operand(0, ""),
            _Operand(1, "tmp"),
        )
        second = _Insn(
            0x401004,
            2,
            _Operand(1, "tmp"),
            _Operand(1, "arg1"),
            _Operand(1, "out"),
        )
        third = _Insn(
            0x401008,
            3,
            _Operand(1, "arg0"),
            _Operand(1, "arg1"),
            _Operand(1, "out"),
        )
        first.next = second
        second.next = third
        return SimpleNamespace(head=first)
