"""Calculation expression, intent-routing, and persistence coverage."""

from __future__ import annotations

import importlib
import json

import pytest

calc_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.calc")


def _ok(result):
    assert result.get("ok") is True, result
    return result


@pytest.mark.parametrize(
    ("intent", "expected"),
    [
        ("offset between 0x140001000 and 0x140001010", "offset"),
        ("align 0x1003 to a boundary", "align"),
        ("resolve file offset 0x200", "resolve"),
        ("pointer chain from 0x140003000", "chain"),
        ("read 0x140003000", "deref"),
        ("0xff xor 0x0f", "bitops"),
    ],
)
def test_calc_natural_language_routes_every_intent(intent, expected, fresh_fake_idb):
    kwargs = {"action": "eval", "intent": intent}
    if expected == "chain":
        kwargs.update(addr="0x140003000", offsets=[0])
    elif expected == "deref":
        kwargs.update(addr="0x140003000", type="u8")
    elif expected == "align":
        kwargs.update(value=0x1003, size=16)
    elif expected == "bitops":
        kwargs.update(value=0xFF, target=0x0F)
    result = _ok(calc_mod.calc(**kwargs))
    assert result["interpreted_action"] == expected


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("4 / 2", 2.0),
        ("4 // 3", 1),
        ("5 % 2", 1),
        ("1 | 2", 3),
        ("3 & 1", 1),
        ("5 ^ 1", 4),
        ("2 << 3", 16),
        ("16 >> 2", 4),
        ("+4", 4),
        ("abs(-4)", 4),
        ("int(3.8)", 3),
    ],
)
def test_calc_expression_ast_operations(expression, expected):
    assert _ok(calc_mod.calc(action="eval", expr=expression))["value"] == expected


def test_calc_expression_functions_comparisons_and_memory(fresh_fake_idb):
    fresh_fake_idb.patch_bytes(0x140003100, b"\x05\x00\x00\x00")
    for expression, expected in (
        ("1 <= 1", True),
        ("2 > 1", True),
        ("2 == 2", True),
        ("2 != 3", True),
        ("1 or 0", True),
        ("1 and 1", True),
        ("u8(0x140003100)", 5),
        ("u16(0x140003100)", 5),
        ("u64(0x140003100)", 5),
        ("s8(0x140003100)", 5),
        ("s16(0x140003100)", 5),
        ("s64(0x140003100)", 5),
        ("ptr(0x140003100, 4)", 5),
    ):
        assert _ok(calc_mod.calc(action="eval", expr=expression))["value"] == expected
    assert _ok(calc_mod.calc(action="eval", expr="hex(15)"))["value"] == "0xf"
    assert calc_mod.calc(action="eval", expr="sum(1)")["error"] is True
    assert calc_mod.calc(action="eval", expr="'text'")["error"] is True


def test_calc_symbol_fallback_and_typed_read_fallbacks(monkeypatch, fresh_fake_idb):
    with monkeypatch.context() as local:
        local.setattr(calc_mod.idautils, "Names", lambda: iter([(0x140001000, "packet_handler")]))
        local.setattr(calc_mod.idc, "get_name_ea_simple", lambda _name: calc_mod.idaapi.BADADDR)
        local.setattr(calc_mod, "parse_address_canonical", lambda _value: (None, {"message": "bad", "hint": "use an address"}))
        local.setattr(calc_mod, "compile_smart_pattern", lambda *_args, **_kwargs: lambda _text: True)
        local.setattr(calc_mod, "semantic_scores", lambda *_args, **_kwargs: [1.0])
        assert calc_mod.calc(action="offset", addr="packet_handler", target="0x140001000")["error"] is True

    monkeypatch.setattr(calc_mod.idc, "get_strlit_contents", lambda *_args: None)
    fresh_fake_idb.patch_bytes(0x140003120, b"printable fallback\x00")
    string = _ok(calc_mod.calc(action="deref", addr="0x140003120", type="string"))
    assert string["value"] == "printable fallback"
    fresh_fake_idb.patch_bytes(0x140003130, b"\x01not printable")
    assert _ok(calc_mod.calc(action="deref", addr="0x140003130", type="string"))["value"] is None
    assert calc_mod.calc(action="deref", addr="0x140004000", type="u64")["error"] is True


def test_calc_persist_records_question_and_answer_for_supported_actions(monkeypatch, fresh_fake_idb):
    board_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.blackboard")

    class Store:
        writes = []

        def exists_similar(self, *_args):
            return False

        def write(self, **kwargs):
            self.writes.append(kwargs)

    monkeypatch.setattr(board_mod, "BlackboardStore", Store)
    _ok(calc_mod.calc(action="eval", expr="2 + 2", persist=True))
    _ok(calc_mod.calc(action="resolve", addr="0x140001000", persist=True))
    _ok(calc_mod.calc(action="deref", addr="0x140003000", type="u8", persist=True))
    fresh_fake_idb.patch_bytes(0x140003100, (0x140003200).to_bytes(8, "little"))
    _ok(calc_mod.calc(action="chain", addr="0x140003100", offsets=[0], persist=True))
    assert len(Store.writes) == 4
    assert json.loads(Store.writes[0]["content"])["expr"] == "2 + 2"
    assert {row["category"] for row in Store.writes} == {"calc_eval", "calc_resolve", "calc_deref", "calc_chain"}


def test_calc_action_normalization_and_bitop_intent_matrix(monkeypatch, fresh_fake_idb):
    assert calc_mod._normalize_calc_action(None, fallback="offset") == "offset"
    monkeypatch.setattr(calc_mod, "semantic_scores", lambda *_args, **_kwargs: [])
    assert calc_mod._normalize_calc_action("unrelated", fallback="align") == "align"
    monkeypatch.setattr(calc_mod, "semantic_scores", lambda _query, actions, **_kwargs: [0.0] * len(actions))
    assert calc_mod._normalize_calc_action("still-unrelated", fallback="chain") == "chain"

    interpreted = _ok(
        calc_mod.calc(
            action="eval",
            semantic_action="offset",
            addr="0x140001000",
            target="0x140001010",
        )
    )
    assert interpreted["interpreted_action"] == "offset"

    cases = (
        ("1 and 2", "and", 1, 2, 1 & 2),
        ("1 or 2", "or", 1, 2, 1 | 2),
        ("1 xor 2", "xor", 1, 2, 1 ^ 2),
        ("1 not 0", "not", 1, 2, ~1),
        ("1 shl 2", "shl", 1, 2, 1 << 2),
        ("4 shr 1", "shr", 4, 1, 4 >> 1),
    )
    for intent, operation, lhs, rhs, expected in cases:
        result = _ok(calc_mod.calc(action="bitops", intent=intent, value=lhs, target=rhs))
        assert result["op"] == operation
        assert result["result"] == expected

    assert _ok(calc_mod.calc(action="bitops", addr="0x10", op="not"))["lhs"] == 0x10
    assert calc_mod.calc(action="bitops", op="not")["error"] is True
    assert calc_mod.calc(action="bitops", value="not-a-value", op="not")["error"] is True
    assert calc_mod.calc(action="bitops", value=1, op="xor", target="not-a-value")["error"] is True


def test_calc_value_context_and_mapping_failure_modes(monkeypatch, fresh_fake_idb):
    assert _ok(calc_mod.calc(action="convert", value="0123"))["dec"] == 123
    assert _ok(calc_mod.calc(action="offset", addr="4k", target="0x140001000"))["delta_int"] == 0x140000000
    reverse = _ok(calc_mod.calc(action="resolve", intent="file offset 0x200"))
    assert reverse["direction"] == "file_offset_to_va"

    import idaapi

    monkeypatch.setattr(idaapi, "get_fileregion_ea", lambda _offset: idaapi.BADADDR, raising=False)
    unmapped = calc_mod.calc(action="resolve", addr="0x200", from_file=True)
    assert unmapped["error"] is True and "not mapped" in unmapped["message"]

    assert calc_mod.calc(action="align", value=1, size="bad")["error"] is True
    assert calc_mod.calc(action="align", expr="1.5", size=4)["error"] is True
    assert calc_mod.calc(action="align", expr="1 / 0", size=4)["error"] is True
    assert calc_mod.calc(action="align", value="bad", addr="0x1003")["error"] is True

    assert "error" not in calc_mod.calc(action="deref", addr="0x140003000", type="u32", deref_depth="bad")
    assert calc_mod.calc(action="deref", addr="0x140004000", type="f64")["error"] is True
    assert calc_mod.calc(action="chain", addr="0x140003000", offsets=[])["error"] is True
    assert calc_mod.calc(action="chain", addr="0x140003000", offsets=["bad"])["error"] is True


def test_calc_persist_capture_noop_dedup_and_write_failure_modes(monkeypatch):
    board_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.blackboard")

    class DedupStore:
        def __init__(self):
            self.writes = []

        def exists_similar(self, *_args):
            return True

        def write(self, **kwargs):
            self.writes.append(kwargs)

    store = DedupStore()
    monkeypatch.setattr(board_mod, "BlackboardStore", lambda: store)
    calc_mod._calc_persist_capture({"expr": ""}, {"value": 1}, "eval")
    calc_mod._calc_persist_capture({"addr": "0x1"}, {"va": ""}, "resolve")
    calc_mod._calc_persist_capture({"addr": "0x1"}, {"value": None}, "deref")
    calc_mod._calc_persist_capture({"addr": "0x1", "offsets": []}, {"steps": [], "final": ""}, "chain")
    calc_mod._calc_persist_capture({}, {}, "unknown")
    calc_mod._calc_persist_capture({"expr": "2 + 2"}, {"value": 4}, "eval")
    assert store.writes == []

    monkeypatch.setattr(board_mod, "BlackboardStore", lambda: (_ for _ in ()).throw(RuntimeError("store unavailable")))
    calc_mod._calc_persist_capture({"expr": "2 + 2"}, {"value": 4}, "eval")

    class BrokenStore:
        def exists_similar(self, *_args):
            return False

        def write(self, **_kwargs):
            raise RuntimeError("write unavailable")

    monkeypatch.setattr(board_mod, "BlackboardStore", BrokenStore)
    calc_mod._calc_persist_capture({"expr": "2 + 2"}, {"value": 4}, "eval")
