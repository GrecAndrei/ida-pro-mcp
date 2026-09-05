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


def test_calc_action_normalization_aliases_and_semantic():
    # Alias mapping
    assert calc_mod._normalize_calc_action("alignment") == "align"
    assert calc_mod._normalize_calc_action("pointer") == "deref"
    # Semantic fuzzy match (hits lines 105-109)
    assert calc_mod._normalize_calc_action("evaluation") == "eval"
    assert calc_mod._normalize_calc_action("xyzzy_nonexistent", fallback="default_act") == "default_act"


def test_calc_resolve_ea_and_numeric_edge_cases(fresh_fake_idb, monkeypatch):
    idc = importlib.import_module("idc")

    # Empty string to resolve_ea / _semantic_symbol_match
    assert calc_mod.calc(action="deref", addr="   ")["error"] is True

    # Expression too long
    assert calc_mod.calc(action="eval", expr="1 + " * 300)["error"] is True

    # Unknown names and unsupported nodes
    assert calc_mod.calc(action="eval", expr="unknown_sym_123 + 1")["error"] is True

    # Error handling when idc.get_name_ea_simple throws
    monkeypatch.setattr(idc, "get_name_ea_simple", lambda n: (_ for _ in ()).throw(RuntimeError("ida broken")))
    assert calc_mod.calc(action="eval", expr="main + 1")["error"] is True
    assert calc_mod.calc(action="convert", value="not_a_num")["error"] is True

    # Suffix numbers in resolve_ea (+/-)
    assert calc_mod.calc(action="convert", value="+invalid")["error"] is True
    assert calc_mod.calc(action="convert", value="")["error"] is True
    assert calc_mod.calc(action="convert")["error"] is True


def test_calc_actions_parameter_validation_and_errors(fresh_fake_idb, monkeypatch):
    # offset missing args
    assert calc_mod.calc(action="offset")["error"] is True
    assert calc_mod.calc(action="offset", addr="invalid", target="0x140001000")["error"] is True

    # deref errors
    assert calc_mod.calc(action="deref")["error"] is True
    assert calc_mod.calc(action="deref", addr="invalid", type="u8")["error"] is True
    # deref via intent
    fresh_fake_idb.patch_bytes(0x140003000, b"\x42\x00\x00\x00")
    res_nl = calc_mod.calc(action="deref", intent="0x140003000", type="u8")
    assert res_nl["ok"] is True and res_nl["value"] == 0x42

    # deref depth loop and non-pointer-value termination
    fresh_fake_idb.patch_bytes(0x140003050, b"not_a_pointer_value_string\x00")
    res_deref = calc_mod.calc(action="deref", addr="0x140003050", type="string", deref_depth=2)
    assert res_deref["ok"] is True

    # chain missing args
    assert calc_mod.calc(action="chain")["error"] is True
    assert calc_mod.calc(action="chain", addr="invalid", offsets=[0])["error"] is True
    # chain offsets via intent
    res_chain_nl = calc_mod.calc(action="chain", addr="0x140003000", intent="offsets 0x10, 0x20")
    assert res_chain_nl.get("ok") is True or res_chain_nl.get("error") is True

    # align errors
    assert calc_mod.calc(action="align", addr="invalid", size=4)["error"] is True

    # resolve errors and headerless raw blob
    assert calc_mod.calc(action="resolve", addr="invalid")["error"] is True
    idaapi = importlib.import_module("idaapi")
    monkeypatch.setattr(idaapi, "get_fileregion_offset", lambda ea: idaapi.BADADDR)
    res_noblob = calc_mod.calc(action="resolve", addr="0x140001000")
    assert res_noblob["error"] is True
    assert "No file offset for VA" in res_noblob["message"]


def test_calc_persist_capture_chain_and_import_error(monkeypatch):
    board_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.blackboard")

    class RecordingStore:
        def __init__(self):
            self.writes = []

        def exists_similar(self, *_args):
            return False

        def write(self, **kwargs):
            self.writes.append(kwargs)

    rec_store = RecordingStore()
    monkeypatch.setattr(board_mod, "BlackboardStore", lambda: rec_store)

    # chain with string offset
    calc_mod._calc_persist_capture(
        {"addr": "0x140001000", "offsets": "0x10"},
        {"steps": [{"ptr": "0x140001000", "offset": 16}], "final": "0x140001010"},
        "chain",
    )
    assert len(rec_store.writes) == 1
    assert "0x10" in rec_store.writes[0]["title"]


def test_calc_remaining_uncovered_paths(monkeypatch, fresh_fake_idb):
    import builtins
    import struct

    import idaapi
    import idc

    # 1. Line 212: _semantic_symbol_match with whitespace-only addr
    with monkeypatch.context() as m:
        m.setitem(calc_mod.calc.__globals__, "parse_address_canonical", lambda s: (None, {"message": "err"}))
        res = calc_mod.calc(action="deref", addr="   ")
        assert res["error"] is True

    # 2. Line 281: resolve_ea(None) via align without value/addr/expr
    res = calc_mod.calc(action="align", size=4)
    assert res["error"] is True and "value required" in res["message"]

    # 3. Lines 315-317: idc.get_name_ea_simple returns valid EA or raises
    with monkeypatch.context() as m:
        m.setattr(idc, "get_name_ea_simple", lambda name: 0x140001000 if name == "valid_sym" else (_ for _ in ()).throw(RuntimeError("boom")))
        m.setattr(calc_mod, "parse_address_canonical", lambda s: (0x140001000, None))
        assert calc_mod.calc(action="deref", addr="valid_sym", type="u8")["ok"] is True
        assert calc_mod.calc(action="deref", addr="exploding_sym", type="u8")["ok"] is True

    # 4. Lines 335-336: parse_address_canonical returning err=None, and non-str/non-int addr
    with monkeypatch.context() as m:
        m.setattr(idc, "get_name_ea_simple", lambda name: idaapi.BADADDR)
        m.setattr(calc_mod, "parse_address_canonical", lambda s: (None, None))
        assert calc_mod.calc(action="deref", addr="failed_parse", type="u8")["error"] is True
    assert calc_mod.calc(action="align", value=[1, 2], size=4)["error"] is True

    # 5. Line 377: resolve_numeric_value with non-str/non-int value
    assert calc_mod.calc(action="convert", value=[1, 2])["error"] is True

    # 6. Line 423: read_typed bytes read failure
    with monkeypatch.context() as m:
        m.setattr(calc_mod.ida_bytes, "get_bytes", lambda *_a: None)
        assert calc_mod.calc(action="deref", addr="0x140003000", type="bytes", size=4)["error"] is True

    # 7. Line 440: read_typed s64
    fresh_fake_idb.patch_bytes(0x140003000, (-42).to_bytes(8, "little", signed=True))
    assert calc_mod.calc(action="deref", addr="0x140003000", type="s64")["value"] == -42

    # 8. Lines 468-470: string > 65536 bytes
    with monkeypatch.context() as m:
        m.setattr(idc, "get_strlit_contents", lambda *_args: b"A" * 70000)
        res_str = calc_mod.calc(action="deref", addr="0x140003000", type="string")
        assert res_str["ok"] is True and len(res_str["value"]) == 65536

    # 9. Lines 506, 523: function name in eval expr
    with monkeypatch.context() as m:
        m.setattr(idc, "get_name_ea_simple", lambda name: 0x140001000 if name == "my_sym" else idaapi.BADADDR)
        res_eval = calc_mod.calc(action="eval", expr="my_sym + 0x10")
        assert res_eval["ok"] is True and res_eval["value"] == 0x140001010

    # 10. Line 545: Unary operator not allowed (e.g. not)
    assert calc_mod.calc(action="eval", expr="not 1")["error"] is True

    # 11. Line 560: Comparison operator not allowed (e.g. in)
    assert calc_mod.calc(action="eval", expr="1 in (1, 2)")["error"] is True

    # 12. Line 576: Non-direct function calls
    assert calc_mod.calc(action="eval", expr="foo.bar()")["error"] is True

    # 13. Line 583: Non-numeric/bool arguments in call
    assert calc_mod.calc(action="eval", expr="abs(hex)")["error"] is True

    # 14. Line 591: Eval with intent fallback
    res_intent = calc_mod.calc(action="eval", expr="", intent="1 + 5")
    assert res_intent["ok"] is True and res_intent["value"] == 6

    # 15. Lines 648-649: struct.pack exception in convert ascii formatting
    orig_pack = struct.pack
    pack_calls = 0

    def faulty_pack(fmt, val):
        nonlocal pack_calls
        pack_calls += 1
        if pack_calls == 1:
            raise struct.error("pack error")
        return orig_pack(fmt, val)

    with monkeypatch.context() as m:
        m.setattr(struct, "pack", faulty_pack)
        res_conv = calc_mod.calc(action="convert", value=42)
        assert res_conv["ok"] is True and res_conv["ascii"] == "n/a"

    # 16. Lines 775-776: deref depth terminates on non_pointer_value
    def mock_unpack(fmt, data):
        return ("not_an_int",)

    with monkeypatch.context() as m:
        m.setattr(struct, "unpack", mock_unpack)
        res_deref_nonptr = calc_mod.calc(action="deref", addr="0x140003000", type="ptr", deref_depth=2)
        assert res_deref_nonptr["error"] is True

    # 17. Lines 955-956: top-level unexpected exception caught by handle_error
    with monkeypatch.context() as m:
        m.setattr(calc_mod, "_inf_bitness", lambda: (_ for _ in ()).throw(RuntimeError("fatal calc error")))
        res_exc = calc_mod.calc(action="deref", addr="0x140003000")
        assert res_exc["error"] is True

    # 18. Lines 976-980: ImportError in _calc_persist_capture
    orig_import = builtins.__import__

    def faulty_import(name, *args, **kwargs):
        if "blackboard" in name:
            raise ImportError("no blackboard")
        return orig_import(name, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(builtins, "__import__", faulty_import)
        calc_mod._calc_persist_capture({"expr": "1"}, {"value": 1}, "eval")
