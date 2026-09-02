"""Cross-mode behavioral coverage for the calculation operation.

The same calculation backend is reachable through the public ``ida_calc_*``
catalog and through the legacy ``calc(action=...)`` compatibility surface.
These tests keep both contracts beside the real FakeDatabase instead of
testing parser helpers in isolation.
"""

from __future__ import annotations

import struct

import pytest

from ida_pro_mcp.host.agent_operations import get_agent_operation
from ida_pro_mcp.host.schemas import TOOL_ARG_SCHEMAS
from ida_pro_mcp.ida_mcp.tools.calc import calc
from tests.fakes.ida_fake import install_fake_idb


def _assert_ok(result):
    assert result.get("ok") is True, result
    return result


def test_public_and_legacy_calc_surfaces_share_backend_contract():
    operation = get_agent_operation("ida_calc_eval")
    assert operation is not None
    backend_name, backend_args = operation.to_backend_call({"expr": "2 + 3"})
    assert backend_name == "calc"
    assert backend_args == {"action": "eval", "expr": "2 + 3"}
    assert "action" in TOOL_ARG_SCHEMAS["calc"]
    assert _assert_ok(calc(**backend_args))["value"] == 5


def test_eval_safe_language_covers_numeric_boolean_comparison_and_memory(fresh_fake_idb):
    fresh_fake_idb.patch_bytes(0x140003100, (7).to_bytes(4, "little"))
    expressions = {
        "10 // 3": 3,
        "10 % 3": 1,
        "1 < 2 and 3 >= 3": True,
        "1 == 2 or 2 != 3": True,
        "-4 + ~0": -5,
        "u32(0x140003100) + 1": 8,
    }
    for expression, expected in expressions.items():
        result = _assert_ok(calc(action="eval", expr=expression))
        assert result["value"] == expected, expression


@pytest.mark.parametrize(
    ("expression", "message"),
    [
        ("__import__('os')", "forbidden"),
        ("open('x')", "forbidden"),
        ("[1, 2]", "evaluation error"),
        ("unknown_name", "Unknown name"),
        ("2 ** 3", "Operator not allowed"),
        ("hex('x')", "Only numeric/bool"),
    ],
)
def test_eval_rejects_unsafe_or_unsupported_expressions(expression, message):
    result = calc(action="eval", expr=expression)
    assert result.get("ok") is not True
    assert message.lower() in result.get("message", "").lower(), result


def test_numeric_conversion_suffixes_symbols_and_negative_values():
    for value, expected in (("2k", 2048), ("3M", 3 * 1024 * 1024), ("0b1010", 10), ("-7", -7)):
        result = _assert_ok(calc(action="convert", value=value))
        assert result["dec"] == expected
    result = _assert_ok(calc(action="convert", value="main"))
    assert result["dec"] == 0x140001000
    negative = _assert_ok(calc(action="convert", value=-1))
    assert negative["bitmask"] == "n/a"
    invalid = calc(action="convert", value=True)
    assert invalid.get("ok") is not True


def test_offset_negative_delta_and_natural_language_query():
    result = _assert_ok(calc(action="offset", addr="0x140001050", target="0x140001000"))
    assert result["delta_int"] == -0x50
    assert result["delta_hex"] == "-0x50"
    nl = _assert_ok(
        calc(action="eval", intent="distance between 0x140001000 and 0x140001050")
    )
    assert nl["delta_int"] == 0x50
    assert nl["interpreted_action"] == "offset"


def test_resolve_reverse_mapping_and_missing_mapping_helpers(monkeypatch):
    reverse = _assert_ok(calc(action="resolve", addr="0x200", from_file=True))
    assert reverse["direction"] == "file_offset_to_va"
    assert reverse["va"] == "0x140000200"

    import ida_nalt
    import idaapi

    monkeypatch.setattr(idaapi, "get_fileregion_offset", None, raising=False)
    monkeypatch.setattr(idaapi, "get_fileregion_ea", None, raising=False)
    monkeypatch.setattr(ida_nalt, "get_fileregion_offset", None, raising=False)
    monkeypatch.setattr(ida_nalt, "get_fileregion_ea", None, raising=False)
    result = calc(action="resolve", addr="0x140001000")
    assert result.get("ok") is not True
    assert "mapping helpers unavailable" in result.get("message", "")


def test_deref_reads_all_scalar_types_and_bounded_string_fallback(fresh_fake_idb):
    db = fresh_fake_idb
    db.patch_bytes(0x140003100, b"\x7f\xff\xff\xff" + struct.pack("<f", 1.5))
    db.patch_bytes(0x140003108, struct.pack("<d", 2.5))
    db.patch_bytes(0x140003110, b"raw printable\x00")
    expected = {
        "u8": 0x7F,
        "u16": 0xFF7F,
        "u32": 0xFFFFFF7F,
        "s8": 0x7F,
        "s16": -129,
        "s32": -129,
    }
    for value_type, value in expected.items():
        result = _assert_ok(calc(action="deref", addr="0x140003100", type=value_type))
        assert result["value"] == value, value_type
    assert _assert_ok(calc(action="deref", addr="0x140003104", type="f32"))["value"] == 1.5
    assert _assert_ok(calc(action="deref", addr="0x140003108", type="f64"))["value"] == 2.5
    assert _assert_ok(calc(action="deref", addr="0x140003100", type="bytes", size=4))["value"] == "7f ff ff ff"
    assert _assert_ok(calc(action="deref", addr="0x140003110", type="string"))["value"] == "raw printable"


def test_deref_pointer_depth_handles_null_loop_and_invalid_type(fresh_fake_idb):
    db = fresh_fake_idb
    db.patch_bytes(0x140003100, (0x140003200).to_bytes(8, "little"))
    db.patch_bytes(0x140003200, (0x140003100).to_bytes(8, "little"))
    loop = _assert_ok(calc(action="deref", addr="0x140003100", type="ptr", deref_depth=40))
    assert loop["depth"] == 32
    assert any(step.get("terminated") == "loop_detected" for step in loop["steps"])
    db.patch_bytes(0x140003100, b"\x00" * 8)
    null = _assert_ok(calc(action="deref", addr="0x140003100", type="ptr", deref_depth=2))
    assert null["steps"][0]["terminated"] == "null_or_badaddr"
    missing_size = calc(action="deref", addr="0x140003100", type="bytes")
    assert missing_size.get("ok") is not True
    unknown = calc(action="deref", addr="0x140003100", type="u128")
    assert unknown.get("ok") is not True


def test_pointer_chain_accepts_compact_offsets_and_stops_on_null(fresh_fake_idb):
    db = fresh_fake_idb
    db.patch_bytes(0x140003100, (0x140003200).to_bytes(8, "little"))
    db.patch_bytes(0x140003210, (0x140003300).to_bytes(8, "little"))
    result = _assert_ok(calc(action="chain", addr="0x140003100", offsets="0x10->0x10"))
    assert result["offsets"] == [0x10, 0x10]
    assert result["final"] == "0x140003310"
    db.patch_bytes(0x140003100, b"\x00" * 8)
    stopped = _assert_ok(calc(action="chain", addr="0x140003100", offsets=[4]))
    assert stopped["steps"][0]["terminated"] == "null_or_badaddr"


@pytest.mark.parametrize("alignment", [3, 16])
def test_align_covers_non_power_of_two_fallback_and_alias(alignment):
    result = _assert_ok(calc(action="align", value="0x1003", size=alignment))
    assert result["aligned_down"] <= 0x1003 <= result["aligned_up"]
    fallback = _assert_ok(calc(action="align", addr="0x1003", value=16))
    assert fallback["alignment"] == 16
    assert calc(action="align", value=0x1000, size=0).get("ok") is not True


@pytest.mark.parametrize(
    ("op", "lhs", "rhs", "expected"),
    [("and", 0xF0, 0x0F, 0), ("or", 0xF0, 0x0F, 0xFF), ("xor", 0xF0, 0x0F, 0xFF),
     ("shl", 2, 3, 16), ("shr", 16, 2, 4), ("not", 0, None, -1)],
)
def test_bitops_all_operations(op, lhs, rhs, expected):
    kwargs = {"value": lhs, "op": op}
    if rhs is not None:
        kwargs["target"] = rhs
    result = _assert_ok(calc(action="bitops", **kwargs))
    assert result["result"] == expected


def test_bitops_natural_language_and_validation():
    result = _assert_ok(calc(action="bitops", value=0xF0, target=0x0F, intent="0xff xor 0x0f"))
    assert result["op"] == "xor"
    assert calc(action="bitops", value=1, op="and").get("ok") is not True
    assert calc(action="bitops", value=1, op="bogus", target=2).get("ok") is not True
    assert calc(action="unknown", value=1).get("ok") is not True


def test_calc_input_validation_and_backend_error_envelopes():
    for kwargs in (
        {"action": "eval"},
        {"action": "offset", "addr": "bad", "target": "bad"},
        {"action": "resolve"},
        {"action": "deref"},
        {"action": "chain", "addr": "0x140003000"},
        {"action": "align", "value": 1},
        {"action": "bitops"},
    ):
        result = calc(**kwargs)
        assert result.get("ok") is not True, kwargs


def test_big_endian_typed_reads_follow_ida_database_endianness(fresh_fake_idb):
    fresh_fake_idb.endian = "big"
    fresh_fake_idb.patch_bytes(0x140003100, b"\x01\x02\x03\x04")
    result = _assert_ok(calc(action="deref", addr="0x140003100", type="u32"))
    assert result["value"] == 0x01020304
