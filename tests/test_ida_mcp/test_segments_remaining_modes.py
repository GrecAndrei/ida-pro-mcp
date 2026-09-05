"""Segment analysis, mutation, comparison, and register-mode coverage."""

from __future__ import annotations

import importlib
import sys
import types

from tests.fakes.ida_fake import FF_DATA, FF_STRLIT

segments_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.segments")


def _ok(result):
    assert result.get("ok") is True, result
    return result


def test_segment_helpers_and_analysis_cover_empty_and_populated_modes(monkeypatch, fresh_fake_idb):
    seg = fresh_fake_idb.segments[1]
    monkeypatch.setattr(segments_mod.ida_nalt, "STRTYPE_C", 0, raising=False)
    assert segments_mod._perms_string(0) == "---"
    assert segments_mod._perms_string(7) == "rwx"
    assert segments_mod._seg_type_name(0xDEAD) == "type_57005"
    assert segments_mod._seg_entropy(types.SimpleNamespace(start_ea=1, end_ea=1)) == 0.0

    monkeypatch.setattr(segments_mod.ida_bytes, "get_bytes", lambda *_args: b"\x00\x01\x01\x02")
    entropy = segments_mod._seg_entropy(types.SimpleNamespace(start_ea=0, end_ea=4))
    assert entropy > 0
    monkeypatch.setattr(segments_mod.ida_nalt, "get_import_module_qty", lambda: 1)
    monkeypatch.setattr(
        segments_mod.ida_nalt,
        "enum_import_names",
        lambda _idx, callback: callback(seg.start_ea, "imp", 1) and callback(seg.end_ea, "outside", 2),
    )
    assert segments_mod._seg_import_count(seg) == 1
    monkeypatch.setattr(segments_mod.idc, "get_strlit_contents", lambda *_args: "plain")
    assert segments_mod._strlit_value(0x140002000) == "'plain'"

    monkeypatch.setattr(segments_mod.ida_bytes, "get_flags", lambda ea: 1 if ea == seg.start_ea else 0)
    monkeypatch.setattr(segments_mod.ida_bytes, "is_code", lambda flags: flags == 1)
    monkeypatch.setattr(segments_mod.ida_bytes, "is_data", lambda flags: False)
    monkeypatch.setattr(segments_mod.ida_bytes, "is_strlit", lambda _flags: False)
    monkeypatch.setattr(segments_mod.idc, "next_head", lambda ea, _end: ea + 1 if ea == seg.start_ea else segments_mod.idaapi.BADADDR)
    counts = segments_mod._count_heads(seg, max_items=3)
    assert counts[0] == 1
    density = segments_mod._seg_density_analysis(seg)
    assert density["code_data_ratio"] == "inf"

    # The helper accepts both address and name lookup modes.
    assert segments_mod._find_segment(name=segments_mod._compat.get_segment_name(seg.start_ea))[0] is not None
    assert segments_mod._find_segment()[1]["error"] is True


def test_segment_public_actions_cover_mutation_analysis_and_comparison(monkeypatch, fresh_fake_idb):
    monkeypatch.setattr(segments_mod._compat, "set_segment_name", lambda *_args: True)
    monkeypatch.setattr(segments_mod.idaapi, "MOVE_SEGM_OK", 1, raising=False)
    monkeypatch.setattr(segments_mod.ida_nalt, "STRTYPE_C", 0, raising=False)
    listed = _ok(segments_mod.segments(action="list", offset=1, count=1))
    assert listed["count"] == 1
    assert _ok(segments_mod.segments(action="info", name=".rdata"))["segment"]["name"] == ".rdata"

    code = _ok(
        segments_mod.segments(
            action="add", start="0x140004000", end="0x140004100", name=".code_extra", sclass="CODE"
        )
    )
    assert code["perms"] == "rx"
    overlap = segments_mod.segments(action="add", start="0x140004000", end="0x140004020", name=".overlap")
    assert overlap["error"] is True
    assert _ok(segments_mod.segments(action="set_attr", start="0x140004000", attr="name", value=".renamed"))
    assert _ok(segments_mod.segments(action="set_attr", start="0x140004000", attr="perm", value="rw"))
    assert _ok(segments_mod.segments(action="set_attr", start="0x140004000", attr="align", value="0x10"))
    assert segments_mod.segments(action="set_attr", start="0x140004000", attr="unknown", value=1)["error"] is True
    assert segments_mod.segments(action="set_attr", start="0x140004000", attr="align", value="not-an-int")["error"] is True
    assert _ok(segments_mod.segments(action="set_perms", start="0x140004000", value=7))["perms"] == "rwx"
    assert _ok(segments_mod.segments(action="set_perms", start="0x140004000", value="r-x"))["perms"] == "rx"
    moved = _ok(segments_mod.segments(action="move", start="0x140004000", end="0x140005000"))
    assert moved["new"] == "0x140005000"

    monkeypatch.setattr(segments_mod.idautils, "Segments", lambda: iter([0x140001000, 0x140002000, 0x140003000]))
    all_analysis = _ok(segments_mod.segments(action="analyze"))
    assert all_analysis["count"] == 3
    assert _ok(segments_mod.segments(action="analyze", name=".text"))["segments"]
    assert _ok(segments_mod.segments(action="find_code", name=".text"))["count"] >= 1

    # Give find_data one string head and one numeric data head, then make the
    # fake item iterator advance exactly as IDA's next_head would.
    flags = {0x140002000: FF_STRLIT, 0x140002010: FF_DATA}
    monkeypatch.setattr(segments_mod.ida_bytes, "get_flags", lambda ea: flags.get(ea, 0))
    monkeypatch.setattr(segments_mod.ida_bytes, "is_data", lambda value: value in (FF_DATA, FF_STRLIT))
    monkeypatch.setattr(segments_mod.ida_bytes, "is_strlit", lambda value: value == FF_STRLIT)
    monkeypatch.setattr(segments_mod.ida_bytes, "get_item_size", lambda _ea: 4)
    monkeypatch.setattr(segments_mod.ida_bytes, "get_long", lambda _ea: 42, raising=False)
    monkeypatch.setattr(segments_mod.ida_bytes, "get_bytes", lambda _ea, _size: b"hello\x00")
    monkeypatch.setattr(segments_mod.idc, "get_strlit_contents", lambda *_args: b"hello")
    monkeypatch.setattr(
        segments_mod.idc,
        "next_head",
        lambda ea, end: 0x140002010 if ea == 0x140002000 else (end if ea == 0x140002010 else segments_mod.idaapi.BADADDR),
    )
    data = _ok(segments_mod.segments(action="find_data", start="0x140002000"))
    assert data["data_count"] == 2 and data["string_count"] == 1
    compared = _ok(segments_mod.segments(action="compare", name=".text", name2=".rdata"))
    assert "differences" in compared
    merged = _ok(segments_mod.segments(action="merge"))
    assert merged["summary"]["segment_count"] == 3
    _ok(segments_mod.segments(action="add", start="0x140006000", end="0x140006100", name=".delete"))
    assert _ok(segments_mod.segments(action="delete", start="0x140006000"))


def test_segment_register_modes_cover_names_tags_ranges_and_validation(monkeypatch, fresh_fake_idb):
    monkeypatch.setattr(segments_mod, "ida_idp", sys.modules["ida_idp"])
    monkeypatch.setattr(segments_mod, "ida_segregs", sys.modules["ida_segregs"])
    set_result = _ok(segments_mod.segments(action="sreg_set", start="0x140001000", reg="GP", value="0x1234", sr_type="auto"))
    assert set_result["reg"] == "GP" and set_result["sr_type"] == "auto"
    got = _ok(segments_mod.segments(action="sreg_get", start="0x140001000", reg="GP"))
    assert got["value"] == 0x1234 and got["range"]["start"] == "0x140001000"
    ranges = _ok(segments_mod.segments(action="sreg_list", start="0x140001000", reg="GP"))
    assert ranges["count"] >= 1 and ranges["ranges"][0]["sr_type"] == "auto"
    all_ranges = _ok(segments_mod.segments(action="sreg_list", start="0x140001000"))
    assert all_ranges["count"] >= 1
    assert segments_mod.segments(action="sreg_set", start="0x140001000", reg="GP", value=1, sr_type="bad")["error"] is True
    assert segments_mod.segments(action="sreg_get", start="0x140001000", reg="unknown")["error"] is True
    assert segments_mod.segments(action="sreg_set", start="0x140001000", reg="GP", value="bad")["error"] is True


def test_segment_helpers_cover_sparse_ida_and_register_fallback_modes(monkeypatch, fresh_fake_idb):
    seg = fresh_fake_idb.segments[1]
    monkeypatch.setattr(segments_mod, "ida_segment", types.SimpleNamespace(SEG_CODE=1))
    assert segments_mod._seg_type_name(1) == "code"
    assert segments_mod._seg_type_name(2) == "type_2"

    monkeypatch.setattr(segments_mod.ida_bytes, "get_bytes", lambda *_args: None)
    assert segments_mod._seg_entropy(types.SimpleNamespace(start_ea=0, end_ea=4)) == 0.0
    monkeypatch.setattr(segments_mod.ida_nalt, "STRTYPE_C", 0, raising=False)
    monkeypatch.setattr(segments_mod.ida_nalt, "get_import_module_qty", lambda: 0)
    monkeypatch.setattr(segments_mod.idc, "get_strlit_contents", lambda *_args: None)
    assert segments_mod._seg_import_count(seg) == 0
    assert segments_mod._strlit_value(0x1000) == ""
    monkeypatch.setattr(segments_mod.idc, "get_strlit_contents", lambda *_args: object())
    assert segments_mod._strlit_value(0x1000).startswith("<")
    assert segments_mod._seg_density_analysis(types.SimpleNamespace(start_ea=1, end_ea=1))["code_data_ratio"] == 0.0

    monkeypatch.setattr(segments_mod.ida_bytes, "get_flags", lambda _ea: 1)
    monkeypatch.setattr(segments_mod.ida_bytes, "is_code", lambda _flags: False)
    monkeypatch.setattr(segments_mod.ida_bytes, "is_data", lambda _flags: True)
    monkeypatch.setattr(segments_mod.ida_bytes, "is_strlit", lambda _flags: True)
    monkeypatch.setattr(segments_mod.idc, "next_head", lambda _ea, end: end)
    assert segments_mod._count_heads(seg, max_items=0)[:3] == (0, 1, 1)

    assert segments_mod._find_segment(start="bad")[1]["error"] is True
    assert segments_mod._find_segment(name="missing")[1]["error"] is True
    monkeypatch.setattr(segments_mod, "ida_idp", None)
    assert segments_mod._resolve_sreg(None) is None
    assert segments_mod._resolve_sreg(True) is None
    assert segments_mod._sreg_reg_indices() is None
    assert segments_mod._sreg_name(2) == "2"


def test_segment_action_error_matrix_and_optional_data_widths(monkeypatch, fresh_fake_idb):
    assert segments_mod.segments(action="unknown")["error"] is True
    assert segments_mod.segments(action="add")["error"] is True
    assert segments_mod.segments(action="add", start="0x1500")["error"] is True
    assert segments_mod.segments(action="add", start="0x1500", end="0x1400")["error"] is True
    assert segments_mod.segments(action="delete")["error"] is True
    assert segments_mod.segments(action="delete", start="0x1500")["error"] is True
    assert segments_mod.segments(action="info")["error"] is True
    assert segments_mod.segments(action="compare")["error"] is True
    assert segments_mod.segments(action="compare", name=".text")["error"] is True
    assert segments_mod.segments(action="set_attr")["error"] is True
    assert segments_mod.segments(action="set_attr", start="0x140001000")["error"] is True
    assert segments_mod.segments(action="set_attr", start="0x140001000", attr="name")["error"] is True
    assert segments_mod.segments(action="set_perms")["error"] is True
    assert segments_mod.segments(action="set_perms", start="0x140001000")["error"] is True
    assert segments_mod.segments(action="move")["error"] is True
    assert segments_mod.segments(action="move", start="0x140001000")["error"] is True
    assert segments_mod.segments(action="move", start="0x1500", end="0x1600")["error"] is True

    flags = {0x140002000: FF_DATA, 0x140002004: FF_DATA, 0x140002006: FF_DATA}
    sizes = {0x140002000: 1, 0x140002004: 2, 0x140002006: 8}
    monkeypatch.setattr(segments_mod.ida_bytes, "get_flags", lambda ea: flags.get(ea, 0))
    monkeypatch.setattr(segments_mod.ida_bytes, "is_data", lambda value: value == FF_DATA)
    monkeypatch.setattr(segments_mod.ida_bytes, "is_strlit", lambda _value: False)
    monkeypatch.setattr(segments_mod.ida_bytes, "get_item_size", lambda ea: sizes[ea])
    monkeypatch.setattr(segments_mod.ida_bytes, "get_byte", lambda _ea: 1)
    monkeypatch.setattr(segments_mod.ida_bytes, "get_word", lambda _ea: 2)
    monkeypatch.setattr(segments_mod.ida_bytes, "get_qword", lambda _ea: 8)
    monkeypatch.setattr(segments_mod.idc, "next_head", lambda ea, _end: {0x140002000: 0x140002004, 0x140002004: 0x140002006, 0x140002006: segments_mod.idaapi.BADADDR}[ea])
    data = _ok(segments_mod.segments(action="find_data", start="0x140002000"))
    assert [item["size"] for item in data["data_items"]] == [1, 2, 8]


def test_segment_action_failure_and_register_unavailable_modes(monkeypatch, fresh_fake_idb):
    monkeypatch.setattr(segments_mod._compat, "add_segment", lambda *_args: False)
    assert segments_mod.segments(action="add", start="0x1500", end="0x1600")["error"] is True
    monkeypatch.setattr(segments_mod.idaapi, "del_segm", lambda *_args: False)
    assert segments_mod.segments(action="delete", start="0x140001000")["error"] is True
    monkeypatch.setattr(segments_mod._compat, "set_segment_name", lambda *_args: False)
    assert segments_mod.segments(action="set_attr", start="0x140001000", attr="name", value="x")["error"] is True
    monkeypatch.setattr(segments_mod._compat, "set_segment_attr", lambda *_args: False)
    assert segments_mod.segments(action="set_attr", start="0x140001000", attr="align", value=1)["error"] is True
    assert segments_mod.segments(action="set_perms", start="0x140001000", value=1)["error"] is True
    monkeypatch.setattr(segments_mod._compat, "move_segment", lambda *_args: 999)
    assert segments_mod.segments(action="move", start="0x140001000", end="0x1500")["error"] is True

    monkeypatch.setattr(segments_mod, "ida_segregs", None)
    assert segments_mod.segments(action="sreg_get", start="0x140001000", reg="GP")["error"] is True
    assert segments_mod.segments(action="sreg_set", start="0x140001000", reg="GP", value=1)["error"] is True
    assert segments_mod.segments(action="sreg_list", start="0x140001000")["error"] is True


def test_segment_actions_cover_parse_lookup_and_register_failure_boundaries(monkeypatch, fresh_fake_idb):
    """Exercise the compatibility errors callers see when IDA rejects inputs."""
    parse_error = {"error": True, "message": "bad address"}
    monkeypatch.setattr(segments_mod, "parse_address_safe", lambda *_args: (None, parse_error))
    assert segments_mod.segments(action="add", start="0x1500", end="0x1600") is parse_error
    assert segments_mod.segments(action="delete", start="0x1500") is parse_error
    assert segments_mod.segments(action="move", start="0x140001000", end="0x1600") is parse_error

    assert segments_mod.segments(action="set_attr", start="0x1500", attr="name", value="x")["error"] is True
    assert segments_mod.segments(action="set_perms", start="0x1500", value="rwx")["error"] is True
    assert segments_mod.segments(action="find_code", name="missing")["error"] is True
    assert segments_mod.segments(action="find_data", name="missing")["error"] is True
    assert segments_mod.segments(action="analyze", name="missing")["error"] is True
    assert segments_mod.segments(action="compare", name=".text", name2="missing")["error"] is True

    # A stale segment iterator entry is ignored by list/analyze, while a
    # function record that disappeared during enumeration is skipped.
    monkeypatch.setattr(segments_mod.idautils, "Segments", lambda: iter([0x140001000, 0xDEAD]))
    monkeypatch.setattr(segments_mod._compat, "get_segment", lambda ea: None if ea == 0xDEAD else fresh_fake_idb.segments[0])
    listed = _ok(segments_mod.segments(action="list"))
    assert listed["total"] == 1
    monkeypatch.setattr(segments_mod.idautils, "Functions", lambda *_args: iter([0x140001000, 0x140001050]))
    monkeypatch.setattr(
        segments_mod._compat,
        "get_func_info",
        lambda ea: None if ea == 0x140001050 else types.SimpleNamespace(start_ea=ea, end_ea=ea + 8),
    )
    assert _ok(segments_mod.segments(action="find_code", start="0x140001000"))["count"] == 1

    segregs = fresh_fake_idb.segregs
    monkeypatch.setattr(segments_mod, "ida_segregs", segregs)
    monkeypatch.setattr(segregs, "get_sreg_range", lambda *_args: (_ for _ in ()).throw(RuntimeError("range")))
    no_range = _ok(segments_mod.segments(action="sreg_get", start="0x140001000", reg="GP"))
    assert "range" not in no_range
    monkeypatch.setattr(segregs, "split_sreg_range", lambda *_args: False)
    assert segments_mod.segments(action="sreg_set", start="0x140001000", reg="GP", value=1)["error"] is True
    monkeypatch.setattr(segregs, "split_sreg_range", lambda *_args: (_ for _ in ()).throw(RuntimeError("split")))
    assert segments_mod.segments(action="sreg_set", start="0x140001000", reg="GP", value=1)["error"] is True


def test_segment_register_helpers_cover_degraded_processor_tables(monkeypatch):
    class BrokenProcessor:
        ph = type("Processor", (), {"reg_names": None, "reg_first_sreg": "bad", "reg_last_sreg": 1})()

        @staticmethod
        def str2reg(_value):
            raise ValueError("unsupported")

    monkeypatch.setattr(segments_mod, "ida_idp", BrokenProcessor)
    assert segments_mod._resolve_sreg("0x10") == 16
    assert segments_mod._resolve_sreg("GP") is None
    assert segments_mod._sreg_name(2) == "2"
    assert segments_mod._sreg_reg_indices() is None

    class BrokenRanges:
        @staticmethod
        def get_sreg_ranges_qty(_sr):
            raise RuntimeError("qty")

    monkeypatch.setattr(segments_mod, "ida_segregs", BrokenRanges)
    assert segments_mod._sreg_ranges_for_register(0, 10, 1) == []

    class SparseRanges:
        class sreg_range_t:
            pass

        @staticmethod
        def get_sreg_ranges_qty(_sr):
            return 3

        @staticmethod
        def getn_sreg_range(out, _sr, index):
            if index == 0:
                return False
            if index == 1:
                raise RuntimeError("entry")
            out.start_ea, out.end_ea = 20, 30
            return True

    monkeypatch.setattr(segments_mod, "ida_segregs", SparseRanges)
    assert segments_mod._sreg_ranges_for_register(0, 10, 1) == []
    assert segments_mod._sreg_ranges_for_register(20, 40, 1)


def test_segment_find_and_sreg_helper_boundaries(monkeypatch, fresh_fake_idb):
    # Line 76: _find_segment where address is valid but segment does not exist
    monkeypatch.setattr(segments_mod._compat, "get_segment", lambda _ea: None)
    seg, err = segments_mod._find_segment(start="0x140001000")
    assert seg is None and err["error"] is True and "No segment at address" in err["message"]
    monkeypatch.undo()

    # Lines 260-261: _sreg_name with non-int sr when ph has reg_names
    class FakePh:
        reg_names = ["r0", "r1"]

    monkeypatch.setattr(segments_mod.ida_idp, "ph", FakePh, raising=False)
    assert segments_mod._sreg_name("not_an_int") == "not_an_int"

    # Line 271: _sreg_reg_indices where ph is None
    monkeypatch.setattr(segments_mod.ida_idp, "ph", None, raising=False)
    assert segments_mod._sreg_reg_indices() is None

    # Line 278: _sreg_reg_indices where last < first
    class PhInverted:
        reg_first_sreg = 5
        reg_last_sreg = 2

    monkeypatch.setattr(segments_mod.ida_idp, "ph", PhInverted, raising=False)
    assert segments_mod._sreg_reg_indices() is None

    # Line 285 & 296: ida_segregs is None
    monkeypatch.setattr(segments_mod, "ida_segregs", None)
    assert segments_mod._sreg_tag_name(0) == "signed"
    assert segments_mod._sreg_tag_for_type("default") == 0

    # Line 290 & 298: sreg tags with ida_segregs present
    class FakeSegRegs:
        SR_inherit = 10
        SR_user = 20
        SR_auto = 30

    monkeypatch.setattr(segments_mod, "ida_segregs", FakeSegRegs)
    assert segments_mod._sreg_tag_name(20) == "signed"
    assert segments_mod._sreg_tag_for_type("default") == 10

    # Line 322: _sreg_ranges_for_register with range where start_ea or end_ea is None
    class PartialRange:
        start_ea = None
        end_ea = 100

    class FakeSRegRanges:
        sreg_range_t = PartialRange

        @staticmethod
        def get_sreg_ranges_qty(_sr):
            return 1

        @staticmethod
        def getn_sreg_range(_out, _sr, _n):
            return True

    monkeypatch.setattr(segments_mod, "ida_segregs", FakeSRegRanges)
    assert segments_mod._sreg_ranges_for_register(0, 200, 0) == []


def test_segment_mutation_and_move_error_branches(monkeypatch, fresh_fake_idb):
    # Line 540: action == "add", invalid end
    err_add = segments_mod.segments(action="add", start="0x1000", end="invalid_end_ea")
    assert err_add["error"] is True

    # Line 615: action == "set_attr", segment not found
    with monkeypatch.context() as m:
        m.setattr(segments_mod._compat, "get_segment", lambda _ea: None)
        err_attr = segments_mod.segments(action="set_attr", start="0x140001000", attr="name", value="test")
        assert err_attr["error"] is True and "No segment at address" in err_attr["message"]

    # Line 641: action == "set_attr", attr="perm", set_segment_attr returns False
    with monkeypatch.context() as m:
        m.setattr(segments_mod._compat, "set_segment_attr", lambda *_args: False)
        err_perm = segments_mod.segments(action="set_attr", start="0x140001000", attr="perm", value="r")
        assert err_perm["error"] is True and "Failed to set segment attribute 'perm'" in err_perm["message"]

    # Line 655: action == "set_attr", set_segment_attr returns None
    with monkeypatch.context() as m:
        m.setattr(segments_mod._compat, "set_segment_attr", lambda *_args: None)
        err_no_attr = segments_mod.segments(action="set_attr", start="0x140001000", attr="align", value=4)
        assert err_no_attr["error"] is True and "Segment object has no attribute 'align'" in err_no_attr["message"]

    # Line 677 & 686: action == "set_perms", segment not found and "w" in perms
    with monkeypatch.context() as m:
        m.setattr(segments_mod._compat, "get_segment", lambda _ea: None)
        err_no_seg_perm = segments_mod.segments(action="set_perms", start="0x140001000", value="rw")
        assert err_no_seg_perm["error"] is True
    ok_perm_w = segments_mod.segments(action="set_perms", start="0x140001000", value="rw")
    assert ok_perm_w["ok"] is True and "w" in ok_perm_w["perms"]

    # Line 725 & 732-742: action == "move", segment not found and move_errors dict mapping
    with monkeypatch.context() as m:
        m.setattr(segments_mod._compat, "get_segment", lambda _ea: None)
        err_no_seg_move = segments_mod.segments(action="move", start="0x140001000", end="0x150000000")
        assert err_no_seg_move["error"] is True
    for name, val in [
        ("MOVE_SEGM_OK", 0),
        ("MOVE_SEGM_PARAM", -1),
        ("MOVE_SEGM_ROOM", -2),
        ("MOVE_SEGM_IDP", -3),
        ("MOVE_SEGM_CHUNK", -4),
        ("MOVE_SEGM_LOADER", -5),
        ("MOVE_SEGM_ODD", -6),
        ("MOVE_SEGM_ORPHAN", -7),
    ]:
        monkeypatch.setattr(segments_mod.idaapi, name, val, raising=False)
    monkeypatch.setattr(segments_mod._compat, "move_segment", lambda *_args: -2)
    err_room = segments_mod.segments(action="move", start="0x140001000", end="0x150000000")
    assert err_room["error"] is True and "Not enough room at destination" in err_room["message"]


def test_segment_sreg_actions_full_validation_matrix(monkeypatch, fresh_fake_idb):
    segregs = fresh_fake_idb.segregs
    monkeypatch.setattr(segments_mod, "ida_segregs", segregs)

    # sreg_get: 750 (missing start), 753 (missing reg), 760 (bad start), 767 (no seg)
    assert segments_mod.segments(action="sreg_get", start=None, reg="GP")["error"] is True
    assert segments_mod.segments(action="sreg_get", start="0x140001000", reg=None)["error"] is True
    assert segments_mod.segments(action="sreg_get", start="0x140001000", reg="")["error"] is True
    assert segments_mod.segments(action="sreg_get", start="not_an_ea", reg="GP")["error"] is True
    with monkeypatch.context() as m:
        m.setattr(segments_mod._compat, "get_segment", lambda _ea: None)
        assert segments_mod.segments(action="sreg_get", start="0x140001000", reg="GP")["error"] is True

    # sreg_set: 796 (missing start), 799 (missing reg), 802 (missing value), 812 (bad start), 815 (unknown reg), 819 (no seg)
    assert segments_mod.segments(action="sreg_set", start=None, reg="GP", value=1)["error"] is True
    assert segments_mod.segments(action="sreg_set", start="0x140001000", reg="", value=1)["error"] is True
    assert segments_mod.segments(action="sreg_set", start="0x140001000", reg="GP", value=None)["error"] is True
    assert segments_mod.segments(action="sreg_set", start="not_an_ea", reg="GP", value=1)["error"] is True
    assert segments_mod.segments(action="sreg_set", start="0x140001000", reg="TOTALLY_UNKNOWN_REG", value=1)["error"] is True
    with monkeypatch.context() as m:
        m.setattr(segments_mod._compat, "get_segment", lambda _ea: None)
        assert segments_mod.segments(action="sreg_set", start="0x140001000", reg="GP", value=1)["error"] is True

    # sreg_list: 847 (missing start), 854 (bad start), 857 (no seg), 861 (unknown reg)
    assert segments_mod.segments(action="sreg_list", start=None)["error"] is True
    assert segments_mod.segments(action="sreg_list", start="not_an_ea")["error"] is True
    with monkeypatch.context() as m:
        m.setattr(segments_mod._compat, "get_segment", lambda _ea: None)
        assert segments_mod.segments(action="sreg_list", start="0x140001000")["error"] is True
    assert segments_mod.segments(action="sreg_list", start="0x140001000", reg="TOTALLY_UNKNOWN_REG")["error"] is True


def test_segment_read_data_iterations_limit_and_compare_lookup_err(monkeypatch, fresh_fake_idb):
    # Line 972: find_data iterations >= 500000 break
    seg = fresh_fake_idb.segments[0]
    call_c = [0]

    def fast_next_head(head, _end):
        call_c[0] += 1
        if call_c[0] >= 500005:
            return segments_mod.idaapi.BADADDR
        return head

    monkeypatch.setattr(segments_mod.ida_bytes, "is_strlit", lambda _f: False)
    monkeypatch.setattr(segments_mod.ida_bytes, "is_data", lambda _f: False)
    monkeypatch.setattr(segments_mod.idc, "next_head", fast_next_head)
    res_iter = segments_mod.segments(action="find_data", start=hex(seg.start_ea))
    assert res_iter["ok"] is True

    # Line 997: action == "compare", seg_a lookup err
    with monkeypatch.context() as m:
        m.setattr(segments_mod._compat, "get_segment", lambda _ea: None)
        err_comp = segments_mod.segments(action="compare", start="0x140001000", end=hex(seg.start_ea))
        assert err_comp["error"] is True and "No segment at address" in err_comp["message"]


def test_segments_top_level_import_fallbacks(monkeypatch):
    import builtins
    orig_imp = builtins.__import__

    # Provide error_handling module in sys.modules so line 46 succeeds
    fake_eh = types.SimpleNamespace(parse_address_safe=lambda x: (int(str(x), 0), None))
    monkeypatch.setitem(sys.modules, "error_handling", fake_eh)

    def fail_imp(name, globals=None, locals=None, fromlist=(), level=0):
        if name in ("ida_idp", "ida_segregs"):
            raise ImportError(f"no {name}")
        if name in ("ida_mcp.error_handling", "ida_pro_mcp.ida_mcp.error_handling"):
            raise ImportError(f"no {name}")
        return orig_imp(name, globals, locals, fromlist, level)

    sys.modules["ida_pro_mcp.ida_mcp.tools.segments"] = segments_mod
    monkeypatch.setattr(builtins, "__import__", fail_imp)
    try:
        importlib.reload(segments_mod)
        assert segments_mod.ida_idp is None
        assert segments_mod.ida_segregs is None
    finally:
        monkeypatch.undo()
        importlib.reload(segments_mod)


def test_segment_last_four_edge_branches(monkeypatch, fresh_fake_idb):
    # Line 236: _resolve_sreg with int
    assert segments_mod._resolve_sreg(1) == 1

    # Line 561: action="add" with sclass="BSS"
    monkeypatch.setattr(segments_mod._compat, "add_segment", lambda *_args: True)
    res_bss = segments_mod.segments(action="add", start="0x140008000", end="0x140008100", name=".bss_extra", sclass="BSS")
    assert res_bss["ok"] is True

    # Line 571: action="add" without sclass (explicit sclass="")
    res_noclass = segments_mod.segments(action="add", start="0x140009000", end="0x140009100", name=".noclass", sclass="")
    assert res_noclass["ok"] is True and "note" in res_noclass

    # Line 638: action="set_attr", attr="perm", value="rx" (covers "x" in v)
    monkeypatch.setattr(segments_mod._compat, "set_segment_attr", lambda *_args: True)
    res_x = segments_mod.segments(action="set_attr", start="0x140001000", attr="perm", value="rx")
    assert res_x["ok"] is True
