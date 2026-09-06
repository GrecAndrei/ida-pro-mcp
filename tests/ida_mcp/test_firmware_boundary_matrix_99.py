"""Boundary coverage for firmware shaping on mapped and malformed blobs."""

from __future__ import annotations

import types

import pytest

from tests.ida_mcp.raw_blob_fake import fixture_bytes, install_raw_blob


def _load(**kwargs):
    blob = install_raw_blob(fixture_bytes(), processor="riscv", bitness=64, base=0x80000000, **kwargs)
    return blob, blob.load_tool("firmware")


def test_firmware_infrastructure_falls_back_across_ida_versions(monkeypatch):
    blob, mod = _load()
    ida_ida = blob.module("ida_ida")
    idaapi = blob.module("idaapi")
    monkeypatch.delattr(ida_ida, "inf_get_min_ea")
    monkeypatch.delattr(ida_ida, "inf_get_max_ea")
    monkeypatch.setattr(idaapi, "inf_get_min_ea", lambda: blob.base)
    monkeypatch.setattr(idaapi, "inf_get_max_ea", lambda: blob.end_ea)
    assert mod._fw_min_ea() == blob.base and mod._fw_max_ea() == blob.end_ea
    monkeypatch.setattr(idaapi, "inf_get_min_ea", lambda: (_ for _ in ()).throw(RuntimeError("min")))
    monkeypatch.setattr(idaapi, "inf_get_max_ea", lambda: (_ for _ in ()).throw(RuntimeError("max")))
    assert mod._fw_min_ea() is None and mod._fw_max_ea() is None

    monkeypatch.delattr(ida_ida, "inf_is_64bit")
    monkeypatch.delattr(ida_ida, "inf_get_app_bitness")
    monkeypatch.setattr(idaapi, "inf_is_64bit", lambda: True)
    assert mod._fw_ptr_size() == 8
    monkeypatch.setattr(idaapi, "inf_is_64bit", lambda: (_ for _ in ()).throw(RuntimeError("bits")))
    assert mod._fw_ptr_size() == 4
    monkeypatch.delattr(ida_ida, "inf_is_be")
    monkeypatch.setattr(idaapi, "inf_is_be", lambda: True)
    assert mod._fw_is_be() is True


def test_firmware_range_windows_and_read_helpers_cover_empty_and_hole_paths(monkeypatch):
    blob, mod = _load()
    assert mod._fw_image_bounds() == (blob.base, blob.end_ea)
    assert mod._fw_parse_range(None, "0x10")[2]["code"] == "INVALID_ARGS"
    assert mod._fw_parse_range("bad", "0x10")[2]["error"] is True
    assert mod._fw_parse_range("0x20", "0x10")[2]["code"] == "INVALID_ARG_VALUE"
    assert mod._fw_seg_span(None) is None
    assert mod._fw_seg_span(object()) is None
    seg = types.SimpleNamespace(start_ea=1, end_ea=5)
    assert mod._fw_seg_span(seg) == (1, 5)
    assert mod._fw_seg_span(blob.base) == (blob.base, blob.end_ea)

    segments = blob.module("idautils")
    monkeypatch.setattr(segments, "Segments", lambda: (_ for _ in ()).throw(RuntimeError("segments")))
    assert mod._fw_mapped_windows(0x1000, 0x1100) == [(0x1000, 0x1100)]
    assert mod._fw_mapped_windows(0x1100, 0x1000) == []
    assert list(mod._fw_iter_aligned(0, 10, 0)) == []
    assert list(mod._fw_iter_aligned(blob.base, blob.end_ea, 4, max_bytes=4)) == [blob.base]
    assert mod._read_word_bytes(blob.base, 4) == fixture_bytes()[:4]
    monkeypatch.setattr(blob.module("ida_bytes"), "get_bytes", lambda *_args: (_ for _ in ()).throw(RuntimeError("read")))
    assert mod._read_word_bytes(blob.base, 4) is None
    assert mod._read_bytes_range(blob.base, blob.base + 4) == b""
    assert mod._read_bytes_range(blob.base + 4, blob.base + 2) == b""


def test_firmware_load_base_scores_arm_generic_and_invalid_hypotheses(monkeypatch):
    blob, mod = _load()
    assert mod._riscv_jal_target(0x1000, 0) is None
    assert mod._has_riscv_gp_init([(0x1000, "auipc"), (0x1004, "addi")]) is False
    monkeypatch.setattr(mod, "get_arch", lambda: "arm")
    monkeypatch.setattr(mod, "is_arm_family", lambda _arch: True)
    monkeypatch.setattr(mod, "is_riscv_family", lambda _arch: False)
    result = mod._validate_load_base(blob.base, "arm", 4, blob.base, blob.end_ea)
    assert result["confidence"] >= 0.05
    monkeypatch.setattr(mod, "is_arm_family", lambda _arch: False)
    generic = mod._validate_load_base(blob.base, "unknown", 4, blob.base, blob.end_ea)
    assert generic["evidence"]
    outside = mod._validate_load_base(0x1000, "unknown", 4, blob.base, blob.end_ea)
    assert "pointer word" in outside["evidence"][0]
    assert mod._detect_load_base(blob.base, blob.end_ea, "bad", 2)["code"] == "INVALID_ARGS"

    mod.get_arch = lambda: "riscv"
    mod.is_riscv_family = lambda _arch: True
    assert mod._detect_load_base(blob.base, blob.end_ea, [], 2)["candidates"] == []


def test_firmware_mmio_and_rtos_action_edges(monkeypatch):
    blob, mod = _load()
    assert mod._peripheral_match(0x2000) is None
    assert mod._detect_mmio(blob.base, blob.base, None, 0, 2)["ranges"] == []
    assert mod._detect_mmio(blob.base, blob.end_ea, "bad", 0, 2)["error"] is True
    names = blob.module("idautils")
    monkeypatch.setattr(names, "Names", lambda: (_ for _ in ()).throw(RuntimeError("names")), raising=False)
    monkeypatch.setattr(names, "Strings", lambda: (_ for _ in ()).throw(RuntimeError("strings")), raising=False)
    assert mod._rtos_scan(blob.base, blob.end_ea, "freertos", 2)["matches"] == []


def test_firmware_carve_reports_default_names_exports_and_failures(tmp_path, monkeypatch):
    blob, mod = _load()
    assert mod._carve(None, "0x20", None, "DATA", 1, {})["code"] == "INVALID_ARGS"
    assert mod._carve("bad", "0x20", None, "DATA", 1, {})["error"] is True
    assert mod._carve("0x20", "0x10", None, "DATA", 1, {})["code"] == "INVALID_ARG_VALUE"
    monkeypatch.setattr(mod._compat, "get_segment", lambda _ea: types.SimpleNamespace())
    monkeypatch.setattr(mod._compat, "get_segment_name", lambda _ea: ".old")
    assert mod._carve("0x40000000", "0x40000010", None, "DATA", 1, {})["code"] == "SEGMENT_OVERLAP"

    monkeypatch.setattr(mod._compat, "get_segment", lambda _ea: None)
    added = []
    monkeypatch.setattr(mod._compat, "add_segment", lambda *args: added.append(args) or True)
    monkeypatch.setattr(mod.ida_bytes, "get_bytes", lambda _ea, size: fixture_bytes()[:size])
    out = tmp_path / "slice.bin"
    result = mod._carve("0x40000000", "0x40000004", None, "BSS", 1, {"file": str(out)})
    assert result["name"] == "carve_40000000_40000004"
    assert result["perms"] == "rw" and out.read_bytes() == fixture_bytes()[:4]
    assert added[-1][-1] == 3
    monkeypatch.setattr(mod._compat, "add_segment", lambda *_args: False)
    assert mod._carve("0x40000010", "0x40000020", "fail", "CODE", 1, {})["code"] == "IDA_ERROR"
    monkeypatch.setattr(mod.ida_bytes, "get_bytes", lambda *_args: b"x")
    monkeypatch.setattr(__import__("builtins"), "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk")))
    monkeypatch.setattr(mod._compat, "add_segment", lambda *_args: True)
    assert mod._carve("0x40000020", "0x40000024", "save", "CODE", 1, {"path": "/tmp/out"})["save_error"] == "disk"


def test_firmware_public_dispatch_validates_modes_and_bounds(monkeypatch):
    blob, mod = _load()
    assert mod.firmware(action="unknown")["code"] == "INVALID_ARGS"
    assert mod.firmware(action="detect_vector_table", start="0x1")["code"] == "INVALID_ARGS"
    assert mod.firmware(action="detect_vector_table", limit="bad")["ok"] is False
    monkeypatch.setattr(mod, "_fw_image_bounds", lambda: (None, None))
    assert mod.firmware(action="detect_mmio")["code"] == "IDA_ERROR"
    monkeypatch.setattr(mod, "_fw_image_bounds", lambda: (blob.base, blob.end_ea))
    result = mod.firmware(
        action="detect_vector_table",
        address="0x80000008",
        end=hex(blob.end_ea),
        word="u32",
        endian="le",
    )
    assert result["ok"] is True


def test_firmware_deep_branches_99(monkeypatch):
    blob, mod = _load()
    ida_ida = blob.module("ida_ida")
    idaapi = blob.module("idaapi")
    idc = blob.module("idc")
    idautils = blob.module("idautils")

    # 1. Lines 111-112: _fw_ptr_size exception in ida_ida
    monkeypatch.setattr(ida_ida, "inf_is_64bit", lambda: (_ for _ in ()).throw(RuntimeError("64 boom")), raising=False)
    monkeypatch.setattr(ida_ida, "inf_get_app_bitness", lambda: (_ for _ in ()).throw(RuntimeError("bitness boom")), raising=False)
    monkeypatch.setattr(idaapi, "inf_is_64bit", lambda: True)
    assert mod._fw_ptr_size() == 8

    # 2. Lines 127-128 & 131-132: _fw_is_be exceptions
    monkeypatch.setattr(ida_ida, "inf_is_be", lambda: (_ for _ in ()).throw(RuntimeError("be boom")), raising=False)
    monkeypatch.setattr(idaapi, "inf_is_be", lambda: (_ for _ in ()).throw(RuntimeError("api be boom")))
    assert mod._fw_is_be() is False

    # 3. Lines 165-166: _addr_is_mapped exception
    monkeypatch.setattr(idaapi, "is_mapped", lambda _v: (_ for _ in ()).throw(RuntimeError("mapped boom")))
    assert mod._addr_is_mapped(0x1000) is False

    # 4. Lines 192-193 & 197-198 & 218: _fw_seg_span and _fw_mapped_windows
    monkeypatch.setattr(idaapi, "getseg", lambda _ea: (_ for _ in ()).throw(RuntimeError("getseg boom")))
    monkeypatch.setattr(mod.idc, "get_segm_end", lambda _ea: 0x2000, raising=False)
    assert mod._fw_seg_span(0x1000) == (0x1000, 0x2000)

    class BadSeg:
        @property
        def start_ea(self):
            raise RuntimeError("bad start")

    monkeypatch.setattr(idaapi, "getseg", lambda _ea: BadSeg())
    assert mod._fw_seg_span(0x1000) == (0x1000, 0x2000)

    monkeypatch.setattr(idautils, "Segments", lambda: ["bad_seg_item"])
    monkeypatch.setattr(mod, "_fw_seg_span", lambda _item: None)
    assert mod._fw_mapped_windows(0x1000, 0x2000) == [(0x1000, 0x2000)]

    # 5. Lines 346 & 364 & 362: vector table scan limits and runs extending to hi
    monkeypatch.setattr(mod, "_fw_mapped_windows", lambda s, e: [(0x1000, 0x1040)])
    monkeypatch.setattr(mod, "_FW_MAX_SCAN_BYTES", 4)
    res_vt_scanned = mod._detect_vector_table(0x1000, 0x1040, None, "u32", "le", 10)
    assert isinstance(res_vt_scanned, dict)

    monkeypatch.setattr(mod, "_FW_MAX_SCAN_BYTES", 1024 * 1024)
    monkeypatch.setattr(mod, "_addr_is_mapped", lambda _v: True)
    monkeypatch.setattr(mod, "_read_word_bytes", lambda _ea, _sz: b"\x00\x00\x00\x80")
    monkeypatch.setattr(mod, "_fw_mapped_windows", lambda s, e: [(0x1000, 0x1010)])
    res_vt_run = mod._detect_vector_table(0x1000, 0x1010, None, "u32", "le", 10)
    assert len(res_vt_run["candidates"]) >= 1

    # 6. Line 427: RISC-V JAL negative immediate
    tgt_neg = mod._riscv_jal_target(0x100000, 0x8000006F)
    assert tgt_neg is not None
    assert tgt_neg < 0x100000

    # 7. Lines 438-439: _read_instructions mnem exception
    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: (_ for _ in ()).throw(RuntimeError("insn boom")))
    assert mod._read_instructions(0x1000, 2) == []

    # 8. Lines 454-455 & 461 & 464-465: _has_riscv_gp_init branches
    prologue = [(0x1000, "auipc"), (0x1004, "sub"), (0x1008, "addi")]
    monkeypatch.setattr(idc, "print_operand", lambda _ea, _n: (_ for _ in ()).throw(RuntimeError("op boom")))
    assert mod._has_riscv_gp_init(prologue) is False

    def fake_print_operand_err(ea, n):
        if ea == 0x1000:
            return "gp"
        raise RuntimeError("op2 boom")

    monkeypatch.setattr(idc, "print_operand", fake_print_operand_err)
    assert mod._has_riscv_gp_init(prologue) is False

    monkeypatch.setattr(idc, "print_operand", lambda _ea, _n: "gp")
    assert mod._has_riscv_gp_init(prologue) is True

    # 9. Line 476: _count_hypothetical_pointers image_size <= 0
    assert mod._count_hypothetical_pointers(0x2000, 0x1000, 0x1000, 4) == 0

    # 10. Lines 494-495 & 511-514 & 518-519 & 523-524: _validate_load_base branches
    monkeypatch.setattr(mod, "_read_word_bytes", lambda _ea, _sz: None)
    res_no_word = mod._validate_load_base(0x1000, "riscv", 4, 0x1000, 0x2000)
    assert "no readable word" in res_no_word["evidence"][0]

    monkeypatch.setattr(mod, "_read_word_bytes", lambda _ea, _sz: b"\x6f\x00\x00\x00")
    monkeypatch.setattr(mod, "_decode_word", lambda d, enc: 0x6f)
    monkeypatch.setattr(mod, "is_riscv_family", lambda _a: True)
    monkeypatch.setattr(mod, "_riscv_jal_target", lambda b, raw: 0x999999)
    res_tgt_out = mod._validate_load_base(0x1000, "riscv", 4, 0x1000, 0x2000)
    assert any("jumps outside" in ev for ev in res_tgt_out["evidence"])

    monkeypatch.setattr(mod, "_riscv_jal_target", lambda b, raw: None)
    res_not_jump = mod._validate_load_base(0x1000, "riscv", 4, 0x1000, 0x2000)
    assert any("not a RISC-V jal" in ev for ev in res_not_jump["evidence"])

    monkeypatch.setattr(mod, "is_riscv_family", lambda _a: False)
    monkeypatch.setattr(mod, "is_arm_family", lambda _a: True)
    monkeypatch.setattr(mod, "_decode_word", lambda d, enc: 0x1051)
    res_arm_ok = mod._validate_load_base(0x1000, "arm", 4, 0x1000, 0x2000)
    assert any("resolves to mapped" in ev for ev in res_arm_ok["evidence"])

    monkeypatch.setattr(mod, "is_arm_family", lambda _a: False)
    monkeypatch.setattr(mod, "_decode_word", lambda d, enc: 0x1500)
    res_gen_ok = mod._validate_load_base(0x1000, "unknown", 4, 0x1000, 0x2000)
    assert any("resolves inside the mapped image" in ev for ev in res_gen_ok["evidence"])

    # 11. Lines 703 & 714: _rtos_scan names and strings limits
    monkeypatch.setattr(idautils, "Names", lambda: [(0x1000, "vTaskCreate"), (0x1004, "xQueueCreate")], raising=False)
    monkeypatch.setattr(idautils, "Strings", lambda: [f"str_{i}" for i in range(2005)], raising=False)
    res_rtos = mod._rtos_scan(blob.base, blob.end_ea, "freertos", 5)
    assert res_rtos["ok"] is True
