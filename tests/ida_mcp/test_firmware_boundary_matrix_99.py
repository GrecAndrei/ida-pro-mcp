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
