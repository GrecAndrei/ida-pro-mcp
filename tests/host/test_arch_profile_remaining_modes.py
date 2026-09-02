"""Boundary coverage for architecture inference and profile normalization."""

from __future__ import annotations

import struct

from ida_pro_mcp.host.analysis import arch_profile


def test_normalize_arch_options_drops_empty_and_coerces_address_variants():
    normalized, meta = arch_profile.normalize_arch_options(
        {
            "processor": " ",
            "bitness": 0,
            "endian": "not-an-endian",
            "loader": None,
            "flags": 0,
            "baseaddr": "00401000",
            "start_ea": "0x20",
            "min_ea": "bad",
            "max_ea": 64,
        }
    )
    assert "processor" not in normalized
    assert normalized["baseaddr"] == 0x401000
    assert normalized["start_ea"] == 0x20
    assert normalized["min_ea"] == "bad"
    assert normalized["max_ea"] == 64
    assert any("dropped_empty" in item for item in meta["normalizations"])


def test_profile_math_handles_empty_and_degenerate_inputs():
    assert arch_profile._byte_2gram_embedding(b"") == {}
    assert arch_profile._byte_2gram_embedding(b"x") == {}
    assert arch_profile._byte_2gram_embedding(b"abcd")
    assert arch_profile._sparse_cosine({}, {1: 1.0}) == 0.0
    assert arch_profile._sparse_cosine({1: 0.0}, {1: 1.0}) == 0.0
    assert arch_profile._riscv_bitness(b"\x00" * 8) == (0.5, 0.5)
    assert arch_profile._dominant_hi20(b"\x00" * 16) is None
    assert arch_profile._raw_arch_candidates(b"") == []
    assert arch_profile._cortex_m_vector_plausible(b"\x00" * 16, 0x70000001) is False


def test_infer_binary_headers_and_unreadable_path_modes(tmp_path):
    cases = [
        ("elf.bin", b"\x7fELF" + b"\x00" * 80, "elf", None),
        ("macho.bin", b"\xfe\xed\xfa\xce" + b"\x00" * 80, "macho", None),
        ("pe-x64.bin", _pe_header(0x8664), "pe", 64),
        ("pe-arm64.bin", _pe_header(0xAA64), "pe", 64),
        ("pe-arm.bin", _pe_header(0x01C0), "pe", 32),
        ("pe-x86.bin", _pe_header(0x014C), "pe", 32),
    ]
    for filename, payload, kind, bits in cases:
        path = tmp_path / filename
        path.write_bytes(payload)
        result = arch_profile.infer_binary_arch_profile(str(path))
        assert result["file_kind"] == kind
        if bits is not None:
            assert result["bitness"] == bits

    unreadable = arch_profile.infer_binary_arch_profile(str(tmp_path / "missing.bin"))
    assert unreadable["reason"] == "binary unreadable"
    assert unreadable["file_kind"] == "unknown"


def _pe_header(machine: int) -> bytes:
    data = bytearray(0x80)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", data, 0x44, machine)
    return bytes(data)
