"""Chip family fingerprint database for cross-session firmware analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class MagicSignature:
    offset: int
    value: bytes
    description: str = ""


@dataclass(frozen=True)
class ChipProfile:
    chip_family: str
    signatures: List[MagicSignature]
    load_base: int
    processor: str
    bitness: int
    endian: str
    header_parser: str
    memory_map: List[Dict[str, Any]]
    peripheral_addresses: List[Dict[str, Any]]


def _profile_dict(p: ChipProfile) -> Dict[str, Any]:
    return {
        "chip_family": p.chip_family,
        "signatures": [
            {"offset": s.offset, "value_hex": s.value.hex(), "description": s.description}
            for s in p.signatures
        ],
        "load_base": p.load_base,
        "processor": p.processor,
        "bitness": p.bitness,
        "endian": p.endian,
        "header_parser": p.header_parser,
        "memory_map": p.memory_map,
        "peripheral_addresses": p.peripheral_addresses,
    }


CHIP_PROFILES: List[ChipProfile] = [
    ChipProfile(
        chip_family="AIC8800D80",
        signatures=[MagicSignature(offset=0x20, value=b"WFFW", description="AIC firmware header magic")],
        load_base=0x00120000,
        processor="arm",
        bitness=32,
        endian="little",
        header_parser="aic_wffw_header",
        memory_map=[
            {"name": "rom", "start": "0x00100000", "end": "0x001FFFFF", "perm": "r-x"},
            {"name": "sram", "start": "0x20000000", "end": "0x2007FFFF", "perm": "rw-"},
        ],
        peripheral_addresses=[
            {"name": "wifi_mac", "addr": "0x40010000"},
            {"name": "bt_base", "addr": "0x40020000"},
        ],
    ),
    ChipProfile(
        chip_family="ESP32",
        signatures=[
            MagicSignature(offset=0x00, value=b"\xE9", description="ESP image header magic"),
        ],
        load_base=0x400D0000,
        processor="xtensa",
        bitness=32,
        endian="little",
        header_parser="esp_image_header",
        memory_map=[
            {"name": "irom", "start": "0x400D0000", "end": "0x40400000", "perm": "r-x"},
            {"name": "dram", "start": "0x3FFB0000", "end": "0x40000000", "perm": "rw-"},
        ],
        peripheral_addresses=[
            {"name": "uart0", "addr": "0x3FF40000"},
            {"name": "spi0", "addr": "0x3FF42000"},
        ],
    ),
    ChipProfile(
        chip_family="STM32",
        signatures=[],
        load_base=0x08000000,
        processor="arm",
        bitness=32,
        endian="little",
        header_parser="cortex_m_vector_table",
        memory_map=[
            {"name": "flash", "start": "0x08000000", "end": "0x081FFFFF", "perm": "r-x"},
            {"name": "sram", "start": "0x20000000", "end": "0x2004FFFF", "perm": "rw-"},
        ],
        peripheral_addresses=[
            {"name": "rcc", "addr": "0x40023800"},
            {"name": "gpioa", "addr": "0x40020000"},
        ],
    ),
    ChipProfile(
        chip_family="Generic Cortex-M",
        signatures=[],
        load_base=0x08000000,
        processor="arm",
        bitness=32,
        endian="little",
        header_parser="cortex_m_vector_table",
        memory_map=[
            {"name": "flash", "start": "0x08000000", "end": "0x08FFFFFF", "perm": "r-x"},
            {"name": "sram", "start": "0x20000000", "end": "0x3FFFFFFF", "perm": "rw-"},
        ],
        peripheral_addresses=[
            {"name": "periph", "addr": "0x40000000"},
        ],
    ),
]


def identify_chip_from_bytes(head: bytes) -> Optional[Dict[str, Any]]:
    for profile in CHIP_PROFILES:
        if not profile.signatures:
            continue
        matched = True
        for sig in profile.signatures:
            end = sig.offset + len(sig.value)
            if end > len(head) or head[sig.offset:end] != sig.value:
                matched = False
                break
        if matched:
            out = _profile_dict(profile)
            out["confidence"] = 0.98
            out["match_reason"] = "magic_signature"
            return out
    return None


def find_chip_profile(chip_family: str) -> Optional[Dict[str, Any]]:
    key = chip_family.lower()
    for profile in CHIP_PROFILES:
        if profile.chip_family.lower() == key:
            return _profile_dict(profile)
    return None


def get_chip_family_catalog() -> List[Dict[str, Any]]:
    return [_profile_dict(p) for p in CHIP_PROFILES]


def find_chip_profile(chip_family: str) -> Optional[Dict[str, Any]]:
    needle = str(chip_family or "").strip().lower()
    for p in CHIP_PROFILES:
        if p.chip_family.lower() == needle:
            return _profile_dict(p)
    return None
