"""Canonical crypto, packer, and obfuscation heuristics.

Single source of truth for all detection constants used by security.py.
Imported by: security.py

Crypto constants come from downloaded FindCrypt YARA rules — the YARA
scanner compiles and matches them directly. This module only stores the
path to the downloaded rules plus non-YARA heuristics (packer signatures,
anti-debug APIs, game anti-cheat, API hashing).
"""

from __future__ import annotations

import os
from typing import Any

# ── FINDCRYPT YARA RULES PATH ──────────────────────────────────────────────

def findcrypt_rules_dir() -> str | None:
    """Return the directory containing downloaded FindCrypt YARA rules, or None."""
    try:
        from ..host.config import CACHE_DIR
    except ImportError:
        from host.config import CACHE_DIR  # type: ignore[no-redef]
    # Check SourceParser download cache
    source_dir = os.path.join(CACHE_DIR, "corpus_sources", "findcrypt")
    if os.path.isdir(source_dir):
        # Walk to find .yar/.yara/.rules files
        for root, _dirs, files in os.walk(source_dir):
            if any(f.endswith((".yar", ".yara", ".rules")) for f in files):
                return root
    # Check bron_corpus download cache
    bron_dir = os.path.join(CACHE_DIR, "threat_corpus_sources", "findcrypt")
    if os.path.isdir(bron_dir):
        for root, _dirs, files in os.walk(bron_dir):
            if any(f.endswith((".yar", ".yara", ".rules")) for f in files):
                return root
    return None


def findcrypt_available() -> bool:
    """Check if FindCrypt YARA rules are available locally."""
    return findcrypt_rules_dir() is not None


# ── API HASHING CONSTANTS ──────────────────────────────────────────────────

KNOWN_HASH_CONSTANTS: dict[str, int] = {
    "ror13_additive": 0x0D,
    "djb2": 0x1505,
    "sdbm": 0x1003F,
    "fnv1a_32": 0x811C9DC5,
}

HASH_RESOLVE_FUNCS: list[str] = [
    "GetProcAddress", "GetProcAddressA",
    "LdrGetProcedureAddress", "LdrGetProcedureAddressEx",
]


# ── PACKER SIGNATURES ──────────────────────────────────────────────────────

PACKER_SIGNATURES: list[dict] = [
    {"label": "UPX",       "weight": 0.9,  "check": "section_names", "patterns": [".UPX0", ".UPX1", ".UPX2", "UPX!", "UPX0", "UPX1"]},
    {"label": "UPX",       "weight": 0.95, "check": "strings",       "patterns": ["$Info: This file is packed with the UPX executable packer", "$Id: UPX"]},
    {"label": "MPRESS",    "weight": 0.85, "check": "section_names", "patterns": [".MPRESS1", ".MPRESS2"]},
    {"label": "VMProtect", "weight": 0.9,  "check": "strings",       "patterns": ["VMProtect", "VMP0", "VMP1", "VMP2", ".vmp0", ".vmp1"]},
    {"label": "VMProtect", "weight": 0.85, "check": "section_names", "patterns": [".vmp0", ".vmp1", ".vmp2"]},
    {"label": "Themida",   "weight": 0.85, "check": "strings",       "patterns": ["Themida", "WinLicense", ".themida"]},
    {"label": "ASPack",    "weight": 0.8,  "check": "section_names", "patterns": [".aspack", ".adata"]},
    {"label": "Petite",    "weight": 0.8,  "check": "section_names", "patterns": [".petite"]},
    {"label": "kkrunchy",  "weight": 0.75, "check": "section_names", "patterns": [".kkrunchy", "kkrunchy"]},
]

PACKER_DISPLAY_NAMES: dict[str, str] = {
    "upx": "UPX", "mpress": "MPRESS", "aspack": "ASPack", "petite": "Petite",
    "kkrunchy": "kkrunchy", "vmprotect": "VMProtect", "themida": "Themida",
    "custom_or_unknown": "custom/unknown protector", "none": "unpacked",
}


# ── ANTI-DEBUG / ANTI-VM ──────────────────────────────────────────────────

ANTI_DEBUG_APIS: list[str] = [
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "NtQuerySystemInformation",
    "OutputDebugStringA", "OutputDebugStringW",
    "NtSetInformationThread", "NtClose",
    "UnhandledExceptionFilter", "NtQueryObject",
]

ANTI_VM_STRINGS: list[str] = [
    "SbieDll.dll", "Sbx", "vmtoolsd.exe", "vmware", "vboxservice", "vboxguest",
    "vbox", "qemu", "xen", "cuckoomon", "snxhk.dll", "sbiedll", "vmcheck",
    "wine_get_unix_file_name",
]


# ── GAME ANTI-CHEAT ───────────────────────────────────────────────────────

GAME_ANTI_CHEAT: dict[str, list[str]] = {
    "EasyAntiCheat": ["EasyAntiCheat", "easyanticheat", "eac.dll", "eac_x64.dll", "EasyAntiCheat_x64.sys"],
    "BattlEye": ["BattlEye", "BEDaisy", "BEClient", "BEService", "battleye"],
    "nProtect": ["nProtect", "GameGuard", "GGAuth", "GameMon.des", "npptnt2.sys"],
    "Vanguard": ["Vanguard", "vgk.sys", "vgkboot.sys", "Riot Vanguard"],
    "Xigncode": ["Xigncode", "XIGNCODE", "XignCodeService"],
    "FACEIT": ["FACEIT", "faceit_ac"],
    "PunkBuster": ["PunkBuster", "PnkBstrA", "PnkBstrB", "pbcl.dll", "pbag.dll"],
    "EAC_Alt": ["anticheat", "anti-cheat"],
}
