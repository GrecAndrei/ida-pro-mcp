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


# ── CRYPTO CONSTANT NAMES ──────────────────────────────────────────────────
# Unified map of well-known crypto constant values → human-readable names.
# Used by: search/core.py (build_constant_db), intelligence.py (annotation)
# Source: FindCrypt YARA rules + standard algorithm specifications.

CRYPTO_CONSTANT_NAMES: dict[int, str] = {
    # MD5 init values
    0x67452301: "MD5_INIT_A",
    0xEFCDAB89: "MD5_INIT_B",
    0x98BADCFE: "MD5_INIT_C",
    0x10325476: "MD5_INIT_D",
    # SHA-256 H values
    0x6A09E667: "SHA256_H0",
    0xBB67AE85: "SHA256_H1",
    0x3C6EF372: "SHA256_H2",
    0xA54FF53A: "SHA256_H3",
    0x510E527F: "SHA256_H4",
    0x9B05688C: "SHA256_H5",
    0x1F83D9AB: "SHA256_H6",
    0x5BE0CD19: "SHA256_H7",
    # SHA-1
    0xC3D2E1F0: "SHA1_H4",
    # AES round constants
    0x01000000: "AES_RCON_1",
    0x02000000: "AES_RCON_2",
    # ChaCha20 sigma constants
    0x61707865: "CHACHA_CONST_0",
    0x3320646E: "CHACHA_CONST_1",
    0x79622D32: "CHACHA_CONST_2",
    0x6B206574: "CHACHA_CONST_3",
    # Blake2b IV (64-bit)
    0x6A09E667F3BCC908: "BLAKE2B_IV0",
    0xBB67AE8584CAA73B: "BLAKE2B_IV1",
    # CRC32
    0xEDB88320: "CRC32_POLY",
    0x04C11DB7: "CRC32_POLY_REV",
    0x36E8E8E9: "CRC32",
    # Blowfish P-array
    0x243F6A88: "BLOWFISH_P0",
    0x85A308D3: "BLOWFISH_P1",
    # TEA
    0x9E3779B9: "TEA_DELTA",
    # RSA common exponents
    0x10001: "RSA_E_65537",
    0x3: "RSA_E_3",
    # FNV hash
    0xCBF29CE484222325: "FNV_OFFSET",
    0x100000001B3: "FNV_PRIME",
}


# ── DECOMPILER CRYPTO SIGNATURES ───────────────────────────────────────────
# String hints for detecting crypto algorithms in decompiler pseudocode.
# Used by: code_helpers.py

DECOMP_CRYPTO_SIGS: dict[str, list[str]] = {
    "AES": ["0x63636363", "0x7c777c77", "aes_key", "aes_encrypt", "aes_decrypt", "aes_"],
    "SHA256": ["0x6a09e667", "0xbb67ae85", "sha256", "sha_256"],
    "SHA1": ["0x67452301", "sha1", "sha_1"],
    "MD5": ["0xefcdab89", "0x67452301", "md5_", "md5update"],
    "RC4": ["rc4_", "ksa", "prga"],
    "ChaCha20": ["chacha", "0x61707865"],
    "PBKDF2": ["pbkdf2", "hmac", "iterations"],
}
