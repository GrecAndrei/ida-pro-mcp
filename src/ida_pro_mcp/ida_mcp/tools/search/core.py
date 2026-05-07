"""SEARCH.CORE - Shared utilities, constants, and base helpers for search actions.

VOERA Architecture:
- Context Density Optimization: compact output, line clipping
- Neuro-Symbolic Governance: semantic target resolution with thresholds
- Structured Semantic Retrieval: schema helpers
"""

import re
import heapq
import time as _time
from collections import OrderedDict
from typing import Optional, Sequence, Mapping

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from ..semantic_matching import normalize_action, semantic_score, semantic_tokens
except ImportError:
    from semantic_matching import normalize_action, semantic_score, semantic_tokens  # type: ignore[import-not-found]

# ============================================================================
# VOERA: Module-Level Caches
# ============================================================================

_SEARCH_CACHE: OrderedDict[str, object] = OrderedDict()
_MAX_CACHE_SIZE = 64

# Database-level caches (invalidated when the IDB changes)
_MAX_DB_CACHE_ITEMS = 50000
_CONSTANT_DB_CACHE: Optional[dict] = None
_IMPORTS_CACHE: Optional[list] = None
_STRINGS_CACHE: Optional[list] = None
_DB_FINGERPRINT: Optional[str] = None


def _cache_key(prefix: str, *args) -> str:
    return f"{prefix}:{':'.join(str(a) for a in args)}"


def _cache_get(key: str):
    if key in _SEARCH_CACHE:
        _SEARCH_CACHE.move_to_end(key)
        return _SEARCH_CACHE[key]
    return None


def _cache_set(key: str, value) -> None:
    _SEARCH_CACHE[key] = value
    if len(_SEARCH_CACHE) > _MAX_CACHE_SIZE:
        _SEARCH_CACHE.popitem(last=False)


def _cache_clear() -> None:
    _SEARCH_CACHE.clear()
    global _CONSTANT_DB_CACHE, _IMPORTS_CACHE, _STRINGS_CACHE, _DB_FINGERPRINT
    _CONSTANT_DB_CACHE = None
    _IMPORTS_CACHE = None
    _STRINGS_CACHE = None
    _DB_FINGERPRINT = None


class SearchTimeout:
    """Simple timeout helper for long-running search loops."""
    def __init__(self, timeout_ms: int):
        self.deadline = _time.time() + (max(0, timeout_ms) / 1000.0) if timeout_ms > 0 else None

    def is_expired(self) -> bool:
        if self.deadline is None:
            return False
        return _time.time() >= self.deadline

    def check(self):
        if self.is_expired():
            raise TimeoutError("Search timeout exceeded")


def _get_db_fingerprint() -> str:
    """Generate a fingerprint for the current database state."""
    try:
        md5 = ida_nalt.retrieve_input_file_md5()
        if md5:
            return md5.hex()
    except Exception:
        pass
    # Fallback: count functions + segments + total names
    func_count = sum(1 for _ in idautils.Functions())
    seg_count = sum(1 for _ in idautils.Segments())
    name_count = sum(1 for _ in idautils.Names())
    return f"fallback:{func_count}:{seg_count}:{name_count}"


def _db_changed() -> bool:
    """Check if the database has changed since our last cache."""
    global _DB_FINGERPRINT
    current = _get_db_fingerprint()
    if _DB_FINGERPRINT is None or _DB_FINGERPRINT != current:
        _DB_FINGERPRINT = current
        return True
    return False


def get_cached_constant_db() -> dict[int, str]:
    """Return cached constant DB, rebuilding if the database changed."""
    global _CONSTANT_DB_CACHE
    if _CONSTANT_DB_CACHE is None or _db_changed():
        _CONSTANT_DB_CACHE = build_constant_db()
    return _CONSTANT_DB_CACHE


def get_cached_imports() -> list[dict]:
    """Return cached import list, rebuilding if the database changed.

    Capped at _MAX_DB_CACHE_ITEMS to prevent memory bombs on huge databases.
    If the cap is exceeded, the list is returned uncached.
    """
    global _IMPORTS_CACHE
    if _IMPORTS_CACHE is not None and not _db_changed():
        return _IMPORTS_CACHE
    imports = []
    for mod_idx in range(ida_nalt.get_import_module_qty()):
        mod_name = ida_nalt.get_import_module_name(mod_idx) or f"mod_{mod_idx}"

        def make_cb(mod):
            def cb(ea, name, ordinal):
                if name:
                    imports.append({"ea": ea, "name": name, "module": mod, "ordinal": ordinal})
                return True
            return cb

        ida_nalt.enum_import_names(mod_idx, make_cb(mod_name))
        if len(imports) >= _MAX_DB_CACHE_ITEMS:
            break
    if len(imports) < _MAX_DB_CACHE_ITEMS:
        _IMPORTS_CACHE = imports
    return imports


def get_cached_strings() -> list[dict]:
    """Return cached string list, rebuilding if the database changed.

    Capped at _MAX_DB_CACHE_ITEMS to prevent memory bombs on huge databases.
    If the cap is exceeded, the list is returned uncached.
    """
    global _STRINGS_CACHE
    if _STRINGS_CACHE is not None and not _db_changed():
        return _STRINGS_CACHE
    strings = []
    for sc in safe_get_strlist_items():
        if len(strings) >= _MAX_DB_CACHE_ITEMS:
            break
        try:
            s = safe_get_strlit_contents(sc.ea)
            if s is not None:
                strings.append({"ea": sc.ea, "string": s})
        except Exception:
            pass
    if len(strings) < _MAX_DB_CACHE_ITEMS:
        _STRINGS_CACHE = strings
    return strings


# ============================================================================
# Configuration
# ============================================================================

MAX_LIMIT = 500
LINE_MAX = 240
_FIND_INSTRUCTION_CAP = 2000
_FIND_INSTRUCTION_LIMIT_MULTIPLIER = 40

SCORE_EXACT = 120.0
SCORE_SUBSTRING = 60.0
SCORE_TOKEN_OVERLAP = 45.0
SCORE_FUZZY = 20.0

MNEMONIC_BASE_SCORE = 95.0
MNEMONIC_GROUP_SCORE = 120.0
MNEMONIC_TOKEN_WEIGHT = 14.0
MNEMONIC_CAP = 160.0
MNEMONIC_THRESHOLD = 82.0

INSTRUCTION_CAP = 175.0
INSTRUCTION_TOKEN_WEIGHT = 10.0
INSTRUCTION_BASE_SCORE = 90.0
INSTRUCTION_THRESHOLD = 90.0
FIND_INSTRUCTION_MIN_SCORE = 88.0

CALL_XREF_TYPES = frozenset([getattr(idaapi, "fl_CN", 17), getattr(idaapi, "fl_CF", 18),
                            getattr(idaapi, "fl_JN", 19), getattr(idaapi, "fl_JF", 20),
                            getattr(idaapi, "fl_F", 21)])

SEARCH_ACTIONS = {
    "bytes", "string", "immediate", "name", "insns", "mnemonic", "instruction",
    "text", "operand", "comment", "data_ref", "code_ref", "regex", "func_by_sig",
    "find", "semantic", "callers", "callees", "api", "vulnerable", "constants", "decompiled", "structured",
    "type", "export", "summary",
}

SEARCH_ALIASES = {
    "byte": "bytes", "bytesearch": "bytes",
    "str": "string", "strings": "string", "literal": "string",
    "imm": "immediate", "constant": "immediate",
    "symbol": "name", "names": "name",
    "instruction_seq": "insns", "instruction_sequence": "insns",
    "instructions": "instruction", "mnemonics": "mnemonic", "mnem": "mnemonic",
    "opcode": "mnemonic", "opcodes": "mnemonic",
    "insn_text": "instruction", "instruction_text": "instruction",
    "asm_text": "instruction", "semantic_instruction": "instruction",
    "disasm": "text", "disassembly": "text",
    "ops": "operand", "operands": "operand",
    "comments": "comment",
    "xref": "code_ref", "xrefs": "code_ref",
    "datarefs": "data_ref", "coderefs": "code_ref",
    "function_signature": "func_by_sig", "signature": "func_by_sig",
    "lookup": "find", "discover": "find",
    "semantic_find": "semantic", "nl": "semantic", "natural_language": "semantic",
    "caller": "callers", "callee": "callees",
    "imports": "api", "import": "api", "apis": "api",
    "vuln": "vulnerable", "vulns": "vulnerable",
    "crypto_constants": "constants", "magic_constants": "constants",
    "pseudo": "decompiled", "pseudocode": "decompiled",
    "types": "type", "typedef": "type", "typeinfo": "type",
    "exports": "export", "exported": "export",
    "overview": "summary", "count": "summary", "stats": "summary",
}

SEARCH_INTENT_PATTERNS = [
    (re.compile(r"^\s*(?:who\s+)?(?:callers?|calls?)\s+(?:of\s+)?(.+)$", re.IGNORECASE), "callers"),
    (re.compile(r"^\s*(?:what\s+)?callees?\s+(?:of\s+)?(.+)$", re.IGNORECASE), "callees"),
    (re.compile(r"^\s*(?:api|import)s?(?:\s+usage|\s+calls?)?\s+(?:of|for)?\s+(.+)$", re.IGNORECASE), "api"),
    (re.compile(r"^\s*(?:code\s+)?xrefs?\s+(?:to|for)\s+(.+)$", re.IGNORECASE), "code_ref"),
    (re.compile(r"^\s*data\s+xrefs?\s+(?:to|for)\s+(.+)$", re.IGNORECASE), "data_ref"),
    (re.compile(r"^\s*(?:decompiled|pseudocode)\s+(?:search\s+)?(?:for|of)?\s+(.+)$", re.IGNORECASE), "decompiled"),
    (re.compile(r"^\s*(?:mnemonic|opcode)s?\s+(?:search\s+)?(?:for|of)?\s+(.+)$", re.IGNORECASE), "mnemonic"),
    (re.compile(r"^\s*(?:instruction|assembly|asm)\s+(?:search\s+)?(?:for|of)?\s+(.+)$", re.IGNORECASE), "instruction"),
    (re.compile(r"^\s*(?:type|struct|typedef|union|enum)\s+(?:search\s+)?(?:for|of)?\s+(.+)$", re.IGNORECASE), "type"),
    (re.compile(r"^\s*(?:export|exported)\s+(?:search\s+)?(?:for|of)?\s+(.+)$", re.IGNORECASE), "export"),
    (re.compile(r"^\s*(?:summary|overview|count|stats)\s+(?:of|for)?\s+(.+)$", re.IGNORECASE), "summary"),
]

MNEMONIC_GROUPS = {
    "call": ("call", "bl", "blx", "jal", "jsr"),
    "branch": ("j", "b", "cb", "tb", "br"),
    "jump": ("j", "b", "br"),
    "return": ("ret", "retn", "bx", "jr", "blr"),
    "compare": ("cmp", "test", "cmn", "tst"),
    "move": ("mov", "lea", "ld", "st", "ldr", "str"),
    "arithmetic": ("add", "sub", "mul", "imul", "div", "idiv", "adc", "sbb"),
    "logic": ("and", "or", "xor", "not", "shl", "shr", "rol", "ror"),
    "stack": ("push", "pop", "enter", "leave"),
    "syscall": ("syscall", "sysenter", "svc", "ecall", "int"),
}

# ============================================================================
# Shared Helpers
# ============================================================================


def clip_text(text: Optional[str], max_len: int = LINE_MAX) -> str:
    if text is None:
        return ""
    compact = " ".join(str(text).split())
    if len(compact) <= max_len:
        return compact
    return compact[: max_len - 3] + "..."


def paginate_records(records, offset: int, limit: int, sort_key=None, reverse: bool = True):
    rows = list(records)
    if sort_key is not None:
        rows.sort(key=sort_key, reverse=reverse)
    total = len(rows)
    page = rows[offset : offset + limit]
    is_truncated = (offset + len(page)) < total
    return page, total, is_truncated


def xref_count_limited(ea: int, max_count: int = 256) -> int:
    count = 0
    for _ in idautils.XrefsTo(ea, 0):
        count += 1
        if count >= max_count:
            break
    return count


def iter_segments(range_start=None, range_end=None, require_exec: bool = True):
    """Yield (seg_start, seg_end) for searchable segments."""
    if range_start is not None and range_end is not None:
        seg = idaapi.getseg(range_start)
        while seg and seg.start_ea < range_end:
            if not require_exec or (seg.perm & idaapi.SEGPERM_EXEC):
                yield (max(seg.start_ea, range_start), min(seg.end_ea, range_end))
            seg = idaapi.get_next_seg(seg.end_ea)
    else:
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg:
                continue
            if not require_exec or (seg.perm & idaapi.SEGPERM_EXEC):
                yield (seg.start_ea, seg.end_ea)


def iter_code(seg_start, seg_end):
    """Yield executable addresses within segment bounds."""
    ea = seg_start
    while ea < seg_end:
        if ida_bytes.is_code(ida_bytes.get_flags(ea)):
            yield ea
        ea = idc.next_head(ea, seg_end)
        if ea == idaapi.BADADDR:
            break


def build_response(matches, offset: int, limit: int, total_matches: int, truncated: bool, **extra):
    """Unified response builder for all search actions."""
    response = {
        "ok": True,
        "matches": "\n".join(str(m) for m in matches),
        "count": len(matches),
        "total": total_matches,
        "offset": offset,
        "truncated": truncated,
    }
    response.update(extra)
    return response


# ============================================================================
# Semantic Target Resolution
# ============================================================================


def resolve_target(
    raw_target: Optional[str],
    *,
    require_function: bool = False,
    include_imports: bool = False,
    semantic_min_score: float = 0.0,
    include_alternatives: bool = False,
):
    """Resolve a target name/address with short-circuiting."""
    if raw_target is None:
        return idaapi.BADADDR, "target is required", {}

    target = str(raw_target).strip()
    if not target:
        return idaapi.BADADDR, "target is required", {}

    # Fast path: exact address
    if looks_like_address(target):
        ea, err = validate_addr(target)
        if not err and ea != idaapi.BADADDR:
            if require_function and not idaapi.get_func(ea):
                return idaapi.BADADDR, f"No function at {hex(ea)}", {}
            return ea, None, {"match": "address"}

    # Fast path: exact name
    exact_ea = idc.get_name_ea_simple(target)
    if exact_ea != idaapi.BADADDR:
        if require_function and not idaapi.get_func(exact_ea):
            return idaapi.BADADDR, f"No function at {hex(exact_ea)}", {}
        return exact_ea, None, {"match": "exact_name"}

    # Slow path: fuzzy matching
    matcher = compile_smart_pattern(target, case_sensitive=False)
    prelim = []
    max_candidates = 512

    def record_candidate(ea, raw_name, display_name, kind, module_name=None, exact_bonus=0.0):
        quick_score = semantic_score(target, raw_name, substring_bonus=SCORE_SUBSTRING, include_fuzzy=False)
        if raw_name.lower() == target.lower():
            quick_score += exact_bonus
        if quick_score > 0:
            prelim.append((quick_score, ea, raw_name, display_name, kind, module_name))

    for sym_ea, sym_name in idautils.Names():
        if not sym_name or not matcher(sym_name):
            continue
        is_func = bool(idaapi.get_func(sym_ea))
        if require_function and not is_func:
            continue
        record_candidate(sym_ea, sym_name, sym_name, "function" if is_func else "symbol", exact_bonus=40.0)

    if include_imports:
        for mod_idx in range(ida_nalt.get_import_module_qty()):
            mod_name = ida_nalt.get_import_module_name(mod_idx) or f"mod_{mod_idx}"

            def make_cb(mod):
                def cb(import_ea, import_name, _ordinal):
                    if not import_name or not matcher(import_name):
                        return True
                    record_candidate(import_ea, import_name, f"{mod}!{import_name}", "import", mod, exact_bonus=45.0)
                    return True
                return cb

            ida_nalt.enum_import_names(mod_idx, make_cb(mod_name))

    if not prelim:
        return idaapi.BADADDR, f"Target '{target}' not found", {}

    prelim.sort(key=lambda r: (r[0], r[1]), reverse=True)
    ranked = []
    for _, cand_ea, raw_name, display_name, kind, module_name in prelim[:max_candidates]:
        final_score = semantic_score(target, raw_name, substring_bonus=SCORE_SUBSTRING)
        if raw_name.lower() == target.lower():
            final_score += 45.0 if kind == "import" else 40.0
        final_score += min(xref_count_limited(cand_ea, 64), 64)
        ranked.append((final_score, cand_ea, display_name, kind, module_name))

    ranked.sort(key=lambda r: (r[0], r[1]), reverse=True)
    top_score, top_ea, top_name, top_kind, top_module = ranked[0]

    if require_function:
        top_func = idaapi.get_func(top_ea)
        if top_func:
            top_ea = top_func.start_ea

    if top_score < semantic_min_score:
        return idaapi.BADADDR, (
            f"Target '{target}' best semantic match below threshold "
            f"({top_score:.2f} < {semantic_min_score:.2f})"
        ), {}

    details = {
        "match": "semantic",
        "semantic_target": top_name,
        "semantic_kind": top_kind,
        "semantic_score": round(top_score, 2),
    }
    if top_kind == "import" and top_module:
        details["semantic_module"] = top_module
    if include_alternatives and len(ranked) > 1:
        details["semantic_alternatives"] = [
            {"name": r[2], "address": hex(r[1]), "kind": r[3], "score": round(r[0], 2)}
            for r in ranked[1:6]
        ]
    return top_ea, None, details


# ============================================================================
# Vulnerability Derivation Helper
# ============================================================================


def derive_vuln_type(api_name: str) -> str:
    """Derive vulnerability category from API name (dynamic, no hardcoded dicts)."""
    lname = api_name.lower()

    # Buffer overflow / unsafe copy
    if any(s in lname for s in ("strcpy", "strcat", "sprintf", "gets", "scanf", "wcscpy", "wcscat", "lstrcpy", "lstrcat", "rtlcopymemory")):
        return "buffer_overflow"
    if lname in ("memcpy", "memmove"):
        return "buffer_overflow"

    # Format string
    if any(s in lname for s in ("printf", "fprintf", "sprintf", "snprintf", "vprintf", "vsprintf", "vsnprintf", "syslog")):
        return "format_string"

    # Command injection
    if any(s in lname for s in ("system", "popen", "execl", "execv", "execve", "shellexecute", "winexec", "createprocess")):
        return "command_injection"

    # Injection / RWX
    if any(s in lname for s in ("createremotethread", "writeprocessmemory", "ntwritevirtualmemory", "virtualalloc", "virtualprotect", "rtlcreateuserthread", "ntcreatethreadex")):
        return "injection"

    # Privilege escalation
    if any(s in lname for s in ("adjusttokenprivileges", "impersonateloggedonuser")):
        return "privilege_escalation"

    # Persistence
    if any(s in lname for s in ("regsetvalueex", "createservice", "setwindowshookex")):
        return "persistence"

    # Evasion / dynamic loading
    if any(s in lname for s in ("loadlibrary", "getprocaddress", "urldownloadtofile")):
        return "evasion"

    # Memory management
    if any(s in lname for s in ("malloc", "calloc", "realloc", "free", "heapalloc", "heapfree", "virtualfree")):
        return "memory_issue"

    return "dangerous"


# ============================================================================
# Constant Database Builder
# ============================================================================


# ============================================================================
# IDA API Compatibility Wrappers
# ============================================================================


def safe_generate_disasm_line(ea):
    """Generate disassembly line with fallback for API changes across IDA versions."""
    if ea == idaapi.BADADDR:
        return None
    for fn in (
        lambda: ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_FORCE_CODE),
        lambda: ida_lines.generate_disasm_line(ea, 0),
        lambda: idc.generate_disasm_line(ea, 0),
    ):
        try:
            result = fn()
            if result:
                return result
        except Exception:
            continue
    return None


def safe_get_strlist_items():
    """Yield string info objects, using ida_strlist if available."""
    try:
        import ida_strlist
        for i in range(ida_strlist.get_strlist_qty()):
            si = ida_strlist.string_info_t()
            if ida_strlist.get_strlist_item(si, i):
                yield si
    except (ImportError, AttributeError):
        for i in range(idaapi.get_strlist_qty()):
            sc = idaapi.string_info_t()
            if idaapi.get_strlist_item(sc, i):
                yield sc


def safe_get_strlit_contents(ea):
    """Get string literal contents with version-agnostic fallback."""
    try:
        stype = idc.get_str_type(ea)
        if stype is not None and stype >= 0:
            s = idc.get_strlit_contents(ea, -1, stype)
            if s:
                return s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
    except Exception:
        pass
    try:
        s = idc.get_strlit_contents(ea)
        if s:
            return s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
    except Exception:
        pass
    return None


def build_constant_db() -> dict[int, str]:
    """Build dynamic constant database from _api_categories and crypto_id."""
    db = {}
    # Magic constants from _api_categories (imported via _common)
    if "MAGIC_CONSTANTS" in globals():
        db.update(MAGIC_CONSTANTS)

    # Crypto init constants
    crypto_inits = {
        0x67452301: "MD5_INIT_A",
        0xEFCDAB89: "MD5_INIT_B",
        0x98BADCFE: "MD5_INIT_C",
        0x10325476: "MD5_INIT_D",
        0x6A09E667: "SHA256_H0",
        0xBB67AE85: "SHA256_H1",
        0x3C6EF372: "SHA256_H2",
        0xA54FF53A: "SHA256_H3",
        0x510E527F: "SHA256_H4",
        0x9B05688C: "SHA256_H5",
        0x1F83D9AB: "SHA256_H6",
        0x5BE0CD19: "SHA256_H7",
        0xC3D2E1F0: "SHA1_H4",
        0x01000000: "AES_RCON_1",
        0x02000000: "AES_RCON_2",
        0x61707865: "CHACHA_CONST_0",
        0x3320646E: "CHACHA_CONST_1",
        0x79622D32: "CHACHA_CONST_2",
        0x6B206574: "CHACHA_CONST_3",
        0x6a09e667f3bcc908: "BLAKE2B_IV0",
        0xbb67ae8584caa73b: "BLAKE2B_IV1",
        0xEDB88320: "CRC32_POLY",
        0x04C11DB7: "CRC32_POLY_REV",
        0x243F6A88: "BLOWFISH_P0",
        0x85A308D3: "BLOWFISH_P1",
        0x9E3779B9: "TEA_DELTA",
        0x10001: "RSA_E_65537",
        0x3: "RSA_E_3",
    }
    db.update(crypto_inits)
    return db
