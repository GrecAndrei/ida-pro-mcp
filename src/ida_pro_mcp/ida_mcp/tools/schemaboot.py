"""
SchemaBoot - Deterministic Function Attribute Extraction and Structured Search.

This module provides a standalone, zero-ML function attribute index for IDA Pro.
It extracts deterministic structural attributes from every function using only
IDA's native APIs, stores them in a fast SQLite index, and enables SQL-style
structured queries that run orders of magnitude faster than iterating functions
in Python.

Attributes extracted per function:
- Basic metadata: name, address, size, segment
- Instruction mix: counts per mnemonic category
- API calls: imported functions referenced
- String references: string literals used
- Cross-reference stats: incoming/outgoing counts
- Structural metrics: basic block count, cyclomatic complexity
- Binary entropy: Shannon entropy of function bytes
- Behavioral flags: is_thunk, is_library, has_loops, etc.

All extraction is deterministic and requires no external models.
"""

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    import ida_loader
except ImportError:
    ida_loader = None  # type: ignore[assignment]

import os
import re
import json
import math
import time
import sqlite3
import tempfile
import hashlib
from collections import Counter
from typing import Any

# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS function_attrs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ea INTEGER NOT NULL UNIQUE,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    segment TEXT,
    is_thunk INTEGER DEFAULT 0,
    is_library INTEGER DEFAULT 0,
    bb_count INTEGER DEFAULT 0,
    cyclomatic_complexity INTEGER DEFAULT 0,
    incoming_xrefs INTEGER DEFAULT 0,
    outgoing_xrefs INTEGER DEFAULT 0,
    entropy REAL DEFAULT 0.0,
    call_count INTEGER DEFAULT 0,
    xor_count INTEGER DEFAULT 0,
    mov_count INTEGER DEFAULT 0,
    cmp_count INTEGER DEFAULT 0,
    jmp_count INTEGER DEFAULT 0,
    ret_count INTEGER DEFAULT 0,
    push_count INTEGER DEFAULT 0,
    pop_count INTEGER DEFAULT 0,
    lea_count INTEGER DEFAULT 0,
    test_count INTEGER DEFAULT 0,
    api_count INTEGER DEFAULT 0,
    string_count INTEGER DEFAULT 0,
    data_ref_count INTEGER DEFAULT 0,
    has_loops INTEGER DEFAULT 0,
    max_loop_depth INTEGER DEFAULT 0,
    has_crypto_constants INTEGER DEFAULT 0,
    xor_ratio REAL DEFAULT 0.0,
    created_at REAL DEFAULT 0.0,
    updated_at REAL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS function_apis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    func_ea INTEGER NOT NULL,
    api_name TEXT NOT NULL,
    FOREIGN KEY (func_ea) REFERENCES function_attrs(ea)
);

CREATE TABLE IF NOT EXISTS function_strings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    func_ea INTEGER NOT NULL,
    string_text TEXT NOT NULL,
    string_ea INTEGER NOT NULL,
    FOREIGN KEY (func_ea) REFERENCES function_attrs(ea)
);

CREATE TABLE IF NOT EXISTS function_constants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    func_ea INTEGER NOT NULL,
    constant_value INTEGER NOT NULL,
    constant_name TEXT,
    FOREIGN KEY (func_ea) REFERENCES function_attrs(ea)
);

CREATE INDEX IF NOT EXISTS idx_apis_func ON function_apis(func_ea);
CREATE INDEX IF NOT EXISTS idx_apis_name ON function_apis(api_name);
CREATE INDEX IF NOT EXISTS idx_strings_func ON function_strings(func_ea);
CREATE INDEX IF NOT EXISTS idx_strings_text ON function_strings(string_text);
CREATE INDEX IF NOT EXISTS idx_constants_func ON function_constants(func_ea);
CREATE INDEX IF NOT EXISTS idx_constants_val ON function_constants(constant_value);
CREATE INDEX IF NOT EXISTS idx_attrs_segment ON function_attrs(segment);
CREATE INDEX IF NOT EXISTS idx_attrs_entropy ON function_attrs(entropy);
CREATE INDEX IF NOT EXISTS idx_attrs_bb ON function_attrs(bb_count);
CREATE INDEX IF NOT EXISTS idx_attrs_calls ON function_attrs(call_count);
CREATE INDEX IF NOT EXISTS idx_attrs_xor ON function_attrs(xor_count);
CREATE INDEX IF NOT EXISTS idx_attrs_size ON function_attrs(size);
CREATE INDEX IF NOT EXISTS idx_attrs_loops ON function_attrs(has_loops);
CREATE INDEX IF NOT EXISTS idx_attrs_api_count ON function_attrs(api_count);
CREATE INDEX IF NOT EXISTS idx_attrs_string_count ON function_attrs(string_count);
CREATE INDEX IF NOT EXISTS idx_attrs_cyclomatic ON function_attrs(cyclomatic_complexity);
CREATE INDEX IF NOT EXISTS idx_attrs_xrefs_in ON function_attrs(incoming_xrefs);
CREATE INDEX IF NOT EXISTS idx_attrs_xrefs_out ON function_attrs(outgoing_xrefs);
CREATE INDEX IF NOT EXISTS idx_attrs_crypto ON function_attrs(has_crypto_constants);
CREATE INDEX IF NOT EXISTS idx_attrs_xor_ratio ON function_attrs(xor_ratio);
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _db_path(idb_path: str | None = None) -> str:
    """Return the SQLite DB path for the current IDB."""
    if idb_path is None:
        if ida_loader is not None:
            idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
        else:
            idb_path = ""
    if not idb_path:
        idb_path = "unknown"
    base = os.path.splitext(idb_path)[0]
    return f"{base}.schemaboot.db"


def _ensure_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA_SQL)
    conn.commit()


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)


def _extract_function_attributes(func_ea: int) -> dict[str, Any]:
    """Extract deterministic attributes for a single function using only IDA APIs."""
    func = ida_funcs.get_func(func_ea)
    if not func:
        return {}

    start = func.start_ea
    end = func.end_ea
    size = end - start
    name = idc.get_func_name(start) or f"sub_{start:X}"
    seg = idaapi.getseg(start)
    seg_name = ida_segment.get_segm_name(seg) if seg else ""

    # Flags
    flags = func.flags
    is_thunk = 1 if (flags & idaapi.FUNC_THUNK) else 0
    is_library = 1 if (flags & idaapi.FUNC_LIB) else 0

    # Instruction counts
    mnem_counts: Counter = Counter()
    bb_count = 0
    has_loops = 0
    max_loop_depth = 0
    apis: set[str] = set()
    strings: list[tuple[str, int]] = []
    data_refs = 0
    crypto_constants: list[tuple[int, int]] = []  # (value, ea)

    # Known crypto constant values (subset)
    _CRYPTO_CONSTS: dict[int, str] = {
        0x67452301: "MD5_A", 0xEFCDAB89: "MD5_B", 0x98BADCFE: "MD5_C", 0x10325476: "MD5_D",
        0x6A09E667: "SHA256_H0", 0xBB67AE85: "SHA256_H1", 0x3C6EF372: "SHA256_H2",
        0xA54FF53A: "SHA256_H3", 0x510E527F: "SHA256_H4", 0x9B05688C: "SHA256_H5",
        0x1F83D9AB: "SHA256_H6", 0x5BE0CD19: "SHA256_H7",
        0x36E8E8E9: "CRC32", 0x04C11DB7: "CRC32_POLY",
        0xCBF29CE484222325: "FNV_OFFSET", 0x100000001B3: "FNV_PRIME",
    }

    # Walk basic blocks
    import ida_ua
    flow = idaapi.FlowChart(func)
    for block in flow:
        bb_count += 1
        for ea in idautils.Heads(block.start_ea, block.end_ea):
            mnem = idc.print_insn_mnem(ea)
            if not mnem:
                continue
            mnem_l = mnem.lower()
            mnem_counts[mnem_l] += 1

            # API calls via xrefs
            if mnem_l in ("call", "jmp"):
                for xref in idautils.XrefsFrom(ea, 0):
                    if xref.type == idaapi.fl_CN or xref.type == idaapi.fl_CF:
                        tgt_name = idc.get_name(xref.to)
                        if tgt_name:
                            apis.add(tgt_name)

            # String refs via operand xrefs
            for i in range(idaapi.UA_MAXOP):
                op_type = idc.get_operand_type(ea, i)
                if op_type == idc.o_imm:
                    val = idc.get_operand_value(ea, i)
                    s = idc.get_strlit_contents(val)
                    if s:
                        txt = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                        if len(txt) >= 4:
                            strings.append((txt[:256], val))
                    # Check for crypto constants in immediates
                    if val in _CRYPTO_CONSTS:
                        crypto_constants.append((val, ea))

            # Try decoding instruction to check operands for crypto constants
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) > 0:
                for op in insn.ops:
                    if op.type == ida_ua.o_imm:
                        val = op.value
                        if val in _CRYPTO_CONSTS and (val, ea) not in crypto_constants:
                            crypto_constants.append((val, ea))

            # Data refs
            for xref in idautils.XrefsFrom(ea, 0):
                if xref.iscode == 0:
                    data_refs += 1

    # Check for loops via back-edges and compute max loop depth
    for block in flow:
        loop_depth = 0
        for succ in block.succs():
            if succ.start_ea <= block.start_ea:
                has_loops = 1
                # Estimate depth by counting nested conditions
                loop_depth += 1
        max_loop_depth = max(max_loop_depth, loop_depth)

    # Also count structured loop patterns in decompiled output
    try:
        cfunc = ida_hexrays.decompile(start)
        if cfunc:
            pseudo_text = str(cfunc)
            for_pats = len(re.findall(r'\bfor\s*\(', pseudo_text))
            while_pats = len(re.findall(r'\bwhile\s*\(', pseudo_text))
            do_pats = len(re.findall(r'\bdo\s*\{', pseudo_text))
            decompiled_loops = for_pats + while_pats + do_pats
            if decompiled_loops > max_loop_depth:
                max_loop_depth = decompiled_loops
            if decompiled_loops > 0:
                has_loops = 1
    except Exception:
        pass

    # Cyclomatic complexity: E - N + 2P
    edges = sum(len(list(b.succs())) for b in flow)
    cyclomatic = edges - bb_count + 2

    # Xref counts
    incoming = sum(1 for _ in idautils.XrefsTo(start, 0))
    outgoing = sum(1 for _ in idautils.XrefsFrom(start, 0))

    # Entropy
    func_bytes = ida_bytes.get_bytes(start, min(size, 4096))
    entropy = _shannon_entropy(func_bytes) if func_bytes else 0.0

    # Derived metrics
    total_insns = sum(mnem_counts.values())
    xor_ratio = round(mnem_counts.get("xor", 0) / max(1, total_insns), 4)
    has_crypto_constants = 1 if crypto_constants else 0

    return {
        "ea": start,
        "name": name,
        "size": size,
        "segment": seg_name,
        "is_thunk": is_thunk,
        "is_library": is_library,
        "bb_count": bb_count,
        "cyclomatic_complexity": max(1, cyclomatic),
        "incoming_xrefs": incoming,
        "outgoing_xrefs": outgoing,
        "entropy": entropy,
        "call_count": mnem_counts.get("call", 0),
        "xor_count": mnem_counts.get("xor", 0),
        "mov_count": mnem_counts.get("mov", 0) + mnem_counts.get("movzx", 0) + mnem_counts.get("movsx", 0),
        "cmp_count": mnem_counts.get("cmp", 0),
        "jmp_count": mnem_counts.get("jmp", 0) + mnem_counts.get("je", 0) + mnem_counts.get("jne", 0) + mnem_counts.get("jz", 0) + mnem_counts.get("jnz", 0),
        "ret_count": mnem_counts.get("ret", 0) + mnem_counts.get("retn", 0),
        "push_count": mnem_counts.get("push", 0),
        "pop_count": mnem_counts.get("pop", 0),
        "lea_count": mnem_counts.get("lea", 0),
        "test_count": mnem_counts.get("test", 0),
        "api_count": len(apis),
        "string_count": len(strings),
        "data_ref_count": data_refs,
        "has_loops": has_loops,
        "max_loop_depth": max_loop_depth,
        "has_crypto_constants": has_crypto_constants,
        "xor_ratio": xor_ratio,
        "apis": sorted(apis),
        "strings": strings,
        "crypto_constants": crypto_constants,
    }


def _upsert_function(conn: sqlite3.Connection, attrs: dict[str, Any]) -> None:
    """Insert or update a function's attributes in the database."""
    now = time.time()
    cursor = conn.cursor()

    # Upsert main attrs
    cursor.execute(
        """
        INSERT INTO function_attrs
        (ea, name, size, segment, is_thunk, is_library, bb_count, cyclomatic_complexity,
         incoming_xrefs, outgoing_xrefs, entropy, call_count, xor_count, mov_count,
         cmp_count, jmp_count, ret_count, push_count, pop_count, lea_count, test_count,
         api_count, string_count, data_ref_count, has_loops, max_loop_depth,
         has_crypto_constants, xor_ratio, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ea) DO UPDATE SET
        name=excluded.name, size=excluded.size, segment=excluded.segment,
        is_thunk=excluded.is_thunk, is_library=excluded.is_library,
        bb_count=excluded.bb_count, cyclomatic_complexity=excluded.cyclomatic_complexity,
        incoming_xrefs=excluded.incoming_xrefs, outgoing_xrefs=excluded.outgoing_xrefs,
        entropy=excluded.entropy, call_count=excluded.call_count, xor_count=excluded.xor_count,
        mov_count=excluded.mov_count, cmp_count=excluded.cmp_count, jmp_count=excluded.jmp_count,
        ret_count=excluded.ret_count, push_count=excluded.push_count, pop_count=excluded.pop_count,
        lea_count=excluded.lea_count, test_count=excluded.test_count, api_count=excluded.api_count,
        string_count=excluded.string_count, data_ref_count=excluded.data_ref_count,
        has_loops=excluded.has_loops, max_loop_depth=excluded.max_loop_depth,
        has_crypto_constants=excluded.has_crypto_constants, xor_ratio=excluded.xor_ratio,
        updated_at=excluded.updated_at
        """,
        (
            attrs["ea"], attrs["name"], attrs["size"], attrs["segment"],
            attrs["is_thunk"], attrs["is_library"], attrs["bb_count"],
            attrs["cyclomatic_complexity"], attrs["incoming_xrefs"],
            attrs["outgoing_xrefs"], attrs["entropy"], attrs["call_count"],
            attrs["xor_count"], attrs["mov_count"], attrs["cmp_count"],
            attrs["jmp_count"], attrs["ret_count"], attrs["push_count"],
            attrs["pop_count"], attrs["lea_count"], attrs["test_count"],
            attrs["api_count"], attrs["string_count"], attrs["data_ref_count"],
            attrs["has_loops"], attrs.get("max_loop_depth", 0),
            attrs.get("has_crypto_constants", 0), attrs.get("xor_ratio", 0.0),
            now, now,
        ),
    )

    # Delete old junction data and re-insert
    cursor.execute("DELETE FROM function_apis WHERE func_ea=?", (attrs["ea"],))
    cursor.execute("DELETE FROM function_strings WHERE func_ea=?", (attrs["ea"],))
    cursor.execute("DELETE FROM function_constants WHERE func_ea=?", (attrs["ea"],))

    for api in attrs.get("apis", []):
        cursor.execute("INSERT INTO function_apis (func_ea, api_name) VALUES (?, ?)", (attrs["ea"], api))

    for txt, ea in attrs.get("strings", []):
        cursor.execute("INSERT INTO function_strings (func_ea, string_text, string_ea) VALUES (?, ?, ?)", (attrs["ea"], txt, ea))

    for const_val, const_ea in attrs.get("crypto_constants", []):
        name = ""
        cursor.execute(
            "INSERT INTO function_constants (func_ea, constant_value, constant_name) VALUES (?, ?, ?)",
            (attrs["ea"], const_val, name),
        )

    conn.commit()


# ---------------------------------------------------------------------------
# L1 / L2 Integration Helpers
# ---------------------------------------------------------------------------

def _cache_dir() -> str:
    """Return the host cache directory (same logic as host/config.py)."""
    explicit = os.environ.get("IDA_MCP_CACHE_DIR") or os.environ.get("IDA_MCP_DATA_DIR")
    if explicit:
        return os.path.realpath(os.path.expanduser(explicit))
    return os.path.realpath(os.path.join(os.path.expanduser("~"), ".local", "state", "ida-pro-mcp"))


def _insight_index_path() -> str:
    return os.path.join(_cache_dir(), "insight_index.json")


def _global_facts_db_path() -> str:
    return os.path.join(_cache_dir(), "global_facts.db")


def _detect_behavior_tags(attrs: dict[str, Any]) -> list[str]:
    """Infer behavior tags from function attributes."""
    tags: list[str] = []
    apis = set(attrs.get("apis", []))
    strings = [s[0].lower() for s in attrs.get("strings", [])]
    name = attrs.get("name", "").lower()

    if any(a in apis for a in ("CryptEncrypt", "CryptDecrypt", "AES", "RSA", "DES", "Blowfish", "ChaCha20", "RC4", "SHA1", "SHA256", "MD5", "hash")):
        tags.append("crypto")
    if any(a in apis for a in ("socket", "connect", "recv", "send", "WSAStartup", "gethostbyname", "inet_addr", "InternetOpen", "HttpSendRequest")):
        tags.append("network")
    if any(a in apis for a in ("CreateFile", "ReadFile", "WriteFile", "fopen", "fread", "fwrite", "open", "read", "write")):
        tags.append("file_io")
    if any(a in apis for a in ("RegOpenKeyEx", "RegQueryValueEx", "RegSetValueEx", "RegCreateKeyEx")):
        tags.append("registry")
    if any(a in apis for a in ("CreateProcess", "OpenProcess", "VirtualAlloc", "VirtualProtect", "NtCreateThread", "exec", "system", "WinExec")):
        tags.append("process")
    if any(a in apis for a in ("strcpy", "strncpy", "memcpy", "memmove", "sprintf", "snprintf", "MultiByteToWideChar", "WideCharToMultiByte")):
        tags.append("string_decode")
    if any(a in apis for a in ("malloc", "calloc", "realloc", "free", "HeapAlloc", "HeapFree", "LocalAlloc", "GlobalAlloc")):
        tags.append("allocator")
    if any(a in apis for a in ("SetUnhandledExceptionFilter", "RtlAddVectoredExceptionHandler", "__C_specific_handler")):
        tags.append("exception_handler")
    if attrs.get("has_loops", 0):
        tags.append("loop")
    if attrs.get("is_thunk", 0):
        tags.append("thunk")
    if attrs.get("is_library", 0):
        tags.append("library")
    if name in ("main", "wmain", "winmain", "wWinMain"):
        tags.append("main")
    if "init" in name or "constructor" in name or "_init" in name:
        tags.append("init")
    if "deinit" in name or "destructor" in name or "_fini" in name:
        tags.append("cleanup")
    entropy = float(attrs.get("entropy", 0.0) or 0.0)
    xor_count = float(attrs.get("xor_count", 0) or 0)
    mov_count = float(attrs.get("mov_count", 0) or 0)
    cmp_count = float(attrs.get("cmp_count", 0) or 0)
    loop_bias = 0.08 if int(attrs.get("has_loops", 0) or 0) else 0.0
    xor_ratio = xor_count / max(1.0, xor_count + mov_count + cmp_count)
    entropy_norm = max(0.0, min(1.0, entropy / 8.0))
    signal = (entropy_norm * 0.62) + (xor_ratio * 0.30) + loop_bias
    if signal >= 0.5:
        tags.append("obfuscation")
    return tags


def _detect_global_facts(attrs: dict[str, Any]) -> list[tuple[str, str, str, float]]:
    """Detect global facts from function attributes. Returns list of (category, key, value, confidence)."""
    facts: list[tuple[str, str, str, float]] = []
    apis = set(attrs.get("apis", []))
    name = attrs.get("name", "")

    # Compiler signatures
    if name in ("__libc_start_main", "__libc_csu_init"):
        facts.append(("compiler_signature", "gcc_main", "GCC CRT startup function detected", 0.90))
    if name in ("_initterm", "_initterm_e", "__security_init_cookie"):
        facts.append(("compiler_signature", "msvc_rtl", "MSVC RTL initialization pattern", 0.85))
    if "__clang" in name:
        facts.append(("compiler_signature", "clang_ctor", "LLVM/Clang constructor pattern", 0.80))

    # Common APIs
    for api in apis:
        if api in ("VirtualAlloc", "VirtualAllocEx", "HeapAlloc", "LocalAlloc", "GlobalAlloc", "malloc", "calloc"):
            facts.append(("common_api", api, f"{api} allocator usage", 0.95))
        if api in ("strcpy", "strncpy", "memcpy", "sprintf", "gets"):
            facts.append(("common_api", api, f"{api} potential sink", 0.90))
        if api in ("CryptEncrypt", "CryptDecrypt", "CryptHashData"):
            facts.append(("common_api", api, f"{api} Windows crypto API", 0.95))
        if api in ("RegOpenKeyEx", "RegQueryValueEx", "RegSetValueEx"):
            facts.append(("common_api", api, f"{api} registry API", 0.95))
        if api in ("CreateFileW", "CreateFileA", "ReadFile", "WriteFile"):
            facts.append(("common_api", api, f"{api} file I/O API", 0.95))
        if api in ("socket", "connect", "recv", "send", "WSAStartup"):
            facts.append(("common_api", api, f"{api} network API", 0.95))

    # Calling convention hints (x64)
    if attrs.get("size", 0) > 0:
        # This is a heuristic — real detection requires architecture info
        pass

    return facts


def _write_insight_index(func_attrs_list: list[dict[str, Any]]) -> None:
    """Rebuild the L1 insight index JSON from ingested function attributes."""
    path = _insight_index_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tag_map: dict[str, list[str]] = {}
    func_map: dict[str, dict[str, Any]] = {}

    for attrs in func_attrs_list:
        addr = hex(attrs["ea"])
        tags = _detect_behavior_tags(attrs)
        meta = {
            "addr": addr,
            "name": attrs.get("name", ""),
            "tier": "L2" if _detect_global_facts(attrs) else "L1",
            "target_id": "",
            "tags": tags,
            "indexed_at": time.time(),
            "access_count": 0,
        }
        func_map[addr] = meta
        for tag in tags:
            tag = tag.lower()
            if addr not in tag_map.get(tag, []):
                tag_map.setdefault(tag, []).append(addr)

    payload = {
        "func_map": func_map,
        "tag_map": tag_map,
        "saved_at": time.time(),
    }
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _add_global_facts(facts: list[tuple[str, str, str, float]]) -> None:
    """Write detected facts to the L2 global facts SQLite DB."""
    if not facts:
        return
    db_path = _global_facts_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS global_facts (
                fact_id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                fact_key TEXT NOT NULL,
                fact_value TEXT NOT NULL,
                confidence REAL DEFAULT 0.5,
                source TEXT DEFAULT '',
                timestamp REAL NOT NULL,
                access_count INTEGER DEFAULT 0,
                last_accessed REAL DEFAULT 0.0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_facts_category ON global_facts(category)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_facts_key ON global_facts(fact_key)")
        now = time.time()
        for category, key, value, confidence in facts:
            fact_id = f"fact_{hashlib.sha256((category + ':' + key).encode()).hexdigest()[:16]}"
            conn.execute("""
                INSERT OR REPLACE INTO global_facts
                (fact_id, category, fact_key, fact_value, confidence, source, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (fact_id, category, key, value, confidence, "schemaboot", now))
        conn.commit()
        conn.close()
    except Exception:
        pass


def _build_where_clause(constraints: dict[str, Any]) -> tuple[str, list[Any]]:
    """Build SQL WHERE clause from structured constraints.
    
    Supports legacy format (min_size, max_size, apis, etc.) and
    operator format ({"size": (">=", 100), "name": ("~", "pattern")}).
    """
    conditions: list[str] = []
    params: list[Any] = []

    # Try operator format first: value is (op, val) tuple
    operator_format = any(
        isinstance(v, (list, tuple)) and len(v) == 2 and str(v[0]) in ("==", "!=", "<", ">", "<=", ">=", "contains", "~")
        for v in constraints.values()
    )

    if operator_format:
        # Route through hybrid search query builder
        from .hybrid_search import HybridQueryBuilder
        where_clause, wc_params, _ = HybridQueryBuilder.build(constraints, table_alias="function_attrs")
        if where_clause:
            # Strip the "WHERE " prefix added by HybridQueryBuilder
            where_clause = where_clause.replace("WHERE ", "", 1) if where_clause.startswith("WHERE ") else where_clause
            return where_clause, wc_params
        return "", []

    # Legacy format handling
    for key, val in constraints.items():
        if val is None:
            continue
        if key == "apis":
            conditions.append(
                "EXISTS (SELECT 1 FROM function_apis WHERE function_apis.func_ea = function_attrs.ea AND function_apis.api_name = ?)"
            )
            params.append(val)
        elif key == "strings_like":
            conditions.append(
                "EXISTS (SELECT 1 FROM function_strings WHERE function_strings.func_ea = function_attrs.ea AND function_strings.string_text LIKE ?)"
            )
            params.append(f"%{val}%")
        elif key == "string_contains":
            conditions.append(
                "EXISTS (SELECT 1 FROM function_strings WHERE function_strings.func_ea = function_attrs.ea AND function_strings.string_text LIKE ?)"
            )
            params.append(f"%{val}%")
        elif key == "name_like":
            conditions.append("name LIKE ?")
            params.append(f"%{val}%")
        elif key == "segment":
            conditions.append("segment = ?")
            params.append(val)
        elif key == "min_size":
            conditions.append("size >= ?")
            params.append(int(val))
        elif key == "max_size":
            conditions.append("size <= ?")
            params.append(int(val))
        elif key == "min_entropy":
            conditions.append("entropy >= ?")
            params.append(float(val))
        elif key == "max_entropy":
            conditions.append("entropy <= ?")
            params.append(float(val))
        elif key == "min_bb_count":
            conditions.append("bb_count >= ?")
            params.append(int(val))
        elif key == "max_bb_count":
            conditions.append("bb_count <= ?")
            params.append(int(val))
        elif key == "has_loops":
            conditions.append("has_loops = ?")
            params.append(1 if val else 0)
        elif key == "has_crypto_constants":
            conditions.append("has_crypto_constants = ?")
            params.append(1 if val else 0)
        elif key == "is_thunk":
            conditions.append("is_thunk = ?")
            params.append(1 if val else 0)
        elif key == "is_library":
            conditions.append("is_library = ?")
            params.append(1 if val else 0)
        elif key == "min_api_count":
            conditions.append("api_count >= ?")
            params.append(int(val))
        elif key == "min_string_count":
            conditions.append("string_count >= ?")
            params.append(int(val))
        elif key == "min_xor_count":
            conditions.append("xor_count >= ?")
            params.append(int(val))
        elif key == "min_call_count":
            conditions.append("call_count >= ?")
            params.append(int(val))
        elif key == "min_cyclomatic":
            conditions.append("cyclomatic_complexity >= ?")
            params.append(int(val))
        elif key == "max_cyclomatic":
            conditions.append("cyclomatic_complexity <= ?")
            params.append(int(val))
        elif key == "min_data_ref_count":
            conditions.append("data_ref_count >= ?")
            params.append(int(val))
        elif key == "min_xor_ratio":
            conditions.append("xor_ratio >= ?")
            params.append(float(val))
        elif key == "max_xor_ratio":
            conditions.append("xor_ratio <= ?")
            params.append(float(val))
        elif key == "min_max_loop_depth":
            conditions.append("max_loop_depth >= ?")
            params.append(int(val))
        elif key == "addr":
            ea, err = validate_addr(val)
            if err:
                continue
            conditions.append("ea = ?")
            params.append(ea)

    if conditions:
        return "WHERE " + " AND ".join(conditions), params
    return "", []


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

@tool
@idaread
def schemaboot(
    action: Annotated[Literal["ingest", "query", "refresh", "stats", "delete", "get"], "SchemaBoot action"],
    constraints: Annotated[Optional[dict], "Structured query constraints for 'query' action"] = None,
    addr: Annotated[Optional[str], "Function address for 'get' or 'refresh'"] = None,
    limit: Annotated[int, "Max results"] = 50,
    offset: Annotated[int, "Skip first N results"] = 0,
    order_by: Annotated[Optional[str], "Column to order by (e.g., 'entropy DESC', 'size ASC')"] = None,
    include_apis: Annotated[bool, "Include API list in results"] = False,
    include_strings: Annotated[bool, "Include string refs in results"] = False,
    **kwargs
) -> dict:
    """
    Deterministic function attribute extraction and structured search.

    Actions:
    - ingest: Walk all functions and build the SQLite attribute index.
      This is a one-time cost per binary. Subsequent queries are instant.
    - query: Structured SQL-style filtering using constraints dict.
      Supported constraints:
        apis (str): function calls this API
        strings_like (str): function references a string containing this text
        name_like (str): function name contains this text
        segment (str): function is in this segment
        min_size, max_size (int): function size bounds
        min_entropy, max_entropy (float): byte entropy bounds
        min_bb_count, max_bb_count (int): basic block count bounds
        has_loops (bool): function contains a loop
        is_thunk (bool): function is a thunk
        is_library (bool): function is a library function
        min_api_count (int): minimum number of APIs called
        min_string_count (int): minimum number of string refs
        min_xor_count (int): minimum XOR instructions
        min_call_count (int): minimum CALL instructions
        min_cyclomatic (int): minimum cyclomatic complexity
        addr (str): exact function address
    - refresh: Re-extract attributes for a single function (or all if no addr).
    - stats: Show index statistics (total functions, coverage, etc.).
    - delete: Delete the index database for this binary.
    - get: Get full attributes for a single function by addr.

    Example:
        schemaboot(action="ingest")
        schemaboot(action="query", constraints={"apis": "VirtualAlloc", "has_loops": True}, limit=10)
        schemaboot(action="query", constraints={"min_entropy": 6.5, "min_xor_count": 4})
        schemaboot(action="stats")
    """
    db_path = _db_path()

    try:
        if action == "delete":
            if os.path.exists(db_path):
                os.remove(db_path)
                return {"ok": True, "deleted": db_path}
            return make_error(MCPError.FILE_NOT_FOUND, f"No index found at {db_path}")

        if action == "ingest":
            conn = sqlite3.connect(db_path)
            _ensure_tables(conn)

            funcs = list(idautils.Functions())
            total = len(funcs)
            ingested = 0
            start_time = time.time()
            all_attrs: list[dict[str, Any]] = []
            all_facts: list[tuple[str, str, str, float]] = []

            for func_ea in funcs:
                attrs = _extract_function_attributes(func_ea)
                if attrs:
                    _upsert_function(conn, attrs)
                    all_attrs.append(attrs)
                    all_facts.extend(_detect_global_facts(attrs))
                    ingested += 1

            elapsed = round(time.time() - start_time, 2)
            conn.close()

            # Update L1 insight index
            _write_insight_index(all_attrs)
            # Update L2 global facts
            _add_global_facts(all_facts)

            return {
                "ok": True,
                "action": "ingest",
                "total_functions": total,
                "ingested": ingested,
                "db_path": db_path,
                "elapsed_seconds": elapsed,
                "l1_indexed": len(all_attrs),
                "l2_facts_added": len(all_facts),
            }

        if action == "refresh":
            conn = sqlite3.connect(db_path)
            _ensure_tables(conn)

            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                attrs = _extract_function_attributes(ea)
                if attrs:
                    _upsert_function(conn, attrs)
                    conn.close()
                    # Update L1 / L2 for single function
                    _write_insight_index([attrs])
                    _add_global_facts(_detect_global_facts(attrs))
                    return {"ok": True, "refreshed": 1, "ea": hex(ea)}
                return make_error(MCPError.ADDRESS_INVALID, "Failed to extract attributes")
            else:
                # Refresh all
                return schemaboot(action="ingest")

        if action == "stats":
            if not os.path.exists(db_path):
                return make_error(MCPError.FILE_NOT_FOUND, "No index found. Run schemaboot(action='ingest') first.")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM function_attrs")
            total_indexed = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT func_ea) FROM function_apis")
            funcs_with_apis = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT func_ea) FROM function_strings")
            funcs_with_strings = cursor.fetchone()[0]

            cursor.execute("SELECT AVG(size), AVG(entropy), AVG(bb_count), AVG(cyclomatic_complexity) FROM function_attrs")
            avg_size, avg_entropy, avg_bb, avg_cc = cursor.fetchone()

            cursor.execute("SELECT segment, COUNT(*) FROM function_attrs GROUP BY segment")
            segments = {row[0]: row[1] for row in cursor.fetchall()}

            conn.close()
            return {
                "ok": True,
                "db_path": db_path,
                "total_indexed": total_indexed,
                "funcs_with_apis": funcs_with_apis,
                "funcs_with_strings": funcs_with_strings,
                "avg_size": round(avg_size or 0, 1),
                "avg_entropy": round(avg_entropy or 0, 2),
                "avg_bb_count": round(avg_bb or 0, 1),
                "avg_cyclomatic": round(avg_cc or 0, 1),
                "segments": segments,
            }

        if action == "get":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for get")
            ea, err = validate_addr(addr)
            if err:
                return err

            if not os.path.exists(db_path):
                return make_error(MCPError.FILE_NOT_FOUND, "No index found")

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM function_attrs WHERE ea=?", (ea,))
            row = cursor.fetchone()
            if not row:
                conn.close()
                return make_error(MCPError.NOT_FOUND, f"Function {addr} not in index")

            cols = [d[0] for d in cursor.description]
            result = dict(zip(cols, row))

            if include_apis:
                cursor.execute("SELECT api_name FROM function_apis WHERE func_ea=?", (ea,))
                result["apis"] = [r[0] for r in cursor.fetchall()]
            if include_strings:
                cursor.execute("SELECT string_text, string_ea FROM function_strings WHERE func_ea=?", (ea,))
                result["strings"] = [{"text": r[0], "ea": hex(r[1])} for r in cursor.fetchall()]

            conn.close()
            # Convert ea to hex
            result["ea"] = hex(result["ea"])
            return {"ok": True, "function": result}

        if action == "query":
            if not os.path.exists(db_path):
                return make_error(MCPError.FILE_NOT_FOUND, "No index found. Run schemaboot(action='ingest') first.")

            # Extract semantic query terms from constraints for Phase 2 BM25 rerank
            _query_apis: list = []
            _query_strings: list = []
            if isinstance(constraints, dict):
                if "apis" in constraints:
                    _query_apis = [constraints["apis"]] if isinstance(constraints["apis"], str) else list(constraints["apis"])
                if "strings_like" in constraints or "string_contains" in constraints:
                    v = constraints.get("strings_like") or constraints.get("string_contains")
                    if v:
                        _query_strings = [v]

            # Use HybridSearchEngine for Phase 1 + Phase 2 BM25 when we have semantic terms
            if _query_apis or _query_strings:
                try:
                    from .hybrid_search import HybridSearchEngine
                    engine = HybridSearchEngine(db_path)
                    ranked = engine.search_ranked(
                        constraints or {},
                        query_apis=_query_apis or None,
                        query_strings=_query_strings or None,
                        top_k=limit,
                        bm25_weight=0.4,
                    )
                    if ranked.get("ok"):
                        cands = ranked.get("candidates") or []
                        # Map to schemaboot response format
                        results = []
                        for c in cands[offset:offset + limit]:
                            d = {k: v for k, v in c.items() if not k.startswith("_")}
                            d.setdefault("has_loops", bool(d.get("has_loops", False)))
                            results.append(d)
                        return {
                            "ok": True,
                            "total_matches": ranked.get("total_matches", len(results)),
                            "returned": len(results),
                            "offset": offset,
                            "limit": limit,
                            "phase": ranked.get("phase", "sql+bm25"),
                            "functions": results,
                        }
                except Exception:
                    pass  # fall through to original implementation

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            where_clause, params = _build_where_clause(constraints or {})

            order_clause = ""
            if order_by:
                # Sanitize: only allow known column names and ASC/DESC
                allowed_cols = {
                    "ea", "name", "size", "segment", "entropy", "bb_count",
                    "cyclomatic_complexity", "incoming_xrefs", "outgoing_xrefs",
                    "call_count", "xor_count", "api_count", "string_count",
                    "created_at", "updated_at",
                }
                parts = order_by.strip().split()
                col = parts[0]
                direction = parts[1].upper() if len(parts) > 1 else "ASC"
                if col in allowed_cols and direction in ("ASC", "DESC"):
                    order_clause = f"ORDER BY {col} {direction}"

            count_sql = f"SELECT COUNT(*) FROM function_attrs {where_clause}"
            cursor.execute(count_sql, params)
            total_matches = cursor.fetchone()[0]

            sql = f"""
                SELECT ea, name, size, segment, entropy, bb_count,
                       cyclomatic_complexity, incoming_xrefs, outgoing_xrefs,
                       call_count, xor_count, api_count, string_count, has_loops
                FROM function_attrs
                {where_clause}
                {order_clause}
                LIMIT ? OFFSET ?
            """
            cursor.execute(sql, params + [limit, offset])

            rows = cursor.fetchall()
            results = []
            for row in rows:
                d = {
                    "ea": hex(row[0]),
                    "name": row[1],
                    "size": row[2],
                    "segment": row[3],
                    "entropy": row[4],
                    "bb_count": row[5],
                    "cyclomatic_complexity": row[6],
                    "incoming_xrefs": row[7],
                    "outgoing_xrefs": row[8],
                    "call_count": row[9],
                    "xor_count": row[10],
                    "api_count": row[11],
                    "string_count": row[12],
                    "has_loops": bool(row[13]),
                }
                if include_apis:
                    cursor.execute("SELECT api_name FROM function_apis WHERE func_ea=?", (row[0],))
                    d["apis"] = [r[0] for r in cursor.fetchall()]
                if include_strings:
                    cursor.execute("SELECT string_text, string_ea FROM function_strings WHERE func_ea=?", (row[0],))
                    d["strings"] = [{"text": r[0], "ea": hex(r[1])} for r in cursor.fetchall()]
                results.append(d)

            conn.close()
            return {
                "ok": True,
                "total_matches": total_matches,
                "returned": len(results),
                "offset": offset,
                "limit": limit,
                "functions": results,
            }

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except sqlite3.Error as e:
        return make_error(MCPError.DB_ERROR, f"SQLite error: {e}")
    except Exception as e:
        return handle_error(e)
