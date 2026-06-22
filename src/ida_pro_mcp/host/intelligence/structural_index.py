"""StructuralIndex - Rebuilt, optimized, host-side function attribute index for SchemaBoot.

Handles SQLite storage, queries, and batch transactions.
Offloads execution from IDA's thread and executes queries on the host.
"""

from __future__ import annotations

import os
import time
import sqlite3
import hashlib
import json
from typing import Any, Optional

# Re-use safety paths and validation from config/policy
from ..config import CACHE_DIR
from ..errors import MCPError, make_error

# SQLite Schema Definition
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
    cfg_hash TEXT,
    reconstructed_structs TEXT,
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
CREATE INDEX IF NOT EXISTS idx_attrs_cfg ON function_attrs(cfg_hash);
"""


def get_db_path(idb_path: str) -> str:
    """Return the SQLite DB path for the given IDB path."""
    if not idb_path:
        idb_path = "unknown"
    base = os.path.splitext(idb_path)[0]
    primary_path = f"{base}.schemaboot.db"
    
    # Check if primary path directory is writable
    db_dir = os.path.dirname(os.path.abspath(primary_path))
    if os.path.isdir(db_dir) and os.access(db_dir, os.W_OK):
        return primary_path
    elif not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
            return primary_path
        except (OSError, PermissionError):
            pass
            
    # Fallback path inside CACHE_DIR
    h = hashlib.sha256(os.path.abspath(primary_path).encode("utf-8")).hexdigest()[:16]
    fallback_dir = os.path.join(CACHE_DIR, "fallback_indexes")
    os.makedirs(fallback_dir, exist_ok=True)
    return os.path.join(fallback_dir, f"{h}.schemaboot.db")


def ensure_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA_SQL)
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(function_attrs)")
        columns = [row[1] for row in cursor.fetchall()]
        if "cfg_hash" not in columns:
            cursor.execute("ALTER TABLE function_attrs ADD COLUMN cfg_hash TEXT")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_attrs_cfg ON function_attrs(cfg_hash)")
            conn.commit()
        if "reconstructed_structs" not in columns:
            cursor.execute("ALTER TABLE function_attrs ADD COLUMN reconstructed_structs TEXT")
            conn.commit()
    except Exception:
        pass
    conn.commit()


def _detect_behavior_tags(attrs: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    apis = set(attrs.get("apis", []))
    [s[0].lower() for s in attrs.get("strings", [])] if isinstance(attrs.get("strings"), list) else []
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
    facts: list[tuple[str, str, str, float]] = []
    apis = set(attrs.get("apis", []))
    name = attrs.get("name", "")

    if name in ("__libc_start_main", "__libc_csu_init"):
        facts.append(("compiler_signature", "gcc_main", "GCC CRT startup function detected", 0.90))
    if name in ("_initterm", "_initterm_e", "__security_init_cookie"):
        facts.append(("compiler_signature", "msvc_rtl", "MSVC RTL initialization pattern", 0.85))
    if "__clang" in name:
        facts.append(("compiler_signature", "clang_ctor", "LLVM/Clang constructor pattern", 0.80))

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

    return facts


def write_insight_index(func_attrs_list: list[dict[str, Any]]) -> None:
    path = os.path.join(CACHE_DIR, "insight_index.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tag_map: dict[str, list[str]] = {}
    func_map: dict[str, dict[str, Any]] = {}

    for attrs in func_attrs_list:
        addr = hex(attrs["ea"]) if isinstance(attrs["ea"], int) else str(attrs["ea"])
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


def add_global_facts(facts: list[tuple[str, str, str, float]]) -> None:
    if not facts:
        return
    db_path = os.path.join(CACHE_DIR, "global_facts.db")
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


def upsert_functions_batch(conn: sqlite3.Connection, attrs_list: list[dict[str, Any]]) -> int:
    """Insert or update multiple functions inside a single, fast batch transaction."""
    now = time.time()
    cursor = conn.cursor()
    count = 0

    # Ensure transaction
    with conn:
        for attrs in attrs_list:
            structs_json = None
            if "reconstructed_structs" in attrs:
                try:
                    structs_json = json.dumps(attrs["reconstructed_structs"])
                except Exception:
                    pass
            cursor.execute(
                """
                INSERT INTO function_attrs
                (ea, name, size, segment, is_thunk, is_library, bb_count, cyclomatic_complexity,
                 incoming_xrefs, outgoing_xrefs, entropy, call_count, xor_count, mov_count,
                 cmp_count, jmp_count, ret_count, push_count, pop_count, lea_count, test_count,
                 api_count, string_count, data_ref_count, has_loops, max_loop_depth,
                 has_crypto_constants, xor_ratio, cfg_hash, reconstructed_structs, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                cfg_hash=excluded.cfg_hash, reconstructed_structs=excluded.reconstructed_structs, updated_at=excluded.updated_at
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
                    attrs.get("cfg_hash"), structs_json, now, now,
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
                cursor.execute(
                    "INSERT INTO function_constants (func_ea, constant_value, constant_name) VALUES (?, ?, ?)",
                    (attrs["ea"], const_val, ""),
                )
            count += 1

    return count


def execute_host_query(db_path: str, constraints: dict, limit: int = 50, offset: int = 0, order_by: Optional[str] = None, include_apis: bool = False, include_strings: bool = False) -> dict:
    """Execute SQLite structured query directly on the host, bypassing IDA entirely."""
    if not os.path.exists(db_path):
        return make_error(MCPError.FILE_NOT_FOUND, "No index found. Ingest the session first.")

    # 1. Check if semantic terms exist (BM25 rerank via HybridSearchEngine)
    _query_apis: list = []
    _query_strings: list = []
    if isinstance(constraints, dict):
        if "apis" in constraints:
            _query_apis = [constraints["apis"]] if isinstance(constraints["apis"], str) else list(constraints["apis"])
        if "strings_like" in constraints or "string_contains" in constraints:
            v = constraints.get("strings_like") or constraints.get("string_contains")
            if v:
                _query_strings = [v]

    if _query_apis or _query_strings:
        try:
            from .bridge_retrieval import HybridSearchEngine
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
            pass  # fall through to direct SQL query

    # 2. Direct SQL Query
    try:
        from ..support.hybrid_search import HybridQueryBuilder
    except ImportError:
        from support.hybrid_search import HybridQueryBuilder

    normalized = dict(constraints or {})
    # Extract exact address mapping
    addr = normalized.pop("addr", None)
    if addr is not None:
        try:
            normalized["ea"] = int(addr, 0) if isinstance(addr, str) else addr
        except ValueError:
            pass

    where_clause, params = HybridQueryBuilder.build_legacy(normalized)

    order_clause = ""
    if order_by:
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

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Get count
        count_sql = f"SELECT COUNT(*) FROM function_attrs {where_clause}"
        cursor.execute(count_sql, params)
        total_matches = cursor.fetchone()[0]

        # Get rows
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
    except Exception as e:
        return make_error(MCPError.DB_ERROR, f"SQLite query error: {e}")
