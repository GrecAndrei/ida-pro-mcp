#!/usr/bin/env python3
"""
Smart pattern matching: regex auto-detection, glob, semantic/fuzzy search.
No IDA dependencies — safe to import from both host and runtime.
"""
import contextlib
import fnmatch
import os
import re
import time
from functools import lru_cache
from typing import Any

_SEMANTIC_CANONICALS = {
    "find": "search",
    "lookup": "search",
    "locate": "search",
    "discover": "search",
    "query": "search",
    "match": "search",
    "decompiler": "decompile",
    "decompiled": "decompile",
    "pseudocode": "decompile",
    "pseudo": "decompile",
    "pcode": "decompile",
    "hexrays": "decompile",
    "ctree": "decompile",
    "routine": "function",
    "procedure": "function",
    "proc": "function",
    "method": "function",
    "subroutine": "function",
    "global": "data",
    "variable": "data",
    "memory": "data",
    "xref": "reference",
    "ref": "reference",
    "refs": "reference",
    "callsite": "reference",
    "caller": "reference",
    "callee": "reference",
    "literal": "string",
    "text": "string",
    "api": "import",
    "symbol": "import",
    "extern": "import",
}

_SEMANTIC_SINGLE_TOKEN_MIN_LEN = 5
_SEMANTIC_FUZZY_CUTOFF = 0.86
_SEMANTIC_CAMEL_BOUNDARY_1 = re.compile(r"([a-z])([A-Z])")
_SEMANTIC_CAMEL_BOUNDARY_2 = re.compile(r"([A-Z]+)([A-Z][a-z])")

_SMART_MATCH_MODE = (
    str(os.environ.get("IDA_MCP_SMART_MATCH_MODE", "balanced")).strip().lower()
)
if _SMART_MATCH_MODE not in {"off", "conservative", "balanced", "aggressive"}:
    _SMART_MATCH_MODE = "balanced"

_SMART_MATCH_MODE_DEFAULTS = {
    "off": {"semantic_enabled": False, "fuzzy_cutoff": 1.0},
    "conservative": {"semantic_enabled": True, "fuzzy_cutoff": 0.92},
    "balanced": {"semantic_enabled": True, "fuzzy_cutoff": _SEMANTIC_FUZZY_CUTOFF},
    "aggressive": {"semantic_enabled": True, "fuzzy_cutoff": 0.80},
}


def _adaptive_fuzzy_cutoff(pattern: str, mode_default: float) -> float:
    """
    Derive fuzzy cutoff from query complexity/profile instead of fixed constants.
    Higher-specificity queries get stricter cutoffs; short/noisy queries get looser.
    """
    toks = _semantic_tokenize(pattern)
    if not toks:
        return float(mode_default)
    uniq = len(set(toks))
    avg_len = sum(len(t) for t in toks) / max(1, len(toks))
    has_path_chars = bool(re.search(r"[./\\:_-]", str(pattern or "")))
    # Specificity signal in [0,1].
    spec = (
        min(1.0, uniq / max(1.0, uniq + 2.0))
        + min(1.0, avg_len / 10.0)
        + (0.15 if has_path_chars else 0.0)
    ) / 2.15
    # Map specificity to dynamic cutoff band and blend with mode default.
    dynamic = 0.74 + (spec * 0.24)
    blended = (float(mode_default) * 0.6) + (dynamic * 0.4)
    return max(0.6, min(0.99, blended))


def _resolve_optional_param(provided, default):
    return default if provided is None else provided


def _normalize_semantic_token(token: str) -> str:
    tok = token.lower().strip()
    if not tok:
        return tok
    # Words ending in "-sis" (analysis, synthesis, basis): the trailing 's' is
    # part of the root, so stripping it leaves a mangled "analysi".  Strip
    # "is" instead to reach the clean stem "analys".
    if len(tok) > 4 and tok.endswith("sis"):
        return _SEMANTIC_CANONICALS.get(tok[:-2], tok[:-2])
    # Strip plurals ("es"/"s") BEFORE agent-noun suffixes ("ers"/"er") so
    # "decompilers" becomes "decompiler" (a canonical key → "decompile")
    # rather than "decompil", which is not in _SEMANTIC_CANONICALS.
    for suffix in ("ing", "ies", "ied", "es", "s", "ers", "er", "ed"):
        if len(tok) > 4 and tok.endswith(suffix):
            tok = tok[:-3] + "y" if suffix in ("ies", "ied") else tok[:-len(suffix)]
            break
    return _SEMANTIC_CANONICALS.get(tok, tok)


def _semantic_tokenize(text: str):
    if not text:
        return []
    tokens = []
    for raw in re.findall(r"[A-Za-z0-9_]+", text):
        expanded = _SEMANTIC_CAMEL_BOUNDARY_2.sub(r"\1 \2", raw)
        expanded = _SEMANTIC_CAMEL_BOUNDARY_1.sub(r"\1 \2", expanded)
        for part in expanded.replace("_", " ").split():
            tok = _normalize_semantic_token(part)
            if len(tok) >= 2:
                tokens.append(tok)
    return tokens


def _compile_semantic_matcher(pattern: str, *, fuzzy_cutoff: float = _SEMANTIC_FUZZY_CUTOFF):
    query_tokens = _semantic_tokenize(pattern)
    if not query_tokens:
        return None
    if (
        len(query_tokens) == 1
        and len(query_tokens[0]) < _SEMANTIC_SINGLE_TOKEN_MIN_LEN
        and " " not in pattern
    ):
        return None

    query_set = set(query_tokens)
    pathlike_query = len(query_set) == 2 and bool(re.search(r"[./\\:_-]", pattern))
    overlap_needed = 2 if pathlike_query else max(1, (len(query_set) + 1) // 2)

    def _semantic_matches(text: str) -> bool:
        text_tokens = set(_semantic_tokenize(text))
        if not text_tokens:
            return False
        overlap = len(query_set.intersection(text_tokens))
        if overlap >= overlap_needed:
            return True
        # Only fuzzy-match tokens that are NOT already exact matches — a token
        # in `overlap` would otherwise be double-counted by best_match (ratio
        # 1.0 >= cutoff), silently defeating the overlap_needed threshold.
        fuzzy_tokens = [
            tok for tok in query_set if tok not in text_tokens
            and len(tok) >= _SEMANTIC_SINGLE_TOKEN_MIN_LEN
        ]
        if not fuzzy_tokens:
            return False
        from ..intelligence.helpers import best_match
        fuzzy_hits = 0
        for qtok in fuzzy_tokens:
            if best_match(qtok, list(text_tokens), n=1, cutoff=fuzzy_cutoff):
                fuzzy_hits += 1
                if overlap + fuzzy_hits >= overlap_needed:
                    return True
        return False

    return _semantic_matches


def _is_regex(pattern):
    if not pattern:
        return False
    if pattern.startswith("/") and pattern.count("/") >= 2:
        return True
    for ind in (r"\d", r"\w", r"\s", r"\b", r"\D", r"\W", r"\S", r"\B"):
        if ind in pattern:
            return True
    # Literal queries frequently contain regex metacharacters that are NOT
    # regex constructs: "foo[0]", "v3 + 0x10", "func()".  Only treat the
    # pattern as a regex when it carries unambiguous regex syntax — an anchor
    # at the start (^) or end ($), a backslash escape of a punctuation char
    # (\., \\, \*), or a bracket expression that is a genuine character class
    # (contains a class range like [a-z] or a negation [^…]).  A bare '+',
    # '()', '{}', '[]' or '|' is more likely literal text than regex.
    if pattern.startswith("^") or pattern.endswith("$"):
        return True
    if re.search(r"\\[.^$*+?{}()|[\]\\]", pattern):
        return True
    return bool(re.search(r"\[\^[^\[\]]*\]|\[[^\[\]]+-[^\[\]]+\]", pattern))


@lru_cache(maxsize=1024)
def _compile_smart_pattern_cached(
    pattern, case_sensitive, semantic_enabled, fuzzy_cutoff
):
    return _compile_smart_pattern_uncached(
        pattern,
        case_sensitive=case_sensitive,
        semantic_enabled=semantic_enabled,
        fuzzy_cutoff=fuzzy_cutoff,
    )


def _compile_smart_pattern_uncached(
    pattern,
    *,
    case_sensitive=False,
    semantic_enabled=True,
    fuzzy_cutoff=_SEMANTIC_FUZZY_CUTOFF,
):
    if not pattern:
        return lambda _t: True
    regex = None
    if pattern.startswith("/") and pattern.count("/") >= 2:
        ls = pattern.rfind("/")
        body, fs = pattern[1:ls], pattern[ls + 1 :]
        flags = 0
        for c in fs:
            if c == "i":
                flags |= re.IGNORECASE
            elif c == "m":
                flags |= re.MULTILINE
            elif c == "s":
                flags |= re.DOTALL
        with contextlib.suppress(re.error):
            regex = re.compile(
                body, flags or (0 if case_sensitive else re.IGNORECASE)
            )
    elif _is_regex(pattern):
        with contextlib.suppress(re.error):
            regex = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
    if regex is not None:
        return lambda _t, _r=regex: bool(_r.search(_t))
    if "*" in pattern or "?" in pattern:
        pl = pattern.lower()
        # A bare '?' without '*' is far more likely a literal character — the
        # leading '?' of MSVC-mangled C++ symbols — than a single-char glob
        # wildcard.  Escape it so '?str@std@@' matches literally instead of
        # matching any one character.  Skip when bracket classes are present
        # ('[?]' would corrupt them).
        if "?" in pl and "*" not in pl and "[" not in pl and "]" not in pl:
            pl = pl.replace("?", "[?]")
        return lambda _t, _p=pl: fnmatch.fnmatch(_t.lower(), _p)
    if case_sensitive:
        return lambda _t, _p=pattern: _p in _t
    pl = pattern.lower()
    if not semantic_enabled:
        return lambda _t, _p=pl: _p in _t.lower()
    semantic_match = _compile_semantic_matcher(pattern, fuzzy_cutoff=fuzzy_cutoff)
    if semantic_match is None:
        return lambda _t, _p=pl: _p in _t.lower()
    return lambda _t, _p=pl, _sem=semantic_match: (_p in _t.lower()) or _sem(_t)


def compile_smart_pattern(
    pattern,
    case_sensitive=False,
    *,
    semantic_enabled=None,
    fuzzy_cutoff=None,
):
    defaults = _SMART_MATCH_MODE_DEFAULTS[_SMART_MATCH_MODE]
    use_semantic = bool(
        _resolve_optional_param(semantic_enabled, defaults["semantic_enabled"])
    )
    raw_cutoff = _resolve_optional_param(fuzzy_cutoff, defaults["fuzzy_cutoff"])
    # Preserve explicit caller override; otherwise derive adaptive cutoff from pattern.
    use_cutoff = _adaptive_fuzzy_cutoff(str(pattern or ""), float(raw_cutoff)) if fuzzy_cutoff is None else float(raw_cutoff)
    use_cutoff = max(0.0, min(1.0, use_cutoff))
    return _compile_smart_pattern_cached(
        pattern, case_sensitive, use_semantic, use_cutoff
    )


def smart_match(pattern, text, case_sensitive=False):
    return compile_smart_pattern(pattern, case_sensitive)(text)


# ============================================================================
# L2 — Global Facts Database (SQLite-backed domain knowledge)
# ============================================================================

import hashlib  # noqa: E402
import sqlite3  # noqa: E402
import threading  # noqa: E402


class GlobalFactsDatabase:
    """
    L2 Global Facts: stable domain knowledge stored in SQLite.

    Categories:
        "compiler_signature", "common_api", "known_struct",
        "calling_convention", "obfuscator_signature"

    Integration:
        - Structural metadata is indexed alongside embeddings.
        - L3 skills reference L2 facts by ID.
        - L4 archive queries L2 for context.

    No LLM dependencies. Standard library only.
    """

    _DEFAULT_FACTS = [
        # Compiler signatures
        ("compiler_signature", "msvc_rtl", "RTL initialization pattern detected", 0.85, "builtin"),
        ("compiler_signature", "gcc_main", "GCC __libc_start_main pattern", 0.90, "builtin"),
        ("compiler_signature", "clang_ctor", "LLVM global constructor pattern", 0.80, "builtin"),
        # Common APIs
        ("common_api", "VirtualAlloc", "Windows memory allocation", 0.95, "builtin"),
        ("common_api", "malloc", "C standard heap allocation", 0.95, "builtin"),
        ("common_api", "strcpy", "Unsafe string copy (potential sink)", 0.90, "builtin"),
        ("common_api", "memcpy", "Memory copy (potential sink)", 0.90, "builtin"),
        ("common_api", "CreateFileW", "Windows file creation", 0.95, "builtin"),
        ("common_api", "RegOpenKeyEx", "Windows registry access", 0.95, "builtin"),
        ("common_api", "socket", "BSD socket creation", 0.95, "builtin"),
        ("common_api", "recv", "Network receive", 0.95, "builtin"),
        ("common_api", "send", "Network transmit", 0.95, "builtin"),
        ("common_api", "CryptEncrypt", "Windows crypto API", 0.95, "builtin"),
        # Known structs
        ("known_struct", "IMAGE_DOS_HEADER", "PE DOS header", 0.95, "builtin"),
        ("known_struct", "IMAGE_NT_HEADERS", "PE NT headers", 0.95, "builtin"),
        ("known_struct", "sockaddr_in", "IPv4 socket address", 0.95, "builtin"),
        # Calling conventions
        ("calling_convention", "x64_fastcall", "Windows x64 fastcall (RCX, RDX, R8, R9)", 0.95, "builtin"),
        ("calling_convention", "amd64_systemv", "System V AMD64 ABI (RDI, RSI, RDX, RCX, R8, R9)", 0.95, "builtin"),
        ("calling_convention", "x86_stdcall", "x86 stdcall (callee cleanup)", 0.95, "builtin"),
        ("calling_convention", "x86_cdecl", "x86 cdecl (caller cleanup)", 0.95, "builtin"),
        # Obfuscator signatures
        ("obfuscator_signature", "flattened_cfg", "Control-flow flattening detected", 0.75, "builtin"),
        ("obfuscator_signature", "opaque_predicate", "Opaque predicate detected", 0.70, "builtin"),
        ("obfuscator_signature", "vm_entry", "Virtualization obfuscator entry", 0.65, "builtin"),
    ]

    def __init__(self, db_path: str | None = None):
        if db_path is None:
            db_path = os.path.join(os.path.expanduser("~"), ".ida-pro-mcp", "global_facts.db")
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite schema and populate with defaults on first run."""
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA cache_size=-64000")

        self._conn.execute("""
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
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_facts_category ON global_facts(category)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_facts_key ON global_facts(fact_key)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_facts_access ON global_facts(access_count)
        """)
        self._conn.commit()

        # Populate defaults if table is empty
        cursor = self._conn.execute("SELECT COUNT(*) FROM global_facts")
        if cursor.fetchone()[0] == 0:
            for category, key, value, confidence, source in self._DEFAULT_FACTS:
                self.add_fact(category, key, value, confidence, source)

    def add_fact(
        self,
        category: str,
        key: str,
        value: str,
        confidence: float = 0.5,
        source: str = "",
    ) -> str:
        """
        Insert or replace a global fact.

        Returns the deterministic fact_id (SHA256 prefix of category+key).
        """
        fact_id = f"fact_{hashlib.sha256((category + ':' + key).encode()).hexdigest()[:16]}"
        now = time.time()
        with self._lock:
            self._conn.execute("""
                INSERT OR REPLACE INTO global_facts
                (fact_id, category, fact_key, fact_value, confidence, source, timestamp, access_count, last_accessed)
                VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT access_count FROM global_facts WHERE fact_id=?), 0), COALESCE((SELECT last_accessed FROM global_facts WHERE fact_id=?), 0.0))
            """, (fact_id, category, key, value, confidence, source, now, fact_id, fact_id))
            self._conn.commit()
        return fact_id

    def query_facts(self, category: str | None = None, key_pattern: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """
        Query facts by category and/or key pattern (substring match).

        Parameters
        ----------
        category : str, optional
            Filter by exact category.
        key_pattern : str, optional
            Substring match against fact_key (case-insensitive).
        limit : int
            Max results.
        """
        conditions = []
        params: list[Any] = []
        if category:
            conditions.append("category = ?")
            params.append(category)
        if key_pattern:
            conditions.append("fact_key LIKE ?")
            params.append(f"%{key_pattern}%")

        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        sql = f"SELECT fact_id, category, fact_key, fact_value, confidence, source, timestamp, access_count FROM global_facts {where_clause} ORDER BY access_count DESC, confidence DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            cursor = self._conn.execute(sql, params)
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append({
                    "fact_id": row[0],
                    "category": row[1],
                    "key": row[2],
                    "value": row[3],
                    "confidence": row[4],
                    "source": row[5],
                    "timestamp": row[6],
                    "access_count": row[7],
                })
            return results

    def count(self) -> int:
        with self._lock:
            cursor = self._conn.execute("SELECT COUNT(*) FROM global_facts")
            return cursor.fetchone()[0] or 0

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __repr__(self) -> str:
        return f"<GlobalFactsDatabase: {self.count()} facts at {self.db_path}>"
