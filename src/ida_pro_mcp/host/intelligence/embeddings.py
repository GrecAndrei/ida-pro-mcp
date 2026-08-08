"""Embedding index storage helpers for intelligence core."""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import sqlite3
import threading
import time
from collections import Counter
from contextlib import closing, suppress
from datetime import UTC, datetime
from typing import Any

from .helpers import (
    batch_cosine_similarity as _batch_cosine_similarity,
    pack_floats as _pack_floats,
    unpack_floats as _unpack_floats,
)

logger = logging.getLogger(__name__)


_SEARCH_TOKEN_RE = re.compile(r"0x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]{1,}|\b\d+\b")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_DECOMP_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b")
_DECOMP_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_DECOMP_STRING_RE = re.compile(r'(?s)(?:L|u8|u|U)?"((?:\\.|[^"\\])*)"')
_DECOMP_CONSTANT_RE = re.compile(r"\b(?:0x[0-9A-Fa-f]{2,}|\d{3,})\b")
_DECOMP_NOISE = frozenset(
    {
        "auto", "bool", "break", "case", "char", "const", "continue", "default",
        "do", "double", "else", "enum", "extern", "false", "float", "for", "goto",
        "if", "inline", "int", "long", "null", "return", "short", "signed", "sizeof",
        "static", "struct", "switch", "true", "typedef", "union", "unsigned", "void",
        "volatile", "while", "this", "result", "value", "arg", "args", "ptr", "data",
    }
)

# Consolidated noise-word set used by both text-search tokenisation and
# signature extraction.  Kept in one place to avoid drift between the two
# subsystems.  Imported by ``intelligence/core.py``.
NOISE_WORDS = frozenset({
    "the", "and", "for", "with", "this", "that", "from", "into", "while",
    "void", "char", "int", "uint", "long", "short", "bool", "true", "false",
    "const", "struct", "class", "return", "case", "break", "default", "null",
    "auto", "static", "extern", "signed", "unsigned", "size", "len", "buf",
    "ptr", "tmp", "ret", "arg", "args", "result", "value", "values", "data",
    "var", "vars", "out", "dst", "src", "count", "index", "idx",
    "NULL", "sizeof", "else", "inline", "typedef", "goto", "continue",
    "switch", "type", "flag", "mode", "num", "res", "val", "msg", "function", "functions",
    "str", "memcpy", "memset", "memcmp", "memmove", "malloc", "calloc",
    "free", "printf", "sprintf", "strcpy", "strlen", "strcat", "strcmp",
})

_SEARCH_NOISE_TOKENS = NOISE_WORDS

_TOKEN_SYNONYMS: dict[str, tuple[str, ...]] = {
    "aes": ("crypto", "cipher", "encrypt", "decrypt"),
    "cipher": ("crypto", "encrypt", "decrypt"),
    "encrypt": ("crypto", "cipher"),
    "decrypt": ("crypto", "cipher", "xor"),
    "hash": ("digest", "sha", "md5"),
    "digest": ("hash", "sha", "md5"),
    "http": ("network", "socket", "header", "headers", "request", "response"),
    "https": ("http", "network", "socket"),
    "recv": ("receive", "socket", "network"),
    "send": ("socket", "network"),
    "socket": ("network", "connect", "recv", "send"),
    "connect": ("network", "socket"),
    "file": ("open", "read", "write", "path"),
    "registry": ("persistence", "autorun"),
    "service": ("persistence", "autorun"),
    "debugger": ("antidebug", "anti", "debug"),
    "vm": ("virtual", "sandbox"),
    "sandbox": ("vm", "evasion"),
    "overflow": ("bounds", "memcpy", "strcpy"),
    "uaf": ("use", "after", "free"),
    "format": ("printf", "syslog", "snprintf"),
    "print": ("puts", "printf", "fprintf", "write"),
    "prints": ("print", "puts", "printf", "fprintf", "write"),
}
_INDEX_QUALITY_RANK = {"unknown": 0, "fast_fallback": 1, "fast": 1, "full": 2}


def _unique_matches(pattern: re.Pattern, text: str, limit: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in pattern.finditer(text):
        value = match.group(1) if match.lastindex else match.group(0)
        value = re.sub(r"\s+", " ", str(value or "")).strip()
        key = value.lower()
        if not value or key in seen:
            continue
        seen.add(key)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def _sample_pseudocode_lines(pseudocode: str, char_budget: int) -> str:
    """Keep representative code from the whole function within a fixed budget."""
    if char_budget <= 0:
        return ""
    lines = [re.sub(r"\s+", " ", line).strip() for line in pseudocode.splitlines()]
    lines = [line for line in lines if line]
    if not lines:
        return ""
    compact = "\n".join(lines)
    if len(compact) <= char_budget:
        return compact

    priority: list[int] = []
    seen_priority: set[int] = set()

    def prioritize(index: int) -> None:
        if index not in seen_priority:
            seen_priority.add(index)
            priority.append(index)

    # Literal- and control-bearing lines usually carry more behavioral signal
    # than long runs of assignments/calls. Reserve those before even sampling.
    for index, line in enumerate(lines):
        if '"' in line:
            prioritize(index)
    for index, line in enumerate(lines):
        if re.search(r"\b(if|else|for|while|switch|case|return)\b", line):
            prioritize(index)
    for index in list(range(min(4, len(lines)))) + list(range(max(0, len(lines) - 4), len(lines))):
        prioritize(index)
    sample_count = min(len(lines), max(8, char_budget // 96))
    if sample_count > 1:
        for index in range(sample_count):
            prioritize(round(index * (len(lines) - 1) / (sample_count - 1)))
    else:
        prioritize(0)
    for index in range(len(lines)):
        prioritize(index)

    selected_indexes: list[int] = []
    used = 0
    for index in priority:
        line = lines[index]
        cost = len(line) + (1 if selected_indexes else 0)
        if used + cost > char_budget:
            continue
        selected_indexes.append(index)
        used += cost
    return "\n".join(lines[index] for index in sorted(selected_indexes))


def _format_document_section(label: str, values: list[str], char_budget: int, separator: str = " ") -> str:
    if not values or char_budget <= len(label) + 2:
        return ""
    prefix = f"{label}: "
    available = char_budget - len(prefix)
    priority: list[int] = []
    left, right = 0, len(values) - 1
    while left <= right:
        priority.append(left)
        if right != left:
            priority.append(right)
        left += 1
        right -= 1
    selected: list[int] = []
    used = 0
    for index in priority:
        value = re.sub(r"\s+", " ", str(values[index])).strip()
        cost = len(value) + (len(separator) if selected else 0)
        if not value or used + cost > available:
            continue
        selected.append(index)
        used += cost
    if not selected:
        return prefix + re.sub(r"\s+", " ", str(values[0])).strip()[:available]
    return prefix + separator.join(str(values[index]).strip() for index in sorted(selected))


def _decomp_operation_features(pseudocode: str) -> list[str]:
    features: list[str] = []
    checks = (
        ("%", "modulo"),
        ("[", "array_index"),
        ("^", "bitwise_xor"),
        ("<<", "shift_left"),
        (">>", "shift_right"),
        ("+=", "state_update"),
        ("-=", "state_update"),
    )
    for marker, feature in checks:
        if marker in pseudocode and feature not in features:
            features.append(feature)
    if re.search(r"\b(?:memcpy|memmove|strcpy|strncpy)\s*\(", pseudocode):
        features.append("buffer_copy")
    return features


def build_decomp_document(name: str, pseudocode: str, max_chars: int = 5760) -> str:
    """Build a context-bounded embedding document from a whole decompilation."""
    pseudo = str(pseudocode or "").strip()
    safe_name = re.sub(r"\s+", " ", str(name or "function")).strip()[:256]
    max_chars = max(1024, min(int(max_chars or 5760), 32768))
    operation_features = _decomp_operation_features(pseudo)
    if len(pseudo) <= max_chars:
        name_budget = min(160, max(32, max_chars // 6))
        prefix = f"function: {safe_name[:name_budget]}"
        if operation_features:
            prefix += "\noperations: " + " ".join(operation_features)
        return f"{prefix}\n{pseudo}"[:max_chars]

    all_identifiers: list[str] = []
    seen_identifiers: set[str] = set()
    for match in _DECOMP_IDENTIFIER_RE.finditer(pseudo):
        ident = match.group(0)
        low = ident.lower()
        if low in _DECOMP_NOISE or low in seen_identifiers:
            continue
        seen_identifiers.add(low)
        all_identifiers.append(ident)
    if len(all_identifiers) <= 160:
        identifiers = all_identifiers
    else:
        identifiers = all_identifiers[:80] + all_identifiers[-80:]
    strings = [value[:96] for value in _unique_matches(_DECOMP_STRING_RE, pseudo, 128)]
    calls = [
        value
        for value in _unique_matches(_DECOMP_CALL_RE, pseudo, 256)
        if value.lower() not in _DECOMP_NOISE
    ]
    constants = _unique_matches(_DECOMP_CONSTANT_RE, pseudo, 128)
    controls = {
        "calls": len(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(", pseudo)),
        "branches": len(re.findall(r"\b(?:if|else|switch|case)\b", pseudo)),
        "loops": len(re.findall(r"\b(?:for|while|do)\b", pseudo)),
        "returns": len(re.findall(r"\breturn\b", pseudo)),
    }
    header_parts = [
        _format_document_section("function", [safe_name], int(max_chars * 0.10)),
        _format_document_section("string_literals", strings, int(max_chars * 0.16), " | "),
        _format_document_section("calls", calls, int(max_chars * 0.18)),
        _format_document_section("constants", constants, int(max_chars * 0.08)),
        _format_document_section("behavior_identifiers", identifiers, int(max_chars * 0.18)),
        _format_document_section("operations", operation_features, int(max_chars * 0.07)),
        _format_document_section(
            "control_profile",
            [f"{key}={value}" for key, value in controls.items()],
            int(max_chars * 0.07),
        ),
    ]
    header = "\n".join(part for part in header_parts if part)
    code_budget = max_chars - len(header) - len("\npseudocode:\n")
    sample = _sample_pseudocode_lines(pseudo, code_budget)
    return f"{header}\npseudocode:\n{sample}"[:max_chars]


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _safe_file_head_sha256(path: str, max_bytes: int = 16 * 1024 * 1024) -> str:
    if not path or not os.path.isfile(path):
        return ""
    h = hashlib.sha256()
    read_bytes = 0
    with open(path, "rb") as f:
        while read_bytes < max_bytes:
            chunk = f.read(min(1024 * 1024, max_bytes - read_bytes))
            if not chunk:
                break
            h.update(chunk)
            read_bytes += len(chunk)
    return h.hexdigest()


def _file_mtime_ns(path: str) -> int:
    """Latest nanosecond mtime across a SQLite DB and its WAL/SHM sidecars.

    The main ``.db`` file's mtime is NOT a reliable change signal under WAL
    journaling: small commits live in the ``-wal`` file and only reach the
    main file at checkpoint.  Tracking the newest of the three lets readers
    cheaply detect an index rebuild regardless of journal mode.
    """
    latest = 0
    for candidate in (path, path + "-wal", path + "-shm"):
        try:
            latest = max(latest, os.stat(candidate).st_mtime_ns)
        except OSError:
            continue
    return latest


def _safe_stat(path: str) -> tuple[int, int]:
    if not path or not os.path.isfile(path):
        return 0, 0
    st = os.stat(path)
    return int(st.st_size), int(st.st_mtime_ns)


def _split_identifier_token(token: str) -> list[str]:
    """Split RE identifiers into searchable semantic pieces."""
    raw = str(token or "").strip()
    if not raw:
        return []
    if raw.lower().startswith("0x") or raw.isdigit():
        return [raw.lower()]
    parts: list[str] = []
    for chunk in re.split(r"[_\W]+", raw):
        if not chunk:
            continue
        split = [sub for sub in _CAMEL_BOUNDARY_RE.split(chunk) if sub]
        if len(split) == 1:
            parts.append(chunk.lower())
        else:
            parts.extend(sub.lower() for sub in split)
    return parts


def _expand_query_tokens(tokens: set[str]) -> set[str]:
    expanded = set(tokens)
    for tok in list(tokens):
        expanded.update(_TOKEN_SYNONYMS.get(tok, ()))
    return expanded


def _search_token_forms(token: str) -> list[str]:
    """Return a token plus conservative English verb/plural variants."""
    forms = [token]
    if len(token) > 4 and token.endswith("ies"):
        forms.append(token[:-3] + "y")
    elif len(token) > 4 and token.endswith(("ches", "shes", "xes")):
        forms.append(token[:-2])
    elif len(token) > 3 and token.endswith("s") and not token.endswith("ss"):
        forms.append(token[:-1])
    if len(token) > 5 and token.endswith("ing"):
        stem = token[:-3]
        forms.append(stem)
        forms.append(stem + "e")
    return list(dict.fromkeys(forms))


def _idf_scores(docs: list[set[str]]) -> dict[str, float]:
    df: Counter[str] = Counter()
    for doc in docs:
        df.update(doc)
    total = max(1, len(docs))
    return {tok: math.log((total + 1.0) / (cnt + 0.5)) + 1.0 for tok, cnt in df.items()}


def _weighted_token_score(query_tokens: set[str], row_tokens: set[str], idf: dict[str, float]) -> tuple[float, list[str]]:
    if not query_tokens or not row_tokens:
        return 0.0, []
    expanded = _expand_query_tokens(query_tokens)
    direct = query_tokens.intersection(row_tokens)
    indirect = (expanded - query_tokens).intersection(row_tokens)
    numerator = sum(idf.get(tok, 1.0) for tok in direct)
    numerator += 0.55 * sum(idf.get(tok, 1.0) for tok in indirect)
    denominator = sum(idf.get(tok, 1.0) for tok in query_tokens) or 1.0
    coverage = min(1.0, numerator / denominator)
    precision = min(1.0, numerator / (sum(idf.get(tok, 1.0) for tok in row_tokens) or 1.0))
    score = (0.82 * coverage) + (0.18 * precision)
    return score, sorted(direct.union(indirect))[:16]


def _normalize_search_text(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "").strip().lower())


def _tokenize_search_text(text: str, max_tokens: int = 96) -> list[str]:
    seen = set()
    out: list[str] = []
    for raw in _SEARCH_TOKEN_RE.findall(str(text or "").replace("_", " ")):
        for low in _split_identifier_token(raw):
            for form in _search_token_forms(low):
                if form in seen or form in _SEARCH_NOISE_TOKENS:
                    continue
                if form.isdigit() and len(form) < 3:
                    continue
                seen.add(form)
                out.append(form)
                if len(out) >= max_tokens:
                    return out
    for raw in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", str(text or "")):
        low = raw.lower()
        if low in seen or low in _SEARCH_NOISE_TOKENS:
            continue
        for part in [low] + _split_identifier_token(raw):
            for form in _search_token_forms(part):
                if form in seen or form in _SEARCH_NOISE_TOKENS:
                    continue
                seen.add(form)
                out.append(form)
                if len(out) >= max_tokens:
                    return out
    return out


def _extract_signature_text(pseudocode: str, max_tokens: int = 96) -> str:
    return " ".join(_tokenize_search_text(pseudocode, max_tokens=max_tokens))


def _clip_signature(text: str, max_len: int = 160) -> str:
    compact = re.sub(r"\s+", " ", str(text or "").strip())
    if len(compact) <= max_len:
        return compact
    return compact[: max_len - 3] + "..."


class FunctionEmbeddingIndex:
    """
    Stores model-native float32 embeddings of decompiled functions,
    one SQLite database per binary (<idb_path>.embeddings.db).

    Replaces the spectral-CFG encoder (MbaGCN — untrained random SSM)
    and TurboQuant (quantization of tabular features it was never
    designed for).
    """

    INDEX_SCHEMA_VERSION = 4

    def __init__(self, db_path: str, embedder: Any):
        self._embedder = embedder
        self._cache: dict[str, list[float]] = {}  # ea_hex -> embedding
        self._cache_lock = threading.Lock()
        self._db_mtime_ns = 0
        # Bounded fire-and-forget queue: cap concurrent background index
        # threads so a large index_async burst cannot spawn unbounded threads.
        self._async_gate = threading.Semaphore(4)

        try:
            from ..config import CACHE_DIR
        except ImportError:
            try:
                from host.config import CACHE_DIR
            except ImportError:
                CACHE_DIR = os.path.join(os.path.expanduser("~"), ".local", "state", "ida-pro-mcp")

        self._db_path = db_path
        try:
            db_dir = os.path.dirname(db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            # Try to connect and execute a command to verify write access
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.close()
            self._init_db()
        except (sqlite3.OperationalError, OSError, PermissionError):
            h = hashlib.sha256(os.path.abspath(db_path).encode("utf-8")).hexdigest()[:16]
            fallback_dir = os.path.join(CACHE_DIR, "fallback_indexes")
            os.makedirs(fallback_dir, exist_ok=True)
            self._db_path = os.path.join(fallback_dir, f"{h}.embeddings.db")
            self._init_db()

        self._init_meta()
        try:
            if self.needs_rebuild(self._embedder):
                with closing(sqlite3.connect(self._db_path)) as rebuild_conn:
                    rebuild_conn.execute("PRAGMA journal_mode=WAL")
                    rebuild_conn.execute("BEGIN")
                    rebuild_conn.execute("DELETE FROM func_embeddings")
                    now = _now_iso()
                    base = {
                        "index_schema_version": str(self.INDEX_SCHEMA_VERSION),
                        "signature_extractor_version": "v2",
                        "anchor_set_hash": "",
                        "created_at": now,
                        "updated_at": now,
                        "source_idb_path": self._source_idb_path(),
                        "source_binary_path": "",
                        "source_fingerprint": self._source_fingerprint(),
                    }
                    base.update(self._embedder_meta_snapshot())
                    for k, v in base.items():
                        self._meta_set(rebuild_conn, k, v)
                    rebuild_conn.commit()
                self._cache.clear()
        except Exception as e:
            logger.exception("needs_rebuild transaction failed: %s", e)
            raise
        self._load_cache()

    def _conn(self) -> sqlite3.Connection:
        # timeout gives the writer a grace window when another thread (e.g. the
        # background _persist thread or a batch index) holds the write lock, so
        # concurrent enrichment does not drop rows with an immediate SQLITE_BUSY.
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS func_embeddings (
                    ea       TEXT PRIMARY KEY,
                    name     TEXT,
                    dim      INTEGER,
                    vec_blob BLOB NOT NULL,
                    pseudo_hash TEXT,
                    indexed_at  REAL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fe_name ON func_embeddings(name)")
            # Additive migration for semantic provenance fields.
            cols = {str(row[1]) for row in conn.execute("PRAGMA table_info(func_embeddings)").fetchall()}
            if "source_kind" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN source_kind TEXT DEFAULT 'function'")
            if "source_hash" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN source_hash TEXT")
            if "signature_text" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN signature_text TEXT")
            if "signature_hash" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN signature_hash TEXT")
            # Full bounded document text used for cross-encoder reranking.  The
            # short signature_text is a tokenized lexical fingerprint; the
            # cross-encoder needs the same text that was embedded (the bounded
            # decompilation) to score (query, doc) pairs.
            if "document_text" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN document_text TEXT")
            # Structural metadata (replaces SchemaBoot)
            if "func_size" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN func_size INTEGER DEFAULT 0")
            if "bb_count" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN bb_count INTEGER DEFAULT 0")
            if "has_loops" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN has_loops INTEGER DEFAULT 0")
            if "api_count" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN api_count INTEGER DEFAULT 0")
            if "string_count" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN string_count INTEGER DEFAULT 0")
            if "segment" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN segment TEXT")
            if "is_thunk" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN is_thunk INTEGER DEFAULT 0")
            if "cyclomatic" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN cyclomatic INTEGER DEFAULT 0")
            if "index_quality" not in cols:
                conn.execute("ALTER TABLE func_embeddings ADD COLUMN index_quality TEXT DEFAULT 'unknown'")
            # Indexes for structural filters
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fe_size ON func_embeddings(func_size)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fe_bb ON func_embeddings(bb_count)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fe_loops ON func_embeddings(has_loops)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fe_segment ON func_embeddings(segment)")
            conn.commit()

    def _meta_set(self, conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            """
            INSERT INTO embedding_meta(key, value) VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (key, value),
        )

    def _meta_get(self, conn: sqlite3.Connection, key: str) -> str | None:
        row = conn.execute("SELECT value FROM embedding_meta WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        return str(row[0])

    def _source_idb_path(self) -> str:
        p = self._db_path
        suffix = ".embeddings.db"
        if p.endswith(suffix):
            return p[: -len(suffix)]
        return p

    def _source_fingerprint(self) -> str:
        src = self._source_idb_path()
        if src and os.path.isfile(src):
            st = os.stat(src)
            return hashlib.sha256(f"{src}:{st.st_size}:{st.st_mtime_ns}".encode()).hexdigest()
        return hashlib.sha256(src.encode("utf-8")).hexdigest() if src else ""

    def _embedder_meta_snapshot(self, embedder: Any | None = None) -> dict[str, str]:
        """Snapshot the embedder's identity for metadata persistence.

        ``embedder`` defaults to the index's own embedder.  Callers that
        verify against a *candidate* embedder (e.g. a replacement backend)
        must pass it explicitly — otherwise the snapshot silently reflects
        the stale embedder the index was built with and a changed
        ``embedding_format`` would never be detected.
        """
        embedder = embedder if embedder is not None else self._embedder
        backend = str(getattr(embedder, "backend", "unknown"))
        dim = str(getattr(embedder, "dim", 0) or 0)
        model_path = ""
        server_bin = ""
        try:
            status = getattr(embedder, "status", None)
            if callable(status):
                st = status(probe=False)
                model_path = str(st.get("model_path") or "")
                server_bin = str(st.get("server_bin") or "")
        except Exception:
            pass
        if not model_path:
            model_path = str(getattr(embedder, "_model_path", "") or "")
        if not server_bin:
            server_bin = str(getattr(embedder, "_server_bin", "") or "")
        model_size, _ = _safe_stat(model_path)
        server_size, _ = _safe_stat(server_bin)
        return {
            "embedding_backend": backend,
            "embedding_dim": dim,
            "embedding_format": str(getattr(embedder, "embedding_format", backend)),
            "model_path": model_path,
            "model_size": str(model_size),
            "model_sha256_head": _safe_file_head_sha256(model_path),
            "server_bin": server_bin,
            "server_size": str(server_size),
            "server_sha256_head": _safe_file_head_sha256(server_bin),
        }

    def _init_meta(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS embedding_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            now = _now_iso()
            base = {
                "index_schema_version": str(self.INDEX_SCHEMA_VERSION),
                "signature_extractor_version": "v2",
                "anchor_set_hash": "",
                "created_at": now,
                "updated_at": now,
                "source_idb_path": self._source_idb_path(),
                "source_binary_path": "",
                "source_fingerprint": self._source_fingerprint(),
            }
            base.update(self._embedder_meta_snapshot())
            for k, v in base.items():
                if self._meta_get(conn, k) is None:
                    self._meta_set(conn, k, v)
            self._meta_set(conn, "updated_at", now)
            conn.commit()

    def metadata(self) -> dict[str, Any]:
        with self._conn() as conn:
            rows = conn.execute("SELECT key, value FROM embedding_meta").fetchall()
        out: dict[str, Any] = {str(k): str(v) for k, v in rows}
        for key in ("index_schema_version", "embedding_dim", "model_size", "server_size"):
            if key in out:
                with suppress(Exception):
                    out[key] = int(out[key])
        return out

    def recent_functions(self, limit: int = 64) -> list[dict[str, Any]]:
        """Return most recently indexed function refs for state tracking."""
        rows: list[dict[str, Any]] = []
        try:
            with closing(self._conn()) as conn:
                for row in conn.execute(
                    """
                    SELECT ea, name, indexed_at, signature_hash
                    FROM func_embeddings
                    ORDER BY indexed_at DESC
                    LIMIT ?
                    """,
                    (max(1, int(limit)),),
                ):
                    rows.append(
                        {
                            "ea": str(row[0]),
                            "name": str(row[1] or row[0]),
                            "indexed_at": row[2],
                            "signature_hash": str(row[3] or ""),
                        }
                    )
        except Exception:
            return []
        return rows

    def quality_counts(self) -> dict[str, int]:
        """Return persisted function counts by indexing quality."""
        try:
            with closing(self._conn()) as conn:
                rows = conn.execute(
                    "SELECT COALESCE(index_quality, 'unknown'), COUNT(*) FROM func_embeddings GROUP BY index_quality"
                ).fetchall()
            return {str(quality): int(count) for quality, count in rows}
        except Exception:
            return {}

    def build_embedding_state_payload(self) -> dict[str, Any]:
        """Build an embedding state payload."""
        meta = self.metadata()
        model_head = str(meta.get("model_sha256_head") or "")
        index_metadata = {
            "implementation": "FunctionEmbeddingIndex",
            "db_path": self._db_path,
            "index_schema_version": int(meta.get("index_schema_version") or self.INDEX_SCHEMA_VERSION),
            "source_idb_path": str(meta.get("source_idb_path") or ""),
            "source_binary_path": str(meta.get("source_binary_path") or ""),
            "source_fingerprint": str(meta.get("source_fingerprint") or ""),
            "embedding_backend": str(meta.get("embedding_backend") or ""),
            "function_count": int(self.size),
            "quality_counts": self.quality_counts(),
            "updated_at": str(meta.get("updated_at") or _now_iso()),
        }
        return {
            "backend": str(meta.get("embedding_backend") or getattr(self._embedder, "backend", "unknown")),
            "model_path": str(meta.get("model_path") or ""),
            "model_hash": model_head,
            "embedding_dim": int(meta.get("embedding_dim") or getattr(self._embedder, "dim", 0) or 0),
            "index_metadata": index_metadata,
             "anchor_metadata": {},
             "last_indexed_functions": self.recent_functions(limit=64),
             "thresholds": {},
            "created_at": str(meta.get("created_at") or _now_iso()),
            "updated_at": _now_iso(),
        }

    def verify_metadata(self, current_embedder: Any) -> dict[str, Any]:
        stored = self.metadata()
        current_backend = str(getattr(current_embedder, "backend", "unknown"))
        current_dim = int(getattr(current_embedder, "dim", 0) or 0)
        current = {
            "embedding_backend": current_backend,
            "embedding_dim": current_dim,
        }
        current_snapshot = self._embedder_meta_snapshot(current_embedder)
        mismatches: dict[str, dict[str, Any]] = {}
        try:
            stored_schema = int(stored.get("index_schema_version", 0) or 0)
        except Exception:
            stored_schema = 0
        if stored_schema != self.INDEX_SCHEMA_VERSION:
            mismatches["index_schema_version"] = {
                "stored": stored_schema,
                "current": self.INDEX_SCHEMA_VERSION,
            }
        if str(stored.get("embedding_backend", "")) != current_backend:
            mismatches["embedding_backend"] = {
                "stored": stored.get("embedding_backend"),
                "current": current_backend,
            }
        try:
            stored_dim = int(stored.get("embedding_dim", 0) or 0)
        except Exception:
            stored_dim = 0
        if stored_dim != current_dim:
            mismatches["embedding_dim"] = {"stored": stored_dim, "current": current_dim}
        for key in ("embedding_format", "model_sha256_head"):
            stored_value = str(stored.get(key) or "")
            current_value = str(current_snapshot.get(key) or "")
            if stored_value != current_value:
                mismatches[key] = {"stored": stored_value, "current": current_value}
        return {
            "ok": not mismatches,
            "mismatches": mismatches,
            "stored": stored,
            "current": current,
        }

    def needs_rebuild(self, current_embedder: Any, source_fingerprint: str | None = None) -> bool:
        chk = self.verify_metadata(current_embedder)
        if chk["mismatches"]:
            return True
        if source_fingerprint is None:
            source_fingerprint = self._source_fingerprint()
        stored = chk.get("stored", {})
        return str(stored.get("source_fingerprint", "")) != str(source_fingerprint or "")

    def _load_cache(self) -> None:
        """Load all stored embeddings into RAM for fast cosine search.

        This is a full reload: rows removed since the previous load (e.g. an
        index rebuild) must not linger in the in-RAM cache, or every later
        search ranks against stale vectors.  The DB mtime is recorded so
        callers can cheaply detect a rebuild by another code path.
        """
        try:
            with self._cache_lock:
                self._cache.clear()
            with closing(self._conn()) as conn:
                for row in conn.execute("SELECT ea, vec_blob FROM func_embeddings"):
                    ea, blob = row
                    with self._cache_lock:
                        self._cache[ea] = _unpack_floats(blob)
        except Exception:
            pass
        self._db_mtime_ns = _file_mtime_ns(self._db_path)

    def db_changed_since_load(self) -> bool:
        """True when the on-disk index was rewritten after the last cache load.

        Cheap (one stat) so callers can check it on every read path; a full
        index rebuild (fast -> decompile quality) must not keep serving
        vectors from the previous index generation.
        """
        return self._db_mtime_ns != _file_mtime_ns(self._db_path)

    def refresh_from_disk(self) -> int:
        """Observe rows written or copied by another process and return size."""
        self._load_cache()
        return self.size

    def _pack(self, vec: list[float]) -> bytes:
        return _pack_floats(vec)

    def _unpack(self, blob: bytes) -> list[float]:
        return _unpack_floats(blob)

    def _phash(self, text: str) -> str:
        return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()[:16]

    def _row_meta_for_eas(self, eas: list[str]) -> dict[str, dict[str, Any]]:
        if not eas:
            return {}
        rows: dict[str, dict[str, Any]] = {}
        try:
            with closing(self._conn()) as conn:
                ph = ",".join("?" * len(eas))
                for row in conn.execute(
                    f"SELECT ea, name, signature_text, indexed_at FROM func_embeddings WHERE ea IN ({ph})",
                    eas,
                ):
                    rows[str(row[0])] = {
                        "name": str(row[1] or row[0]),
                        "signature_text": str(row[2] or ""),
                        "indexed_at": row[3],
                    }
        except Exception:
            return {}
        return rows

    def _row_docs_for_eas(self, eas: list[str]) -> dict[str, str]:
        """Return the persisted bounded document text for a set of addresses.

        Used by the cross-encoder rerank stage: the short ``signature_text``
        is a lexical fingerprint, but a reranker scores the *document* that
        was embedded.  Addresses with no persisted text (legacy rows indexed
        before this column existed) are simply absent from the result; the
        caller falls back to re-decompiling those.
        """
        if not eas:
            return {}
        out: dict[str, str] = {}
        try:
            with closing(self._conn()) as conn:
                ph = ",".join("?" * len(eas))
                for row in conn.execute(
                    f"SELECT ea, document_text FROM func_embeddings WHERE ea IN ({ph})",
                    eas,
                ):
                    if row[1]:
                        out[str(row[0])] = str(row[1])
        except Exception:
            return {}
        return out

    def index(self, func_ea: str, name: str, pseudocode: str, metadata: dict | None = None) -> bool:
        """Embed and store one function, returning whether the index is usable."""
        result = self.index_many([(func_ea, name, pseudocode, metadata)])
        return result["indexed"] == 1

    def index_many(self, functions: list[tuple[str, str, str, dict | None]]) -> dict[str, int | str | None]:
        """Embed and persist functions in batches.

        Existing, unchanged rows are refreshed without an embedding request. New
        or changed rows are passed to the embedder together so a cold model is
        loaded once and the embedding backend can use its configured batch size.
        """
        prepared: list[dict[str, Any]] = []
        indexed = 0
        failed = 0
        try:
            with closing(self._conn()) as conn:
                for func_ea, name, pseudocode, metadata in functions:
                    ph = self._phash(pseudocode)
                    signature_text = _extract_signature_text(pseudocode, max_tokens=256)
                    signature_hash = self._phash(signature_text or pseudocode)
                    md = metadata or {}
                    row = conn.execute(
                        "SELECT pseudo_hash, name, signature_hash, signature_text, index_quality FROM func_embeddings WHERE ea=?",
                        (func_ea,),
                    ).fetchone()
                    incoming_quality = str(md.get("index_quality") or "unknown")
                    stored_quality = str(row[4] or "unknown") if row else "unknown"
                    if row and _INDEX_QUALITY_RANK.get(stored_quality, 0) > _INDEX_QUALITY_RANK.get(incoming_quality, 0):
                        # The stored row is higher quality: keep it intact.  Only
                        # refresh the name when the incoming row carries one (a
                        # user/analysis rename).  Never clobber the stored
                        # structural metadata with empty/default values from a
                        # metadata-less caller (e.g. a modify.py re-index).
                        if name and name != (row[1] or ""):
                            conn.execute(
                                "UPDATE func_embeddings SET name=? WHERE ea=?",
                                (name, func_ea),
                            )
                        indexed += 1
                        continue
                    if row and row[0] == ph:
                        stored_sig_hash = str(row[2] or "")
                        stored_sig_text = str(row[3] or "")
                        if row[1] == name and stored_sig_hash == signature_hash and stored_sig_text == signature_text:
                            if md:
                                conn.execute(
                                    "UPDATE func_embeddings SET func_size=?, bb_count=?, has_loops=?, api_count=?, string_count=?, segment=?, is_thunk=?, cyclomatic=?, index_quality=? WHERE ea=?",
                                    (
                                        md.get("func_size", 0), md.get("bb_count", 0), md.get("has_loops", 0),
                                        md.get("api_count", 0), md.get("string_count", 0), md.get("segment", ""),
                                        md.get("is_thunk", 0), md.get("cyclomatic", 0), md.get("index_quality", "unknown"), func_ea,
                                    ),
                                )
                        else:
                            conn.execute(
                                "UPDATE func_embeddings SET name=?, signature_text=?, signature_hash=?, indexed_at=? WHERE ea=?",
                                (name, signature_text, signature_hash, time.time(), func_ea),
                            )
                        indexed += 1
                        continue
                    prepared.append(
                        {
                            "ea": func_ea,
                            "name": name,
                            "pseudocode": pseudocode,
                            "pseudo_hash": ph,
                            "signature_text": signature_text,
                            "signature_hash": signature_hash,
                            "metadata": md,
                        }
                    )
                if indexed:
                    self._meta_set(conn, "updated_at", _now_iso())
                conn.commit()
        except Exception:
            return {"indexed": 0, "failed": len(functions), "resume_after_ea": None}

        if not prepared:
            return {"indexed": indexed, "failed": failed}

        embed_batch = getattr(self._embedder, "embed_documents", None)
        if not callable(embed_batch):
            embed_batch = getattr(self._embedder, "embed_batch", None)
        try:
            embedded = embed_batch([entry["pseudocode"] for entry in prepared]) if callable(embed_batch) else None
        except Exception:
            embedded = None
        if not isinstance(embedded, list) or len(embedded) != len(prepared):
            embedded = [getattr(self._embedder, "embed_vector", lambda _text: None)(entry["pseudocode"]) for entry in prepared]

        ready: list[tuple[dict[str, Any], list[float]]] = []
        failed_eas: set[str] = set()
        for entry, result in zip(prepared, embedded, strict=True):
            vec = getattr(result, "vector", result)
            if vec is None:
                failed += 1
                failed_eas.add(str(entry["ea"]))
                continue
            ready.append((entry, vec))

        if not ready:
            return {"indexed": indexed, "failed": failed, "resume_after_ea": None}

        try:
            with closing(self._conn()) as conn:
                for entry, vec in ready:
                    md = entry["metadata"]
                    conn.execute(
                        """
                        INSERT INTO func_embeddings(
                            ea, name, dim, vec_blob, pseudo_hash, indexed_at,
                            source_kind, source_hash, signature_text, signature_hash, document_text,
                            func_size, bb_count, has_loops, api_count, string_count,
                            segment, is_thunk, cyclomatic, index_quality
                        )
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(ea) DO UPDATE SET
                            name=excluded.name,
                            dim=excluded.dim,
                            vec_blob=excluded.vec_blob,
                            pseudo_hash=excluded.pseudo_hash,
                            indexed_at=excluded.indexed_at,
                            source_kind=excluded.source_kind,
                            source_hash=excluded.source_hash,
                            signature_text=excluded.signature_text,
                            signature_hash=excluded.signature_hash,
                            document_text=excluded.document_text,
                            func_size=excluded.func_size,
                            bb_count=excluded.bb_count,
                            has_loops=excluded.has_loops,
                            api_count=excluded.api_count,
                            string_count=excluded.string_count,
                            segment=excluded.segment,
                            is_thunk=excluded.is_thunk,
                            cyclomatic=excluded.cyclomatic,
                            index_quality=excluded.index_quality
                        """,
                        (
                            entry["ea"], entry["name"], len(vec), self._pack(vec), entry["pseudo_hash"], time.time(),
                            "function", hashlib.sha256(f"{entry['ea']}:{entry['pseudo_hash']}".encode()).hexdigest()[:24],
                            entry["signature_text"], entry["signature_hash"], entry["pseudocode"],
                            md.get("func_size", 0), md.get("bb_count", 0),
                            md.get("has_loops", 0), md.get("api_count", 0), md.get("string_count", 0), md.get("segment", ""),
                            md.get("is_thunk", 0), md.get("cyclomatic", 0), md.get("index_quality", "unknown"),
                        ),
                    )
                self._meta_set(conn, "updated_at", _now_iso())
                self._meta_set(conn, "source_fingerprint", self._source_fingerprint())
                for k, v in self._embedder_meta_snapshot().items():
                    self._meta_set(conn, k, v)
                conn.commit()
        except Exception:
            return {"indexed": indexed, "failed": failed + len(ready), "resume_after_ea": None}

        with self._cache_lock:
            for entry, vec in ready:
                self._cache[entry["ea"]] = vec
        result: dict[str, int | str | None] = {
            "indexed": indexed + len(ready), "failed": failed,
        }
        if failed:
            # A timed-out request can still have written a valid prefix.
            # Return its exact boundary so callers resume after that prefix,
            # rather than retrying the same commit forever.
            resume_after_ea = None
            for func_ea, _name, _pseudocode, _metadata in functions:
                if func_ea in failed_eas:
                    break
                resume_after_ea = func_ea
            result["resume_after_ea"] = resume_after_ea
        return result

    def index_async(self, func_ea: str, name: str, pseudocode: str, metadata: dict | None = None) -> None:
        """Non-blocking index: fire-and-forget in background thread.

        Concurrency is bounded by ``_async_gate``: when the gate is saturated
        the index runs inline (synchronous) rather than spawning an unbounded
        number of threads.
        """
        ph = self._phash(pseudocode)
        signature_text = _extract_signature_text(pseudocode, max_tokens=256)
        signature_hash = self._phash(signature_text or pseudocode)
        with self._cache_lock:
            cached_vec = self._cache.get(func_ea)
        if cached_vec is not None:
            # Check if we already have this exact pseudocode
            try:
                with closing(self._conn()) as conn:
                    row = conn.execute(
                        "SELECT pseudo_hash, name, signature_hash, signature_text FROM func_embeddings WHERE ea=?",
                        (func_ea,),
                    ).fetchone()
                    if row and row[0] == ph and row[1] == name and str(row[2] or "") == signature_hash and str(row[3] or "") == signature_text:
                        return
            except Exception:
                pass
        if not self._async_gate.acquire(blocking=False):
            # Saturated: run inline so the caller is not dropped on the floor.
            self.index(func_ea, name, pseudocode, metadata)
            return

        def _run() -> None:
            try:
                self.index(func_ea, name, pseudocode, metadata)
            finally:
                self._async_gate.release()

        t = threading.Thread(target=_run, daemon=True)
        t.start()

    def _similarity_candidates(
        self,
        exclude_ea: str | None,
        address_ranges: list[tuple[int, int]] | None,
    ) -> list[tuple[str, list[float]]]:
        """Snapshot the cache, dropping excluded / out-of-range rows."""
        if self.db_changed_since_load():
            self.refresh_from_disk()
        with self._cache_lock:
            if not self._cache:
                return []
            snapshot = list(self._cache.items())
        if exclude_ea is None and not address_ranges:
            return snapshot
        out: list[tuple[str, list[float]]] = []
        for ea, vec in snapshot:
            if ea == exclude_ea:
                continue
            if address_ranges:
                try:
                    ea_int = int(str(ea), 0)
                except (TypeError, ValueError):
                    continue
                if not any(start <= ea_int < end for start, end in address_ranges):
                    continue
            out.append((ea, vec))
        return out

    def similar_vec(
        self,
        query_vec: list[float],
        top_k: int = 5,
        exclude_ea: str | None = None,
        threshold: float = 0.6,
        address_ranges: list[tuple[int, int]] | None = None,
    ) -> list[dict[str, Any]]:
        """Return top-k most similar functions given a pre-computed query vector."""
        candidates = self._similarity_candidates(exclude_ea, address_ranges)
        if not candidates:
            return []
        eas = [ea for ea, _ in candidates]
        vecs = [vec for _, vec in candidates]
        sims = _batch_cosine_similarity(query_vec, vecs)
        scored = [
            (sim, ea)
            for sim, ea in zip(sims, eas, strict=True)
            if sim >= threshold
        ]
        scored.sort(reverse=True)
        if not scored:
            return []
        top_eas = [ea for _, ea in scored[:top_k]]
        meta = self._row_meta_for_eas(top_eas)
        return [
            {
                "ea": ea,
                "name": meta.get(ea, {}).get("name", ea),
                "similarity": round(sim, 4),
                "signature": _clip_signature(str(meta.get(ea, {}).get("signature_text") or "")),
            }
            for sim, ea in scored[:top_k]
        ]

    def similar(
        self,
        pseudocode: str,
        top_k: int = 5,
        exclude_ea: str | None = None,
        threshold: float = 0.6,
        address_ranges: list[tuple[int, int]] | None = None,
    ) -> list[dict[str, Any]]:
        """Return top-k functions similar to *pseudocode* by cosine similarity.

        Embeds the query with the index's embedder, then ranks with
        :meth:`similar_vec` so both entry points share one scoring path.
        """
        if not pseudocode or not str(pseudocode).strip():
            return []
        with self._cache_lock:
            if not self._cache:
                return []
        embed_document = getattr(self._embedder, "embed_document", None)
        if callable(embed_document):
            embedded = embed_document(pseudocode)
            q = getattr(embedded, "vector", embedded)
        else:
            q = self._embedder.embed_vector(pseudocode)
        if q is None:
            return []
        return self.similar_vec(
            q,
            top_k=top_k,
            exclude_ea=exclude_ea,
            threshold=threshold,
            address_ranges=address_ranges,
        )

    def search_text(
        self,
        query: str,
        top_k: int = 10,
        threshold: float = 0.0,
        exclude_ea: str | None = None,
        address_ranges: list[tuple[int, int]] | None = None,
    ) -> list[dict[str, Any]]:
        """Rank indexed functions by lexical overlap over stored signatures and names."""
        q_norm = _normalize_search_text(query)
        q_tokens = set(_tokenize_search_text(query, max_tokens=48))
        if not q_norm and not q_tokens:
            return []

        raw_rows: list[tuple[str, str, str, Any, set[str], str]] = []
        try:
            with closing(self._conn()) as conn:
                for row in conn.execute(
                    "SELECT ea, name, signature_text, indexed_at FROM func_embeddings"
                ):
                    ea = str(row[0])
                    if exclude_ea and ea == exclude_ea:
                        continue
                    if address_ranges:
                        try:
                            ea_int = int(ea, 0)
                        except (TypeError, ValueError):
                            continue
                        if not any(start <= ea_int < end for start, end in address_ranges):
                            continue
                    name = str(row[1] or ea)
                    signature_text = str(row[2] or "")
                    blob = f"{name} {signature_text}".strip()
                    if not blob:
                        continue
                    raw_rows.append((ea, name, signature_text, row[3], set(_tokenize_search_text(blob, max_tokens=160)), blob))
        except Exception:
            return []

        idf = _idf_scores([r[4] for r in raw_rows])
        rows: list[dict[str, Any]] = []
        try:
            for ea, name, signature_text, indexed_at, row_tokens, blob in raw_rows:
                if not row_tokens:
                    continue
                blob_norm = _normalize_search_text(blob)
                token_score, matched = _weighted_token_score(q_tokens, row_tokens, idf)
                exact = 1.0 if q_norm and q_norm in blob_norm else 0.0
                name_norm = name.lower()
                prefix = 0.35 if q_norm and (name_norm.startswith(q_norm) or any(tok.startswith(q_norm) for tok in row_tokens)) else 0.0
                name_bonus = 0.25 if q_tokens and q_tokens.issubset(row_tokens.intersection(set(_tokenize_search_text(name, max_tokens=64)))) else 0.0
                score = round((exact * 1.25) + token_score + prefix + name_bonus, 4)
                if score < float(threshold):
                    continue
                rows.append(
                    {
                        "ea": ea,
                        "name": name,
                        "score": score,
                        "exact_match": bool(exact),
                        "matched_tokens": matched,
                        "signature": _clip_signature(signature_text),
                        "indexed_at": indexed_at,
                    }
                )
        except Exception:
            return []

        rows.sort(
            key=lambda r: (
                float(r.get("score") or 0.0),
                len(r.get("matched_tokens") or []),
                float(r.get("indexed_at") or 0.0),
            ),
            reverse=True,
        )
        return rows[: max(1, int(top_k))]

    def hybrid_search(
        self,
        query: str,
        top_k: int = 10,
        threshold: float = 0.0,
        exclude_ea: str | None = None,
        address_ranges: list[tuple[int, int]] | None = None,
    ) -> list[dict[str, Any]]:
        """Blend semantic similarity with lexical signature overlap."""
        if not query:
            return []

        semantic_hits: list[dict[str, Any]] = []
        lexical_hits = self.search_text(
            query,
            top_k=max(max(1, int(top_k)) * 6, 48),
            threshold=0.0,
            exclude_ea=exclude_ea,
            address_ranges=address_ranges,
        )
        try:
            query_text = _extract_signature_text(query, max_tokens=64) or str(query)
            embed_query = getattr(self._embedder, "embed_query_vector", None)
            query_vec = (
                embed_query(query_text)
                if callable(embed_query)
                else self._embedder.embed_vector(query_text)
            )
            if query_vec is None:
                raise RuntimeError("embedding unavailable")
            semantic_hits = self.similar_vec(
                query_vec,
                top_k=max(max(1, int(top_k)) * 6, 48),
                exclude_ea=exclude_ea,
                threshold=0.0,
                address_ranges=address_ranges,
            )
        except Exception:
            semantic_hits = []

        sem_max = max((float(h.get("similarity") or 0.0) for h in semantic_hits), default=1.0) or 1.0
        lex_max = max((float(h.get("score") or 0.0) for h in lexical_hits), default=1.0) or 1.0
        merged: dict[str, dict[str, Any]] = {}

        for hit in semantic_hits:
            ea = str(hit.get("ea") or "")
            if not ea:
                continue
            merged[ea] = {
                "ea": ea,
                "name": hit.get("name") or ea,
                "similarity": round(float(hit.get("similarity") or 0.0), 4),
                "lexical_score": 0.0,
                "exact_match": False,
                "matched_tokens": [],
                "signature": hit.get("signature") or "",
            }

        for hit in lexical_hits:
            ea = str(hit.get("ea") or "")
            if not ea:
                continue
            row = merged.setdefault(
                ea,
                {
                    "ea": ea,
                    "name": hit.get("name") or ea,
                    "similarity": 0.0,
                    "lexical_score": 0.0,
                    "exact_match": False,
                    "matched_tokens": [],
                    "signature": hit.get("signature") or "",
                },
            )
            row["name"] = row.get("name") or hit.get("name") or ea
            row["lexical_score"] = round(max(float(row.get("lexical_score") or 0.0), float(hit.get("score") or 0.0)), 4)
            row["exact_match"] = bool(row.get("exact_match") or hit.get("exact_match"))
            row["matched_tokens"] = sorted(set(list(row.get("matched_tokens") or []) + list(hit.get("matched_tokens") or [])))[:12]
            if not row.get("signature"):
                row["signature"] = hit.get("signature") or ""

        q_tokens = set(_tokenize_search_text(query, max_tokens=48))
        ranked: list[dict[str, Any]] = []
        for row in merged.values():
            sem_norm = float(row.get("similarity") or 0.0) / sem_max if sem_max > 0 else 0.0
            lex_norm = float(row.get("lexical_score") or 0.0) / lex_max if lex_max > 0 else 0.0
            exact_bonus = 0.12 if row.get("exact_match") else 0.0
            matched = set(row.get("matched_tokens") or [])
            token_coverage = len(q_tokens.intersection(matched)) / max(1, len(q_tokens)) if q_tokens else 0.0
            score = (0.54 * sem_norm) + (0.38 * lex_norm) + (0.08 * token_coverage) + exact_bonus
            row["score"] = round(score, 4)
            row["rank_reason"] = {
                "semantic": round(sem_norm, 4),
                "lexical": round(lex_norm, 4),
                "token_coverage": round(token_coverage, 4),
                "exact": bool(row.get("exact_match")),
            }
            if float(row.get("score") or 0.0) >= float(threshold):
                ranked.append(row)

        ranked.sort(
            key=lambda r: (
                float(r.get("score") or 0.0),
                float(r.get("similarity") or 0.0),
                float(r.get("lexical_score") or 0.0),
            ),
            reverse=True,
        )
        return ranked[: max(1, int(top_k))]

    def search(
        self,
        query_or_vec: Any,
        top_k: int = 10,
        threshold: float = 0.0,
        exclude_ea: str | None = None,
        address_ranges: list[tuple[int, int]] | None = None,
    ) -> list[dict[str, Any]]:
        """Compatibility entrypoint for semantic or hybrid function search."""
        if isinstance(query_or_vec, (list, tuple)):
            try:
                vec = [float(v) for v in query_or_vec]
            except Exception:
                return []
            return self.similar_vec(
                vec,
                top_k=top_k,
                exclude_ea=exclude_ea,
                threshold=threshold,
                address_ranges=address_ranges,
            )
        return self.hybrid_search(
            str(query_or_vec or ""),
            top_k=top_k,
            threshold=threshold,
            exclude_ea=exclude_ea,
            address_ranges=address_ranges,
        )

    def search_structured(
        self,
        constraints: dict[str, Any],
        query: str | None = None,
        top_k: int = 50,
        threshold: float = 0.0,
    ) -> list[dict[str, Any]]:
        """Query functions by structural constraints with optional semantic ranking.

        Constraints (all optional):
          min_size / max_size: function byte size range
          min_bb / max_bb: basic block count range
          has_loops: bool
          min_api / max_api: API call count range
          min_strings / max_strings: string reference count range
          segment: str (e.g. ".text")
          is_thunk: bool
          min_cyclomatic / max_cyclomatic: complexity range
          apis: list[str] — functions calling these APIs
          query: str — optional semantic query for ranking
        """
        clauses = []
        params = []
        if constraints.get("min_size") is not None:
            clauses.append("func_size >= ?")
            params.append(int(constraints["min_size"]))
        if constraints.get("max_size") is not None:
            clauses.append("func_size <= ?")
            params.append(int(constraints["max_size"]))
        if constraints.get("min_bb") is not None:
            clauses.append("bb_count >= ?")
            params.append(int(constraints["min_bb"]))
        if constraints.get("max_bb") is not None:
            clauses.append("bb_count <= ?")
            params.append(int(constraints["max_bb"]))
        if constraints.get("has_loops") is not None:
            clauses.append("has_loops = ?")
            params.append(1 if constraints["has_loops"] else 0)
        if constraints.get("min_api") is not None:
            clauses.append("api_count >= ?")
            params.append(int(constraints["min_api"]))
        if constraints.get("max_api") is not None:
            clauses.append("api_count <= ?")
            params.append(int(constraints["max_api"]))
        if constraints.get("min_strings") is not None:
            clauses.append("string_count >= ?")
            params.append(int(constraints["min_strings"]))
        if constraints.get("max_strings") is not None:
            clauses.append("string_count <= ?")
            params.append(int(constraints["max_strings"]))
        if constraints.get("segment"):
            clauses.append("segment = ?")
            params.append(str(constraints["segment"]))
        if constraints.get("is_thunk") is not None:
            clauses.append("is_thunk = ?")
            params.append(1 if constraints["is_thunk"] else 0)
        if constraints.get("min_cyclomatic") is not None:
            clauses.append("cyclomatic >= ?")
            params.append(int(constraints["min_cyclomatic"]))
        if constraints.get("max_cyclomatic") is not None:
            clauses.append("cyclomatic <= ?")
            params.append(int(constraints["max_cyclomatic"]))

        sql = "SELECT ea, name, func_size, bb_count, has_loops, api_count, string_count, segment, is_thunk, cyclomatic FROM func_embeddings"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)

        rows = []
        try:
            with closing(self._conn()) as conn:
                for row in conn.execute(sql, params):
                    rows.append({
                        "ea": str(row[0]),
                        "name": str(row[1] or row[0]),
                        "func_size": int(row[2] or 0),
                        "bb_count": int(row[3] or 0),
                        "has_loops": bool(row[4]),
                        "api_count": int(row[5] or 0),
                        "string_count": int(row[6] or 0),
                        "segment": str(row[7] or ""),
                        "is_thunk": bool(row[8]),
                        "cyclomatic": int(row[9] or 0),
                    })
        except Exception:
            return []

        # Optional API filter (checks signature_text for API names)
        if constraints.get("apis"):
            apis = constraints["apis"] if isinstance(constraints["apis"], list) else [constraints["apis"]]
            filtered = []
            for r in rows:
                # Check if any requested API appears in the function's signature
                try:
                    with closing(self._conn()) as conn:
                        sig_row = conn.execute("SELECT signature_text FROM func_embeddings WHERE ea=?", (r["ea"],)).fetchone()
                        sig = str(sig_row[0] or "") if sig_row else ""
                        if any(api.lower() in sig.lower() for api in apis):
                            filtered.append(r)
                except Exception:
                    pass
            rows = filtered

        # Optional semantic ranking
        if query:
            q_lower = query.lower()
            for r in rows:
                name_score = 2.0 if q_lower in r["name"].lower() else 0.0
                size_score = 1.0 / (1.0 + abs(r["func_size"] - 200) / 200)
                r["score"] = name_score + size_score
            rows.sort(key=lambda r: r.get("score", 0), reverse=True)

        return rows[: max(1, int(top_k))]

    def cache_store(self, ea: str, vec: list[float]) -> None:
        with self._cache_lock:
            self._cache[ea] = vec

    def cache_snapshot(self) -> list[tuple[str, list[float]]]:
        with self._cache_lock:
            return list(self._cache.items())

    def cache_keys(self) -> set:
        with self._cache_lock:
            return set(self._cache.keys())

    @property
    def size(self) -> int:
        with self._cache_lock:
            return len(self._cache)
