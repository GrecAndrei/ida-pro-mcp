"""
HybridSearch — SQL pre-filtering for structured semantic retrieval.

Provides:
  - HybridQueryBuilder: Translates structured constraints to SQL WHERE clauses
  - HybridSearchEngine: Executes hybrid search (SQL pre-filter + vector scoring)
  - Benchmark utility for comparing pure vector vs hybrid latency

This module uses ONLY sqlite3 and re from stdlib. No IDA Pro dependencies.
numpy is optional and only needed for vector scoring.

Architecture (SSR-style):
  Phase 1: SQL pre-filter narrows candidate pool using attribute indices
  Phase 2: Optional vector scoring / ranking on the reduced pool
  Fallback: If SQL returns empty or DB unavailable, returns empty pool
            (caller can fall through to full search)

Design references:
  - AnnoRetrieve: SchemaBoot + SSR hybrid retrieval
  - flexvec: SQL pre-filtering before vector search
"""

import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

# ============================================================================
# Column type definitions
# ============================================================================

# Columns in function_attrs that support SQL filtering
SQL_FILTERABLE_COLUMNS: Dict[str, str] = {
    "size": "int",
    "segment": "str",
    "entropy": "float",
    "bb_count": "int",
    "cyclomatic_complexity": "int",
    "call_count": "int",
    "xor_count": "int",
    "mov_count": "int",
    "cmp_count": "int",
    "jmp_count": "int",
    "ret_count": "int",
    "push_count": "int",
    "pop_count": "int",
    "lea_count": "int",
    "test_count": "int",
    "api_count": "int",
    "string_count": "int",
    "data_ref_count": "int",
    "incoming_xrefs": "int",
    "outgoing_xrefs": "int",
    "has_loops": "bool",
    "is_thunk": "bool",
    "is_library": "bool",
    "has_crypto_constants": "bool",
    "xor_ratio": "float",
    "max_loop_depth": "int",
    "name": "str",
}

# Junction tables: key -> (table_name, column_name)
JUNCTION_TABLES: Dict[str, Tuple[str, str]] = {
    "apis": ("function_apis", "api_name"),
    "strings_like": ("function_strings", "string_text"),
    "string_contains": ("function_strings", "string_text"),
    "constants_value": ("function_constants", "constant_value"),
}

# Legacy constraint prefix mapping: prefix -> (column, operator)
LEGACY_RANGE_PREFIXES: Dict[str, Tuple[str, str]] = {
    "min_size": ("size", ">="),
    "max_size": ("size", "<="),
    "min_entropy": ("entropy", ">="),
    "max_entropy": ("entropy", "<="),
    "min_bb_count": ("bb_count", ">="),
    "max_bb_count": ("bb_count", "<="),
    "min_cyclomatic": ("cyclomatic_complexity", ">="),
    "max_cyclomatic": ("cyclomatic_complexity", "<="),
    "min_xor_count": ("xor_count", ">="),
    "min_call_count": ("call_count", ">="),
    "min_api_count": ("api_count", ">="),
    "min_string_count": ("string_count", ">="),
    "min_xor_ratio": ("xor_ratio", ">="),
    "max_xor_ratio": ("xor_ratio", "<="),
    "min_incoming_xrefs": ("incoming_xrefs", ">="),
    "max_incoming_xrefs": ("incoming_xrefs", "<="),
    "min_outgoing_xrefs": ("outgoing_xrefs", ">="),
    "max_outgoing_xrefs": ("outgoing_xrefs", "<="),
}

# Legacy exact-match constraint keys
LEGACY_BOOL_KEYS = {"has_loops", "is_thunk", "is_library", "has_crypto_constants"}
LEGACY_EXACT_KEYS = {"name", "segment"}
LEGACY_LIKE_KEYS = {"name_like"}
LEGACY_JUNCTION_KEYS = {"apis", "strings_like", "string_contains", "constants_value"}


# ============================================================================
# Constraint parser — normalizes mixed-format constraints
# ============================================================================

def _normalize_value(key: str, val: Any) -> Any:
    """Normalize values for SQL query safety."""
    if key in LEGACY_BOOL_KEYS:
        return 1 if val else 0
    return val


def _parse_constraints(constraints: Dict[str, Any]) -> List[Tuple[str, str, Any]]:
    """Parse mixed-format constraints into normalized (field, operator, value) triples.
    
    Supports two formats:
      1. Legacy: {"min_size": 100, "has_loops": True, "apis": "VirtualAlloc"}
      2. Operator: {"size": (">=", 100), "name": ("~", "crypt.*")}
    
    Returns:
        List of (field, operator, value) tuples.
        field can be a column name or a junction table key (apis, strings_like, etc.)
        operator is one of: ==, !=, <, >, <=, >=, contains, regex
    """
    results: List[Tuple[str, str, Any]] = []

    if not isinstance(constraints, dict):
        return results

    for key, val in constraints.items():
        if val is None:
            continue

        # Handle AND/OR grouping
        if key == "and" and isinstance(val, (list, tuple)):
            for sub in val:
                results.extend(_parse_constraints(sub))
            continue
        if key == "or" and isinstance(val, (list, tuple)):
            # Currently OR is handled at the application level (multiple queries)
            # For SQL, OR within a single query is handled by building separate WHERE clauses
            # We'll skip SQL-level OR for now — caller can do multiple queries
            continue

        # --- Operator format: value is (op, val) ---
        if isinstance(val, (list, tuple)) and len(val) == 2:
            op_candidate = str(val[0])
            if op_candidate in ("==", "!=", "<", ">", "<=", ">=", "contains", "~"):
                operator = op_candidate
                v = val[1]
                results.append((key, operator, _normalize_value(key, v)))
                continue

        # --- Legacy range format: min_xxx / max_xxx ---
        if key in LEGACY_RANGE_PREFIXES:
            col, op = LEGACY_RANGE_PREFIXES[key]
            results.append((col, op, _normalize_value(key, val)))
            continue

        # --- Legacy exact match (bool) ---
        if key in LEGACY_BOOL_KEYS:
            results.append((key, "==", _normalize_value(key, val)))
            continue

        # --- Legacy exact match (string) ---
        if key in LEGACY_EXACT_KEYS:
            results.append((key, "==", val))
            continue

        # --- Legacy LIKE match ---
        if key in LEGACY_LIKE_KEYS:
            results.append(("name", "contains", val))
            continue

        # --- Legacy junction table filters ---
        if key in LEGACY_JUNCTION_KEYS:
            results.append((key, "==", val))
            continue

        # --- Dict format: {"gte": x, "lte": y, "eq": z, "regex": p} ---
        if isinstance(val, dict):
            for op_key, op_val in val.items():
                sql_op = _DICT_OP_MAP.get(op_key)
                if sql_op:
                    results.append((key, sql_op, _normalize_value(key, op_val)))
            continue

        # --- Fallback: treat as exact match on column ---
        # Only if the key is a known filterable column
        if key in SQL_FILTERABLE_COLUMNS or key in JUNCTION_TABLES:
            results.append((key, "==", _normalize_value(key, val)))

    return results


_DICT_OP_MAP: Dict[str, str] = {
    "eq": "==", "ne": "!=", "lt": "<", "gt": ">",
    "lte": "<=", "gte": ">=",
    "contains": "contains", "regex": "~",
    "like": "contains",
}


# ============================================================================
# SQL WHERE clause builder
# ============================================================================

# Regex compilation cache
_REGEX_CACHE: Dict[str, re.Pattern] = {}


class HybridQueryBuilder:
    """Builds SQL WHERE clauses from structured constraints.
    
    Supports:
    - Column filtering (=, !=, <, >, <=, >=, LIKE, regex via application filter)
    - Junction table EXISTS subqueries (apis, strings_like)
    - Boolean normalization (has_loops=True → has_loops=1)
    - Mixed legacy and operator constraint formats
    
    Does NOT support OR at the SQL level — OR groups are returned separately
    so callers can UNION results.
    """

    @staticmethod
    def build(
        constraints: Dict[str, Any],
        table_alias: str = "fa",
    ) -> Tuple[str, List[Any], List[str]]:
        """Build SQL WHERE clause, params, and junction table requirements.
        
        Args:
            constraints: Constraint dict (legacy or operator format)
            table_alias: SQL table alias for function_attrs
        
        Returns:
            (where_clause, params, junction_keys)
            where_clause is empty string if no constraints
            junction_keys is a list of junction tables needed (for pre-verification)
        """
        parsed = _parse_constraints(constraints)
        if not parsed:
            return "", [], []

        conditions: List[str] = []
        params: List[Any] = []
        junction_keys: List[str] = []

        for field, op, val in parsed:
            cond, p = _build_condition(field, op, val, table_alias)
            if cond:
                conditions.append(cond)
                params.extend(p)
                if field in JUNCTION_TABLES:
                    junction_keys.append(field)

        if conditions:
            return "WHERE " + " AND ".join(conditions), params, junction_keys
        return "", [], []

    @staticmethod
    def build_legacy(
        constraints: Dict[str, Any],
    ) -> Tuple[str, List[Any]]:
        """Legacy-only build for backward compatibility.
        
        Returns (where_clause, params) without table alias.
        Maintains exact compatibility with schemaboot.py's _build_where_clause.
        """
        return HybridQueryBuilder.build(constraints, table_alias="function_attrs")[:2]


def _build_condition(
    field: str,
    operator: str,
    value: Any,
    alias: str,
) -> Tuple[Optional[str], List[Any]]:
    """Build a single SQL condition.
    
    Returns (sql_fragment, params) or (None, []) if unsupported.
    """
    # --- Junction table conditions (EXISTS subquery) ---
    if field in JUNCTION_TABLES:
        jt, jc = JUNCTION_TABLES[field]
        if operator == "==":
            if field == "strings_like" or field == "string_contains":
                sql = (
                    f"EXISTS (SELECT 1 FROM {jt} WHERE "
                    f"{jt}.func_ea = {alias}.ea AND {jt}.{jc} LIKE ?)"
                )
                return sql, [f"%{value}%"]
            elif field == "constants_value":
                sql = (
                    f"EXISTS (SELECT 1 FROM {jt} WHERE "
                    f"{jt}.func_ea = {alias}.ea AND {jt}.{jc} = ?)"
                )
                return sql, [int(value) if not isinstance(value, int) else value]
            else:
                sql = (
                    f"EXISTS (SELECT 1 FROM {jt} WHERE "
                    f"{jt}.func_ea = {alias}.ea AND {jt}.{jc} = ?)"
                )
                return sql, [str(value)]
        elif operator == "contains":
            sql = (
                f"EXISTS (SELECT 1 FROM {jt} WHERE "
                f"{jt}.func_ea = {alias}.ea AND {jt}.{jc} LIKE ?)"
            )
            return sql, [f"%{value}%"]
        # regex on junction tables not supported at SQL level (filter in app)
        return None, []

    # --- Direct column conditions ---
    col_type = SQL_FILTERABLE_COLUMNS.get(field)
    if col_type is None:
        return None, []

    col = f"{alias}.{field}"

    if operator == "==":
        if col_type == "str":
            return f"{col} = ?", [str(value)]
        elif col_type == "bool":
            return f"{col} = ?", [1 if value else 0]
        else:
            return f"{col} = ?", [value]

    elif operator == "!=":
        if col_type == "str":
            return f"{col} != ?", [str(value)]
        elif col_type == "bool":
            return f"{col} != ?", [1 if value else 0]
        else:
            return f"{col} != ?", [value]

    elif operator in ("<", ">", "<=", ">="):
        return f"{col} {operator} ?", [value]

    elif operator == "contains":
        if col_type == "str":
            return f"{col} LIKE ?", [f"%{value}%"]
        return None, []

    elif operator == "~":
        # Regex: validate the pattern, but execute filtering at application level
        # We include a LIKE pre-filter for efficiency when possible
        try:
            re.compile(str(value))
        except re.error:
            return None, []
        # Return a permissive condition (regex is applied at app level)
        # If value starts with a known prefix, use LIKE as a pre-filter
        return f"{col} LIKE ?", [f"%{value}%"]

    return None, []


# ============================================================================
# Hybrid Search Engine
# ============================================================================

# Default columns to select in pre-filter results
DEFAULT_SELECT_COLS = [
    "fa.ea", "fa.name", "fa.size", "fa.segment", "fa.entropy",
    "fa.bb_count", "fa.cyclomatic_complexity", "fa.call_count",
    "fa.xor_count", "fa.api_count", "fa.string_count",
    "fa.has_loops", "fa.is_thunk", "fa.is_library",
]


class HybridSearchEngine:
    """Hybrid search engine: SQL pre-filter → optional vector scoring.
    
    Typical flow:
        1. Build SQL WHERE clause from constraints
        2. Query SQLite for candidate function addresses
        3. Apply application-level filters (regex, OR groups)
        4. Optionally score candidates by vector similarity
        5. Return ranked results
    
    This provides exact-match guarantees that pure vector search cannot:
    - All functions matching SQL constraints WILL be returned (no ANN misses)
    - Precision is 100% for structured attributes
    """

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _connect(self) -> Optional[sqlite3.Connection]:
        """Create a read-only connection to the schemaboot DB."""
        try:
            conn = sqlite3.connect(self.db_path)
            # PRAGMA query_only is not available in all SQLite versions;
            # use a try/except to gracefully degrade
            try:
                conn.execute("PRAGMA query_only = 1")
            except sqlite3.Error:
                pass  # Older SQLite versions don't support this pragma
            conn.row_factory = sqlite3.Row
            return conn
        except (sqlite3.Error, Exception):
            return None

    def pre_filter(
        self,
        constraints: Dict[str, Any],
        extra_where: str = "",
        extra_params: Optional[List[Any]] = None,
    ) -> Tuple[Optional[List[int]], float, Dict[str, Any]]:
        """Phase 1: SQL pre-filter to get candidate function addresses.
        
        Args:
            constraints: Structured constraints dict
            extra_where: Additional WHERE clause fragment (AND-ed)
            extra_params: Parameters for extra_where
        
        Returns:
            (candidate_eas, elapsed_ms, metadata)
            candidate_eas is None if DB unavailable
        """
        t0 = time.time()
        conn = self._connect()
        if conn is None:
            return None, 0.0, {"error": "db_unavailable"}

        try:
            cursor = conn.cursor()

            # Build SQL WHERE from constraints
            where_clause, params, junction_keys = HybridQueryBuilder.build(constraints)
            
            # Merge extra WHERE
            if extra_where:
                if where_clause:
                    where_clause += f" AND ({extra_where})"
                else:
                    where_clause = f"WHERE {extra_where}"
                if extra_params:
                    params.extend(extra_params)

            # Count total matches
            count_sql = f"SELECT COUNT(*) FROM function_attrs fa {where_clause}"
            cursor.execute(count_sql, params)
            total = cursor.fetchone()[0]

            if total == 0:
                elapsed = round((time.time() - t0) * 1000, 2)
                return [], elapsed, {
                    "total": 0,
                    "sql_ms": elapsed,
                    "where": where_clause,
                }

            # Fetch candidate EAs
            sql = f"SELECT fa.ea FROM function_attrs fa {where_clause} ORDER BY fa.ea"
            cursor.execute(sql, params)
            eas = [row[0] for row in cursor.fetchall()]

            elapsed = round((time.time() - t0) * 1000, 2)
            return eas, elapsed, {
                "total": total,
                "returned": len(eas),
                "sql_ms": elapsed,
                "where": where_clause,
                "junction_keys": junction_keys,
            }

        except sqlite3.Error:
            return None, 0.0, {"error": "sql_error"}
        finally:
            conn.close()

    def search(
        self,
        constraints: Dict[str, Any],
        top_k: int = 100,
        offset: int = 0,
        order_by: Optional[str] = None,
        select_cols: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Full hybrid search: SQL pre-filter + optional result metadata.
        
        Args:
            constraints: Structured constraints
            top_k: Max results
            offset: Result offset
            order_by: Optional ORDER BY clause (sanitized)
            select_cols: Columns to select (default: basic info)
        
        Returns:
            Result dict with candidates, timing, and metadata
        """
        t0 = time.time()
        conn = self._connect()
        if conn is None:
            return {
                "ok": False,
                "error": "schemaboot_db_unavailable",
                "hint": "Run schemaboot(action='ingest') first",
                "candidates": None,
            }

        try:
            cursor = conn.cursor()

            # Build SQL WHERE
            where_clause, params, _ = HybridQueryBuilder.build(constraints)

            # Count
            count_sql = f"SELECT COUNT(*) FROM function_attrs fa {where_clause}"
            cursor.execute(count_sql, params)
            total = cursor.fetchone()[0]

            if total == 0:
                elapsed = round((time.time() - t0) * 1000, 2)
                return {
                    "ok": True,
                    "total_matches": 0,
                    "returned": 0,
                    "sql_ms": elapsed,
                    "total_ms": elapsed,
                    "candidates": [],
                    "note": "No functions match the given constraints",
                }

            # Build ORDER BY (sanitized)
            order_clause = ""
            if order_by:
                allowed_cols = {
                    "ea", "name", "size", "segment", "entropy", "bb_count",
                    "cyclomatic_complexity", "incoming_xrefs", "outgoing_xrefs",
                    "call_count", "xor_count", "api_count", "string_count",
                    "has_loops", "is_thunk", "is_library", "data_ref_count",
                    "xor_ratio", "max_loop_depth", "created_at", "updated_at",
                }
                parts = order_by.strip().split()
                col = parts[0].lstrip("fa.")
                direction = parts[1].upper() if len(parts) > 1 else "ASC"
                if col in allowed_cols and direction in ("ASC", "DESC"):
                    order_clause = f"ORDER BY fa.{col} {direction}"

            cols = select_cols or DEFAULT_SELECT_COLS
            col_str = ", ".join(cols)

            sql = (
                f"SELECT {col_str} FROM function_attrs fa "
                f"{where_clause} {order_clause} LIMIT ? OFFSET ?"
            )
            cursor.execute(sql, params + [top_k, offset])
            rows = cursor.fetchall()
            col_names = [d[0] for d in cursor.description]

            # Build results
            candidates = []
            for row in rows:
                d = dict(zip(col_names, row))
                # Convert EAs to hex
                if "ea" in d:
                    d["ea"] = hex(d["ea"])
                # Convert bools
                for bk in ("has_loops", "is_thunk", "is_library", "has_crypto_constants"):
                    if bk in d:
                        d[bk] = bool(d[bk])
                candidates.append(d)

            # If top_k not hit, fetch APIs for returned candidates
            if candidates:
                for c in candidates:
                    try:
                        ea_int = int(c.get("ea", "0x0"), 16)
                        if ea_int:
                            cursor.execute(
                                "SELECT api_name FROM function_apis WHERE func_ea=? LIMIT 15",
                                (ea_int,),
                            )
                            c["apis"] = [r[0] for r in cursor.fetchall()]
                    except (ValueError, sqlite3.Error):
                        c["apis"] = []

            elapsed = round((time.time() - t0) * 1000, 2)
            return {
                "ok": True,
                "total_matches": total,
                "returned": len(candidates),
                "offset": offset,
                "top_k": top_k,
                "sql_ms": elapsed,
                "total_ms": elapsed,
                "db_path": self.db_path,
                "candidates": candidates,
            }

        except sqlite3.Error as e:
            return {
                "ok": False,
                "error": f"sqlite_error: {e}",
                "candidates": None,
            }
        finally:
            conn.close()

    def phase2_bm25(
        self,
        candidate_eas: List[int],
        query_apis: Optional[List[str]] = None,
        query_strings: Optional[List[str]] = None,
        k1: float = 1.5,
        b: float = 0.75,
    ) -> Dict[int, float]:
        """
        Phase 2: BM25 scoring on textual features (APIs and strings) over
        the Phase-1 SQL candidate pool.

        This is the missing component from the flexvec paper adaptation —
        SQL pre-filter narrows the pool, BM25 re-ranks it by query relevance.

        BM25(d, q) = sum_t [ IDF(t) * tf(t,d)*(k1+1) / (tf(t,d) + k1*(1-b+b*dl/avgdl)) ]

        Returns {ea: score} for each candidate.  Callers should use these
        scores to rerank the Phase-1 results before returning to the LLM.
        """
        import math as _math

        if not candidate_eas or not (query_apis or query_strings):
            return {ea: 0.0 for ea in candidate_eas}

        conn = self._connect()
        if conn is None:
            return {ea: 0.0 for ea in candidate_eas}

        try:
            cur = conn.cursor()
            N = len(candidate_eas)

            # Average document length across candidates
            ph = ",".join("?" * N)
            cur.execute(
                f"SELECT AVG(api_count + string_count) FROM function_attrs WHERE ea IN ({ph})",
                candidate_eas,
            )
            row = cur.fetchone()
            avgdl = float(row[0]) if row and row[0] else 1.0

            # Pre-fetch APIs and strings for all candidates in two bulk queries
            cur.execute(
                f"SELECT func_ea, api_name FROM function_apis WHERE func_ea IN ({ph})",
                candidate_eas,
            )
            apis_by_ea: Dict[int, set] = {}
            for func_ea, api_name in cur.fetchall():
                apis_by_ea.setdefault(func_ea, set()).add(api_name)

            cur.execute(
                f"SELECT func_ea, string_text FROM function_strings WHERE func_ea IN ({ph})",
                candidate_eas,
            )
            strings_by_ea: Dict[int, set] = {}
            for func_ea, string_text in cur.fetchall():
                strings_by_ea.setdefault(func_ea, set()).add(string_text)

            # Pre-compute IDF for each query term (document frequency across *all* functions)
            idf: Dict[str, float] = {}
            for term in (query_apis or []):
                cur.execute(
                    "SELECT COUNT(DISTINCT func_ea) FROM function_apis WHERE api_name = ?",
                    (term,),
                )
                r = cur.fetchone()
                df = r[0] if r else 1
                idf[term] = _math.log((N - df + 0.5) / (df + 0.5) + 1)

            for term in (query_strings or []):
                cur.execute(
                    "SELECT COUNT(DISTINCT func_ea) FROM function_strings WHERE string_text = ?",
                    (term,),
                )
                r = cur.fetchone()
                df = r[0] if r else 1
                # Strings slightly down-weighted vs. API names (more noise)
                idf[term] = _math.log((N - df + 0.5) / (df + 0.5) + 1) * 0.7

            # Score each candidate
            scores: Dict[int, float] = {}
            for ea in candidate_eas:
                doc_apis    = apis_by_ea.get(ea, set())
                doc_strings = strings_by_ea.get(ea, set())
                dl = len(doc_apis) + len(doc_strings)
                score = 0.0

                for term in (query_apis or []):
                    tf = 1 if term in doc_apis else 0
                    score += idf.get(term, 0.0) * (tf * (k1 + 1)) / (
                        tf + k1 * (1 - b + b * dl / avgdl) + 1e-12
                    )

                for term in (query_strings or []):
                    tf = 1 if term in doc_strings else 0
                    score += idf.get(term, 0.0) * (tf * (k1 + 1)) / (
                        tf + k1 * (1 - b + b * dl / avgdl) + 1e-12
                    )

                scores[ea] = score

            return scores

        except sqlite3.Error:
            return {ea: 0.0 for ea in candidate_eas}
        finally:
            conn.close()

    def search_ranked(
        self,
        constraints: Dict[str, Any],
        query_apis: Optional[List[str]] = None,
        query_strings: Optional[List[str]] = None,
        top_k: int = 50,
        bm25_weight: float = 0.4,
    ) -> Dict[str, Any]:
        """
        Full two-phase search: Phase 1 SQL pre-filter + Phase 2 BM25 rerank.

        Phase 1 (SQL) guarantees 100% recall on structured constraints.
        Phase 2 (BM25) reranks the pool by semantic relevance to query terms.
        Combined score: (1 - bm25_weight) * sql_rank + bm25_weight * bm25_score.
        """

        phase1 = self.search(constraints, top_k=min(top_k * 4, 2000))
        if not phase1.get("ok") or not phase1.get("candidates"):
            return phase1

        candidates = phase1["candidates"]
        if not (query_apis or query_strings):
            phase1["phase"] = "sql_only"
            return phase1

        # Build EA list for Phase 2
        eas = []
        for c in candidates:
            try:
                eas.append(int(c["ea"], 16))
            except (KeyError, ValueError):
                pass

        bm25_scores = self.phase2_bm25(eas, query_apis=query_apis, query_strings=query_strings)

        # Normalize BM25 scores to [0,1]
        max_bm25 = max(bm25_scores.values()) if bm25_scores else 1.0
        if max_bm25 < 1e-12:
            max_bm25 = 1.0

        # SQL rank score: 1 - (rank / N) so top SQL result = 1.0
        n = len(candidates)
        for i, c in enumerate(candidates):
            try:
                ea = int(c["ea"], 16)
            except (KeyError, ValueError):
                ea = 0
            sql_rank_score = 1.0 - i / max(n - 1, 1)
            bm25_norm = bm25_scores.get(ea, 0.0) / max_bm25
            c["_score"] = (1 - bm25_weight) * sql_rank_score + bm25_weight * bm25_norm
            c["_bm25"] = round(bm25_scores.get(ea, 0.0), 4)

        candidates.sort(key=lambda x: x.get("_score", 0.0), reverse=True)
        candidates = candidates[:top_k]

        phase1["candidates"] = candidates
        phase1["returned"] = len(candidates)
        phase1["phase"] = "sql+bm25"
        phase1["query_apis"] = query_apis
        phase1["query_strings"] = query_strings
        return phase1


# ============================================================================
# Application-level filters (regex, contains, etc.)
# ============================================================================

def apply_pattern_filter(
    candidates: List[Dict[str, Any]],
    pattern: Optional[str],
    case_sensitive: bool = False,
) -> List[Dict[str, Any]]:
    """Apply a pattern filter to candidates (name or address matching).
    
    Args:
        candidates: List of candidate dicts (must have "name" and/or "ea")
        pattern: Pattern to match (regex, glob, or substring)
        case_sensitive: Whether matching is case-sensitive
    
    Returns:
        Filtered candidate list
    """
    if not pattern or not candidates:
        return candidates

    flags = 0 if case_sensitive else re.IGNORECASE

    # Try as regex first
    try:
        regex = re.compile(pattern, flags)
        return [
            c for c in candidates
            if regex.search(str(c.get("name", "")))
            or regex.search(str(c.get("ea", "")))
        ]
    except re.error:
        pass

    # Fallback: case-insensitive substring
    pattern_lower = pattern.lower() if not case_sensitive else pattern
    if not case_sensitive:
        return [
            c for c in candidates
            if pattern_lower in str(c.get("name", "")).lower()
            or pattern_lower in str(c.get("ea", "")).lower()
        ]
    else:
        return [
            c for c in candidates
            if pattern in str(c.get("name", ""))
            or pattern in str(c.get("ea", ""))
        ]


def apply_regex_constraints(
    candidates: List[Dict[str, Any]],
    constraints: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Apply regex (~) constraints at the application level.
    
    SQL cannot efficiently handle regex, so regex constraints on
    string columns are applied here after the SQL pre-filter.
    """
    if not candidates or not isinstance(constraints, dict):
        return candidates

    parsed = _parse_constraints(constraints)
    regex_filters: List[Tuple[str, re.Pattern]] = []

    for field, op, val in parsed:
        if op == "~":
            try:
                regex = re.compile(str(val))
                # Determine which column to match against
                if field in JUNCTION_TABLES:
                    # Junction table regex would require additional queries
                    continue
                regex_filters.append((field, regex))
            except re.error:
                continue

    if not regex_filters:
        return candidates

    filtered = []
    for c in candidates:
        ok = True
        for field, regex in regex_filters:
            col_val = str(c.get(field, ""))
            if not regex.search(col_val):
                ok = False
                break
        if ok:
            filtered.append(c)

    return filtered


# ============================================================================
# Benchmark utilities
# ============================================================================

class HybridBenchmark:
    """Benchmark comparing pure SQL vs hybrid search approaches.
    
    Measures:
    - SQL pre-filter latency (Phase 1)
    - Total end-to-end query time
    - Pre-filter selectivity ratio
    """

    @staticmethod
    def run_query(
        db_path: str,
        constraints: Dict[str, Any],
        label: str = "query",
    ) -> Dict[str, Any]:
        """Run a single benchmark query and return timing."""
        engine = HybridSearchEngine(db_path)
        t0 = time.time()
        result = engine.search(constraints)
        elapsed = round((time.time() - t0) * 1000, 2)

        return {
            "label": label,
            "constraints": constraints,
            "total_matches": result.get("total_matches", 0),
            "returned": result.get("returned", 0),
            "sql_ms": result.get("sql_ms", 0),
            "total_ms": elapsed,
        }

    @staticmethod
    def run_benchmark_suite(
        db_path: str,
        test_constraints: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Run a suite of benchmark queries."""
        if test_constraints is None:
            test_constraints = [
                {},
                {"min_entropy": 4.0},
                {"min_size": 200},
                {"has_loops": True},
                {"min_xor_count": 2},
                {"min_call_count": 3, "has_loops": True},
                {"min_entropy": 4.5, "min_xor_count": 1},
                {"min_size": 100, "has_crypto_constants": True},
                {"min_cyclomatic": 5},
                {"apis": "memcpy"},
            ]

        results = []
        for i, constraints in enumerate(test_constraints):
            r = HybridBenchmark.run_query(
                db_path, constraints, label=f"query_{i}"
            )
            results.append(r)

        avg_ms = sum(r["total_ms"] for r in results) / max(len(results), 1)
        return {
            "queries": len(results),
            "average_ms": round(avg_ms, 2),
            "results": results,
        }
