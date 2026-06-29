from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional

from ..stores.symbol_db import SymbolDB
from .bridge_retrieval import MultiHopBridgeIndex
from .structural_index import get_db_path


class PPAAEngine:
    """Predictive Pointer & Address Anticipator (PPAA) Engine.

    Queries local SchemaBoot indexes, Multi-Hop Bridge indexes, and SymbolDB
    to retrieve pre-computed function details, string references, constants,
    and related nodes without querying the live IDA process.
    """

    def __init__(self, idb_path: Optional[str] = None):
        self.idb_path = idb_path
        self.db_path = get_db_path(idb_path) if idb_path else None

        # Initialize bridge search index
        self.bridge_index = None
        if self.db_path and os.path.exists(self.db_path):
            with contextlib.suppress(Exception):
                self.bridge_index = MultiHopBridgeIndex(self.db_path)

        # Lazy symbol DB
        self._symbol_db = None

    @property
    def symbol_db(self) -> Optional[SymbolDB]:
        if self._symbol_db is None:
            with contextlib.suppress(Exception):
                self._symbol_db = SymbolDB()
        return self._symbol_db

    def _conn(self) -> Optional[sqlite3.Connection]:
        if not self.db_path or not os.path.exists(self.db_path):
            return None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            return conn
        except Exception:
            return None

    def query_function_metadata(self, ea: int) -> Optional[Dict[str, Any]]:
        """Retrieve attributes, APIs, constants, and strings for a function."""
        conn = self._conn()
        if not conn:
            return None
        try:
            cur = conn.cursor()
            # 1. Fetch function characteristics
            cur.execute(
                """
                SELECT name, size, segment, is_thunk, is_library, bb_count, cyclomatic_complexity,
                       incoming_xrefs, outgoing_xrefs, entropy, call_count, cfg_hash, reconstructed_structs
                FROM function_attrs WHERE ea = ?
                """,
                (ea,),
            )
            row = cur.fetchone()
            if not row:
                conn.close()
                return None

            meta = {
                "name": row[0],
                "size": row[1],
                "segment": row[2],
                "is_thunk": bool(row[3]),
                "is_library": bool(row[4]),
                "bb_count": row[5],
                "cyclomatic_complexity": row[6],
                "incoming_xrefs": row[7],
                "outgoing_xrefs": row[8],
                "entropy": row[9],
                "call_count": row[10],
                "cfg_hash": row[11],
                "reconstructed_structs": json.loads(row[12]) if row[12] else [],
            }

            # 2. Fetch referenced APIs
            cur.execute("SELECT api_name FROM function_apis WHERE func_ea = ?", (ea,))
            meta["referenced_apis"] = sorted({r[0] for r in cur.fetchall()})

            # 3. Fetch referenced strings
            cur.execute("SELECT string_text, string_ea FROM function_strings WHERE func_ea = ?", (ea,))
            meta["referenced_strings"] = [
                {"text": r[0], "ea": hex(r[1])} for r in cur.fetchall()
            ]

            # 4. Fetch referenced constants
            cur.execute("SELECT constant_value, constant_name FROM function_constants WHERE func_ea = ?", (ea,))
            meta["referenced_constants"] = [
                {"value": r[0], "name": r[1]} for r in cur.fetchall()
            ]

            conn.close()
            return meta
        except Exception:
            with contextlib.suppress(Exception):
                conn.close()
            return None

    def query_symbol_analogy(self, name: str) -> Optional[Dict[str, Any]]:
        """Lookup renaming and analysis analogies in SymbolDB."""
        if not self.symbol_db or not name:
            return None
        try:
            with self.symbol_db._conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT symbol_name, source_binary, confidence
                    FROM symbols WHERE symbol_name = ? LIMIT 1
                    """,
                    (name,),
                )
                row = cur.fetchone()
                if row:
                    return {
                        "matched_symbol": row[0],
                        "source_binary": row[1],
                        "confidence": float(row[2]),
                    }
        except Exception:
            pass
        return None

    def query_functions_by_cfg_hash(self, cfg_hash: str, exclude_ea: Optional[int] = None) -> List[Dict[str, Any]]:
        """Find functions with the matching cfg_hash."""
        conn = self._conn()
        if not conn or not cfg_hash:
            return []
        try:
            cur = conn.cursor()
            if exclude_ea is not None:
                cur.execute(
                    """
                    SELECT ea, name, segment, size
                    FROM function_attrs
                    WHERE cfg_hash = ? AND ea != ? LIMIT 10
                    """,
                    (cfg_hash, exclude_ea),
                )
            else:
                cur.execute(
                    """
                    SELECT ea, name, segment, size
                    FROM function_attrs
                    WHERE cfg_hash = ? LIMIT 10
                    """,
                    (cfg_hash,),
                )
            rows = cur.fetchall()
            conn.close()
            results = []
            for r in rows:
                results.append({
                    "address": hex(r[0]),
                    "name": r[1],
                    "segment": r[2],
                    "size": r[3],
                })
            return results
        except Exception:
            with contextlib.suppress(Exception):
                conn.close()
        return []

    def query_related_bridges(self, ea: int, top_k: int = 3) -> List[Dict[str, Any]]:
        """Run Multi-Hop Bridge retrieval to get structurally similar functions."""
        if not self.bridge_index:
            return []
        try:
            bridges = self.bridge_index.extract_bridges(func_ea=ea, max_bridges=10)
            if not bridges or (not bridges.get("apis") and not bridges.get("strings")):
                return []
            candidates = self.bridge_index.search_via_bridges(
                bridges, top_k=top_k, exclude_ea=ea, seed_ea=ea
            )
            results = []
            for c in candidates:
                results.append({
                    "address": hex(c.get("ea", 0)),
                    "name": c.get("name", ""),
                    "segment": c.get("segment", ""),
                    "score": round(float(c.get("score", 0.0)), 3)
                })
            return results
        except Exception:
            return []

    def query_string_metadata(self, ea: int) -> Optional[Dict[str, Any]]:
        """Retrieve string literal content and referencing function name if the address is a string."""
        conn = self._conn()
        if not conn:
            return None
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT fs.string_text, fa.name, fs.func_ea
                FROM function_strings fs
                LEFT JOIN function_attrs fa ON fs.func_ea = fa.ea
                WHERE fs.string_ea = ? LIMIT 1
                """,
                (ea,),
            )
            row = cur.fetchone()
            conn.close()
            if row:
                return {
                    "string_text": row[0],
                    "referencing_function": row[1],
                    "referencing_function_ea": hex(row[2]) if row[2] else None,
                }
        except Exception:
            with contextlib.suppress(Exception):
                conn.close()
        return None

    def query_constant_usage(self, val: int) -> List[Dict[str, Any]]:
        """Find functions using this value as a constant."""
        conn = self._conn()
        if not conn:
            return []
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT fc.constant_name, fa.name, fc.func_ea
                FROM function_constants fc
                LEFT JOIN function_attrs fa ON fc.func_ea = fa.ea
                WHERE fc.constant_value = ? LIMIT 5
                """,
                (val,),
            )
            rows = cur.fetchall()
            conn.close()
            results = []
            for r in rows:
                results.append({
                    "constant_name": r[0] or "",
                    "used_in_function": r[1] or "",
                    "function_ea": hex(r[2]) if r[2] else None,
                })
            return results
        except Exception:
            with contextlib.suppress(Exception):
                conn.close()
        return []
