"""
BridgeRAG: Bridge-conditioned Multi-Hop Search for Reverse Engineering.

Deterministic multi-hop retrieval that finds structurally related functions
through shared bridge entities (APIs, strings, xrefs).  Uses SchemaBoot's
SQLite index as the bridge source.  No LLM required.

Inspired by VOERA's BridgeRAG architecture:
  s(q, b, c) = conditional utility of candidate c given query q and bridge b.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Dict, List, Optional, Set, Tuple

try:
    from ._common import *
except ImportError:
    try:
        from _common import *  # type: ignore[import-not-found]
    except ImportError:
        pass

# Safety fallbacks if _common import partially failed
if "tool" not in globals():
    tool = lambda f: f  # type: ignore
if "idaread" not in globals():
    idaread = lambda f: f  # type: ignore
if "idawrite" not in globals():
    idawrite = lambda f: f  # type: ignore
if "IDAError" not in globals():
    IDAError = Exception  # type: ignore


# ---------------------------------------------------------------------------
# SchemaBoot DB helpers (reused from schemaboot to avoid import issues)
# ---------------------------------------------------------------------------

def _db_path() -> str:
    try:
        import ida_loader
        return ida_loader.get_path(ida_loader.PATH_TYPE_IDB) + ".schemaboot.db"
    except Exception:
        pass
    try:
        import idautils
        import idc
        return idc.get_idb_path() + ".schemaboot.db"
    except Exception:
        pass
    return "unknown.schemaboot.db"


# ---------------------------------------------------------------------------
# BridgeRAG Engine
# ---------------------------------------------------------------------------

class BridgeRAGSearch:
    """
    Multi-hop search using SchemaBoot as the bridge entity source.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or _db_path()

    def _conn(self):
        return sqlite3.connect(self.db_path)

    # ------------------------------------------------------------------
    # Hop-1: Bridge extraction
    # ------------------------------------------------------------------

    def extract_bridges(
        self,
        func_ea: Optional[int] = None,
        func_name: Optional[str] = None,
        bridge_types: Tuple[str, ...] = ("apis", "strings"),
        max_bridges: int = 10,
    ) -> Dict[str, List[str]]:
        """
        Extract bridge entities from a seed function.
        Returns {"apis": [...], "strings": [...]} sorted by frequency.
        """
        bridges: Dict[str, List[str]] = {}

        if func_ea is not None:
            where = "fa.func_ea = ?"
            param = (func_ea,)
        elif func_name is not None:
            where = "fa.name = ?"
            param = (func_name,)
        else:
            return bridges

        try:
            conn = self._conn()
            cur = conn.cursor()

            if "apis" in bridge_types:
                cur.execute(
                    f"""
                    SELECT api_name FROM function_apis fa
                    JOIN function_attrs attrs ON fa.func_ea = attrs.ea
                    WHERE {where}
                    ORDER BY fa.func_ea
                    """,
                    param,
                )
                bridges["apis"] = [r[0] for r in cur.fetchall()]

            if "strings" in bridge_types:
                cur.execute(
                    f"""
                    SELECT string_value FROM function_strings fs
                    JOIN function_attrs attrs ON fs.func_ea = attrs.ea
                    WHERE {where}
                    ORDER BY fs.func_ea
                    """,
                    param,
                )
                bridges["strings"] = [r[0] for r in cur.fetchall()]

            conn.close()
        except sqlite3.OperationalError:
            # SchemaBoot DB missing or tables don't exist
            return bridges

        # Deduplicate and limit
        for k in bridges:
            seen: Set[str] = set()
            uniq: List[str] = []
            for v in bridges[k]:
                if v not in seen:
                    seen.add(v)
                    uniq.append(v)
                    if len(uniq) >= max_bridges:
                        break
            bridges[k] = uniq

        return bridges

    # ------------------------------------------------------------------
    # Hop-2: Candidate retrieval via bridges
    # ------------------------------------------------------------------

    def search_via_bridges(
        self,
        bridges: Dict[str, List[str]],
        top_k: int = 20,
        exclude_ea: Optional[int] = None,
    ) -> List[Dict]:
        """
        Find functions that share bridge entities with the seed.
        Scored by weighted bridge overlap.
        """
        if not bridges or not any(bridges.values()):
            return []

        conn = self._conn()
        cur = conn.cursor()

        # Collect all candidate EAs that match any bridge
        candidate_eas: Set[int] = set()
        bridge_scores: Dict[int, float] = {}

        api_bridges = bridges.get("apis", [])
        string_bridges = bridges.get("strings", [])

        if api_bridges:
            placeholders = ",".join("?" * len(api_bridges))
            cur.execute(
                f"SELECT func_ea FROM function_apis WHERE api_name IN ({placeholders})",
                tuple(api_bridges),
            )
            for row in cur.fetchall():
                ea = row[0]
                if exclude_ea is not None and ea == exclude_ea:
                    continue
                candidate_eas.add(ea)
                bridge_scores[ea] = bridge_scores.get(ea, 0.0) + 2.0  # APIs are strong bridges

        if string_bridges:
            placeholders = ",".join("?" * len(string_bridges))
            cur.execute(
                f"SELECT func_ea FROM function_strings WHERE string_value IN ({placeholders})",
                tuple(string_bridges),
            )
            for row in cur.fetchall():
                ea = row[0]
                if exclude_ea is not None and ea == exclude_ea:
                    continue
                candidate_eas.add(ea)
                bridge_scores[ea] = bridge_scores.get(ea, 0.0) + 1.0  # Strings are weaker bridges

        if not candidate_eas:
            conn.close()
            return []

        # Fetch candidate details
        placeholders = ",".join("?" * len(candidate_eas))
        cur.execute(
            f"""
            SELECT ea, name, segment, size, entropy, bb_count, call_count,
                   cyclomatic_complexity, api_count, string_count, xref_count,
                   has_loops, is_thunk, is_library
            FROM function_attrs
            WHERE ea IN ({placeholders})
            """,
            tuple(candidate_eas),
        )

        results: List[Dict] = []
        for row in cur.fetchall():
            ea = row[0]
            score = bridge_scores.get(ea, 0.0)
            # Bonus for high structural complexity (more likely to be related)
            score += row[7] * 0.1  # cyclomatic_complexity
            score += row[8] * 0.05  # api_count
            results.append(
                {
                    "ea": hex(ea),
                    "name": row[1],
                    "segment": row[2],
                    "size": row[3],
                    "entropy": row[4],
                    "bb_count": row[5],
                    "call_count": row[6],
                    "cyclomatic_complexity": row[7],
                    "api_count": row[8],
                    "string_count": row[9],
                    "xref_count": row[10],
                    "has_loops": bool(row[11]),
                    "is_thunk": bool(row[12]),
                    "is_library": bool(row[13]),
                    "bridge_score": round(score, 2),
                }
            )

        conn.close()
        results.sort(key=lambda x: x["bridge_score"], reverse=True)
        return results[:top_k]

    # ------------------------------------------------------------------
    # Full pipeline: query -> bridges -> candidates
    # ------------------------------------------------------------------

    def multi_hop_search(
        self,
        query_constraints: Dict,
        bridge_types: Tuple[str, ...] = ("apis", "strings"),
        top_k: int = 20,
        hops: int = 2,
    ) -> Dict:
        """
        Full BridgeRAG pipeline.

        1. Query SchemaBoot for seed functions matching *query_constraints*.
        2. Extract bridge entities from the top seed.
        3. Retrieve candidates that share those bridges.
        4. (Optional) For hops > 2, extract bridges from top candidates and repeat.
        """
        conn = self._conn()
        cur = conn.cursor()

        # Step 1: Find seed functions
        from schemaboot import _build_query_sql
        sql, params = _build_query_sql(query_constraints, limit=5, order_by=None)
        cur.execute(sql, params)
        seeds = []
        for row in cur.fetchall():
            seeds.append(
                {
                    "ea": row[0],
                    "name": row[1],
                    "segment": row[2],
                    "size": row[3],
                    "entropy": row[4],
                    "bb_count": row[5],
                    "call_count": row[6],
                    "cyclomatic_complexity": row[7],
                    "api_count": row[8],
                    "string_count": row[9],
                    "xref_count": row[10],
                    "has_loops": bool(row[11]),
                    "is_thunk": bool(row[12]),
                    "is_library": bool(row[13]),
                }
            )
        conn.close()

        if not seeds:
            return {"ok": True, "seeds": [], "bridges": {}, "candidates": [], "total_candidates": 0}

        # Step 2: Extract bridges from top seed
        top_seed = seeds[0]
        bridges = self.extract_bridges(
            func_ea=top_seed["ea"],
            bridge_types=bridge_types,
            max_bridges=15,
        )

        # Step 3: Retrieve candidates
        candidates = self.search_via_bridges(bridges, top_k=top_k, exclude_ea=top_seed["ea"])

        # Step 4: Additional hops (simplified: extract bridges from top candidate and expand)
        if hops > 2 and candidates:
            top_candidate_ea = int(candidates[0]["ea"], 16)
            extra_bridges = self.extract_bridges(
                func_ea=top_candidate_ea,
                bridge_types=bridge_types,
                max_bridges=10,
            )
            # Merge bridges
            for k, v in extra_bridges.items():
                existing = set(bridges.get(k, []))
                for item in v:
                    if item not in existing:
                        bridges[k].append(item)
                        existing.add(item)
            candidates = self.search_via_bridges(bridges, top_k=top_k, exclude_ea=top_seed["ea"])

        return {
            "ok": True,
            "seeds": [{k: (hex(v) if k == "ea" else v) for k, v in s.items()} for s in seeds],
            "bridges": bridges,
            "candidates": candidates,
            "total_candidates": len(candidates),
        }


# ---------------------------------------------------------------------------
# MCP Tool Interface
# ---------------------------------------------------------------------------

from typing import Annotated, Literal


@tool
@idaread
def bridgerag(
    action: Annotated[Literal["search", "bridges"], "BridgeRAG action"] = "search",
    db_path: Annotated[Optional[str], "Override path to SchemaBoot SQLite DB"] = None,
    query_constraints: Annotated[Optional[Dict], "Structured query constraints for 'search' action"] = None,
    func_ea: Annotated[Optional[str], "Hex address of seed function (for action='bridges')"] = None,
    func_name: Annotated[Optional[str], "Name of seed function (for action='bridges')"] = None,
    bridge_types: Annotated[Optional[List[str]], "Bridge types: ['apis'], ['strings'], or ['apis', 'strings']"] = None,
    top_k: Annotated[int, "Max candidates to return"] = 20,
    hops: Annotated[int, "Number of hops (2=standard, >2=extended)"] = 2,
) -> Dict:
    """
    Bridge-conditioned Multi-Hop Search using SchemaBoot as the bridge index.

    Parameters
    ----------
    action : str
        "search"   - full multi-hop pipeline (query -> bridges -> candidates)
        "bridges"  - extract bridge entities from a specific function
        "candidates" - find candidates given pre-computed bridges (not exposed directly)
    db_path : str
        Override path to SchemaBoot SQLite DB.
    query_constraints : dict
        SchemaBoot-style constraints for seed selection.
        e.g. {"apis": "VirtualAlloc", "min_size": 100}
    func_ea : str
        Hex address of seed function (for action="bridges").
    func_name : str
        Name of seed function (for action="bridges").
    bridge_types : list[str]
        Which bridge types to use: ["apis"], ["strings"], or ["apis", "strings"].
    top_k : int
        Max candidates to return.
    hops : int
        Number of hops (2 = standard BridgeRAG, >2 = extended search).
    """
    engine = BridgeRAGSearch(db_path=db_path)
    btypes = tuple(bridge_types or ("apis", "strings"))

    if action == "search":
        if not query_constraints:
            return {"ok": False, "error": "query_constraints required for action=search"}
        return engine.multi_hop_search(
            query_constraints=query_constraints,
            bridge_types=btypes,
            top_k=top_k,
            hops=hops,
        )

    elif action == "bridges":
        ea_int = None
        if func_ea is not None:
            try:
                ea_int = int(func_ea, 16)
            except (ValueError, TypeError):
                return {"ok": False, "error": f"Invalid func_ea: {func_ea}"}
        bridges = engine.extract_bridges(
            func_ea=ea_int,
            func_name=func_name,
            bridge_types=btypes,
            max_bridges=15,
        )
        return {"ok": True, "bridges": bridges}

    else:
        return {"ok": False, "error": f"Unknown action: {action}"}
