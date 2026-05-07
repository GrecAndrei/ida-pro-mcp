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
import numpy as np

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


def _resolve_schemaboot_db_path(candidate: Optional[str] = None) -> str:
    base = candidate or _db_path()
    candidates = [base]
    if base.endswith(".i64.schemaboot.db"):
        candidates.append(base.replace(".i64.schemaboot.db", ".schemaboot.db"))
    parent = os.path.dirname(base) or "."
    bname = os.path.basename(base)
    if ".i64." in bname:
        suffix = bname.split(".i64.", 1)[-1]
        try:
            for name in os.listdir(parent):
                if name.endswith(suffix):
                    candidates.append(os.path.join(parent, name))
        except Exception:
            pass
    for path in candidates:
        if not path or not os.path.exists(path):
            continue
        try:
            conn = sqlite3.connect(path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='function_attrs'")
            ok = cur.fetchone() is not None
            conn.close()
            if ok:
                return path
        except Exception:
            continue
    return base


def _build_where_clause_local(constraints: Dict) -> Tuple[str, List[object]]:
    conditions: List[str] = []
    params: List[object] = []
    for key, val in (constraints or {}).items():
        if val is None:
            continue
        if key == "apis":
            conditions.append(
                "EXISTS (SELECT 1 FROM function_apis WHERE function_apis.func_ea = function_attrs.ea AND function_apis.api_name = ?)"
            )
            params.append(val)
        elif key in ("strings_like", "string_contains"):
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
    if not conditions:
        return "", []
    return "WHERE " + " AND ".join(conditions), params


# ---------------------------------------------------------------------------
# BridgeRAG Engine
# ---------------------------------------------------------------------------

class BridgeRAGSearch:
    """
    Multi-hop search using SchemaBoot as the bridge entity source.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = _resolve_schemaboot_db_path(db_path)

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
            where = "attrs.name = ?"
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
                    SELECT string_text FROM function_strings fs
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

    def _tripartite_score(
        self,
        seed_attrs: Dict,
        bridge_attrs: Dict,
        candidate_attrs: Dict,
    ) -> float:
        """
        Tripartite judge: s(q, b, c) = conditional utility of candidate c
        given query q and bridge b.
        
        Returns score in [0, 1].
        """
        score = 0.0
        
        # Bridge overlap: how many bridge entities does candidate share?
        shared_apis = set(bridge_attrs.get("apis", [])) & set(candidate_attrs.get("apis", []))
        shared_strings = set(bridge_attrs.get("strings", [])) & set(candidate_attrs.get("strings", []))
        score += len(shared_apis) * 0.15
        score += len(shared_strings) * 0.08
        
        # Structural similarity
        seed_size = seed_attrs.get("size", 0)
        cand_size = candidate_attrs.get("size", 0)
        if seed_size > 0 and cand_size > 0:
            size_ratio = min(seed_size, cand_size) / max(seed_size, cand_size)
            score += size_ratio * 0.1
        
        # Complexity match
        seed_cc = seed_attrs.get("cyclomatic_complexity", 0)
        cand_cc = candidate_attrs.get("cyclomatic_complexity", 0)
        if seed_cc > 0:
            cc_ratio = min(seed_cc, cand_cc) / max(seed_cc, cand_cc)
            score += cc_ratio * 0.1
        
        # Segment affinity
        if seed_attrs.get("segment") == candidate_attrs.get("segment"):
            score += 0.05
        
        return min(score, 1.0)

    def _pit_fusion(
        self,
        judge_scores: List[float],
        bridge_scores: List[float],
        alpha: float = 0.1,
    ) -> List[float]:
        """
        Percentile-rank (PIT) fusion of tripartite judge scores and bridge similarity.
        
        F(i) = (1 - alpha) * PIT_judge(i) + alpha * PIT_bridge(i)
        """
        def _pit(scores: List[float]) -> List[float]:
            if not scores:
                return []
            sorted_idx = np.argsort(scores)
            ranks = np.empty_like(sorted_idx, dtype=float)
            ranks[sorted_idx] = np.linspace(0.0, 1.0, len(scores))
            return ranks.tolist()
        
        pit_judge = _pit(judge_scores)
        pit_bridge = _pit(bridge_scores)
        
        fused = []
        for i in range(len(judge_scores)):
            f = (1 - alpha) * pit_judge[i] + alpha * pit_bridge[i]
            fused.append(f)
        return fused

    def search_via_bridges(
        self,
        bridges: Dict[str, List[str]],
        top_k: int = 20,
        exclude_ea: Optional[int] = None,
        seed_ea: Optional[int] = None,
    ) -> List[Dict]:
        """
        Find functions that share bridge entities with the seed.
        Uses tripartite judging + PIT fusion for ranking.
        """
        if not bridges or not any(bridges.values()):
            return []

        conn = self._conn()
        cur = conn.cursor()

        # Get seed attributes for tripartite judging
        seed_attrs = {}
        if seed_ea is not None:
            cur.execute(
                "SELECT name, segment, size, entropy, cyclomatic_complexity, api_count, string_count FROM function_attrs WHERE ea = ?",
                (seed_ea,)
            )
            row = cur.fetchone()
            if row:
                seed_attrs = {
                    "name": row[0], "segment": row[1], "size": row[2],
                    "entropy": row[3], "cyclomatic_complexity": row[4],
                    "api_count": row[5], "string_count": row[6],
                    "apis": bridges.get("apis", []),
                    "strings": bridges.get("strings", []),
                }

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
                bridge_scores[ea] = bridge_scores.get(ea, 0.0) + 2.0

        if string_bridges:
            placeholders = ",".join("?" * len(string_bridges))
            cur.execute(
                f"SELECT func_ea FROM function_strings WHERE string_text IN ({placeholders})",
                tuple(string_bridges),
            )
            for row in cur.fetchall():
                ea = row[0]
                if exclude_ea is not None and ea == exclude_ea:
                    continue
                candidate_eas.add(ea)
                bridge_scores[ea] = bridge_scores.get(ea, 0.0) + 1.0

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

        candidates = []
        for row in cur.fetchall():
            ea = row[0]
            cand_attrs = {
                "name": row[1], "segment": row[2], "size": row[3],
                "entropy": row[4], "bb_count": row[5], "call_count": row[6],
                "cyclomatic_complexity": row[7], "api_count": row[8],
                "string_count": row[9], "xref_count": row[10],
                "has_loops": bool(row[11]), "is_thunk": bool(row[12]),
                "is_library": bool(row[13]),
            }
            
            # Tripartite judging
            judge_score = self._tripartite_score(seed_attrs, seed_attrs, cand_attrs) if seed_attrs else 0.5
            
            # Bridge overlap score
            bscore = bridge_scores.get(ea, 0.0)
            bscore += row[7] * 0.1  # cyclomatic complexity bonus
            bscore += row[8] * 0.05  # api count bonus
            
            candidates.append({
                "ea": hex(ea),
                "attrs": cand_attrs,
                "judge_score": judge_score,
                "bridge_score": bscore,
            })

        conn.close()

        # PIT fusion
        judge_scores = [c["judge_score"] for c in candidates]
        bridge_scores_list = [c["bridge_score"] for c in candidates]
        fused_scores = self._pit_fusion(judge_scores, bridge_scores_list, alpha=0.1)
        
        for i, c in enumerate(candidates):
            c["fused_score"] = round(fused_scores[i], 4)
            # Merge attrs into result
            result = dict(c["attrs"])
            result["ea"] = c["ea"]
            result["tripartite_score"] = round(c["judge_score"], 4)
            result["bridge_score"] = round(c["bridge_score"], 2)
            result["fused_score"] = c["fused_score"]
            candidates[i] = result

        candidates.sort(key=lambda x: x["fused_score"], reverse=True)
        return candidates[:top_k]

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
        where, params = _build_where_clause_local(query_constraints or {})
        sql = (
            "SELECT ea, name, segment, size, entropy, bb_count, call_count, "
            "cyclomatic_complexity, api_count, string_count, (incoming_xrefs + outgoing_xrefs) AS xref_count, "
            "has_loops, is_thunk, is_library FROM function_attrs "
            f"{where} LIMIT 5"
        )
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

        # Step 3: Retrieve candidates with tripartite judging
        candidates = self.search_via_bridges(bridges, top_k=top_k, exclude_ea=top_seed["ea"], seed_ea=top_seed["ea"])

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
