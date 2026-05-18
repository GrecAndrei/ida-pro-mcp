"""
Unified Query Hub - Routes queries to appropriate tools.
This provides a single entry point for all read operations.
"""

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


@tool
@idaread
def query(
    action: Annotated[Literal["data", "search", "idb", "code", "types", "imports_deep", "symbols", "patterns", "nl", "nl_batch"],
                      "Action: data|search|idb|code|types|imports_deep|symbols|patterns|nl|nl_batch"],
    subaction: Annotated[Optional[str], "Sub-action to perform"] = None,
    args: Annotated[Optional[dict], "Arguments to pass to sub-tool"] = None,
    **kwargs
) -> dict:
    """
    Unified query hub - single entry point for all read operations.
    
    This tool routes queries to the appropriate underlying tool, reducing
    the number of tools an LLM needs to remember.
    
    ACTIONS:
    
    data - Query binary data (functions, strings, imports, exports)
        subaction: functions|strings|imports|exports|globals|lookup
        args: {count, offset, query, addr, ...}
        Example: query(action="data", subaction="functions", args={"count": 10})
        
    search - Search the binary
        subaction: find|callers|callees|api|name|bytes|string
        args: {pattern, limit, ...}
        Example: query(action="search", subaction="find", args={"pattern": "malloc"})
        
    idb - Query database metadata
        subaction: meta|summary|segments|entrypoints
        Example: query(action="idb", subaction="summary")
        
    code - Query code at address
        subaction: decompile|disasm|xrefs_to|xrefs_from|callers|callees
        args: {addr, count, ...}
        Example: query(action="code", subaction="decompile", args={"addr": "0x401000"})
        
    types - Query type information
        subaction: list|get|search_structs
        args: {query, name, ...}
        Example: query(action="types", subaction="list", args={"count": 20})

    imports_deep - Advanced import resolution
        subaction: thunks|delay|forwarded|ordinal|api_sets|resolve
        Example: query(action="imports_deep", subaction="thunks")

    symbols - Symbol management queries
        subaction: status|export
        Example: query(action="symbols", subaction="status")

    patterns - Pattern matching queries
        subaction: list_sigs|matched
        Example: query(action="patterns", subaction="list_sigs")

    nl - Natural language semantic search over indexed functions
        args: {q, limit, min_confidence}
        Example: query(action="nl", args={"q": "function that decrypts data", "limit": 5})

    nl_batch - Run multiple NL queries and merge/rank deduplicated hits
        args: {queries: [str, ...], k, min_confidence}
    """
    try:
        def _nl_like(text: str) -> bool:
            t = str(text or "").strip().lower()
            if len(t.split()) >= 4:
                return True
            hints = ("function", "find", "that", "which", "where", "parse", "decrypt", "handler", "vuln", "protocol")
            return any(h in t for h in hints)

        merged_args = {}
        if isinstance(args, dict):
            merged_args.update(args)
        # Accept direct top-level arguments too, so callers don't have to nest
        # everything inside args={...} for query wrappers.
        for k, v in (kwargs or {}).items():
            if k not in ("action", "subaction", "args") and k not in merged_args:
                merged_args[k] = v
        args = merged_args
        
        if action == "data":
            from .data import data as data_tool
            sub = subaction or "functions"
            return data_tool(action=sub, **args)
            
        elif action == "search":
            from .search import search as search_tool
            sub = subaction or "find"
            q_text = str(args.get("query") or args.get("q") or args.get("pattern") or "").strip()
            # If caller gives a natural-language search intent, route to embedding-backed search.
            if not subaction and q_text and _nl_like(q_text):
                sub = "nl"
                args.setdefault("query", q_text)
            return search_tool(action=sub, **args)
            
        elif action == "idb":
            from .idb import idb as idb_tool
            sub = subaction or "summary"
            return idb_tool(action=sub, **args)
            
        elif action == "code":
            from .code import code as code_tool
            sub = subaction or "disasm"
            return code_tool(action=sub, **args)
            
        elif action == "types":
            from .types import types as types_tool
            sub = subaction or "list"
            return types_tool(action=sub, **args)

        elif action == "imports_deep":
            from .imports_deep import imports_deep as imports_deep_tool
            sub = subaction or "thunks"
            return imports_deep_tool(action=sub, **args)

        elif action == "symbols":
            from .symbols import symbols as symbols_tool
            sub = subaction or "status"
            return symbols_tool(action=sub, **args)

        elif action == "patterns":
            from .patterns import patterns as patterns_tool
            sub = subaction or "list_sigs"
            return patterns_tool(action=sub, **args)

        elif action in ("nl", "nl_batch"):
            if action == "nl_batch":
                queries = args.get("queries") or []
                if not isinstance(queries, list) or not queries:
                    return make_error(MCPError.INVALID_ARGS, "queries (list[str]) required")
                k = int(args.get("k") or args.get("limit") or 5)
                min_conf = float(args.get("min_confidence", 0.25) or 0.25)
                merged: Dict[str, Dict[str, Any]] = {}
                for qitem in queries[:16]:
                    sub = query(action="nl", args={"q": str(qitem), "limit": k * 3, "min_confidence": min_conf})
                    if not isinstance(sub, dict) or not sub.get("ok"):
                        continue
                    for row in sub.get("results", []) or []:
                        ea = str(row.get("ea") or "")
                        if not ea:
                            continue
                        score = float(row.get("similarity") or row.get("score") or 0.0)
                        cur = merged.get(ea)
                        if not cur or score > float(cur.get("score", 0.0)):
                            merged[ea] = {
                                "addr": ea,
                                "name": row.get("name", ""),
                                "score": score,
                                "matched_queries": [str(qitem)],
                            }
                        else:
                            mqs = cur.setdefault("matched_queries", [])
                            if str(qitem) not in mqs:
                                mqs.append(str(qitem))
                out = sorted(merged.values(), key=lambda x: float(x.get("score", 0.0)), reverse=True)[:k]
                return {"ok": True, "results": out, "count": len(out)}

            q = args.get("q") or args.get("query") or ""
            if not q:
                return make_error(MCPError.INVALID_ARGS, "q required")
            try:
                from ida_pro_mcp.host.intelligence import BgeCodeEmbedder, FunctionEmbeddingIndex
            except ImportError:
                from host.intelligence import BgeCodeEmbedder, FunctionEmbeddingIndex
            embedder = BgeCodeEmbedder()
            idb_path = ""
            try:
                import idc as _idc
                idb_path = _idc.get_idb_path() or ""
            except Exception:
                pass
            if not idb_path:
                return make_error(MCPError.INVALID_ARGS, "No IDB path")
            idx = FunctionEmbeddingIndex(idb_path + ".embeddings.db", embedder)
            if idx.size == 0:
                return {
                    "ok": True,
                    "query": q,
                    "results": [],
                    "count": 0,
                    "expansion_queries": [],
                    "backend": embedder.backend,
                    "note": "No functions indexed yet. Run code(action='decompile') on functions first.",
                }
            q_vec = embedder.embed(q)
            top_k = int(args.get("limit") or 10)
            min_conf = float(args.get("min_confidence", 0.25) or 0.25)
            results = idx.similar_vec(q_vec, top_k=top_k * 3, threshold=0.0)
            expansion_queries = []
            try:
                from ida_pro_mcp.host.intelligence import BehaviorClassifier
            except ImportError:
                try:
                    from host.intelligence import BehaviorClassifier  # type: ignore
                except ImportError:
                    BehaviorClassifier = None  # type: ignore
            if "BehaviorClassifier" in locals() and BehaviorClassifier is not None:
                try:
                    classifier = BehaviorClassifier.instance(embedder)
                    hits = classifier.classify(str(q)[:500], threshold=0.0, top_k=3, block=False)
                    expansion_queries = [
                        str(h.get("behavior") or "").strip().replace("_", " ")
                        for h in (hits or [])
                        if h.get("behavior")
                    ]
                    expansion_queries = [x for x in expansion_queries if x]
                except Exception:
                    expansion_queries = []
            if expansion_queries:
                by_addr = {}
                for r in results:
                    ea = str(r.get("ea") or "")
                    if ea:
                        by_addr[ea] = dict(r)
                for eq in expansion_queries[:3]:
                    try:
                        ev = embedder.embed(eq)
                        extras = idx.similar_vec(ev, top_k=max(3, top_k), threshold=0.0)
                    except Exception:
                        continue
                    for r in extras:
                        ea = str(r.get("ea") or "")
                        if not ea:
                            continue
                        sim = float(r.get("similarity") or 0.0)
                        cur = by_addr.get(ea)
                        if not cur:
                            row = dict(r)
                            row["similarity"] = sim * 0.92
                            row["expansion_query"] = eq
                            by_addr[ea] = row
                        else:
                            if sim > float(cur.get("similarity") or 0.0):
                                cur["similarity"] = sim * 0.96
                                cur["expansion_query"] = eq
                results = sorted(by_addr.values(), key=lambda x: float(x.get("similarity") or 0.0), reverse=True)
            sims = [float(r.get("similarity") or 0.0) for r in results]
            if sims:
                ss = sorted(sims)
                q50 = ss[len(ss) // 2]
                q75 = ss[min(len(ss) - 1, int(round((len(ss) - 1) * 0.75)))]
                gate = q50 + max(0.0, q75 - q50)
                filtered = [r for r in results if float(r.get("similarity") or 0.0) >= gate]
                results = (filtered or results)[:top_k]
            results = [r for r in results if float(r.get("similarity") or 0.0) >= min_conf]
            return {
                "ok": True,
                "query": q,
                "expansion_queries": expansion_queries[:3],
                "results": results,
                "count": len(results),
                "backend": embedder.backend,
                "min_confidence": min_conf,
            }

        else:
            return make_error(MCPError.ACTION_NOT_FOUND, f"Unknown query action: {action}",
                            hint="Valid actions: data, search, idb, code, types, imports_deep, symbols, patterns")
            
    except Exception as e:
        return handle_error(e)
