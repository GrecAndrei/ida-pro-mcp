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
    action: Annotated[Literal["data", "search", "idb", "code", "types", "imports_deep", "symbols", "patterns", "nl"],
                      "Action: data|search|idb|code|types|imports_deep|symbols|patterns|nl"],
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
        args: {q, limit}
        Example: query(action="nl", args={"q": "function that decrypts data", "limit": 5})
    """
    try:
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

        elif action == "nl":
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
                return {"ok": True, "results": [], "note": "No functions indexed yet. Run code(action='decompile') on functions first."}
            q_vec = embedder.embed(q)
            top_k = int(args.get("limit") or 10)
            results = idx.similar_vec(q_vec, top_k=top_k, threshold=0.3)
            return {"ok": True, "query": q, "results": results, "count": len(results), "backend": embedder.backend}

        else:
            return make_error(MCPError.ACTION_NOT_FOUND, f"Unknown query action: {action}",
                            hint="Valid actions: data, search, idb, code, types, imports_deep, symbols, patterns")
            
    except Exception as e:
        return handle_error(e)
