"""SEARCH.COMBINATORS - Compositional search actions: bool, neighborhood, etc.

These are *compositional* search actions: they combine primitive search results
into higher-level queries and analyses that the basic/advanced/unified modules
don't cover.

Actions provided:
  - search_bool:        composite boolean query language
                        e.g. "(api:Crypt* AND name:key) OR (string:password AND NOT obf:true)"
  - search_analyze:     unified structural analysis (neighborhood/outlier/similar/vulnerable/semantic)
  - search_neighborhood: 360 degree context around a function addr (delegates to analyze)
  - search_outlier:     find structurally anomalous functions (delegates to analyze)
  - search_fingerprint: embedding-similar functions via bge-code-v1 cosine similarity (delegates to analyze)
  - search_path:        shortest call-graph path between two symbols
  - search_reach:       functions reachable from a root within N hops
  - search_noreach:     functions NOT reachable from any known entrypoint
"""

import re
from collections import defaultdict, deque
from typing import Optional

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

from .core import (
    CALL_XREF_TYPES,
    resolve_target,
)

# ============================================================================
# Set arithmetic on function addresses (the "address algebra")
# ============================================================================

def _all_func_eas() -> set[int]:
    """Return every function EA in the program as a set."""
    try:
        return {int(ea) for ea in idautils.Functions()}
    except Exception:
        return set()


def _func_name(ea: int) -> str:
    try:
        return idc.get_func_name(ea) or hex(ea)
    except Exception:
        return hex(ea)


def _set_to_items(eas: set[int], offset: int, limit: int) -> list[dict]:
    """Convert a set of EAs into the standard item-list format."""
    sorted_eas = sorted(eas)
    window = sorted_eas[offset:offset + limit]
    items = []
    for ea in window:
        try:
            name = _func_name(ea)
        except Exception:
            name = hex(ea)
        items.append({"addr": hex(ea), "ea": ea, "name": name})
    return items


def _set_to_text(items: list[dict]) -> str:
    return "\n".join(f"{it['addr']}  {it['name']}" for it in items)


# ============================================================================
# Primitive extractors (used by the bool parser)
# ============================================================================

def _prim_funcs_by_name(pattern: str) -> set[int]:
    """Functions whose name matches pattern (glob or substring)."""
    matcher = compile_smart_pattern(pattern, case_sensitive=False)
    out = set()
    for ea in idautils.Functions():
        if matcher(_func_name(ea)):
            out.add(int(ea))
    return out


def _prim_funcs_by_string(pattern: str) -> set[int]:
    """Functions whose decompiled code contains a string literal matching pattern."""
    import ida_hexrays
    matcher = compile_smart_pattern(pattern, case_sensitive=False)
    out = set()
    for ea in idautils.Functions():
        try:
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                continue
            text = str(cfunc)
            if matcher(text):
                out.add(int(ea))
        except Exception:
            continue
    return out


def _prim_funcs_by_api(pattern: str) -> set[int]:
    """Functions that call at least one API matching pattern (glob)."""
    import idaapi
    matcher = compile_smart_pattern(pattern, case_sensitive=False)
    out = set()
    for ea in idautils.Functions():
        try:
            for xref in idautils.XrefsFrom(ea, 0):
                if not xref.iscode:
                    continue
                tgt = int(xref.to)
                name = idc.get_name(tgt, idaapi.GN_VISIBLE) or ""
                if name and matcher(name):
                    out.add(int(ea))
                    break
        except Exception:
            continue
    return out


def _prim_funcs_by_mnem(pattern: str) -> set[int]:
    """Functions whose disassembly contains a matching mnemonic."""
    matcher = compile_smart_pattern(pattern, case_sensitive=False)
    out = set()
    for ea in idautils.Functions():
        try:
            func = idaapi.get_func(ea)
            if not func:
                continue
            head = func.start_ea
            end = func.end_ea
            cur = head
            while cur < end:
                mnem = (idc.print_insn_mnem(cur) or "").lower()
                if matcher(mnem):
                    out.add(int(ea))
                    break
                cur = idc.next_head(cur, end)
        except Exception:
            continue
    return out


def _prim_callers(target: str) -> set[int]:
    """Functions that call the given target (name or addr)."""
    ea, err, _ = resolve_target(target)
    if err or ea == idaapi.BADADDR:
        return set()
    out = set()
    for xref in idautils.XrefsTo(ea, 0):
        if not xref.iscode:
            continue
        f = idaapi.get_func(xref.frm)
        if f:
            out.add(int(f.start_ea))
    return out


def _prim_callees(target: str) -> set[int]:
    """Functions called by the given target."""
    ea, err, _ = resolve_target(target)
    if err or ea == idaapi.BADADDR:
        return set()
    out = set()
    func = idaapi.get_func(ea)
    if not func:
        return out
    for xref in idautils.XrefsFrom(func.start_ea, 0):
        if not xref.iscode:
            continue
        f = idaapi.get_func(xref.to)
        if f:
            out.add(int(f.start_ea))
    return out


def _prim_size(pattern: str) -> set[int]:
    """Functions whose size matches a signature constraint (e.g. '>100', '<50', '10-20')."""
    import re as re_mod
    size_rules = []
    for m in re_mod.finditer(r"([<>]?)(\d+)(?:\s*-\s*(\d+))?", pattern):
        op, val1, val2 = m.groups()
        size_rules.append((op or "=", int(val1), int(val2) if val2 else None))
    if not size_rules:
        try:
            size_rules.append(("=", int(pattern), None))
        except ValueError:
            return set()
    out = set()
    for ea in idautils.Functions():
        try:
            func = idaapi.get_func(ea)
            if not func:
                continue
            size = func.end_ea - func.start_ea
            for op, val1, val2 in size_rules:
                if op == ">" and size > val1 or op == "<" and size < val1 or val2 is not None and val1 <= size <= val2 or op in ("", "=") and val2 is None and size == val1:
                    out.add(int(ea))
                    break
        except Exception:
            continue
    return out


def _prim_args(pattern: str) -> set[int]:
    """Functions with matching argument count constraint (e.g., '3', '3+')."""
    import re as re_mod

    import ida_nalt
    import ida_typeinf
    m_args = re_mod.search(r"(\d+)\s*(\+)?", pattern)
    if not m_args:
        return set()
    arg_count = int(m_args.group(1))
    plus = bool(m_args.group(2))
    out = set()
    for ea in idautils.Functions():
        try:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, ea):
                func_data = ida_typeinf.func_type_data_t()
                if tif.get_func_details(func_data):
                    actual_args = func_data.size()
                    if plus and actual_args >= arg_count or not plus and actual_args == arg_count:
                        out.add(int(ea))
        except Exception:
            continue
    return out


def _prim_leaf(pattern: str) -> set[int]:
    """Functions that are leaf functions (no outgoing calls)."""
    out = set()
    for ea in idautils.Functions():
        try:
            has_calls = any(xr.type in CALL_XREF_TYPES for xr in idautils.XrefsFrom(ea))
            if not has_calls:
                out.add(int(ea))
        except Exception:
            continue
    return out


def _prim_no_callers(pattern: str) -> set[int]:
    """Functions with no incoming callers."""
    out = set()
    for ea in idautils.Functions():
        try:
            has_callers = any(xr.iscode for xr in idautils.XrefsTo(ea, 0))
            if not has_callers:
                out.add(int(ea))
        except Exception:
            continue
    return out


# ============================================================================
# search_bool - composite boolean query
# ============================================================================

_BOOL_PRIMITIVES = {
    "name": _prim_funcs_by_name,
    "string": _prim_funcs_by_string,
    "api": _prim_funcs_by_api,
    "mnem": _prim_funcs_by_mnem,
    "caller": _prim_callers,
    "callee": _prim_callees,
    "size": _prim_size,
    "args": _prim_args,
    "leaf": _prim_leaf,
    "no_callers": _prim_no_callers,
}

_BOOL_OPS = {"AND", "OR", "NOT"}


def _tokenize_bool(expr: str) -> list[str]:
    """Tokenize a bool expression into (primitive:value) tokens and operators.

    Supports:
      - name:foo, api:Crypt*, string:password
      - quoted values with escapes: string:"my \"escaped\" secret"
      - logical aliases: &&, ||, !
      - bare keywords: leaf, no_callers
      - AND, OR, NOT (case-insensitive)
      - parentheses
    """
    tokens = []
    i = 0
    n = len(expr)
    while i < n:
        c = expr[i]
        if c.isspace():
            i += 1
            continue
        if c == "(":
            tokens.append("(")
            i += 1
            continue
        if c == ")":
            tokens.append(")")
            i += 1
            continue
        if expr[i:i+2] == "&&":
            tokens.append("AND")
            i += 2
            continue
        if expr[i:i+2] == "||":
            tokens.append("OR")
            i += 2
            continue
        if c == "!":
            tokens.append("NOT")
            i += 1
            continue
        if c == '"':
            m = re.match(r'"((?:[^"\\]|\\.)*)"', expr[i:])
            if m:
                val = m.group(1).replace('\\"', '"').replace('\\\\', '\\')
                tokens.append("LITERAL:" + val)
                i += m.end()
                continue
            j = expr.find('"', i + 1)
            if j == -1:
                j = n
            tokens.append("LITERAL:" + expr[i + 1:j])
            i = j + 1
            continue
        m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)\s*:\s*("(?:[^"\\]|\\.)*"|[^\s()]+)', expr[i:])
        if m:
            key = m.group(1).lower()
            val = m.group(2)
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1].replace('\\"', '"').replace('\\\\', '\\')
            tokens.append(f"{key}:{val}")
            i += m.end()
            continue
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", expr[i:])
        if m:
            word = m.group(0).upper()
            if word in _BOOL_OPS:
                tokens.append(word)
            elif word == "LEAF":
                tokens.append("leaf:true")
            elif word == "NO_CALLERS":
                tokens.append("no_callers:true")
            else:
                tokens.append("LITERAL:" + m.group(0))
            i += m.end()
            continue
        i += 1
    return tokens


class _BoolParser:
    """Recursive-descent parser for the bool expression language.

    Grammar:
      expr   := or_expr
      or_expr := and_expr ('OR' and_expr)*
      and_expr := not_expr ('AND' not_expr)*
      not_expr := 'NOT' not_expr | atom
      atom   := '(' expr ')' | primitive
    """

    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def consume(self, expected: Optional[str] = None) -> str:
        tok = self.peek()
        if tok is None:
            raise ValueError("Unexpected end of expression")
        if expected and tok != expected:
            raise ValueError(f"Expected {expected!r}, got {tok!r}")
        self.pos += 1
        return tok

    def parse_expr(self) -> set[int]:
        return self.parse_or()

    def parse_or(self) -> set[int]:
        left = self.parse_and()
        while self.peek() == "OR":
            self.consume("OR")
            right = self.parse_and()
            left = left | right
        return left

    def parse_and(self) -> set[int]:
        left = self.parse_not()
        while self.peek() == "AND":
            self.consume("AND")
            right = self.parse_not()
            left = left & right
        return left

    def parse_not(self) -> set[int]:
        if self.peek() == "NOT":
            self.consume("NOT")
            inner = self.parse_not()
            return _all_func_eas() - inner
        return self.parse_atom()

    def parse_atom(self) -> set[int]:
        tok = self.peek()
        if tok == "(":
            self.consume("(")
            inner = self.parse_expr()
            self.consume(")")
            return inner
        if tok is None:
            raise ValueError("Unexpected end of expression (expected primitive or '(')")
        if ":" in tok and not tok.startswith("LITERAL:"):
            self.consume()
            key, val = tok.split(":", 1)
            handler = _BOOL_PRIMITIVES.get(key)
            if not handler:
                raise ValueError(f"Unknown primitive: {key!r} (known: {sorted(_BOOL_PRIMITIVES)})")
            return handler(val)
        if tok.startswith("LITERAL:"):
            self.consume()
            return _prim_funcs_by_name(tok[len("LITERAL:"):])
        raise ValueError(f"Unexpected token: {tok!r}")


def search_bool(expr: str, case_sensitive: bool, offset: int, limit: int) -> dict:
    """Composite boolean query across function properties.

    Language:
      Primitives: name:Foo, api:Crypt*, string:password, mnem:ret,
                  caller:main, callee:exit
      Operators:  AND, OR, NOT, parentheses
      Quoted strings for values with spaces: string:"my secret"

    Examples:
      "(api:Crypt* AND name:key) OR (string:password AND NOT obf:true)"
      "name:main AND NOT api:printf"
      "api:Internet* AND (string:http OR string:https)"
    """
    if not expr or not expr.strip():
        return make_error(MCPError.INVALID_ARGS,
                          "expression required for bool search",
                          hint="Example: '(api:Crypt* AND name:key) OR (string:password)'")
    try:
        tokens = _tokenize_bool(expr)
        if not tokens:
            return make_error(MCPError.INVALID_ARGS, "expression parsed to zero tokens")
        parser = _BoolParser(tokens)
        result_set = parser.parse_expr()
        if parser.pos < len(parser.tokens):
            return make_error(MCPError.INVALID_ARGS,
                              f"unparsed tokens at end: {parser.tokens[parser.pos:]}",
                              hint="Operators: AND OR NOT ( ). Primitives: name: api: string: mnem: caller: callee:")
    except ValueError as e:
        return make_error(MCPError.INVALID_ARGS, f"bool parse error: {e}",
                          hint="Operators: AND OR NOT ( ). Primitives: name: api: string: mnem: caller: callee:")

    total = len(result_set)
    items = _set_to_items(result_set, offset, limit)
    text = _set_to_text(items)
    return {
        "ok": True,
        "action": "bool",
        "expression": expr,
        "results": text,
        "count": len(items),
        "total": total,
        "truncated": total > offset + limit,
        "items": items,
        "note": f"Matched {total} functions across {len(_BOOL_PRIMITIVES)} primitives via boolean composition.",
    }


# ============================================================================
# search_neighborhood - 360 degree context around a function
# ============================================================================

def _func_complexity(ea: int) -> int:
    """Approximate cyclomatic complexity via edge count."""
    try:
        import ida_gdl
        g = ida_gdl.FlowChart(idaapi.get_func(ea))
        edges = 0
        nodes = 0
        for block in g:
            nodes += 1
            succs = list(block.succs())
            if len(succs) > 1:
                edges += len(succs)
            elif succs:
                edges += 1
        return max(1, edges - nodes + 2)
    except Exception:
        return 0


def _func_metrics(ea: int) -> dict:
    """Return basic structural metrics for a function."""
    f = idaapi.get_func(ea)
    if not f:
        return {"size": 0, "complexity": 0, "bb_count": 0}
    size = f.end_ea - f.start_ea
    bb_count = 0
    try:
        import ida_gdl
        bb_count = sum(1 for _ in ida_gdl.FlowChart(f))
    except Exception:
        pass
    return {"size": size, "bb_count": bb_count, "complexity": _func_complexity(ea)}


def search_neighborhood(addr: str, radius: int, offset: int, limit: int) -> dict:
    """360-degree context around a function. Delegates to search_analyze."""
    return search_analyze(addr=addr, scope="neighborhood", radius=radius, offset=offset, limit=limit)


# ============================================================================
# search_outlier - structurally anomalous functions
# ============================================================================

def search_outlier(metric: str, top: int, offset: int, limit: int) -> dict:
    """Find structurally anomalous functions. Delegates to search_analyze."""
    return search_analyze(scope="outlier", metric=metric, top=top, offset=offset, limit=limit)


# ============================================================================
# search_fingerprint - structural (callgraph) similarity
# ============================================================================

def search_fingerprint(addr: str, top_k: int, offset: int, limit: int) -> dict:
    """Find embedding-similar functions. Delegates to search_analyze."""
    return search_analyze(addr=addr, scope="similar", top_k=top_k, offset=offset, limit=limit)


# ============================================================================
# search_path - shortest call-graph path between two symbols
# ============================================================================

def _bfs_path(start: int, goal: int, max_depth: int) -> Optional[list[int]]:
    """BFS for the shortest call-graph path from start to goal."""
    if start == goal:
        return [start]
    visited = {start}
    queue = deque([(start, [start])])
    while queue:
        ea, path = queue.popleft()
        if len(path) > max_depth:
            return None
        func = idaapi.get_func(ea)
        if not func:
            continue
        for xref in idautils.XrefsFrom(func.start_ea, 0):
            if not xref.iscode:
                continue
            f = idaapi.get_func(xref.to)
            if not f:
                continue
            nxt = int(f.start_ea)
            if nxt in visited:
                continue
            if nxt == goal:
                return path + [nxt]
            visited.add(nxt)
            queue.append((nxt, path + [nxt]))
    return None


def search_path(src: str, dst: str, max_depth: int) -> dict:
    """Find shortest call-graph path from src to dst.

    Returns the chain of function addresses (and names) such that each calls the next.
    """
    src_ea, src_err, _ = resolve_target(src)
    if src_err or src_ea == idaapi.BADADDR:
        return make_error(MCPError.INVALID_ARGS, f"could not resolve src {src!r}")
    dst_ea, dst_err, _ = resolve_target(dst)
    if dst_err or dst_ea == idaapi.BADADDR:
        return make_error(MCPError.INVALID_ARGS, f"could not resolve dst {dst!r}")
    src_func = idaapi.get_func(src_ea)
    dst_func = idaapi.get_func(dst_ea)
    if not src_func or not dst_func:
        return make_error(MCPError.INVALID_ARGS, "src/dst must be functions")

    path = _bfs_path(int(src_func.start_ea), int(dst_func.start_ea), max_depth=max(1, max_depth))
    if path is None:
        return {
            "ok": True,
            "action": "path",
            "src": {"addr": hex(src_func.start_ea), "name": _func_name(src_func.start_ea)},
            "dst": {"addr": hex(dst_func.start_ea), "name": _func_name(dst_func.start_ea)},
            "results": "",
            "count": 0,
            "items": [],
            "note": f"No path found within max_depth={max_depth}.",
        }
    items = [{"addr": hex(a), "name": _func_name(a)} for a in path]
    text = "\n".join(
        f"{i}. {hex(a)}  {_func_name(a)}{'  <-- dst' if i == len(items) - 1 else '  -->'}"
        for i, (a, _) in enumerate([(it['addr'], it) for it in items])
    )
    return {
        "ok": True,
        "action": "path",
        "src": items[0],
        "dst": items[-1],
        "results": text,
        "count": len(items),
        "hops": len(items) - 1,
        "items": items,
        "note": f"Shortest call-graph path of {len(items) - 1} hop(s).",
    }


# ============================================================================
# search_reach / search_noreach - reachability from a root
# ============================================================================

def _reach_from(root_ea: int, max_depth: int) -> set[int]:
    """BFS forward call graph from root, capped at max_depth."""
    visited = set()
    queue = deque([(int(root_ea), 0)])
    while queue:
        ea, depth = queue.popleft()
        if depth > max_depth:
            continue
        if ea in visited:
            continue
        visited.add(ea)
        func = idaapi.get_func(ea)
        if not func:
            continue
        for xref in idautils.XrefsFrom(func.start_ea, 0):
            if not xref.iscode:
                continue
            f = idaapi.get_func(xref.to)
            if f:
                queue.append((int(f.start_ea), depth + 1))
    return visited


def search_reach(root: str, depth: int, offset: int, limit: int) -> dict:
    """Find functions reachable from a root call site within N hops.

    BFS forward on the call graph.
    """
    root_ea, err, _ = resolve_target(root)
    if err or root_ea == idaapi.BADADDR:
        return make_error(MCPError.INVALID_ARGS, f"could not resolve root {root!r}")
    func = idaapi.get_func(root_ea)
    if not func:
        return make_error(MCPError.INVALID_ARGS, f"root {root!r} is not a function")

    reached = _reach_from(int(func.start_ea), max(0, depth))
    reached.discard(int(func.start_ea))
    total = len(reached)
    items = _set_to_items(reached, offset, limit)
    text = _set_to_text(items)
    return {
        "ok": True,
        "action": "reach",
        "root": {"addr": hex(func.start_ea), "name": _func_name(func.start_ea)},
        "depth": depth,
        "results": text,
        "count": len(items),
        "total": total,
        "truncated": total > offset + limit,
        "items": items,
        "note": f"Forward call-graph reachability within {depth} hop(s).",
    }


def _all_entry_points() -> list[int]:
    """Return all known entry points.

    Includes:
      - Formal export entries (idc.get_entry_qty)
      - The "main" or "_start" function as a fallback (common RE starting point)
    """
    out = set()
    try:
        for idx in range(ida_nalt.get_entry_qty()):
            ea = ida_nalt.get_entry(ida_nalt.get_entry_ordinal(idx))
            if ea != idaapi.BADADDR:
                f = idaapi.get_func(ea)
                if f:
                    out.add(int(f.start_ea))
    except Exception:
        pass
    if not out:
        # Fallback: use main / _start / WinMain as a starting point
        for sym in ("main", "_start", "wmain", "WinMain", "DllMain"):
            try:
                ea = idc.get_name_ea_simple(sym)
                if ea != idaapi.BADADDR:
                    f = idaapi.get_func(ea)
                    if f:
                        out.add(int(f.start_ea))
                        break
            except Exception:
                continue
    return list(out)


def search_noreach(depth: int, offset: int, limit: int) -> dict:
    """Find functions NOT reachable from any known entry point within N hops.

    Useful for finding dead code, hidden routines, or functions reachable
    only through obfuscated dispatchers.
    """
    entries = _all_entry_points()
    if not entries:
        return make_error(MCPError.INVALID_ARGS,
                          "no known entry points to compute reachability from",
                          hint="Make sure the binary has at least one export or use reach= with a specific root.")
    reached: set[int] = set()
    for ep in entries:
        reached |= _reach_from(ep, max(0, depth))
    all_funcs = _all_func_eas()
    unreached = all_funcs - reached
    total = len(unreached)
    items = _set_to_items(unreached, offset, limit)
    text = _set_to_text(items)
    return {
        "ok": True,
        "action": "noreach",
        "depth": depth,
        "entry_points": [hex(e) for e in entries],
        "results": text,
        "count": len(items),
        "total": total,
        "truncated": total > offset + limit,
        "items": items,
        "note": (f"Functions NOT reachable from any of {len(entries)} entry point(s) "
                 f"within {depth} hop(s). Likely dead code or dispatcher-only paths."),
    }


# ============================================================================
# Cached call graph
# ============================================================================

_CALL_GRAPH_CACHE: dict[str, dict] = {}


def _idb_fingerprint() -> str:
    """Return a fingerprint for the current IDB to key the call graph cache."""
    try:
        path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
        func_count = sum(1 for _ in idautils.Functions())
        return f"{path}:{func_count}"
    except Exception:
        return "unknown"


def _get_call_graph() -> dict:
    """Build and cache the full call graph for the current IDB.

    Returns {"callers": {ea: set[ea]}, "callees": {ea: set[ea]}}.
    """
    fp = _idb_fingerprint()
    if fp in _CALL_GRAPH_CACHE:
        return _CALL_GRAPH_CACHE[fp]

    callers: dict[int, set[int]] = defaultdict(set)
    callees: dict[int, set[int]] = defaultdict(set)

    for ea in idautils.Functions():
        func = idaapi.get_func(ea)
        if not func:
            continue
        fea = int(ea)
        for xref in idautils.XrefsFrom(func.start_ea, 0):
            if not xref.iscode:
                continue
            f = idaapi.get_func(xref.to)
            if f:
                callee_ea = int(f.start_ea)
                callees[fea].add(callee_ea)
                callers[callee_ea].add(fea)

    graph = {"callers": dict(callers), "callees": dict(callees)}
    # Keep only the latest graph to avoid memory bloat
    _CALL_GRAPH_CACHE.clear()
    _CALL_GRAPH_CACHE[fp] = graph
    return graph


# ============================================================================
# search_analyze - unified structural analysis
# ============================================================================

# Taint source API names (functions that receive external input).
_TAINT_SOURCE_NAMES = frozenset({
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets", "gets",
    "ioctl", "DeviceIoControl", "NtDeviceIoControlFile",
    "GetEnvironmentVariable", "getenv", "NtQueryInformationFile",
    "URLDownloadToFile", "URLDownloadToCacheFile", "WinHttpReceiveResponse",
    "InternetReadFile", "WinHttpReadData", "sic_recv", "uart_read",
    "spi_receive", "i2c_read", "DMA_Callback", "vfs_read",
})

# Dangerous API → vulnerability category.
_DANGEROUS_APIS = {
    "strcpy": "buffer_overflow", "strcat": "buffer_overflow",
    "gets": "buffer_overflow", "sprintf": "format_string",
    "vsprintf": "format_string", "scanf": "buffer_overflow",
    "sscanf": "buffer_overflow", "fscanf": "buffer_overflow",
    "wsprintf": "format_string", "wvsprintf": "format_string",
    "lstrcpy": "buffer_overflow", "lstrcat": "buffer_overflow",
    "RtlCopyMemory": "buffer_overflow",
    "system": "command_injection", "popen": "command_injection",
    "exec": "command_injection", "execve": "command_injection",
    "ShellExecute": "command_injection", "WinExec": "command_injection",
    "CreateProcess": "command_injection",
    "memcpy": "memory_issue", "memmove": "memory_issue",
    "HeapAlloc": "memory_issue", "VirtualAlloc": "memory_issue",
    "malloc": "memory_issue", "realloc": "memory_issue",
    "LoadLibrary": "dll_injection", "LoadLibraryA": "dll_injection",
    "LoadLibraryW": "dll_injection", "LoadLibraryEx": "dll_injection",
    "GetProcAddress": "dynamic_resolution",
}

# Behavior classifier anchors for vulnerability patterns.
_VULN_ANCHORS = [
    "buffer overflow vulnerable memcpy strcpy unchecked length",
    "command injection system exec shell unsanitized input",
    "format string vulnerability sprintf printf user controlled",
    "use after free dangling pointer freed memory access",
    "integer overflow arithmetic truncation before allocation",
    "hardcoded credential password key embedded secret",
    "heap spray shellcode allocation pattern",
    "race condition unsynchronized shared state",
]


def _get_index_metadata(ea: int) -> dict | None:
    """Get structural metadata for a function from the embedding index."""
    try:
        from ida_pro_mcp.services import get_assembler
        asm = get_assembler()
        idb_path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
        if not idb_path:
            return None
        idx = asm._get_index(idb_path)
        if idx is None or idx.size == 0:
            return None
        # Query the index for this specific function
        with idx._conn() as conn:
            row = conn.execute(
                "SELECT func_size, bb_count, has_loops, api_count, string_count, segment, is_thunk, cyclomatic "
                "FROM func_embeddings WHERE ea = ?",
                (hex(ea),)
            ).fetchone()
            if row:
                return {
                    "func_size": int(row[0] or 0),
                    "bb_count": int(row[1] or 0),
                    "has_loops": bool(row[2]),
                    "api_count": int(row[3] or 0),
                    "string_count": int(row[4] or 0),
                    "segment": str(row[5] or ""),
                    "is_thunk": bool(row[6]),
                    "cyclomatic": int(row[7] or 0),
                }
    except Exception:
        pass
    return None


def _get_behavior_tags(ea: int) -> list[str]:
    """Get behavior tags for a function from the insight index or classifier."""
    tags = []
    # Try L1 insight index first (instant)
    try:
        from . import _load_insight_index
        idx = _load_insight_index()
        if idx:
            tag_map = idx.get("tag_map", {})
            for tag, addrs in tag_map.items():
                if hex(ea) in addrs:
                    tags.append(tag)
    except Exception:
        pass
    return tags


def _get_embedding_similar(ea: int, top_k: int = 10) -> list[dict]:
    """Find embedding-similar functions using the intelligence index."""
    try:
        from ida_pro_mcp.services import get_assembler
        asm = get_assembler()
        idb_path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
        if not idb_path:
            return []
        idx = asm._get_index(idb_path)
        if idx is None or idx.size == 0:
            return []
        # Get the target function's vector
        with idx._conn() as conn:
            row = conn.execute(
                "SELECT vec_blob FROM func_embeddings WHERE ea = ?",
                (hex(ea),)
            ).fetchone()
            if not row or not row[0]:
                return []
            import numpy as np
            vec = np.frombuffer(row[0], dtype=np.float32).copy()
        results = idx.similar_vec(vec, top_k=top_k + 1, threshold=0.0)
        return [r for r in results if _coerce_ea(r.get("ea")) != ea][:top_k]
    except Exception:
        return []


def search_analyze(
    addr: str | None = None,
    scope: str = "auto",
    metric: str = "size",
    top: int = 50,
    top_k: int = 10,
    radius: int = 5,
    depth: int = 5,
    pattern: str | None = None,
    offset: int = 0,
    limit: int = 50,
    include_context: bool = False,
    include_items: bool = True,
    **kwargs,
) -> dict:
    """Unified structural analysis action.

    Scopes (auto-detected from parameters):
      neighborhood — 360° context card around a function (addr required)
      outlier      — structurally anomalous functions (metric required)
      similar      — embedding-similar functions (addr required)
      vulnerable   — taint-aware vulnerability candidates (pattern optional)
      semantic     — semantic function search via embeddings (pattern required)
    """
    # Auto-detect scope
    if scope == "auto":
        if addr and metric and metric != "size":
            scope = "outlier"
        elif addr and pattern:
            scope = "semantic"
        elif addr:
            scope = "neighborhood"
        elif pattern:
            scope = "semantic"
        elif metric:
            scope = "outlier"
        else:
            return make_error(
                MCPError.INVALID_ARGS,
                "analyze requires addr, pattern, or metric",
                hint="Examples: analyze(addr='0x401000'), analyze(pattern='crypto'), analyze(metric='size')",
            )

    # --- NEIGHBORHOOD ---
    if scope == "neighborhood":
        if not addr:
            return make_error(MCPError.INVALID_ARGS, "neighborhood requires addr")
        ea, err, _ = resolve_target(addr)
        if err or ea == idaapi.BADADDR:
            return make_error(MCPError.INVALID_ARGS, f"could not resolve addr {addr!r}")
        func = idaapi.get_func(ea)
        if not func:
            return make_error(MCPError.INVALID_ARGS, f"{hex(ea)} is not inside a function")
        fea = int(func.start_ea)
        name = _func_name(fea)

        # Structural metadata from embedding index (cached in SQLite)
        meta = _get_index_metadata(fea)
        metrics = meta or {"func_size": func.end_ea - func.start_ea}

        # Callers/callees from cached call graph
        graph = _get_call_graph()
        caller_eas = sorted(graph["callers"].get(fea, set()))[:radius]
        callee_eas = sorted(graph["callees"].get(fea, set()))[:radius]

        # Behavior tags
        tags = _get_behavior_tags(fea)

        # Embedding-similar functions
        similar_hits = _get_embedding_similar(fea, top_k=top_k)
        similar = [{"addr": h.get("addr"), "name": h.get("name", ""), "score": round(float(h.get("similarity", 0)), 3)} for h in similar_hits]

        # Blackboard notes
        blackboard = []
        try:
            from blackboard import BlackboardStore  # type: ignore
            store = BlackboardStore()
            entries = store.list(addr=hex(fea), limit=5, include_resolved=False)
            for e in entries:
                blackboard.append({"title": e["title"], "category": e["category"],
                                   "confidence": e.get("confidence")})
        except Exception:
            pass

        # Build text summary
        text_lines = [f"=== {name} @ {hex(fea)} ==="]
        if metrics:
            text_lines.append(f"size={metrics.get('func_size', '?')} bb={metrics.get('bb_count', '?')} cyc={metrics.get('cyclomatic', '?')}")
        if caller_eas:
            text_lines.append(f"callers ({len(caller_eas)}): " + ", ".join(f"{_func_name(a)}({hex(a)})" for a in caller_eas))
        if callee_eas:
            text_lines.append(f"callees ({len(callee_eas)}): " + ", ".join(f"{_func_name(a)}({hex(a)})" for a in callee_eas))
        if tags:
            text_lines.append(f"tags: {', '.join(tags)}")
        if similar:
            text_lines.append(f"similar ({len(similar)}): " + ", ".join(f"{s['name']}({s['score']})" for s in similar[:5]))
        if blackboard:
            text_lines.append(f"blackboard ({len(blackboard)}): " + ", ".join(b["title"] for b in blackboard))

        items_out = []
        if include_items:
            items_out = [
                {"type": "caller", "addr": hex(a), "name": _func_name(a)} for a in caller_eas
            ] + [
                {"type": "callee", "addr": hex(a), "name": _func_name(a)} for a in callee_eas
            ]

        return {
            "ok": True,
            "action": "analyze",
            "scope": "neighborhood",
            "addr": hex(fea),
            "name": name,
            "metrics": metrics,
            "results": "\n".join(text_lines),
            "callers": [{"addr": hex(a), "name": _func_name(a)} for a in caller_eas],
            "callees": [{"addr": hex(a), "name": _func_name(a)} for a in callee_eas],
            "similar": similar,
            "tags": tags,
            "blackboard": blackboard,
            "items": items_out,
            "note": "Context card from embedding index + cached call graph.",
        }

    # --- OUTLIER ---
    if scope == "outlier":
        metric = (metric or "size").lower()
        valid_metrics = {"size", "complexity", "bb_count", "orphan", "leaf", "deep", "hub", "tiny", "huge"}
        if metric not in valid_metrics:
            return make_error(MCPError.INVALID_ARGS, f"unknown metric {metric!r}",
                              hint=f"Known: {', '.join(sorted(valid_metrics))}")

        graph = _get_call_graph()

        # For metrics available in the index, query SQL directly
        index_metrics = {"size": "func_size", "complexity": "cyclomatic", "bb_count": "bb_count"}
        if metric in index_metrics:
            col = index_metrics[metric]
            try:
                from ida_pro_mcp.services import get_assembler
                asm = get_assembler()
                idb_path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
                idx = asm._get_index(idb_path) if idb_path else None
                if idx and idx.size > 0:
                    with idx._conn() as conn:
                        if metric == "tiny":
                            rows = conn.execute(
                                f"SELECT ea, name, {col} FROM func_embeddings WHERE {col} < 16 ORDER BY {col} ASC LIMIT ?",
                                (offset + limit,)
                            ).fetchall()
                        elif metric == "huge":
                            rows = conn.execute(
                                f"SELECT ea, name, {col} FROM func_embeddings WHERE {col} > 4096 ORDER BY {col} DESC LIMIT ?",
                                (offset + limit,)
                            ).fetchall()
                        else:
                            rows = conn.execute(
                                f"SELECT ea, name, {col} FROM func_embeddings ORDER BY {col} DESC LIMIT ?",
                                (offset + limit,)
                            ).fetchall()
                    items = [{"addr": str(r[0]), "name": str(r[1] or r[0]), metric: int(r[2] or 0), "outlier_score": int(r[2] or 0)} for r in rows[offset:]]
                    return {
                        "ok": True, "action": "analyze", "scope": "outlier",
                        "metric": metric, "results": "\n".join(f"{it['addr']}  {it['name']}  {metric}={it[metric]}" for it in items),
                        "count": len(items), "total": len(rows), "items": items,
                        "note": f"Outliers by {metric} from embedding index.",
                    }
            except Exception:
                pass

        # Call-graph-based metrics: use cached graph
        caller_counts = defaultdict(int)
        callee_counts = defaultdict(int)
        for fea, callees_set in graph["callees"].items():
            callee_counts[fea] = len(callees_set)
        for fea, callers_set in graph["callers"].items():
            caller_counts[fea] = len(callers_set)

        items = []
        if metric == "orphan":
            for ea in idautils.Functions():
                if caller_counts.get(int(ea), 0) == 0:
                    items.append({"addr": hex(ea), "name": _func_name(int(ea)), "callers": 0, "outlier_score": 1})
        elif metric == "leaf":
            for ea in idautils.Functions():
                if callee_counts.get(int(ea), 0) == 0:
                    items.append({"addr": hex(ea), "name": _func_name(int(ea)), "callees": 0, "outlier_score": 1})
        elif metric == "hub":
            for ea in idautils.Functions():
                count = caller_counts.get(int(ea), 0)
                if count > 0:
                    items.append({"addr": hex(ea), "name": _func_name(int(ea)), "callers": count, "outlier_score": count})
        elif metric == "deep":
            for ea in idautils.Functions():
                count = callee_counts.get(int(ea), 0)
                if count > 0:
                    items.append({"addr": hex(ea), "name": _func_name(int(ea)), "callees": count, "outlier_score": count})

        items.sort(key=lambda x: x.get("outlier_score", 0), reverse=True)
        total = len(items)
        page = items[offset:offset + limit]
        text = "\n".join(f"{it['addr']}  {it['name']}  " + " ".join(f"{k}={v}" for k, v in it.items() if k not in ("addr", "name", "outlier_score")) for it in page)
        return {
            "ok": True, "action": "analyze", "scope": "outlier",
            "metric": metric, "results": text, "count": len(page), "total": total,
            "truncated": total > offset + limit, "items": page,
            "note": f"Outliers by {metric} from cached call graph.",
        }

    # --- SIMILAR (embedding-based) ---
    if scope == "similar":
        if not addr:
            return make_error(MCPError.INVALID_ARGS, "similar requires addr")
        ea, err, _ = resolve_target(addr)
        if err or ea == idaapi.BADADDR:
            return make_error(MCPError.INVALID_ARGS, f"could not resolve addr {addr!r}")
        func = idaapi.get_func(ea)
        if not func:
            return make_error(MCPError.INVALID_ARGS, f"{hex(ea)} is not inside a function")
        fea = int(func.start_ea)

        similar_hits = _get_embedding_similar(fea, top_k=top_k)
        items = []
        for h in similar_hits:
            meta = _get_index_metadata(_coerce_ea(h.get("ea")))
            item = {"addr": h.get("addr"), "name": h.get("name", ""), "score": round(float(h.get("similarity", 0)), 3)}
            if meta:
                item["size"] = meta["func_size"]
                item["bb_count"] = meta["bb_count"]
                item["cyclomatic"] = meta["cyclomatic"]
            items.append(item)

        page = items[offset:offset + limit]
        text = "\n".join(f"{it['addr']}  {it['name']}  score={it['score']}" for it in page)
        return {
            "ok": True, "action": "analyze", "scope": "similar",
            "reference": {"addr": hex(fea), "name": _func_name(fea)},
            "results": text, "count": len(page), "total": len(items),
            "items": page,
            "note": "Semantic similarity via bge-code-v1 embeddings. Different from structural fingerprint.",
        }

    # --- VULNERABLE ---
    if scope == "vulnerable":
        graph = _get_call_graph()
        taint_depth = max(2, min(int(depth), 12))

        # Phase 1: Find taint sources and their reachable callers
        sources = set()
        for ea, name in idautils.Names():
            base = name.split("@")[0].split("$")[0]
            if base in _TAINT_SOURCE_NAMES:
                func = idaapi.get_func(ea)
                if func:
                    sources.add(int(func.start_ea))

        reachable_from_source: set[int] = set()
        for src in sources:
            # BFS using cached graph
            visited = {src}
            frontier = {src}
            for _ in range(taint_depth):
                if not frontier:
                    break
                next_frontier = set()
                for s in frontier:
                    for caller in graph["callers"].get(s, set()):
                        if caller not in visited:
                            visited.add(caller)
                            next_frontier.add(caller)
                frontier = next_frontier
            reachable_from_source.update(visited)

        # Phase 2: Find dangerous API calls
        vuln_hits = []
        for func_ea in idautils.Functions():
            fea = int(func_ea)
            if fea not in reachable_from_source:
                continue
            func = idaapi.get_func(func_ea)
            if not func:
                continue
            for callee_ea in graph["callees"].get(fea, set()):
                callee_name = idc.get_name(callee_ea) or ""
                if callee_name in _DANGEROUS_APIS:
                    fn_name = _func_name(fea)
                    vuln_hits.append({
                        "addr": hex(fea), "function": fn_name,
                        "api": callee_name, "vuln_type": _DANGEROUS_APIS[callee_name],
                        "severity": "reachable_from_taint",
                        "outlier_score": 1,
                    })

        # Phase 3: Behavior-based vulnerability candidates via embeddings
        try:
            from ida_pro_mcp.services import get_assembler
            asm = get_assembler()
            idb_path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
            idx = asm._get_index(idb_path) if idb_path else None
            classifier = asm._behavior_classifier() if asm else None
            if idx and idx.size > 0 and classifier:
                queries = _VULN_ANCHORS[:4]
                if pattern:
                    queries.insert(0, pattern)
                seen_addrs = {h["addr"] for h in vuln_hits}
                for q in queries:
                    try:
                        hits = idx.search(q, top_k=20, threshold=0.0)
                        for hit in hits:
                            hit_ea = hit.get("addr") or hit.get("ea")
                            if not hit_ea or hit_ea in seen_addrs:
                                continue
                            hit_func = idaapi.get_func(_coerce_ea(hit_ea))
                            if not hit_func:
                                continue
                            hit_fea = int(hit_func.start_ea)
                            if hit_fea not in reachable_from_source:
                                continue
                            seen_addrs.add(hit_ea)
                            vuln_hits.append({
                                "addr": hex(hit_fea), "function": _func_name(hit_fea),
                                "api": "", "vuln_type": "behavior_candidate",
                                "severity": "reachable_from_taint",
                                "outlier_score": float(hit.get("similarity", 0)),
                            })
                    except Exception:
                        continue
        except Exception:
            pass

        if pattern:
            matcher = compile_smart_pattern(pattern, case_sensitive=False)
            vuln_hits = [h for h in vuln_hits if matcher(h.get("api", "")) or matcher(h.get("function", "")) or matcher(h.get("vuln_type", ""))]

        vuln_hits.sort(key=lambda x: x.get("outlier_score", 0), reverse=True)
        total = len(vuln_hits)
        page = vuln_hits[offset:offset + limit]
        text = "\n".join(f"{h['addr']}  {h['api'] or h['vuln_type']}  in:{h['function']}" for h in page)
        return {
            "ok": True, "action": "analyze", "scope": "vulnerable",
            "results": text, "count": len(page), "total": total,
            "truncated": total > offset + limit, "items": page,
            "taint_sources": len(sources), "taint_depth": taint_depth,
            "note": "Vuln candidates reachable from taint sources via cached call graph + embedding behavior classification.",
        }

    # --- SEMANTIC ---
    if scope == "semantic":
        if not pattern:
            return make_error(MCPError.INVALID_ARGS, "semantic scope requires pattern")
        try:
            from ida_pro_mcp.services import get_assembler
            asm = get_assembler()
            idb_path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
            idx = asm._get_index(idb_path) if idb_path else None
            if not idx or idx.size == 0:
                return make_error(MCPError.NOT_FOUND, "No functions indexed. Run intelligence(action='index_fast') first.")
            hits = idx.hybrid_search(pattern, top_k=offset + limit, threshold=0.0)
            page = hits[offset:offset + limit]
            items = []
            for h in page:
                meta = _get_index_metadata(_coerce_ea(h.get("ea")))
                item = {"addr": h.get("addr") or h.get("ea"), "name": h.get("name", ""),
                        "score": round(float(h.get("score", 0)), 3),
                        "similarity": round(float(h.get("similarity", 0)), 3)}
                if meta:
                    item["size"] = meta["func_size"]
                    item["bb_count"] = meta["bb_count"]
                    item["cyclomatic"] = meta["cyclomatic"]
                items.append(item)
            text = "\n".join(f"{it['addr']}  {it['name']}  score={it['score']}" for it in items)
            return {
                "ok": True, "action": "analyze", "scope": "semantic",
                "results": text, "count": len(items), "total": len(hits),
                "truncated": len(hits) > offset + limit, "items": items,
                "note": "Hybrid semantic+lexical search via bge-code-v1 embeddings.",
            }
        except Exception as e:
            return make_error(MCPError.NOT_FOUND, f"Semantic search failed: {e}")

    return make_error(MCPError.INVALID_ARGS, f"unknown scope: {scope!r}",
                      hint="Scopes: neighborhood, outlier, similar, vulnerable, semantic")
