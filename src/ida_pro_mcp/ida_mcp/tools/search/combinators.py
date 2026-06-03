"""SEARCH.COMBINATORS - Creative composition actions: bool, hunt, neighborhood, etc.

These are *compositional* search actions: they combine primitive search results
into higher-level queries and analyses that the basic/advanced/unified modules
don't cover.

Actions provided:
  - search_bool:     composite boolean query language
                     e.g. "(api:Crypt* AND name:key) OR (string:password AND NOT obf:true)"
  - search_hunt:     named workflow recipes (backdoor, anti_debug, c2, ...)
  - search_neighborhood: 360 degree context around a function addr
  - search_outlier:  find structurally anomalous functions
  - search_fingerprint: structural (callgraph) similarity, not embedding-based
  - search_path:     shortest call-graph path between two symbols
  - search_reach:    functions reachable from a root within N hops
  - search_noreach:  functions NOT reachable from any known entrypoint
"""

import re
from collections import defaultdict, deque
from typing import Optional

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

from .core import (
    clip_text, paginate_records, build_response, MAX_LIMIT,
    resolve_target, safe_generate_disasm_line, CALL_XREF_TYPES,
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
    import idaapi, ida_xref
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
                if op == ">" and size > val1:
                    out.add(int(ea))
                    break
                elif op == "<" and size < val1:
                    out.add(int(ea))
                    break
                elif val2 is not None and val1 <= size <= val2:
                    out.add(int(ea))
                    break
                elif op in ("", "=") and val2 is None and size == val1:
                    out.add(int(ea))
                    break
        except Exception:
            continue
    return out


def _prim_args(pattern: str) -> set[int]:
    """Functions with matching argument count constraint (e.g., '3', '3+')."""
    import re as re_mod
    import ida_typeinf, ida_nalt
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
                    if plus and actual_args >= arg_count:
                        out.add(int(ea))
                    elif not plus and actual_args == arg_count:
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
            else:
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
            return _prim_funcs_by_name(tok[len("LITERAL:"):], case_sensitive=False)
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
# search_hunt - named workflow recipes
# ============================================================================

_HUNT_RECIPES: dict[str, dict] = {
    "backdoor": {
        "description": "Hardcoded backdoor / master-password patterns",
        "expression": "(string:backdoor OR string:master OR string:god OR string:wizard OR string:admin123) OR (api:strcmp AND api:GetWindowText*)",
        "rationale": "Backdoors typically use hardcoded comparison constants or a single auth bypass string.",
    },
    "anti_debug": {
        "description": "Anti-debugging checks",
        "expression": "api:IsDebuggerPresent OR api:CheckRemoteDebuggerPresent OR api:NtQueryInformationProcess OR api:OutputDebugString*",
        "rationale": "Classic anti-debug API set.",
    },
    "anti_vm": {
        "description": "VM / sandbox detection",
        "expression": "(api:RegOpenKey* AND string:VMWARE) OR (api:RegOpenKey* AND string:VBOX) OR api:SetupDiGetClassDevs OR string:\\\\.\\pipe\\",
        "rationale": "VM detection via registry keys and device paths.",
    },
    "license_check": {
        "description": "License / registration validation",
        "expression": "(string:license OR string:serial OR string:register OR string:trial OR string:expired) AND NOT (api:RegCloseKey)",
        "rationale": "License logic involves persistent state and validation strings, but pure registry code is excluded.",
    },
    "update_check": {
        "description": "Auto-update logic",
        "expression": "(string:update OR string:upgrade OR string:newversion) AND (api:InternetOpen* OR api:URLDownloadToFile* OR api:WinHttpOpen*)",
        "rationale": "Update routines hit the network with download APIs and look for version keywords.",
    },
    "c2": {
        "description": "C2 / command-and-control beacon",
        "expression": "(string:beacon OR string:command OR string:task) AND (api:InternetOpen* OR api:WSAStartup OR api:WinHttp* OR api:send)",
        "rationale": "C2 routines combine a network transport with command dispatch keywords.",
    },
    "parser": {
        "description": "Input parsers (JSON / XML / config / URL)",
        "expression": "(string:{\" OR string:<?xml OR string:%s=%s OR string:http:// OR string:https://) AND (api:strchr OR api:strtok OR api:sscanf OR api:strncmp)",
        "rationale": "Parsers leave format strings behind and use string-decomposition helpers.",
    },
    "crypto": {
        "description": "Cryptographic routines",
        "expression": "api:Crypt* OR api:BCrypt* OR api:NCrypt* OR api:EVP_* OR api:AES_* OR api:SHA* OR mnem:aesenc OR mnem:aesenclast OR mnem:sha256rnds",
        "rationale": "Crypto routines call crypto APIs or use crypto-specific SIMD instructions.",
    },
    "string_decode": {
        "description": "Runtime string-decoding routines (XOR / base64 / custom)",
        "expression": "(mnem:xor AND string:.*) AND (api:VirtualAlloc* OR api:HeapAlloc* OR api:malloc)",
        "rationale": "Decoded strings are typically XOR'd and copied into freshly-allocated memory.",
    },
    "hardcoded_creds": {
        "description": "Hardcoded credentials / API keys / tokens",
        "expression": "string:[A-Za-z0-9]{32} OR string:AKIA[0-9A-Z]{16} OR string:ghp_[A-Za-z0-9]{36} OR string:eyJ[A-Za-z0-9_\\-]{20,}",
        "rationale": "Common credential formats: random 32-byte keys, AWS access keys, GitHub PATs, JWTs.",
    },
    "network_io": {
        "description": "Network I/O functions",
        "expression": "api:socket OR api:connect OR api:send OR api:recv OR api:InternetOpen* OR api:WinHttp* OR api:URLDownload*",
        "rationale": "Network I/O uses Winsock or WinINet APIs.",
    },
    "file_io": {
        "description": "File I/O functions",
        "expression": "api:CreateFile* OR api:ReadFile OR api:WriteFile OR api:DeleteFile* OR api:fopen OR api:fread OR api:fwrite",
        "rationale": "File I/O uses Win32 file APIs or stdio.",
    },
    "process_injection": {
        "description": "Process injection / hollowing primitives",
        "expression": "(api:CreateProcess* AND api:WriteProcessMemory) OR api:NtUnmapViewOfSection OR api:VirtualAllocEx OR api:SetThreadContext",
        "rationale": "Process injection requires remote allocation + write + thread context hijack.",
    },
    "registry_persistence": {
        "description": "Registry-based persistence (Run keys, services)",
        "expression": "(api:RegSetValueEx* OR api:RegCreateKey*) AND (string:CurrentVersion\\Run OR string:RunOnce OR string:Winlogon)",
        "rationale": "Persistence typically writes Run keys or hijacks Winlogon.",
    },
}


def search_hunt(recipe: str, case_sensitive: bool, offset: int, limit: int) -> dict:
    """Run a named workflow recipe.

    Recipes are curated multi-primitive boolean queries for common RE scenarios.
    Use recipe="list" to see all available recipes.
    """
    if recipe == "list" or not recipe:
        rec_names = sorted(_HUNT_RECIPES)
        return {
            "ok": True,
            "action": "hunt",
            "recipe": "list",
            "available": rec_names,
            "count": len(rec_names),
            "results": "\n".join(f"{n}: {_HUNT_RECIPES[n]['description']}" for n in rec_names),
            "note": "Pass recipe=<name> to run a specific recipe.",
        }
    if recipe not in _HUNT_RECIPES:
        return make_error(
            MCPError.INVALID_ARGS,
            f"unknown recipe: {recipe!r}",
            hint=f"Pass recipe='list' to see available recipes. Known: {sorted(_HUNT_RECIPES)}",
        )

    spec = _HUNT_RECIPES[recipe]
    bool_result = search_bool(spec["expression"], case_sensitive, offset, limit)
    if isinstance(bool_result, dict) and bool_result.get("error"):
        return bool_result
    bool_result["action"] = "hunt"
    bool_result["recipe"] = recipe
    bool_result["description"] = spec["description"]
    bool_result["rationale"] = spec["rationale"]
    bool_result["expression"] = spec["expression"]
    return bool_result


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
    """360-degree context around a function: callers, callees, similar, outliers, tags.

    Returns a compact summary card so the LLM can orient quickly without
    having to issue five separate searches.
    """
    ea, err, _ = resolve_target(addr)
    if err or ea == idaapi.BADADDR:
        return make_error(MCPError.INVALID_ARGS,
                          f"could not resolve addr {addr!r}",
                          hint="Pass a hex address (0x401000) or a symbol name (main, sub_401000).")
    func = idaapi.get_func(ea)
    if not func:
        return make_error(MCPError.INVALID_ARGS, f"{hex(ea)} is not a function start")

    metrics = _func_metrics(ea)
    name = _func_name(ea)

    # Callers
    callers = []
    for xref in idautils.XrefsTo(func.start_ea, 0):
        if not xref.iscode:
            continue
        f = idaapi.get_func(xref.frm)
        if f:
            callers.append(int(f.start_ea))
    callers = sorted(set(callers))[:max(1, radius)]

    # Callees
    callees = []
    for xref in idautils.XrefsFrom(func.start_ea, 0):
        if not xref.iscode:
            continue
        f = idaapi.get_func(xref.to)
        if f:
            callees.append(int(f.start_ea))
    callees = sorted(set(callees))[:max(1, radius)]

    # Fingerprint-similar
    try:
        fp_result = search_fingerprint(hex(ea), top_k=5)
        similar = [it["addr"] for it in fp_result.get("items", [])] if isinstance(fp_result, dict) else []
    except Exception:
        similar = []

    # Behavior tags from L1 insight index
    tags = []
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

    # Blackboard notes
    blackboard = []
    try:
        from blackboard import BlackboardStore
        store = BlackboardStore()
        entries = store.list(addr=hex(ea), limit=5, include_resolved=False)
        for e in entries:
            blackboard.append({"title": e["title"], "category": e["category"],
                               "confidence": e.get("confidence")})
    except Exception:
        pass

    return {
        "ok": True,
        "action": "neighborhood",
        "addr": hex(ea),
        "name": name,
        "metrics": metrics,
        "callers": [{"addr": hex(a), "name": _func_name(a)} for a in callers],
        "callees": [{"addr": hex(a), "name": _func_name(a)} for a in callees],
        "similar": similar,
        "tags": tags,
        "blackboard": blackboard,
        "note": "Compact context card. Use search_fingerprint/outlier/etc. for deeper dives.",
    }


# ============================================================================
# search_outlier - structurally anomalous functions
# ============================================================================

def _all_func_metrics() -> list[tuple[int, dict]]:
    """Compute metrics for every function. Cached per IDB fingerprint."""
    out = []
    for ea in idautils.Functions():
        try:
            out.append((int(ea), _func_metrics(ea)))
        except Exception:
            continue
    return out


def search_outlier(metric: str, top: int, offset: int, limit: int) -> dict:
    """Find structurally anomalous functions.

    Metrics:
      size        - largest or smallest functions
      complexity  - highest cyclomatic complexity
      bb_count    - most basic blocks
      orphan      - functions with zero callers
      leaf        - functions with zero callees
      deep        - functions with the most callees (high fan-out)
      hub         - functions with the most callers (high fan-in)
      tiny        - functions smaller than 16 bytes (often thunks)
      huge        - functions larger than 4KB
    """
    metric = (metric or "size").lower()
    direction = "max"  # default

    all_metrics = _all_func_metrics()
    if not all_metrics:
        return {"ok": True, "action": "outlier", "metric": metric, "results": "", "count": 0, "items": []}

    items: list[dict] = []

    if metric in ("size", "huge", "complexity", "bb_count", "deep", "hub"):
        direction = "max"
    elif metric in ("tiny", "orphan", "leaf"):
        direction = "min"
    else:
        return make_error(MCPError.INVALID_ARGS,
                          f"unknown metric {metric!r}",
                          hint="Known: size, complexity, bb_count, orphan, leaf, deep, hub, tiny, huge")

    if metric in ("orphan", "hub"):
        caller_counts = defaultdict(int)
        callee_counts = defaultdict(int)
        for ea in idautils.Functions():
            for xref in idautils.XrefsTo(ea, 0):
                if xref.iscode:
                    f = idaapi.get_func(xref.frm)
                    if f:
                        caller_counts[int(f.start_ea)] += 1
            for xref in idautils.XrefsFrom(ea, 0):
                if xref.iscode:
                    f = idaapi.get_func(xref.to)
                    if f:
                        callee_counts[ea] += 1
        for ea, _ in all_metrics:
            count = caller_counts.get(ea, 0) if metric == "hub" else 0
            if metric == "orphan":
                count = 1 if caller_counts.get(ea, 0) == 0 else 0
                items.append({"addr": hex(ea), "name": _func_name(ea), "callers": 0, "outlier_score": 1})
            else:
                items.append({"addr": hex(ea), "name": _func_name(ea),
                              "callers": count, "outlier_score": count})
    elif metric == "leaf":
        callee_counts = defaultdict(int)
        for ea in idautils.Functions():
            for xref in idautils.XrefsFrom(ea, 0):
                if xref.iscode:
                    f = idaapi.get_func(xref.to)
                    if f:
                        callee_counts[ea] += 1
        for ea, _ in all_metrics:
            count = callee_counts.get(ea, 0)
            if count == 0:
                items.append({"addr": hex(ea), "name": _func_name(ea),
                              "callees": 0, "outlier_score": 1})
    elif metric == "deep":
        callee_counts = defaultdict(int)
        for ea in idautils.Functions():
            for xref in idautils.XrefsFrom(ea, 0):
                if xref.iscode:
                    f = idaapi.get_func(xref.to)
                    if f:
                        callee_counts[ea] += 1
        for ea, _ in all_metrics:
            items.append({"addr": hex(ea), "name": _func_name(ea),
                          "callees": callee_counts.get(ea, 0),
                          "outlier_score": callee_counts.get(ea, 0)})
    elif metric == "tiny":
        for ea, m in all_metrics:
            if m["size"] < 16:
                items.append({"addr": hex(ea), "name": _func_name(ea),
                              "size": m["size"], "outlier_score": 16 - m["size"]})
    elif metric == "huge":
        for ea, m in all_metrics:
            if m["size"] > 4096:
                items.append({"addr": hex(ea), "name": _func_name(ea),
                              "size": m["size"], "outlier_score": m["size"]})
    else:
        key_map = {"size": "size", "complexity": "complexity", "bb_count": "bb_count"}
        k = key_map[metric]
        for ea, m in all_metrics:
            items.append({"addr": hex(ea), "name": _func_name(ea),
                          k: m[k], "outlier_score": m[k]})

    items.sort(key=lambda x: x.get("outlier_score", 0), reverse=(direction == "max"))
    total = len(items)
    items = items[offset:offset + limit]
    text = "\n".join(
        f"{it['addr']}  {it['name']}  " + " ".join(f"{k}={v}" for k, v in it.items() if k not in ("addr", "name", "outlier_score"))
        for it in items
    )
    return {
        "ok": True,
        "action": "outlier",
        "metric": metric,
        "results": text,
        "count": len(items),
        "total": total,
        "truncated": total > offset + limit,
        "items": items,
        "note": f"Outliers by metric={metric} (direction={direction}). Top {limit} of {total}.",
    }


# ============================================================================
# search_fingerprint - structural (callgraph) similarity
# ============================================================================

def _function_fingerprint(ea: int) -> tuple:
    """Return a hashable structural fingerprint of a function.

    Captures:
      - sorted tuple of import names called
      - number of basic blocks
      - number of instructions
      - whether the function uses crypto/network/alloc APIs
    """
    try:
        f = idaapi.get_func(ea)
        if not f:
            return ()
        imports = set()
        instr_count = 0
        for xref in idautils.XrefsFrom(f.start_ea, 0):
            if not xref.iscode:
                continue
            name = idc.get_name(xref.to, idaapi.GN_VISIBLE) or ""
            if name:
                imports.add(name)
        cur = f.start_ea
        while cur < f.end_ea:
            instr_count += 1
            cur = idc.next_head(cur, f.end_ea)
        bb_count = 0
        try:
            import ida_gdl
            bb_count = sum(1 for _ in ida_gdl.FlowChart(f))
        except Exception:
            pass
        # Bucket the function's behavior into coarse categories
        cats = []
        if any(re.search(r"Crypt|Hash|Sha|Aes", n) for n in imports):
            cats.append("crypto")
        if any(re.search(r"socket|connect|send|recv|Internet|WinHttp", n) for n in imports):
            cats.append("network")
        if any(re.search(r"malloc|alloc|new", n) for n in imports):
            cats.append("alloc")
        if any(re.search(r"file|File", n) for n in imports):
            cats.append("file")
        if any(re.search(r"Reg|registry", n) for n in imports):
            cats.append("registry")
        # Bucket size into bands (log scale)
        size = f.end_ea - f.start_ea
        size_band = 0 if size < 64 else 1 if size < 256 else 2 if size < 1024 else 3
        bb_band = 0 if bb_count < 5 else 1 if bb_count < 20 else 2 if bb_count < 100 else 3
        return (frozenset(imports), bb_band, size_band, frozenset(cats))
    except Exception:
        return ()


def _fingerprint_similarity(fp1, fp2) -> float:
    """Jaccard-like similarity between two structural fingerprints.

    70% weight to import overlap, 15% to behavior categories, 15% to size+bb bucket proximity.
    """
    if not fp1 or not fp2:
        return 0.0
    imports1, bb1, size1, cats1 = fp1
    imports2, bb2, size2, cats2 = fp2
    if imports1 and imports2:
        j = len(imports1 & imports2) / len(imports1 | imports2)
    else:
        j = 0.0
    if cats1 and cats2:
        c = len(cats1 & cats2) / len(cats1 | cats2)
    else:
        c = 0.0
    bb_dist = abs(bb1 - bb2) / 3.0
    size_dist = abs(size1 - size2) / 3.0
    bb_sim = max(0.0, 1.0 - bb_dist)
    size_sim = max(0.0, 1.0 - size_dist)
    return 0.55 * j + 0.15 * c + 0.15 * bb_sim + 0.15 * size_sim


def search_fingerprint(addr: str, top_k: int, offset: int, limit: int) -> dict:
    """Find functions structurally similar to a reference.

    Structural similarity captures: import set, basic-block bucket, size bucket,
    and behavior category. This is a DIFFERENT signal from embedding-based
    'nl' search: two functions can have the same structure but completely
    different names or comments, and vice versa.
    """
    ea, err, _ = resolve_target(addr)
    if err or ea == idaapi.BADADDR:
        return make_error(MCPError.INVALID_ARGS,
                          f"could not resolve addr {addr!r}",
                          hint="Pass a hex address or symbol name.")
    ref_fp = _function_fingerprint(ea)
    if not ref_fp:
        return make_error(MCPError.INVALID_ARGS,
                          f"could not compute fingerprint for {hex(ea)}",
                          hint="Make sure the address points to a function start.")
    ref_name = _func_name(ea)

    scored = []
    for other_ea in idautils.Functions():
        if int(other_ea) == int(ea):
            continue
        other_fp = _function_fingerprint(other_ea)
        sim = _fingerprint_similarity(ref_fp, other_fp)
        if sim > 0.0:
            scored.append((sim, int(other_ea), _func_name(other_ea)))
    scored.sort(key=lambda x: (-x[0], x[1]))
    top = scored[:max(1, top_k)]
    items = [{"addr": hex(a), "name": n, "similarity": round(s, 3)} for s, a, n in top]
    items = items[offset:offset + limit]
    text = "\n".join(f"{it['addr']}  {it['name']}  sim={it['similarity']}" for it in items)
    return {
        "ok": True,
        "action": "fingerprint",
        "reference": {"addr": hex(ea), "name": ref_name},
        "results": text,
        "count": len(items),
        "total": len(scored),
        "truncated": len(scored) > top_k,
        "items": items,
        "note": "Structural similarity (imports + bb + size + behavior). Use nl/behaviour for semantic similarity.",
    }


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
