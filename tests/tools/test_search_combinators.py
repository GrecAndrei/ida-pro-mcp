"""Tests for the new combinator search actions (bool, hunt, neighborhood, etc.).

These tests are pure-Python (no IDA required) and verify:
  1. The combinators module exists and exposes the expected functions.
  2. The router wires them in (search() can dispatch to each new action).
  3. The bool expression tokenizer + parser work correctly.
  4. The hunt recipe dictionary is populated.
  5. The action set / aliases include the new actions.
  6. The public API of the router mentions the new actions in the Literal.
"""

import ast
import os
import re
import sys
import types

from tests._isolated_repo_loader import load_tool_submodule

ROOT = os.path.dirname(os.path.dirname(__file__))
SEARCH_DIR = os.path.join(
    ROOT, "src", "ida_pro_mcp", "ida_mcp", "tools", "search"
)
COMBINATORS = os.path.join(SEARCH_DIR, "combinators.py")
INIT = os.path.join(SEARCH_DIR, "__init__.py")
CORE = os.path.join(SEARCH_DIR, "core.py")

# Mock IDA modules in-place to avoid breaking other tests
for mod_name in ("idaapi", "idautils", "idc", "ida_bytes", "ida_nalt",
                  "ida_lines", "ida_xref", "ida_funcs", "ida_hexrays",
                  "ida_typeinf", "ida_search", "ida_gdl", "ida_segment", "ida_kernwin", "ida_netnode", "ida_name", "ida_frame"):
    if mod_name not in sys.modules:
        sys.modules[mod_name] = types.ModuleType(mod_name)

sys.modules["idaapi"].BADADDR = 0xFFFFFFFF
sys.modules["idaapi"].get_kernel_version = lambda: "9.2"
sys.modules["idaapi"].MFF_FAST = 1
sys.modules["idaapi"].MFF_WRITE = 2
sys.modules["idaapi"].MFF_READ = 4

sys.modules["ida_kernwin"].MFF_FAST = 1
sys.modules["ida_kernwin"].MFF_WRITE = 2
sys.modules["ida_kernwin"].MFF_READ = 4
sys.modules["ida_funcs"].func_t = type("func_t", (), {})
sys.modules["ida_typeinf"].tinfo_t = type("tinfo_t", (), {})
sys.modules["ida_hexrays"].user_lvar_modifier_t = type("user_lvar_modifier_t", (), {})
sys.modules["ida_netnode"].netnode = type("netnode", (), {
    "__init__": lambda *a, **kw: None,
    "longval": lambda *a: 0,
    "altval": lambda *a: 0,
    "getblob": lambda *a, **kw: None,
    "setblob": lambda *a, **kw: None,
})
sys.modules["idc"].batch = lambda x: 0
sys.modules["idc"].get_func_name = lambda ea: ""
sys.modules["idc"].get_name = lambda ea, *a: ""
sys.modules["idc"].print_insn_mnem = lambda ea: ""
sys.modules["idc"].next_head = lambda ea, end: ea + 1
sys.modules["idautils"].Functions = lambda: []
sys.modules["idautils"].XrefsFrom = lambda ea, *a: []
sys.modules["idautils"].XrefsTo = lambda ea, *a: []

# Mock rpc and sync modules in-place
for mod_name in ("rpc", "sync"):
    if mod_name not in sys.modules:
        sys.modules[mod_name] = types.ModuleType(mod_name)

sys.modules["rpc"].tool = lambda f: f
sys.modules["rpc"].unsafe = lambda f: f
sys.modules["rpc"].prompt = lambda f: f

sys.modules["sync"].idaread = lambda f: f
sys.modules["sync"].idawrite = lambda f: f
if not hasattr(sys.modules["sync"], "IDAError"):
    sys.modules["sync"].IDAError = type("IDAError", (Exception,), {})

cb = load_tool_submodule("search.combinators")


def _read(path):
    with open(path) as f:
        return f.read()


def _functions(src):
    """Return all top-level function AND class names."""
    tree = ast.parse(src)
    return {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}


# ---- 1. combinators.py exists with the right surface ------------------------

def test_bool_tokenizer_handles_simple_primitive():
    """Test the tokenizer by importing the function with stub IDA modules."""
    toks = cb._tokenize_bool("api:Crypt* AND name:key")
    assert toks == ["api:Crypt*", "AND", "name:key"], f"got {toks}"

    toks = cb._tokenize_bool("(string:\"my secret\" OR name:foo) AND NOT mnem:ret")
    assert toks == ["(", "string:my secret", "OR", "name:foo", ")", "AND", "NOT", "mnem:ret"], f"got {toks}"

    # Test logical aliases
    toks = cb._tokenize_bool("(string:\"my secret\" || name:foo) && ! mnem:ret")
    assert toks == ["(", "string:my secret", "OR", "name:foo", ")", "AND", "NOT", "mnem:ret"], f"got {toks}"

    # Test bare keywords
    toks = cb._tokenize_bool("api:Crypt* && leaf")
    assert toks == ["api:Crypt*", "AND", "leaf:true"], f"got {toks}"

    # Test escaped double quotes
    toks = cb._tokenize_bool("string:\"my \\\"escaped\\\" secret\"")
    assert toks == ["string:my \"escaped\" secret"], f"got {toks}"


def test_bool_parser_precedence():
    """AND binds tighter than OR; NOT applies to the next atom."""
    # Stub the handlers so we can test parser precedence without IDA.
    s_name, s_api = {1, 2}, {2, 3}
    cb._BOOL_PRIMITIVES["name"] = lambda pat, **kw: {int(p) for p in pat.split(",") if p}
    cb._BOOL_PRIMITIVES["api"] = lambda pat: {int(p) for p in pat.split(",") if p}
    cb._prim_funcs_by_name = lambda pat, **kw: {int(p) for p in pat.split(",") if p}
    cb._prim_funcs_by_api = lambda pat: {int(p) for p in pat.split(",") if p}
    cb._all_func_eas = lambda: {1, 2, 3, 4, 5}

    # 1 AND 2 OR 3 = (1&2) | 3 = {2, 3}
    toks = cb._tokenize_bool("name:1,2 OR name:3")
    parser = cb._BoolParser(toks)
    assert parser.parse_expr() == {1, 2, 3}

    # 1 OR 2 AND 3 = 1 | (2&3) = {1}
    toks = cb._tokenize_bool("name:1 OR name:2 AND api:3")
    parser = cb._BoolParser(toks)
    assert parser.parse_expr() == {1}

    # NOT name:1 = all - 1
    toks = cb._tokenize_bool("NOT name:1")
    parser = cb._BoolParser(toks)
    assert parser.parse_expr() == {2, 3, 4, 5}


# ---- 5. search_hunt 'list' sub-action ---------------------------------------

def test_bool_new_primitives():
    class MockFunc:
        def __init__(self, start, end):
            self.start_ea = start
            self.end_ea = end

    cb.idautils.Functions = lambda: [0x401000, 0x402000]
    cb.idaapi.get_func = lambda ea: MockFunc(0x401000, 0x401200) if ea == 0x401000 else MockFunc(0x402000, 0x402030)

    # Test size primitive
    assert cb._prim_size(">100") == {0x401000}
    assert cb._prim_size("<100") == {0x402000}

    # Test leaf / no_callers
    cb.CALL_XREF_TYPES = {21}
    class MockXref:
        def __init__(self, iscode=True, xtype=21):
            self.iscode = iscode
            self.type = xtype
    cb.idautils.XrefsFrom = lambda ea, *a: [MockXref()] if ea == 0x401000 else []
    cb.idautils.XrefsTo = lambda ea, *a: [MockXref()] if ea == 0x401000 else []

    assert cb._prim_leaf("") == {0x402000}
    assert cb._prim_no_callers("") == {0x402000}

