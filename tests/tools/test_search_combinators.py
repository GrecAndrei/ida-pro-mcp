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

def test_combinators_file_exists():
    assert os.path.exists(COMBINATORS), f"missing {COMBINATORS}"


def test_combinators_exposes_all_actions():
    src = _read(COMBINATORS)
    names = _functions(src)
    expected = {
        "search_bool", "search_hunt", "search_neighborhood",
        "search_outlier", "search_fingerprint", "search_path",
        "search_reach", "search_noreach",
    }
    missing = expected - names
    assert not missing, f"combinators.py missing functions: {missing}"


def test_combinators_exposes_helpers():
    """The internal helpers used by the bool parser should be at module scope."""
    src = _read(COMBINATORS)
    funcs = _functions(src)
    assert "_tokenize_bool" in funcs, "_tokenize_bool must be module-level"
    assert "_BoolParser" in funcs, "_BoolParser must be module-level"


def test_combinators_hunt_recipes_populated():
    """Use AST to find _HUNT_RECIPES assignment and count its keys (string-safe)."""
    import ast
    src = _read(COMBINATORS)
    tree = ast.parse(src)
    # Find the top-level _HUNT_RECIPES assignment
    target = None
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", None) == "_HUNT_RECIPES":
            target = node.value
            break
    assert target is not None, "_HUNT_RECIPES assignment not found at module level"
    assert isinstance(target, ast.Dict), "_HUNT_RECIPES must be a dict literal"
    n = len(target.keys)
    assert n >= 10, f"only {n} hunt recipes (expected >=10)"
    # All keys should be string constants
    for k in target.keys:
        assert isinstance(k, ast.Constant) and isinstance(k.value, str), \
            f"non-string recipe key: {ast.dump(k)}"


def test_combinators_recipes_cover_common_re_scenarios():
    src = _read(COMBINATORS)
    for recipe in (
        "backdoor", "anti_debug", "anti_vm", "license_check",
        "update_check", "c2", "parser", "crypto", "string_decode",
        "hardcoded_creds", "network_io", "file_io",
    ):
        assert f'"{recipe}"' in src, f"missing hunt recipe: {recipe}"


# ---- 2. router wires combinators in -----------------------------------------

def test_router_imports_combinator_functions():
    src = _read(INIT)
    for fn in (
        "search_bool", "search_hunt", "search_neighborhood",
        "search_outlier", "search_fingerprint", "search_path",
        "search_reach", "search_noreach",
    ):
        assert f"from .combinators import" in src and fn in src, \
            f"router missing import of {fn}"


def test_router_dispatches_each_new_action():
    """search() should have an `elif action == ...` branch for each new action."""
    src = _read(INIT)
    for action in ("bool", "hunt", "neighborhood", "outlier",
                   "fingerprint", "path", "reach", "noreach"):
        assert f'elif action == "{action}"' in src, \
            f"router missing dispatcher for action={action}"


def test_router_hunt_accepts_recipe_kwarg():
    src = _read(INIT)
    assert 'pattern_not_required = {"vulnerable", "constants", "summary", "outlier", "noreach", "hunt"}' in src
    assert 'kwargs.get("recipe") or actual_pattern or ""' in src


def test_router_literal_includes_new_actions():
    src = _read(INIT)
    # The Literal[...] type in the search() signature should list every new action
    literal_match = re.search(r"Literal\[(.+?)\]", src, re.DOTALL)
    assert literal_match, "no Literal[...] found in search() signature"
    literal = literal_match.group(1)
    for action in ("bool", "hunt", "neighborhood", "outlier",
                   "fingerprint", "path", "reach", "noreach"):
        assert f'"{action}"' in literal, f"Literal missing action: {action}"


# ---- 3. action set / aliases include new actions -----------------------------

def test_search_actions_set_includes_combinators():
    src = _read(CORE)
    # Find the SEARCH_ACTIONS = {...} set literal
    m = re.search(r"^SEARCH_ACTIONS\s*=\s*\{(.+?)\}", src, re.MULTILINE | re.DOTALL)
    assert m, "SEARCH_ACTIONS literal not found"
    body = m.group(1)
    for action in ("bool", "hunt", "neighborhood", "outlier",
                   "fingerprint", "path", "reach", "noreach"):
        assert f'"{action}"' in body, f"SEARCH_ACTIONS missing {action}"


def test_search_aliases_include_combinator_aliases():
    src = _read(CORE)
    m = re.search(r"^SEARCH_ALIASES\s*=\s*\{(.+?)\n\}", src, re.MULTILINE | re.DOTALL)
    assert m, "SEARCH_ALIASES literal not found"
    body = m.group(1)
    for alias in (
        "boolean", "query", "and_or",
        "recipe", "recipes", "workflow",
        "context", "neighbors", "around",
        "anomaly", "anomalies", "unusual",
        "struct_sim", "structural", "similar_struct",
        "shortest_path", "callgraph_path", "chain",
        "reachable", "forward", "fanout",
        "unreachable", "dead_code", "orphan_reach",
    ):
        assert f'"{alias}"' in body, f"SEARCH_ALIASES missing alias: {alias}"


# ---- 4. bool tokenizer/parser logic (tested via the source) -----------------

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

def test_hunt_recipe_list_is_sorted():
    """Passing recipe='list' should return sorted recipe names."""
    src = _read(COMBINATORS)
    # Find the recipe list branch
    m = re.search(r"if recipe == \"list\" or not recipe:\s*\n\s*rec_names = sorted\(_HUNT_RECIPES\)", src)
    assert m, "hunt action does not return sorted recipe list"


def test_hunt_unknown_recipe_returns_error():
    src = _read(COMBINATORS)
    # Check that we return make_error for unknown recipes
    assert "unknown recipe" in src, "hunt action should error on unknown recipe"


# ---- 6. Documentation --------------------------------------------------------

def test_search_docstring_lists_combinators():
    src = _read(INIT)
    # Find the search() function's docstring by locating the """ after `def search(...):`
    m = re.search(r'def search\([^)]*\)[^:]*:\s*\n\s*"""(.+?)"""', src, re.DOTALL)
    assert m, "could not find search() function docstring"
    doc = m.group(1)
    for action in ("bool", "hunt", "neighborhood", "outlier",
                   "fingerprint", "path", "reach", "noreach"):
        assert action in doc, f"docstring missing mention of action: {action}"


def test_bool_new_primitives():
    class MockFunc:
        def __init__(self, start, end):
            self.start_ea = start
            self.end_ea = end

    sys.modules["idautils"].Functions = lambda: [0x401000, 0x402000]
    sys.modules["idaapi"].get_func = lambda ea: MockFunc(0x401000, 0x401200) if ea == 0x401000 else MockFunc(0x402000, 0x402030)

    # Test size primitive
    assert cb._prim_size(">100") == {0x401000}
    assert cb._prim_size("<100") == {0x402000}

    # Test leaf / no_callers
    cb.CALL_XREF_TYPES = {21}
    class MockXref:
        def __init__(self, iscode=True, xtype=21):
            self.iscode = iscode
            self.type = xtype
    sys.modules["idautils"].XrefsFrom = lambda ea, *a: [MockXref()] if ea == 0x401000 else []
    sys.modules["idautils"].XrefsTo = lambda ea, *a: [MockXref()] if ea == 0x401000 else []

    assert cb._prim_leaf("") == {0x402000}
    assert cb._prim_no_callers("") == {0x402000}


def test_combinators_module_line_count_reasonable():
    """Sanity check: combinators.py should be in the 300-1500 line range."""
    with open(COMBINATORS) as f:
        n = sum(1 for _ in f)
    assert 300 <= n <= 1500, f"combinators.py is {n} lines (expected 300-1500)"


def test_no_duplicate_action_dispatchers():
    """Each action should appear in exactly one elif branch."""
    src = _read(INIT)
    for action in ("bool", "hunt", "neighborhood", "outlier",
                   "fingerprint", "path", "reach", "noreach"):
        n = len(re.findall(rf'elif action == "{action}"', src))
        assert n == 1, f"action {action!r} has {n} dispatcher branches (expected 1)"
