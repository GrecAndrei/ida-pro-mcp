"""Comprehensive benchmarks for the rewritten IDA-backed classifiers.

Exercises :func:`search_vulnerable`, :func:`search_hunt`, and the ``classify``
actions (``binary``, ``initializers``, ``error_handlers``, ``function``,
``wrappers``, ``orphans``) with synthetic IDBs built by :class:`FakeIDB`.

Goals: reachability filtering, category distribution, segment membership,
callee verification — under scale (hundreds of functions) and adversarial
shape (deep chains, cycles, orphans, negatives).
"""
from __future__ import annotations

import os
import sys
import types

from tests._isolated_repo_loader import load_support_module, load_tool_module, load_tool_submodule
from tests.tools.fake_idb import MOCK_EXEC, FakeIDB

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

for _mn in ("idaapi", "idc", "idautils", "ida_funcs", "ida_bytes",
            "ida_segment", "ida_nalt", "ida_hexrays", "ida_lines",
            "ida_name", "ida_typeinf", "ida_kernwin", "ida_loader",
            "ida_dbg", "ida_frame", "ida_struct", "ida_ua", "ida_xref",
            "rpc", "sync"):
    if _mn not in sys.modules:
        sys.modules[_mn] = types.ModuleType(_mn)

sys.modules["idaapi"].BADADDR = 0xFFFFFFFF
sys.modules["idaapi"].SEGPERM_EXEC = 1
sys.modules["idaapi"].fl_CN = 21
sys.modules["idaapi"].fl_CF = 22
sys.modules["ida_funcs"].func_t = type("func_t", (), {})
sys.modules["ida_typeinf"].tinfo_t = type("tinfo_t", (), {})
sys.modules["ida_hexrays"].user_lvar_modifier_t = type("user_lvar_modifier_t", (), {})
sys.modules["rpc"].tool = lambda f: f
sys.modules["rpc"].unsafe = lambda f: f
sys.modules["sync"].idaread = lambda f: f
sys.modules["sync"].idawrite = lambda f: f
sys.modules["sync"].IDAError = type("IDAError", (Exception,), {})
sys.modules["idc"].batch = lambda x: 0
sys.modules["idc"].get_func_name = lambda ea: ""
sys.modules["idc"].get_name = lambda ea, *a: ""
sys.modules["idc"].get_str_type = lambda ea: None
sys.modules["idc"].get_strlit_contents = lambda *a, **kw: None
sys.modules["idc"].next_head = lambda ea, end: ea + 1
sys.modules["idautils"].Functions = list
sys.modules["idautils"].Names = lambda: iter([])
sys.modules["idautils"].Heads = lambda s, e: iter(range(s, e, 2))
sys.modules["idautils"].CodeRefsFrom = lambda ea, *a: []
sys.modules["idautils"].CodeRefsTo = lambda ea, *a: []
sys.modules["idautils"].XrefsFrom = lambda ea, *a: []
sys.modules["idautils"].XrefsTo = lambda ea, *a: []
sys.modules["idaapi"].get_func = lambda ea: None
sys.modules["idaapi"].getseg = lambda ea: None
sys.modules["idaapi"].get_next_seg = lambda ea: None
sys.modules["ida_funcs"].get_func = lambda ea: None
sys.modules["ida_segment"].getseg = lambda ea: None
sys.modules["ida_segment"].get_segm_name = lambda seg: ""
sys.modules["ida_nalt"].get_import_module_qty = lambda: 0
sys.modules["ida_nalt"].get_import_module_name = lambda i: None
sys.modules["ida_hexrays"].decompile = lambda ea: None


class MockXref:
    def __init__(self, frm=0, to=0):
        self.frm = frm
        self.to = to


def _api_cat():
    return load_support_module("_api_categories")


def _load_search_advanced():
    cat = load_support_module("_api_categories")
    return load_tool_submodule("search.advanced", common_overrides={"DANGEROUS_APIS": cat.DANGEROUS_APIS})


def _load_classify():
    cat = load_support_module("_api_categories")
    return load_tool_module("classify", common_overrides={
        "DANGEROUS_APIS": cat.DANGEROUS_APIS,
        "API_CATEGORIES": cat.API_CATEGORIES,
        "API_TO_CATEGORY": cat.API_TO_CATEGORY,
        "MAGIC_CONSTANTS": cat.MAGIC_CONSTANTS,
    })


def _load_combinators():
    return load_tool_submodule("search.combinators")


# =========================================================================
# search_vulnerable — taint reachability BFS
# =========================================================================
class TestSearchVulnerable:

    def test_dangerous_api_directly_from_taint_source(self):
        _api_cat()
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "recv", callees=["memcpy"])
        db.install()
        mod = _load_search_advanced()
        res = mod.search_vulnerable(
            pattern=None, include_context=False, offset=0, limit=100,
            include_items=True, include_breakdown=False,
        )
        assert res["ok"] is True
        apis = {it["api"] for it in res.get("items", [])}
        assert "memcpy" in apis

    def test_dangerous_api_reachable_via_transitive_chain(self):
        # BFS walks UP (caller direction): a function is taint-reachable if
        # it transitively CALLS a taint source.  So the chain is
        # sprintf_user -> middle -> recv, plus sprintf_user -> sprintf.
        _api_cat()
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x403000)
        db.add_func(0x401000, "recv")
        db.add_func(0x401100, "middle")
        db.add_func(0x401200, "sprintf_user")
        db._callees[0x401100] = {0x401000}    # middle calls recv
        db._callers[0x401000] = {0x401100}
        db._callees[0x401200] = {0x401100}    # sprintf_user calls middle
        db._callers.setdefault(0x401100, set()).add(0x401200)
        db._import_ea["sprintf"] = 0xF0001000
        db._names[0xF0001000] = "sprintf"
        db._callees[0x401200].add(0xF0001000)  # sprintf_user -> sprintf
        db.install()
        mod = _load_search_advanced()
        res = mod.search_vulnerable(
            pattern=None, include_context=False, offset=0, limit=100,
            include_items=True, include_breakdown=False,
        )
        apis = {it["api"] for it in res.get("items", [])}
        assert "sprintf" in apis

    def test_unreachable_dangerous_api_is_filtered(self):
        _api_cat()
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x403000)
        db.add_func(0x401000, "recv", callees=[])
        db.add_func(0x402000, "init_module", callees=["strcpy"])
        db.install()
        mod = _load_search_advanced()
        res = mod.search_vulnerable(
            pattern=None, include_context=False, offset=0, limit=100,
            include_items=True, include_breakdown=False,
        )
        apis = {it["api"] for it in res.get("items", [])}
        assert "strcpy" not in apis

    def test_no_taint_sources_means_no_findings(self):
        _api_cat()
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "sub_401000", callees=["strcpy"])
        db.install()
        mod = _load_search_advanced()
        res = mod.search_vulnerable(
            pattern=None, include_context=False, offset=0, limit=100,
            include_items=True, include_breakdown=False,
        )
        assert res.get("count", 0) == 0

    def test_no_dangerous_apis_means_no_findings(self):
        _api_cat()
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "recv", callees=["malloc"])
        db.install()
        mod = _load_search_advanced()
        res = mod.search_vulnerable(
            pattern=None, include_context=False, offset=0, limit=100,
            include_items=True, include_breakdown=False,
        )
        assert res.get("count", 0) == 0

    def test_deep_chain_within_depth_limit(self):
        # Chain: top -> h4 -> h3 -> h2 -> h1 -> recv (depth 5), top -> strcpy
        _api_cat()
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        eas = [0x401000 + i * 0x100 for i in range(6)]
        db.add_func(eas[0], "recv")
        for i in range(1, 6):
            db.add_func(eas[i], "hop_%d" % i)
        # caller direction: hop_1 calls recv, hop_2 calls hop_1, ...
        for i in range(1, 6):
            db._callees.setdefault(eas[i], set()).add(eas[i - 1])
            db._callers.setdefault(eas[i - 1], set()).add(eas[i])
        db._import_ea["strcpy"] = 0xF0002000
        db._names[0xF0002000] = "strcpy"
        db._callees[eas[5]].add(0xF0002000)  # top calls strcpy
        db.install()
        mod = _load_search_advanced()
        res = mod.search_vulnerable(
            pattern=None, include_context=False, offset=0, limit=100,
            include_items=True, include_breakdown=False, taint_depth=5,
        )
        apis = {it["api"] for it in res.get("items", [])}
        assert "strcpy" in apis

    def test_chain_exceeding_depth_limit_is_filtered(self):
        _api_cat()
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x403000)
        eas = [0x401000 + i * 0x100 for i in range(10)]
        db.add_func(eas[0], "recv")
        for i in range(1, 10):
            db.add_func(eas[i], "hop_%d" % i)
        for i in range(1, 10):
            db._callees.setdefault(eas[i], set()).add(eas[i - 1])
            db._callers.setdefault(eas[i - 1], set()).add(eas[i])
        db._import_ea["strcpy"] = 0xF0003000
        db._names[0xF0003000] = "strcpy"
        db._callees[eas[9]].add(0xF0003000)
        db.install()
        mod = _load_search_advanced()
        res = mod.search_vulnerable(
            pattern=None, include_context=False, offset=0, limit=100,
            include_items=True, include_breakdown=False, taint_depth=3,
        )
        apis = {it["api"] for it in res.get("items", [])}
        assert "strcpy" not in apis

    def test_mixed_reachable_and_unreachable(self):
        _api_cat()
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x403000)
        db.add_func(0x401000, "recv", callees=["VirtualAlloc"])
        db.add_func(0x402000, "init_code", callees=["sprintf"])
        db.install()
        mod = _load_search_advanced()
        res = mod.search_vulnerable(
            pattern=None, include_context=False, offset=0, limit=100,
            include_items=True, include_breakdown=False,
        )
        apis = {it["api"] for it in res.get("items", [])}
        assert "VirtualAlloc" in apis
        assert "sprintf" not in apis

    def test_cyclic_call_graph_does_not_hang(self):
        # a and b call each other (cycle); a calls recv; b calls strcpy
        _api_cat()
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "recv")
        db.add_func(0x401100, "a")
        db.add_func(0x401200, "b")
        db._callees[0x401100] = {0x401000, 0x401200}   # a calls recv and b
        db._callers[0x401000] = {0x401100}
        db._callers[0x401200] = {0x401100}
        db._callees[0x401200] = {0x401100}              # b calls a
        db._callers.setdefault(0x401100, set()).add(0x401200)
        db._import_ea["strcpy"] = 0xF0004000
        db._names[0xF0004000] = "strcpy"
        db._callees[0x401200].add(0xF0004000)           # b -> strcpy
        db.install()
        mod = _load_search_advanced()
        res = mod.search_vulnerable(
            pattern=None, include_context=False, offset=0, limit=100,
            include_items=True, include_breakdown=False,
        )
        apis = {it["api"] for it in res.get("items", [])}
        assert "strcpy" in apis

    def test_many_functions_scale(self):
        _api_cat()
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x401000 + 600 * 0x100)
        db.add_func(0x401000, "recv")
        db.add_func(0x401100, "read")
        for i in range(2, 500):
            db.add_func(0x401000 + i * 0x100, "func_%d" % i)
        # caller direction: mid_50 calls recv AND strcpy
        mid = 0x401000 + 50 * 0x100
        db._callees[mid] = {0x401000}
        db._callers[0x401000] = {mid}
        db._import_ea["strcpy"] = 0xF0005000
        db._names[0xF0005000] = "strcpy"
        db._callees[mid].add(0xF0005000)
        # mid_100 calls read AND sprintf
        mid2 = 0x401000 + 100 * 0x100
        db._callees[mid2] = {0x401100}
        db._callers[0x401100] = {mid2}
        db._import_ea["sprintf"] = 0xF0005100
        db._names[0xF0005100] = "sprintf"
        db._callees[mid2].add(0xF0005100)
        # an unreachable dangerous call (no taint path)
        db._import_ea["gets"] = 0xF0005200
        db._names[0xF0005200] = "gets"
        db._callees[0x401000 + 400 * 0x100] = {0xF0005200}
        db.install()
        mod = _load_search_advanced()
        res = mod.search_vulnerable(
            pattern=None, include_context=False, offset=0, limit=200,
            include_items=True, include_breakdown=False,
        )
        apis = {it["api"] for it in res.get("items", [])}
        assert "strcpy" in apis
        assert "sprintf" in apis
        assert "gets" not in apis

    def test_two_taint_sources_reach_same_danger(self):
        # sink calls both recv AND read; sink calls strcpy
        _api_cat()
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "recv")
        db.add_func(0x401100, "read")
        db.add_func(0x401200, "sink")
        db._callees[0x401200] = {0x401000, 0x401100}   # sink calls recv AND read
        db._callers[0x401000] = {0x401200}
        db._callers[0x401100] = {0x401200}
        db._import_ea["strcpy"] = 0xF0006000
        db._names[0xF0006000] = "strcpy"
        db._callees[0x401200].add(0xF0006000)
        db.install()
        mod = _load_search_advanced()
        res = mod.search_vulnerable(
            pattern=None, include_context=False, offset=0, limit=100,
            include_items=True, include_breakdown=False,
        )
        apis = {it["api"] for it in res.get("items", [])}
        assert "strcpy" in apis

    def test_breakdown_and_taint_count(self):
        _api_cat()
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "recv", callees=["strcpy"])
        db.install()
        mod = _load_search_advanced()
        res = mod.search_vulnerable(
            pattern=None, include_context=False, offset=0, limit=100,
            include_items=True, include_breakdown=True,
        )
        assert res["ok"] is True
        assert res["taint_sources"] >= 1


# =========================================================================
# classify(action="binary")
# =========================================================================
class TestClassifyBinary:

    def test_basic_distribution(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "net_handler", callees=["socket", "connect", "send"])
        db.add_func(0x401100, "net_handler2", callees=["recv", "WSAStartup"])
        db.add_func(0x401200, "crypto_thing", callees=["SHA256", "MD5_Init"])
        db.add_func(0x401300, "plain", callees=[])
        db.add_import("kernel32")
        db.add_import("ws2_32")
        db.install()
        mod = _load_classify()
        res = mod.classify(action="binary", limit=50)
        assert res["ok"] is True
        assert res["function_count"] == 4
        dist = res["category_distribution"]
        assert dist.get("network", 0) >= 2
        assert dist.get("crypto", 0) >= 1
        assert "ws2_32" in res["import_modules"]

    def test_empty_binary(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x401000)
        db.install()
        mod = _load_classify()
        res = mod.classify(action="binary", limit=50)
        assert res["ok"] is True
        assert res["function_count"] == 0
        assert res["category_distribution"] == {}

    def test_all_unknown_functions(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        for i in range(10):
            db.add_func(0x401000 + i * 0x100, "sub_%d" % i, callees=[])
        db.install()
        mod = _load_classify()
        res = mod.classify(action="binary", limit=50)
        assert res["ok"] is True
        assert res["function_count"] == 10
        assert res["category_distribution"].get("unknown", 0) == 10

    def test_large_distribution(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x401000 + 300 * 0x100)
        callee_sets = {
            "network": ["socket", "connect"],
            "crypto": ["SHA256", "AES_encrypt"],
            "file_io": ["fopen", "fread"],
            "memory": ["malloc", "free"],
            "process": ["CreateProcess", "OpenProcess"],
        }
        idx = 0
        for cat, apis in callee_sets.items():
            for _ in range(50):
                ea = 0x401000 + idx * 0x100
                db.add_func(ea, "%s_func_%d" % (cat, idx), callees=apis)
                idx += 1
        db.install()
        mod = _load_classify()
        res = mod.classify(action="binary", limit=300)
        assert res["ok"] is True
        assert res["function_count"] == 250
        dist = res["category_distribution"]
        for cat in callee_sets:
            assert dist.get(cat, 0) >= 40, "%s: %d" % (cat, dist.get(cat, 0))


# =========================================================================
# classify(action="initializers")
# =========================================================================
class TestClassifyInitializers:

    def test_function_in_init_array(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_segment(".init_array", 0x405000, 0x405010, perm=0)
        db.add_func(0x401000, "do_init")
        db.add_func(0x401100, "do_fini")
        db.install()

        idu = sys.modules["idautils"]
        orig = idu.XrefsTo

        def _custom(target, flags=0):
            if target == 0x401000:
                return iter([MockXref(frm=0x405000, to=0x401000)])
            return iter([])

        idu.XrefsTo = _custom
        try:
            mod = _load_classify()
            res = mod.classify(action="initializers", limit=50)
            assert res["ok"] is True
            found = [x.split()[1] for x in res["initializers"]]
            assert "do_init" in found
            assert "do_fini" not in found
        finally:
            idu.XrefsTo = orig

    def test_no_init_segments(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "sub1")
        db.add_func(0x401100, "sub2")
        db.install()
        mod = _load_classify()
        res = mod.classify(action="initializers", limit=50)
        assert res["ok"] is True
        assert res["count"] == 0

    def test_init_and_ctors_both_match(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_segment(".init_array", 0x405000, 0x405010, perm=0)
        db.add_segment(".ctors", 0x406000, 0x406010, perm=0)
        db.add_func(0x401000, "init_a")
        db.add_func(0x401100, "ctor_b")
        db.install()

        import idautils
        orig = idautils.XrefsTo

        def _custom(target, flags=0):
            if target == 0x401000:
                return iter([MockXref(frm=0x405000, to=0x401000)])
            if target == 0x401100:
                return iter([MockXref(frm=0x406000, to=0x401100)])
            return iter([])

        idautils.XrefsTo = _custom
        try:
            mod = _load_classify()
            res = mod.classify(action="initializers", limit=50)
            found = [x.split()[1] for x in res["initializers"]]
            assert "init_a" in found
            assert "ctor_b" in found
        finally:
            idautils.XrefsTo = orig


# =========================================================================
# classify(action="error_handlers")
# =========================================================================
class TestClassifyErrorHandlers:

    def test_function_calling_error_api(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "handle_err", callees=["abort"])
        db.add_func(0x401100, "normal_func", callees=["malloc"])
        db.install()
        mod = _load_classify()
        res = mod.classify(action="error_handlers", limit=50)
        assert res["ok"] is True
        found = [x.split()[1] for x in res["error_handlers"]]
        assert "handle_err" in found
        assert "normal_func" not in found

    def test_no_error_handlers(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "normal", callees=["malloc", "free"])
        db.install()
        mod = _load_classify()
        res = mod.classify(action="error_handlers", limit=50)
        assert res["ok"] is True
        assert res["count"] == 0

    def test_suffix_stripping_matches(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "errA", callees=["GetLastError"])
        db.install()
        mod = _load_classify()
        res = mod.classify(action="error_handlers", limit=50)
        found = [x.split()[1] for x in res["error_handlers"]]
        assert "errA" in found

    def test_multiple_error_apis_in_one_function(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "multi_err", callees=["abort", "raise"])
        db.install()
        mod = _load_classify()
        res = mod.classify(action="error_handlers", limit=50)
        assert res["ok"] is True
        assert res["count"] >= 1


# =========================================================================
# search_hunt — named recipes
# =========================================================================
class TestSearchHunt:

    def test_recipe_list(self):
        mod = _load_combinators()
        res = mod.search_hunt(recipe="list", case_sensitive=False, offset=0, limit=10)
        assert res["ok"] is True
        assert "anti_debug" in res["available"]
        assert "crypto" in res["available"]
        assert "network_io" in res["available"]
        assert "file_io" in res["available"]
        assert "process_injection" in res["available"]

    def test_unknown_recipe_returns_error(self):
        mod = _load_combinators()
        res = mod.search_hunt(recipe="nonexistent_recipe", case_sensitive=False, offset=0, limit=10)
        assert res.get("ok") is False or res.get("error") is True

    def test_anti_debug_expression_is_structural(self):
        mod = _load_combinators()
        res = mod.search_hunt(recipe="anti_debug", case_sensitive=False, offset=0, limit=10)
        assert res["ok"] is True
        assert "IsDebuggerPresent" in res.get("expression", "") or "api:" in res.get("expression", "")

    def test_crypto_recipe_expression(self):
        mod = _load_combinators()
        res = mod.search_hunt(recipe="crypto", case_sensitive=False, offset=0, limit=10)
        assert res["ok"] is True
        expr = res.get("expression", "")
        assert "Crypt" in expr or "AES" in expr or "SHA" in expr

    def test_process_injection_recipe_uses_and(self):
        mod = _load_combinators()
        res = mod.search_hunt(recipe="process_injection", case_sensitive=False, offset=0, limit=10)
        assert res["ok"] is True
        expr = res.get("expression", "")
        assert "AND" in expr or "CreateProcess" in expr

    def test_network_io_recipe(self):
        mod = _load_combinators()
        res = mod.search_hunt(recipe="network_io", case_sensitive=False, offset=0, limit=10)
        assert res["ok"] is True
        assert "socket" in res.get("expression", "")

    def test_file_io_recipe(self):
        mod = _load_combinators()
        res = mod.search_hunt(recipe="file_io", case_sensitive=False, offset=0, limit=10)
        assert res["ok"] is True
        expr = res.get("expression", "")
        assert "CreateFile" in expr or "fopen" in expr


# =========================================================================
# classify(action="function")
# =========================================================================
class TestClassifyFunction:

    def test_single_function_classification(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "do_net", callees=["socket", "connect", "send", "recv"])
        db.install()
        mod = _load_classify()
        res = mod.classify(action="function", addr="0x401000", limit=1)
        assert res["ok"] is True
        assert res["category"] == "network"
        assert res["confidence"] == "high"

    def test_unknown_function(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "empty_func", callees=[])
        db.install()
        mod = _load_classify()
        res = mod.classify(action="function", addr="0x401000", limit=1)
        assert res["ok"] is True
        assert res["category"] == "unknown"


# =========================================================================
# classify(action="wrappers")
# =========================================================================
class TestClassifyWrappers:

    def test_wrapper_detected(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "wrapper", size=4, callees=["real_impl"])
        db.install()
        mod = _load_classify()
        res = mod.classify(action="wrappers", limit=50)
        assert res["ok"] is True
        found = [x.split()[1] for x in res["wrappers"]]
        assert "wrapper" in found


# =========================================================================
# classify(action="orphans")
# =========================================================================
class TestClassifyOrphans:

    def test_orphan_detected(self):
        db = FakeIDB()
        db.add_segment(".text", 0x401000, 0x402000)
        db.add_func(0x401000, "orphan_func")
        db.add_func(0x401100, "called_func")
        db._callees[0x401000] = {0x401100}
        db._callers[0x401100] = {0x401000}
        db.install()
        mod = _load_classify()
        res = mod.classify(action="orphans", limit=50)
        assert res["ok"] is True
        found = [x.split()[1] for x in res["orphans"]]
        assert "orphan_func" in found
        assert "called_func" not in found
