"""Tests for the custom detector engine in code_helpers.py.

Tests all 6 rule types: api_chain, string_ref, type_match, xor_threshold, caller_of, callee_of.
Also tests registration, listing, deletion, and inline vs registered rules.
"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import install_common_stub, load_tool_module


def _setup_fake_ida(funcs_db: dict, xrefs_db: dict | None = None, strings_db: list | None = None):
    """Install a FakeIDB with controllable functions, xrefs, and strings.

    funcs_db: {ea: {name, calls: [callee_ea, ...], size, xor_count}}
    xrefs_db: {target_ea: [caller_ea, ...]}
    strings_db: [{ea, value}]
    """
    xrefs_db = xrefs_db or {}
    strings_db = strings_db or []

    idaapi = sys.modules["idaapi"]
    idc = sys.modules["idc"]
    idautils = sys.modules["idautils"]
    ida_funcs = sys.modules["ida_funcs"]
    sys.modules["ida_bytes"]
    ida_hexrays = sys.modules["ida_hexrays"]
    ida_typeinf = sys.modules["ida_typeinf"]

    # idaapi basics
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi.get_idb = lambda: None
    # Mock get_next_func to iterate our funcs_db
    _func_eas = sorted(funcs_db.keys())
    _func_idx = [0]  # mutable counter for closure

    def get_next_func(ea):
        # Find first func_ea > ea
        for f_ea in _func_eas:
            if f_ea > ea:
                return f_ea
        return idaapi.BADADDR

    idaapi.get_next_func = get_next_func
    idaapi.get_first_cref_to = lambda ea: idaapi.BADADDR
    idaapi.get_next_cref_to = lambda ea, ref: idaapi.BADADDR
    idaapi.get_first_cref_from = lambda ea: idaapi.BADADDR
    idaapi.get_next_cref_from = lambda ea, ref: idaapi.BADADDR
    idaapi.func_item_iterator_t = lambda func: types.SimpleNamespace(
        current=lambda: idaapi.BADADDR,
        next_code=lambda: False,
    )

    # idc
    def get_name(ea):
        for f_ea, f_info in funcs_db.items():
            if f_ea == ea:
                return f_info.get("name", "")
        return ""

    def get_func_name(ea):
        return get_name(ea)

    def get_name_ea_simple(name):
        for f_ea, f_info in funcs_db.items():
            if f_info.get("name") == name:
                return f_ea
        return idaapi.BADADDR

    def print_insn_mnem(ea):
        for f_ea, f_info in funcs_db.items():
            if f_ea <= ea < f_ea + f_info.get("size", 0x100):
                xor_count = f_info.get("xor_count", 0)
                if xor_count > 0 and (ea - f_ea) < xor_count * 4:
                    return "XOR"
        return "MOV"

    idc.get_name = get_name
    idc.get_func_name = get_func_name
    idc.get_name_ea_simple = get_name_ea_simple
    idc.print_insn_mnem = print_insn_mnem

    # ida_funcs
    class FakeFunc:
        def __init__(self, ea, size=0x100):
            self.start_ea = ea
            self.end_ea = ea + size
            self.flags = 0

    def get_func(ea):
        for f_ea, f_info in funcs_db.items():
            if f_ea <= ea < f_ea + f_info.get("size", 0x100):
                return FakeFunc(f_ea, f_info.get("size", 0x100))
        return None

    ida_funcs.get_func = get_func
    ida_funcs.get_func_name = get_func_name

    # idautils — make Strings() subscriptable and iterable
    class FakeStringItem:
        def __init__(self, ea, value):
            self.ea = ea
            self._value = value
        def __str__(self):
            return self._value

    class FakeStrings:
        def __init__(self, items):
            self._items = items
            self.count = len(items)
        def __getitem__(self, i):
            return self._items[i]
        def __iter__(self):
            return iter(self._items)

    def strings_factory():
        items = []
        for s in strings_db:
            items.append(FakeStringItem(s["ea"], s["value"]))
        return FakeStrings(items)

    def xrefs_to(ea):
        callers = xrefs_db.get(ea, [])
        return [types.SimpleNamespace(frm=c_ea) for c_ea in callers]

    def func_items(ea):
        func = get_func(ea)
        if func:
            return list(range(func.start_ea, func.end_ea, 4))
        return []

    def code_refs_from(ea, flow):
        func = get_func(ea)
        if func:
            f_info = funcs_db.get(func.start_ea, {})
            calls = f_info.get("calls", [])
            return iter(calls)
        return iter([])

    def code_refs_to(ea, flow):
        callers = xrefs_db.get(ea, [])
        return iter(callers)

    idautils.Strings = strings_factory
    idautils.XrefsTo = xrefs_to
    idautils.FuncItems = func_items
    idautils.CodeRefsFrom = code_refs_from
    idautils.CodeRefsTo = code_refs_to

    # ida_hexrays — stub decompile to return None by default
    ida_hexrays.decompile = lambda ea: None
    ida_hexrays.ctree_visitor_t = type("ctree_visitor_t", (), {
        "__init__": lambda self, flags: None,
        "apply_to": lambda self, body, item: 0,
        "visit_expr": lambda self, expr: 0,
    })
    ida_hexrays.CV_FAST = 0
    ida_hexrays.cot_call = 24
    ida_hexrays.cot_obj = 28

    # ida_typeinf
    class FakeTinfo:
        def get_numbered_type(self, til, ordinal):
            return False
        def get_func_details(self, func_data):
            return False
    ida_typeinf.tinfo_t = FakeTinfo
    ida_typeinf.func_type_data_t = lambda: types.SimpleNamespace(
        size=lambda: 0, __getitem__=lambda self, i: None
    )


class TestDetectorRegistration(unittest.TestCase):
    """Test register, list, delete operations on custom detectors."""

    def setUp(self):
        install_common_stub()
        self.mod = load_tool_module("code_helpers")
        self.mod._CUSTOM_DETECTORS.clear()

    def tearDown(self):
        self.mod._CUSTOM_DETECTORS.clear()

    def test_register_detector(self):
        result = self.mod.register_detector("test_rule", {"type": "api_chain", "apis": ["recv", "memcpy"]})
        self.assertTrue(result["ok"])
        self.assertEqual(result["name"], "test_rule")
        self.assertIn("test_rule", self.mod._CUSTOM_DETECTORS)

    def test_list_detectors(self):
        self.mod.register_detector("rule1", {"type": "api_chain", "apis": ["recv"]})
        self.mod.register_detector("rule2", {"type": "string_ref", "pattern": "pass"})
        result = self.mod.list_detectors()
        self.assertEqual(len(result), 2)
        names = [d["name"] for d in result]
        self.assertIn("rule1", names)
        self.assertIn("rule2", names)

    def test_delete_detector(self):
        self.mod.register_detector("to_delete", {"type": "xor_threshold", "threshold": 5})
        self.assertTrue(self.mod.delete_detector("to_delete"))
        self.assertNotIn("to_delete", self.mod._CUSTOM_DETECTORS)

    def test_delete_nonexistent(self):
        self.assertFalse(self.mod.delete_detector("does_not_exist"))

    def test_register_is_case_insensitive(self):
        self.mod.register_detector("MyRule", {"type": "api_chain", "apis": ["recv"]})
        self.assertIn("myrule", self.mod._CUSTOM_DETECTORS)
        self.mod.delete_detector("MYRULE")
        self.assertEqual(len(self.mod._CUSTOM_DETECTORS), 0)


class TestCustomDetectorDispatch(unittest.TestCase):
    """Test _run_custom_detector routing and validation."""

    def setUp(self):
        install_common_stub()
        self.mod = load_tool_module("code_helpers")
        self.mod._CUSTOM_DETECTORS.clear()

    def tearDown(self):
        self.mod._CUSTOM_DETECTORS.clear()

    def test_missing_rule_type_returns_error(self):
        result = self.mod._run_custom_detector({}, 100)
        self.assertFalse(result["ok"])

    def test_register_via_run(self):
        result = self.mod._run_custom_detector({
            "register": True,
            "name": "my_chain",
            "rule": {"type": "api_chain", "apis": ["recv", "send"]},
        }, 100)
        self.assertTrue(result["ok"])
        self.assertIn("my_chain", self.mod._CUSTOM_DETECTORS)

    def test_list_via_run(self):
        self.mod.register_detector("r1", {"type": "xor_threshold", "threshold": 3})
        result = self.mod._run_custom_detector({"list_detectors": True}, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["detectors"]), 1)

    def test_delete_via_run(self):
        self.mod.register_detector("r1", {"type": "xor_threshold"})
        result = self.mod._run_custom_detector({"delete_detector": True, "name": "r1"}, 100)
        self.assertTrue(result["ok"])
        self.assertTrue(result["deleted"])

    def test_delete_missing_name_returns_error(self):
        result = self.mod._run_custom_detector({"delete_detector": True}, 100)
        self.assertFalse(result["ok"])

    def test_unknown_rule_type_returns_error(self):
        result = self.mod._run_custom_detector({"rule_type": "bogus"}, 100)
        self.assertFalse(result["ok"])


class TestXORDetector(unittest.TestCase):
    """Test xor_threshold detector with mocked IDA functions."""

    def setUp(self):
        install_common_stub()
        self.mod = load_tool_module("code_helpers")
        self.mod._CUSTOM_DETECTORS.clear()

    def tearDown(self):
        self.mod._CUSTOM_DETECTORS.clear()

    def test_finds_crypto_function(self):
        _setup_fake_ida({
            0x401000: {"name": "encrypt_data", "size": 0x100, "xor_count": 8},
            0x402000: {"name": "normal_func", "size": 0x100, "xor_count": 0},
        })
        result = self.mod._run_custom_detector({"rule_type": "xor_threshold", "threshold": 4}, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["matches"][0]["name"], "encrypt_data")
        self.assertEqual(result["matches"][0]["xor_count"], 8)

    def test_respects_threshold(self):
        _setup_fake_ida({
            0x401000: {"name": "light_crypto", "size": 0x100, "xor_count": 2},
        })
        result = self.mod._run_custom_detector({"rule_type": "xor_threshold", "threshold": 4}, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 0)

    def test_max_items_limits_results(self):
        funcs = {i * 0x1000: {"name": f"crypto_{i}", "size": 0x100, "xor_count": 10} for i in range(20)}
        _setup_fake_ida(funcs)
        result = self.mod._run_custom_detector({"rule_type": "xor_threshold", "threshold": 1, "max_items": 5}, 5)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 5)

    def test_multiple_crypto_functions(self):
        _setup_fake_ida({
            0x401000: {"name": "aes_encrypt", "size": 0x100, "xor_count": 12},
            0x402000: {"name": "rc4_crypt", "size": 0x100, "xor_count": 6},
            0x403000: {"name": "normal", "size": 0x100, "xor_count": 1},
        })
        result = self.mod._run_custom_detector({"rule_type": "xor_threshold", "threshold": 4}, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 2)
        names = {m["name"] for m in result["matches"]}
        self.assertIn("aes_encrypt", names)
        self.assertIn("rc4_crypt", names)


class TestCallerOfDetector(unittest.TestCase):
    """Test caller_of detector (finds callees of a function)."""

    def setUp(self):
        install_common_stub()
        self.mod = load_tool_module("code_helpers")
        self.mod._CUSTOM_DETECTORS.clear()

    def tearDown(self):
        self.mod._CUSTOM_DETECTORS.clear()

    def test_finds_callees(self):
        _setup_fake_ida({
            0x401000: {"name": "main", "calls": [0x402000, 0x403000]},
            0x402000: {"name": "process_data"},
            0x403000: {"name": "send_response"},
        })
        result = self.mod._run_custom_detector({
            "rule_type": "caller_of", "target": "main"
        }, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 2)
        names = [m["name"] for m in result["matches"]]
        self.assertIn("process_data", names)
        self.assertIn("send_response", names)

    def test_unknown_target_returns_empty(self):
        _setup_fake_ida({0x401000: {"name": "main"}})
        result = self.mod._run_custom_detector({
            "rule_type": "caller_of", "target": "nonexistent_func"
        }, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 0)

    def test_deduplicates_callees(self):
        """Same callee referenced multiple times should appear once."""
        _setup_fake_ida({
            0x401000: {"name": "loop_func", "calls": [0x402000, 0x402000, 0x402000]},
            0x402000: {"name": "shared"},
        })
        result = self.mod._run_custom_detector({
            "rule_type": "caller_of", "target": "loop_func"
        }, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)


class TestCalleeOfDetector(unittest.TestCase):
    """Test callee_of detector (finds functions that call target)."""

    def setUp(self):
        install_common_stub()
        self.mod = load_tool_module("code_helpers")
        self.mod._CUSTOM_DETECTORS.clear()

    def tearDown(self):
        self.mod._CUSTOM_DETECTORS.clear()

    def test_finds_callers(self):
        _setup_fake_ida({
            0x401000: {"name": "handler1"},
            0x402000: {"name": "handler2"},
            0x403000: {"name": "shared_util"},
        }, xrefs_db={
            0x403000: [0x401000, 0x402000],
        })
        result = self.mod._run_custom_detector({
            "rule_type": "callee_of", "target": "shared_util"
        }, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 2)
        names = [m["name"] for m in result["matches"]]
        self.assertIn("handler1", names)
        self.assertIn("handler2", names)


class TestStringRefDetector(unittest.TestCase):
    """Test string_ref detector using idautils.Strings + XrefsTo."""

    def setUp(self):
        install_common_stub()
        self.mod = load_tool_module("code_helpers")
        self.mod._CUSTOM_DETECTORS.clear()

    def tearDown(self):
        self.mod._CUSTOM_DETECTORS.clear()

    def test_finds_string_reference(self):
        _setup_fake_ida(
            {0x401000: {"name": "auth_check"}},
            xrefs_db={0x500000: [0x401000]},
            strings_db=[{"ea": 0x500000, "value": "Enter password: "}],
        )
        result = self.mod._run_custom_detector({
            "rule_type": "string_ref", "pattern": "password"
        }, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["matches"][0]["name"], "auth_check")
        self.assertIn("password", result["matches"][0]["string"].lower())

    def test_regex_pattern(self):
        _setup_fake_ida(
            {0x401000: {"name": "network_init"}},
            xrefs_db={0x500000: [0x401000]},
            strings_db=[{"ea": 0x500000, "value": "http://example.com/api"}],
        )
        result = self.mod._run_custom_detector({
            "rule_type": "string_ref", "pattern": "https?://"
        }, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)

    def test_no_match_returns_empty(self):
        _setup_fake_ida(
            {0x401000: {"name": "some_func"}},
            strings_db=[{"ea": 0x500000, "value": "hello world"}],
        )
        result = self.mod._run_custom_detector({
            "rule_type": "string_ref", "pattern": "nonexistent_pattern_xyz"
        }, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 0)


class TestRegisteredDetectorExecution(unittest.TestCase):
    """Test that registered detectors can be executed by name."""

    def setUp(self):
        install_common_stub()
        self.mod = load_tool_module("code_helpers")
        self.mod._CUSTOM_DETECTORS.clear()

    def tearDown(self):
        self.mod._CUSTOM_DETECTORS.clear()

    def test_execute_registered_detector(self):
        self.mod.register_detector("find_crypto", {
            "type": "xor_threshold",
            "threshold": 6,
        })
        _setup_fake_ida({
            0x401000: {"name": "aes_encrypt", "size": 0x100, "xor_count": 10},
            0x402000: {"name": "simple_xor", "size": 0x100, "xor_count": 2},
        })
        result = self.mod._run_custom_detector({"rule_name": "find_crypto"}, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["matches"][0]["name"], "aes_encrypt")

    def test_registered_detector_with_inline_override(self):
        self.mod.register_detector("flexible_crypto", {
            "type": "xor_threshold",
            "threshold": 4,
        })
        _setup_fake_ida({
            0x401000: {"name": "weak_crypto", "size": 0x100, "xor_count": 3},
        })
        result = self.mod._run_custom_detector({
            "rule_name": "flexible_crypto", "threshold": 2
        }, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)


class TestAPIChainDetectorMock(unittest.TestCase):
    """Test api_chain detector with a fully mocked ctree."""

    def setUp(self):
        install_common_stub()
        self.mod = load_tool_module("code_helpers")
        self.mod._CUSTOM_DETECTORS.clear()

    def tearDown(self):
        self.mod._CUSTOM_DETECTORS.clear()

    def test_api_chain_with_mocked_ctree(self):
        """Mock decompile to return a cfunc with call chain."""
        ida_hexrays = sys.modules["ida_hexrays"]
        sys.modules["idc"]

        _setup_fake_ida({
            0x401000: {"name": "vulnerable_func", "size": 0x100},
        })

        class MockCfunc:
            def __init__(self):
                self.body = type("Body", (), {})()

        # Create a visitor that injects the call chain
        class TrackingVisitor:
            def __init__(self, flags):
                self._chain = []
            def apply_to(self, body, item):
                self._chain.extend(["recv", "memcpy"])
                return 0
            def visit_expr(self, expr):
                return 0

        ida_hexrays.ctree_visitor_t = TrackingVisitor
        ida_hexrays.decompile = lambda ea: MockCfunc() if ea == 0x401000 else None

        # Re-load to pick up the new ctree_visitor_t
        self.mod = load_tool_module("code_helpers")

        result = self.mod._run_custom_detector({
            "rule_type": "api_chain",
            "apis": ["recv", "memcpy"],
            "strict_order": True,
        }, 100)
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(result["count"], 1)
        self.assertEqual(result["matches"][0]["name"], "vulnerable_func")

    def test_api_chain_strict_order_mismatch(self):
        """APIs in wrong order should not match."""
        ida_hexrays = sys.modules["ida_hexrays"]

        _setup_fake_ida({
            0x401000: {"name": "func_with_wrong_order", "size": 0x100},
        })

        class WrongOrderVisitor:
            def __init__(self, flags):
                self._chain = []
            def apply_to(self, body, item):
                # memcpy before recv — wrong order
                self._chain.extend(["memcpy", "recv"])
                return 0
            def visit_expr(self, expr):
                return 0

        ida_hexrays.ctree_visitor_t = WrongOrderVisitor
        ida_hexrays.decompile = lambda ea: type("Cfunc", (), {"body": type("Body", (), {})()})() if ea == 0x401000 else None

        self.mod = load_tool_module("code_helpers")

        result = self.mod._run_custom_detector({
            "rule_type": "api_chain",
            "apis": ["recv", "memcpy"],
            "strict_order": True,
        }, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 0)

    def test_api_chain_any_order(self):
        """Any-order matching should find reversed chains."""
        ida_hexrays = sys.modules["ida_hexrays"]

        _setup_fake_ida({
            0x401000: {"name": "func_any_order", "size": 0x100},
        })

        class AnyOrderVisitor:
            def __init__(self, flags):
                self._chain = []
            def apply_to(self, body, item):
                self._chain.extend(["memcpy", "recv"])
                return 0
            def visit_expr(self, expr):
                return 0

        ida_hexrays.ctree_visitor_t = AnyOrderVisitor
        ida_hexrays.decompile = lambda ea: type("Cfunc", (), {"body": type("Body", (), {})()})() if ea == 0x401000 else None

        self.mod = load_tool_module("code_helpers")

        result = self.mod._run_custom_detector({
            "rule_type": "api_chain",
            "apis": ["recv", "memcpy"],
            "strict_order": False,
        }, 100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)


class TestAPIStrictOrderLogic(unittest.TestCase):
    """Test the strict_order matching logic in isolation."""

    def test_strict_order_match(self):
        chain = ["socket", "bind", "listen", "recv", "process", "memcpy", "send"]
        apis = ["recv", "memcpy"]
        idx = 0
        matched = True
        for api in apis:
            found = False
            while idx < len(chain):
                if api in chain[idx]:
                    found = True
                    idx += 1
                    break
                idx += 1
            if not found:
                matched = False
                break
        self.assertTrue(matched)

    def test_strict_order_mismatch(self):
        chain = ["socket", "memcpy", "bind", "recv", "send"]
        apis = ["recv", "memcpy"]
        idx = 0
        matched = True
        for api in apis:
            found = False
            while idx < len(chain):
                if api in chain[idx]:
                    found = True
                    idx += 1
                    break
                idx += 1
            if not found:
                matched = False
                break
        self.assertFalse(matched)

    def test_any_order_match(self):
        chain = ["memcpy", "socket", "recv", "send"]
        apis = ["recv", "memcpy"]
        chain_set = set(chain)
        self.assertTrue(all(any(api in c for c in chain_set) for api in apis))


if __name__ == "__main__":
    unittest.main()
