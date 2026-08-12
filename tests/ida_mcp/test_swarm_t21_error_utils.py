"""Regression tests for swarm/t21_error_utils findings.

Covers (each maps to a confirmed finding in the t21 audit):
- prompts QUICKREF_TEXT / WORKFLOW_TRIAGE no longer instruct the LLM to call
  the non-existent `agent(action="analyze_function"/"context_pack")` tool;
  the correct surface is `batch(template="analyze_function"/"deep_function_audit")`.
- prompts WORKFLOW_FIRMWARE no longer calls the non-existent
  `search(action="semantic")`; the NL search action is `search(action="nl")`.
- utils.resolve_symbol's demangled-name fallback actually demangles: it scans
  the name table with ida_name.demangle_name instead of passing the
  demangle-format macro MNG_LONG_FORM into ida_name.get_ea's SN_* flags slot
  (which silently degraded to the already-failed plain name lookup).
- error_handling.make_error produces the {error, code, category, message,
  hint} envelope with a default hint from ERROR_HINTS.

Host-side tests: ida_* modules are stubbed via tests._isolated_repo_loader;
no live IDA session is required.
"""

import sys
import types
import unittest

from tests._isolated_repo_loader import (
    install_common_stub,
    load_ida_module,
)

BADADDR = 0xFFFFFFFFFFFFFFFF


class _FakeServices(types.ModuleType):
    """Stub for the heavy ``ida_pro_mcp.services`` import contract."""

    def __init__(self):
        super().__init__("ida_pro_mcp.services")

        def _csp(pattern, case_sensitive=False, **kwargs):
            if not pattern:
                return lambda _t: True
            p = pattern if case_sensitive else pattern.lower()
            return lambda t, _p=p: _p in (t if t else "")

        self.parse_str_list = lambda value, sep=",": (
            [p.strip() for p in str(value).split(sep)] if isinstance(value, str) else list(value)
        )
        self.compile_smart_pattern = _csp
        self.smart_match = lambda pattern, text, case_sensitive=False: _csp(
            pattern, case_sensitive
        )(text)


class _FakeSync(types.ModuleType):
    """Stub for ``ida_mcp.sync`` so utils.py imports without loading IDA RPC."""

    class IDAError(Exception):
        pass

    def __init__(self):
        super().__init__("ida_pro_mcp.ida_mcp.sync")
        self.IDAError = self.IDAError


class _FakeRpc(types.ModuleType):
    """Stub for ``ida_mcp.rpc`` providing a no-op @prompt decorator."""

    def __init__(self):
        super().__init__("ida_pro_mcp.ida_mcp.rpc")
        self.prompt = lambda fn: fn


class TestPromptsNoDeadToolCalls(unittest.TestCase):
    """QUICKREF / WORKFLOW_* must not reference tools/actions that do not exist."""

    @classmethod
    def setUpClass(cls):
        install_common_stub()
        sys.modules.setdefault("ida_pro_mcp.ida_mcp.rpc", _FakeRpc())
        cls.mod = load_ida_module("prompts")

    def test_quickref_uses_batch_template_not_dead_agent_tool(self):
        text = self.mod.QUICKREF_TEXT
        self.assertNotIn('agent(action="analyze_function"', text)
        self.assertNotIn('agent(action="context_pack"', text)
        # The real surface for a comprehensive one-shot analysis.
        self.assertIn('batch(template="analyze_function"', text)
        self.assertIn('batch(template="deep_function_audit"', text)

    def test_quickref_includes_raw_firmware_triage_guidance(self):
        text = self.mod.QUICKREF_TEXT
        # p01 registration: the quickref must steer headerless-blob work to the
        # r2 sidecar + firmware-shaping ops that replaced the dead tool surface.
        self.assertIn("Raw Firmware Triage", text)
        self.assertIn("ida_r2_bininfo", text)
        self.assertIn("ida_r2_load_hints", text)
        self.assertIn("ida_fw_detect_vector_table", text)
        self.assertIn('search(action="data_value"', text)
        self.assertIn("ida_fw_carve", text)

    def test_triage_workflow_uses_batch_template_not_dead_agent_tool(self):
        text = self.mod.WORKFLOW_TRIAGE
        self.assertNotIn("agent(action=", text)
        self.assertIn('batch(template="analyze_function"', text)

    def test_firmware_workflow_uses_nl_not_dead_semantic_search_action(self):
        text = self.mod.WORKFLOW_FIRMWARE
        self.assertNotIn('search(action="semantic"', text)
        self.assertIn('search(action="nl"', text)

    def test_prompt_functions_return_updated_guidance(self):
        quickref = self.mod.quickref()
        self.assertIn(self.mod.QUICKREF_TEXT, quickref[0]["content"]["text"])
        triage = self.mod.workflow("triage")[0]["content"]["text"]
        self.assertIn('batch(template="analyze_function"', triage)
        firmware = self.mod.workflow("firmware")[0]["content"]["text"]
        self.assertIn('search(action="nl"', firmware)


class TestResolveSymbolDemangleFallback(unittest.TestCase):
    """resolve_symbol must demangle real names, not silently plain-lookup."""

    def setUp(self):
        install_common_stub()
        sys.modules["ida_pro_mcp.services"] = _FakeServices()
        sys.modules["ida_pro_mcp.ida_mcp.sync"] = _FakeSync()
        # utils.py references SDK types at module level (annotations and a
        # subclass base) that the blank stubs do not define.
        sys.modules["ida_funcs"].func_t = type("func_t", (), {})
        sys.modules["ida_typeinf"].tinfo_t = type("tinfo_t", (), {})
        sys.modules["ida_hexrays"].user_lvar_modifier_t = type(
            "user_lvar_modifier_t", (), {}
        )

        self.demangle_map = {}

        ida_name = types.ModuleType("ida_name")
        ida_name.MNG_LONG_FORM = 0x4E
        ida_name.demangle_name = lambda name, mask: self.demangle_map.get(name)

        def _unexpected_get_ea(*args, **kwargs):
            raise AssertionError(
                "ida_name.get_ea must not be used for demangled lookup "
                "(MNG_LONG_FORM is not an SN_* name-search flag)"
            )

        ida_name.get_ea = _unexpected_get_ea
        sys.modules["ida_name"] = ida_name

        idc = types.ModuleType("idc")
        idc.BADADDR = BADADDR
        idc.get_name_ea_simple = lambda name: 0x1000 if name == "main" else BADADDR
        idc.get_name = lambda ea: "start" if ea == 0x401000 else ""
        sys.modules["idc"] = idc

        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = BADADDR
        idaapi.get_func = lambda ea: None
        sys.modules["idaapi"] = idaapi

        # compat.get_func_start resolves ida_funcs via sys.modules; mirror the
        # idaapi.get_func miss (no scanned name is a function here).
        ida_funcs = sys.modules["ida_funcs"]
        ida_funcs.get_func = idaapi.get_func
        ida_funcs.ida_idaapi = types.SimpleNamespace(BADADDR=BADADDR)
        ida_funcs.func_entry_info_t = types.SimpleNamespace
        ida_funcs.get_func_entry_info = lambda out, ea, flags=0: False
        ida_funcs.get_prev_func = lambda ea: None
        ida_funcs.get_next_func = lambda ea: None

        self.names = [
            (0x4000, "_ZTVN7android14SystemKloProxyE"),
            (0x3000, "sub_1234"),
        ]
        idautils = types.ModuleType("idautils")
        idautils.Names = lambda: iter(self.names)
        sys.modules["idautils"] = idautils

        self.mod = load_ida_module("utils")

    def test_demangled_query_resolves_via_name_table_scan(self):
        # A C++ vtable query in long/demangled form is not an exact stored
        # name, so the exact-name step fails and the demangle step must run.
        self.demangle_map["_ZTVN7android14SystemKloProxyE"] = (
            "vtable for android::SystemKloProxy"
        )
        result = self.mod.resolve_symbol("vtable for android::SystemKloProxy")
        self.assertEqual(result["addr"], "0x4000")
        self.assertEqual(result["name"], "_ZTVN7android14SystemKloProxyE")
        self.assertFalse(result["is_func"])

    def test_exact_name_still_resolves(self):
        result = self.mod.resolve_symbol("main")
        self.assertEqual(result["addr"], "0x1000")
        self.assertEqual(result["name"], "main")

    def test_mangled_query_resolves_as_exact_name(self):
        # IDA stores mangled names as the primary symbol, so a mangled query
        # hits the exact-name step (get_name_ea_simple), not the demangle scan.
        self.demangle_map["_ZTVN7android14SystemKloProxyE"] = (
            "vtable for android::SystemKloProxy"
        )
        sys.modules["idc"].get_name_ea_simple = (
            lambda name: 0x4000 if name == "_ZTVN7android14SystemKloProxyE" else BADADDR
        )
        result = self.mod.resolve_symbol("_ZTVN7android14SystemKloProxyE")
        self.assertEqual(result["addr"], "0x4000")

    def test_address_literal_still_resolves(self):
        result = self.mod.resolve_symbol("0x401000")
        self.assertEqual(result["addr"], "0x401000")
        self.assertEqual(result["name"], "start")

    def test_unresolvable_query_raises_ida_error(self):
        with self.assertRaises(self.mod.IDAError):
            self.mod.resolve_symbol("no_such_symbol_anywhere")


class TestErrorHandlingMakeError(unittest.TestCase):
    """error_handling.make_error envelope: {error, code, category, message, hint}."""

    @classmethod
    def setUpClass(cls):
        install_common_stub()
        cls.mod = load_ida_module("error_handling")

    def test_envelope_carries_error_code_category_message_and_default_hint(self):
        err = self.mod.make_error(self.mod.MCPError.NOT_FOUND, "missing thing")
        self.assertIs(err["error"], True)
        self.assertEqual(err["code"], self.mod.MCPError.NOT_FOUND)
        self.assertEqual(err["category"], "user")
        self.assertEqual(err["message"], "missing thing")
        # Default LLM-actionable hint is auto-filled from ERROR_HINTS.
        self.assertIn("not found", err["hint"].lower())

    def test_explicit_hint_and_details_are_preserved(self):
        err = self.mod.make_error(
            self.mod.MCPError.ADDRESS_INVALID,
            "bad addr",
            hint="Use 0x-prefixed hex.",
            details={"given": "abc"},
        )
        self.assertEqual(err["hint"], "Use 0x-prefixed hex.")
        self.assertEqual(err["details"], {"given": "abc"})

    def test_no_ok_true_on_failure(self):
        err = self.mod.make_error(self.mod.MCPError.NO_RESULTS, "none")
        self.assertNotIn("ok", err)
        self.assertIs(err["error"], True)


class TestVestigialHintSurface(unittest.TestCase):
    """The DEBUGGER_*/BOOKMARK_* codes are vestigial: no public debugger or
    bookmark-mutation op exists, so their hints must state the honest path
    (misc(action='python') / ida_dbg, or the host ida_r2_* namespace) and must
    not claim an absent tool. The EMULATION_* codes are kept and used by the
    public ``emulate`` tool, so their hints point at ``emulate(action=...)``
    rather than a vestigial path."""

    VESTIGIAL_CODES = [
        "DEBUGGER_NOT_RUNNING",
        "DEBUGGER_ACTIVE",
        "DEBUGGER_BREAKPOINT_ERROR",
        "DEBUGGER_MEMORY_ERROR",
        "DEBUGGER_REGISTER_ERROR",
        "DEBUGGER_STEP_ERROR",
        "DEBUGGER_PROCESS_ERROR",
        "DEBUGGER_THREAD_ERROR",
        "EMULATION_ERROR",
        "EMULATION_TIMEOUT",
        "BOOKMARK_NOT_FOUND",
        "BOOKMARK_DUPLICATE",
    ]

    EMULATION_CODES = ["EMULATION_ERROR", "EMULATION_TIMEOUT"]

    @classmethod
    def setUpClass(cls):
        install_common_stub()
        cls.mod = load_ida_module("error_handling")
        cls.hints = cls.mod.ERROR_HINTS

    def test_vestigial_codes_kept_and_hints_state_honest_path(self):
        for code in self.VESTIGIAL_CODES:
            self.assertIn(code, self.hints, f"{code} removed from ERROR_HINTS")
            hint = self.hints[code]
            if code in self.EMULATION_CODES:
                # Emulation is a public op now: the hints must not route callers
                # through the vestigial misc(action='python') path, and the
                # error hint must name the public tool for recovery.
                self.assertNotIn("misc(action=", hint, code)
                self.assertNotIn("public op", hint, code)
                continue
            # Honest path: no public op; script via misc(action='python').
            self.assertIn("public", hint, code)
            self.assertIn("misc(action=", hint, code)

    def test_no_claimed_but_absent_tool_in_vestigial_hints(self):
        for code in self.VESTIGIAL_CODES:
            hint = self.hints[code]
            self.assertNotIn("ida_python", hint, (code, hint))
            self.assertNotIn("max_steps", hint, (code, hint))
