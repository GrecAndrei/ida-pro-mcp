"""Regression tests for the t01_analysis audit fixes.

Covers (each maps to a confirmed finding in the t01 audit):
- analysis set_processor: a False return from set_processor_type is reported as
  an IDA_ERROR instead of a false-success {ok: True, result: False} envelope.
- analysis set_loader_options: a False return from set_loader_options is
  reported as an IDA_ERROR instead of a false-success envelope.
- analysis set_architecture: a failed processor switch inside set_architecture
  is reported as an IDA_ERROR instead of embedded-in-applied ok:True.
- analysis save_idb: a False save_database return is an IDA_ERROR, and when no
  path is given the reported saved_to is the real IDB path (idc.get_idb_path),
  not the loaded input binary path.
- analysis reanalyze (blocking): the wait is bounded by poll_timeout — it never
  calls the unbounded ida_auto.auto_wait(), and reports analysis_complete=False
  (instead of hanging the RPC) when the budget runs out.
- ctree: decompile/init failures are distinguished — a genuine decompile
  failure surfaces the hexrays_failure_t message under DECOMPILER_FAILED
  instead of the misleading "Decompiler required for CTree".
"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import load_ida_module, load_tool_module

_EH_CACHE = {}


def _real_eh_overrides():
    """Use the REAL IDA-side error envelope (error/code/category/hint) rather
    than the isolated-loader stub so assertions match production make_error().

    Loaded lazily: load_ida_module() registers the ``ida_pro_mcp`` namespace
    package, which must not happen at module-import time — host tests that
    resolve the installed package via ``importlib.util.find_spec`` (e.g.
    test_auto_reanalyze_text_segments.py) would fail on the shadowed spec.
    """
    eh = _EH_CACHE.get("eh")
    if eh is None:
        eh = load_ida_module("error_handling")
        _EH_CACHE["eh"] = eh
    return {
        "make_error": eh.make_error,
        "MCPError": eh.MCPError,
        "handle_error": eh.handle_error,
        "ERROR_HINTS": eh.ERROR_HINTS,
    }


def _blank_modules(names):
    for name in names:
        sys.modules.setdefault(name, types.ModuleType(name))


def _make_idaapi(**extra):
    mod = types.ModuleType("idaapi")
    mod.BADADDR = 0xFFFFFFFFFFFFFFFF
    mod.get_inf_structure = lambda: None
    mod.SETPROC_LOADER = 0
    mod.SETPROC_LOADER_NON_FATAL = 1
    for k, v in extra.items():
        setattr(mod, k, v)
    return mod


class TestSetProcessorNoFalseSuccess(unittest.TestCase):
    """set_processor must not report success when set_processor_type failed."""

    def setUp(self):
        self.idaapi = _make_idaapi(set_processor_type=lambda proc, flags: False)
        sys.modules["idaapi"] = self.idaapi
        sys.modules["idc"] = types.ModuleType("idc")
        _blank_modules(["ida_ida", "ida_entry", "ida_auto", "ida_segment",
                        "ida_loader", "ida_nalt", "ida_bytes", "ida_funcs",
                        "ida_hexrays", "ida_lines", "idautils"])
        self.mod = load_tool_module("analysis", common_overrides=_real_eh_overrides())

    def test_failed_processor_switch_returns_error(self):
        res = self.mod.analysis(action="set_processor", processor="arm")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "IDA_ERROR")
        self.assertIsNot(res.get("ok"), True)

    def test_successful_processor_switch_returns_ok(self):
        self.idaapi.set_processor_type = lambda proc, flags: True
        res = self.mod.analysis(action="set_processor", processor="arm")
        self.assertEqual(res.get("ok"), True)
        self.assertEqual(res.get("result"), True)


class TestSetLoaderOptionsNoFalseSuccess(unittest.TestCase):
    """set_loader_options must not report success when the loader refused."""

    def setUp(self):
        self.ida_loader = types.ModuleType("ida_loader")
        self.ida_loader.set_loader_options = lambda loader, opts, flags=0: False
        sys.modules["ida_loader"] = self.ida_loader
        sys.modules["idaapi"] = _make_idaapi()
        sys.modules["idc"] = types.ModuleType("idc")
        _blank_modules(["ida_ida", "ida_entry", "ida_auto", "ida_segment",
                        "ida_nalt", "ida_bytes", "ida_funcs", "ida_hexrays",
                        "ida_lines", "idautils"])
        self.mod = load_tool_module("analysis", common_overrides=_real_eh_overrides())

    def test_failed_loader_options_returns_error(self):
        res = self.mod.analysis(action="set_loader_options", loader="elf", value="a=b")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "IDA_ERROR")
        self.assertIsNot(res.get("ok"), True)

    def test_successful_loader_options_returns_ok(self):
        self.ida_loader.set_loader_options = lambda loader, opts, flags=0: True
        res = self.mod.analysis(action="set_loader_options", loader="elf", value="a=b")
        self.assertEqual(res.get("ok"), True)
        self.assertEqual(res.get("result"), True)


class TestSetArchitectureNoFalseSuccess(unittest.TestCase):
    """set_architecture must surface a failed processor switch."""

    def setUp(self):
        self.idaapi = _make_idaapi(set_processor_type=lambda proc, flags: False)
        sys.modules["idaapi"] = self.idaapi
        sys.modules["idc"] = types.ModuleType("idc")
        _blank_modules(["ida_ida", "ida_entry", "ida_auto", "ida_segment",
                        "ida_loader", "ida_nalt", "ida_bytes", "ida_funcs",
                        "ida_hexrays", "ida_lines", "idautils"])
        self.mod = load_tool_module("analysis", common_overrides=_real_eh_overrides())

    def test_failed_processor_switch_returns_error(self):
        res = self.mod.analysis(action="set_architecture", processor="arm")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "IDA_ERROR")

    def test_successful_processor_switch_returns_ok(self):
        self.idaapi.set_processor_type = lambda proc, flags: True
        res = self.mod.analysis(action="set_architecture", processor="arm")
        self.assertEqual(res.get("ok"), True)
        self.assertEqual(res["applied"]["processor"]["result"], True)


class TestSaveIdb(unittest.TestCase):
    """save_idb must surface a failed save and report the real DB path."""

    def setUp(self):
        self.calls = []
        self.ida_loader = types.ModuleType("ida_loader")

        def save_database(outfile=None, flags=0):
            self.calls.append((outfile, flags))
            return True

        self.ida_loader.save_database = save_database
        sys.modules["ida_loader"] = self.ida_loader
        idc = types.ModuleType("idc")
        idc.get_idb_path = lambda: "/tmp/foo.i64"
        sys.modules["idc"] = idc
        sys.modules["idaapi"] = _make_idaapi(get_input_file_path=lambda: "/tmp/foo.so")
        _blank_modules(["ida_ida", "ida_entry", "ida_auto", "ida_segment",
                        "ida_nalt", "ida_bytes", "ida_funcs", "ida_hexrays",
                        "ida_lines", "idautils"])
        self.mod = load_tool_module("analysis", common_overrides=_real_eh_overrides())

    def test_save_failure_returns_error(self):
        self.ida_loader.save_database = lambda outfile=None, flags=0: False
        res = self.mod.analysis(action="save_idb")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "IDA_ERROR")

    def test_inplace_save_reports_idb_path_not_input_binary(self):
        res = self.mod.analysis(action="save_idb")
        self.assertEqual(res.get("ok"), True)
        self.assertEqual(res["saved_to"], "/tmp/foo.i64")
        self.assertEqual(self.calls, [("", 0)])

    def test_explicit_path_save_reports_path(self):
        res = self.mod.analysis(action="save_idb", path="/tmp/custom.i64")
        self.assertEqual(res.get("ok"), True)
        self.assertEqual(res["saved_to"], "/tmp/custom.i64")
        self.assertEqual(self.calls, [("/tmp/custom.i64", 0)])


class TestReanalyzeBlockingBounded(unittest.TestCase):
    """Blocking reanalyze must honor poll_timeout and never call auto_wait()."""

    def setUp(self):
        self.auto_wait_calls = 0
        self.auto_make_step_calls = 0
        self.auto_ok_state = {"n": 0, "flip_after": None}

        def auto_is_ok():
            self.auto_ok_state["n"] += 1
            if self.auto_ok_state["flip_after"] is None:
                return False
            return self.auto_ok_state["n"] > self.auto_ok_state["flip_after"]

        def auto_make_step(s, e):
            self.auto_make_step_calls += 1
            return True

        def auto_wait():
            self.auto_wait_calls += 1
            return True

        ida_auto = types.ModuleType("ida_auto")
        ida_auto.plan_range = lambda s, e: None
        ida_auto.auto_make_step = auto_make_step
        ida_auto.auto_wait = auto_wait
        sys.modules["ida_auto"] = ida_auto

        inf = types.SimpleNamespace(filetype=7)  # ELF — not a raw blob
        self.idaapi = _make_idaapi(auto_is_ok=auto_is_ok, get_inf_structure=lambda: inf)
        sys.modules["idaapi"] = self.idaapi
        sys.modules["idc"] = types.ModuleType("idc")
        idautils = types.ModuleType("idautils")
        idautils.Functions = lambda: iter([])
        sys.modules["idautils"] = idautils
        _blank_modules(["ida_ida", "ida_entry", "ida_segment", "ida_loader",
                        "ida_nalt", "ida_bytes", "ida_funcs", "ida_hexrays",
                        "ida_lines"])
        self.mod = load_tool_module("analysis", common_overrides=_real_eh_overrides())

    def test_pending_work_is_bounded_and_never_calls_auto_wait(self):
        self.auto_ok_state["flip_after"] = None  # analyzer never drains
        res = self.mod.analysis(
            action="reanalyze", start="0x1000", end="0x2000",
            blocking=True, poll_timeout=0.05,
        )
        self.assertEqual(res.get("ok"), True)
        self.assertIs(res.get("analysis_complete"), False)
        # Bounded: the RPC must return within ~poll_timeout, not minutes.
        self.assertLess(res.get("blocking_waited"), 1.0)
        # The unbounded queue-drain must never be invoked.
        self.assertEqual(self.auto_wait_calls, 0)
        # The bounded incremental pump was used instead.
        self.assertGreaterEqual(self.auto_make_step_calls, 1)

    def test_already_drained_returns_immediately(self):
        self.auto_ok_state["flip_after"] = 0  # first call returns True
        res = self.mod.analysis(
            action="reanalyze", start="0x1000", end="0x2000",
            blocking=True, poll_timeout=0.5,
        )
        self.assertEqual(res.get("ok"), True)
        self.assertIs(res.get("analysis_complete"), True)
        self.assertEqual(res.get("blocking_waited"), 0.0)
        self.assertEqual(self.auto_make_step_calls, 0)
        self.assertEqual(self.auto_wait_calls, 0)

    def test_incremental_pump_progresses_to_completion(self):
        self.auto_ok_state["flip_after"] = 2  # drains after two steps
        res = self.mod.analysis(
            action="reanalyze", start="0x1000", end="0x2000",
            blocking=True, poll_timeout=0.5,
        )
        self.assertEqual(res.get("ok"), True)
        self.assertIs(res.get("analysis_complete"), True)
        self.assertGreaterEqual(self.auto_make_step_calls, 2)
        self.assertEqual(self.auto_wait_calls, 0)


class TestCtreeDecompileFailure(unittest.TestCase):
    """ctree must surface real decompile failures, not a phantom init error."""

    def setUp(self):
        class Hf:
            code = 0x1234

            def desc(self):
                return "bad microcode"

        self.ida_hexrays = types.ModuleType("ida_hexrays")
        self.ida_hexrays.hexrays_failure_t = Hf
        self.ida_hexrays.init_hexrays_plugin = lambda: True
        self.ida_hexrays.decompile = lambda ea, hf=None: None
        # ida_mcp.utils defines a module-level lvar modifier subclassing this;
        # it is imported transitively by ctree, so the base must exist.
        self.ida_hexrays.user_lvar_modifier_t = object
        sys.modules["ida_hexrays"] = self.ida_hexrays
        # ctree imports the REAL error_handling.validate_addr, which requires
        # is_mapped and (require_func=True) an existing function at the ea.
        sys.modules["idaapi"] = _make_idaapi(is_mapped=lambda ea: True)
        sys.modules["idc"] = types.ModuleType("idc")
        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + 0x100)
        sys.modules["ida_funcs"] = ida_funcs
        _blank_modules(["ida_ida", "ida_entry", "ida_auto", "ida_segment",
                        "ida_loader", "ida_nalt", "ida_bytes", "ida_lines",
                        "idautils"])
        self.mod = load_tool_module("ctree")

    def test_init_failure_is_ida_error(self):
        self.ida_hexrays.init_hexrays_plugin = lambda: False
        res = self.mod.ctree(addr="0x1000", action="get")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "IDA_ERROR")
        self.assertIn("Decompiler required for CTree", res.get("message", ""))

    def test_decompile_exception_is_decompiler_failed(self):
        def boom(ea, hf=None):
            raise RuntimeError("boom")

        self.ida_hexrays.decompile = boom
        res = self.mod.ctree(addr="0x1000", action="get")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "DECOMPILER_FAILED")
        self.assertIn("boom", res.get("message", ""))
        self.assertNotIn("Decompiler required for CTree", res.get("message", ""))

    def test_decompile_none_surfaces_hexrays_message(self):
        res = self.mod.ctree(addr="0x1000", action="get")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "DECOMPILER_FAILED")
        self.assertIn("bad microcode", res.get("message", ""))
        self.assertEqual(res.get("details", {}).get("hexrays_code"), 0x1234)


if __name__ == "__main__":
    unittest.main()
