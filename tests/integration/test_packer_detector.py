"""
Smoke tests for the packer / protector detector.

The IDA SDK is mocked so we can exercise the pure-Python classification,
recommendation, and indicator-evaluation logic without launching IDA.

Run:
    python -m unittest tests.test_packer_detector
"""
from __future__ import annotations

import os
import sys
import types
import unittest
from unittest import mock


def _install_ida_stub():
    """Install a fake idaapi/idautils/etc. in sys.modules so packer can import."""
    if "idaapi" in sys.modules and "ida_entry" in sys.modules:
        return

    fake = types.ModuleType("idaapi")
    fake.BADADDR = 0xFFFFFFFFFFFFFFFF

    def _get_func_qty():
        return 0

    def _get_strlist_qty():
        return 0

    def _auto_state():
        return 2  # AU_FINAL

    def _get_auto_display():
        return ""

    def _auto_is_ok():
        return True

    def _get_input_file_path():
        return ""

    def _get_idb_path():
        return ""

    def _is_debugger_on():
        return False

    def _get_process_state():
        return 0

    fake.get_func_qty = _get_func_qty
    fake.get_strlist_qty = _get_strlist_qty
    fake.auto_state = _auto_state
    fake.get_auto_display = _get_auto_display
    fake.auto_is_ok = _auto_is_ok
    fake.get_input_file_path = _get_input_file_path
    fake.get_idb_path = _get_idb_path
    fake.is_debugger_on = _is_debugger_on
    fake.get_process_state = _get_process_state
    sys.modules["idaapi"] = fake

    sys.modules["idautils"] = types.ModuleType("idautils")

    stub_names = [
        "idc", "ida_bytes", "ida_nalt", "ida_segment", "ida_entry",
        "ida_kernwin", "ida_funcs", "ida_ida", "ida_frame", "ida_lines",
        "ida_name", "ida_hexrays", "ida_typeinf",
    ]
    for n in stub_names:
        sys.modules.setdefault(n, types.ModuleType(n))


def _load_packer_module():
    """Import packer.py bypassing the _common import path."""
    _install_ida_stub()
    import importlib.util
    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "src", "ida_pro_mcp", "ida_mcp", "tools", "packer.py",
    )
    path = os.path.normpath(path)
    spec = importlib.util.spec_from_file_location("packer_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    fake_common = types.ModuleType("_common")
    import typing
    for name in dir(typing):
        if not name.startswith("_"):
            setattr(fake_common, name, getattr(typing, name))
    fake_common.tool = lambda f: f
    fake_common.idaread = lambda f: f
    fake_common.idawrite = lambda f: f
    fake_common.unsafe = lambda f: f

    class _MCPError(Exception):
        INVALID_ARGS = "INVALID_ARGS"
        IDA_ERROR = "IDA_ERROR"
    fake_common.MCPError = _MCPError
    fake_common.make_error = lambda *a, **kw: {
        "ok": False,
        "error": a[1] if len(a) > 1 else "error",
        "code": a[0] if a else None,
    }
    fake_common.handle_error = lambda e, *a, **kw: {"ok": False, "error": str(e)}

    for n in ("idaapi", "idautils", "idc", "ida_bytes", "ida_nalt",
              "ida_segment", "ida_entry", "ida_kernwin", "ida_funcs",
              "ida_ida", "ida_frame", "ida_lines", "ida_name",
              "ida_hexrays", "ida_typeinf"):
        if n in sys.modules:
            fake_common.__dict__.setdefault(n, sys.modules[n])
    for tool_name in ("binary_info", "entropy", "agent"):
        sys.modules.setdefault(
            f"ida_pro_mcp.ida_mcp.tools.{tool_name}",
            types.ModuleType(f"ida_pro_mcp.ida_mcp.tools.{tool_name}"),
        )
    sys.modules["_common"] = fake_common
    sys.modules["ida_pro_mcp.ida_mcp.tools._common"] = fake_common
    spec.loader.exec_module(mod)
    return mod


PACKER = _load_packer_module()


class TestClassify(unittest.TestCase):
    def test_classify_no_indicators(self):
        result = PACKER._classify([], drm={})
        self.assertEqual(result["packer"], "none")
        self.assertEqual(result["confidence"], 0.0)

    def test_classify_upx_section_names(self):
        indicators = PACKER._evaluate_signatures(
            section_names=[".UPX0", ".UPX1", ".rsrc"],
            strings=[],
        )
        matched = [i for i in indicators if i["matched"]]
        self.assertTrue(any(i["label"] == "UPX" for i in matched))
        cls = PACKER._classify(indicators, drm={})
        self.assertEqual(cls["packer"], "upx")
        self.assertGreaterEqual(cls["confidence"], 0.7)

    def test_classify_vmprotect_strings(self):
        indicators = PACKER._evaluate_signatures(
            section_names=[".text", ".rdata"],
            strings=["this binary uses vmprotect 3.5", "VMP0 section here"],
        )
        cls = PACKER._classify(indicators, drm={})
        self.assertEqual(cls["packer"], "vmprotect")
        self.assertGreaterEqual(cls["confidence"], 0.5)

    def test_classify_themida_strings(self):
        indicators = PACKER._evaluate_signatures(
            section_names=[".text"],
            strings=["Protected by Themida"],
        )
        cls = PACKER._classify(indicators, drm={})
        self.assertEqual(cls["packer"], "themida")

    def test_classify_custom_unknown_fallback(self):
        indicators = [
            {"name": "text_segment_entropy", "label": None, "weight": 0.6,
             "matched": True, "evidence": ["7.84 (threshold 7.2)"]},
        ]
        cls = PACKER._classify(indicators, drm={})
        self.assertEqual(cls["packer"], "custom_or_unknown")
        self.assertEqual(cls["fallback"], "high_entropy_no_signature")


class TestDRM(unittest.TestCase):
    def test_eac_string_reference_detected(self):
        drm = PACKER._evaluate_drm(
            strings=["calls EasyAntiCheat init at runtime", "EAC.dll loaded"],
            imports=[],
        )
        self.assertTrue(any("EasyAntiCheat" in s for s in drm["anti_cheat_strings"]))
        self.assertIsNotNone(drm["note"])

    def test_battleye_imports_detected(self):
        drm = PACKER._evaluate_drm(
            strings=[],
            imports=["BEService_init", "BattlEye_Query"],
        )
        self.assertTrue(any("BattlEye" in s for s in drm["anti_cheat_modules"]))

    def test_no_drm_clean_binary(self):
        drm = PACKER._evaluate_drm(
            strings=["hello world", "this is a normal app"],
            imports=["CreateFileW", "WriteFile"],
        )
        self.assertEqual(drm["anti_cheat_modules"], [])
        self.assertEqual(drm["anti_cheat_strings"], [])
        self.assertIsNone(drm["note"])

    def test_vanguard_strings_detected(self):
        drm = PACKER._evaluate_drm(
            strings=["Riot Vanguard blocked", "vgk.sys not loaded"],
            imports=[],
        )
        self.assertTrue(any("Vanguard" in s for s in drm["anti_cheat_strings"]))


class TestRecommend(unittest.TestCase):
    def test_recommend_auto_unpack_upx(self):
        classification = {"packer": "upx", "confidence": 0.92, "fallback": None}
        rec, warn = PACKER._recommend(classification, matched_count=3, drm={})
        self.assertEqual(rec, "auto_unpack")
        self.assertIsNone(warn)

    def test_recommend_guided_unpack_vmprotect(self):
        classification = {"packer": "vmprotect", "confidence": 0.85, "fallback": None}
        rec, warn = PACKER._recommend(classification, matched_count=2, drm={})
        self.assertEqual(rec, "guided_unpack")
        self.assertIn("VMProtect", warn)

    def test_recommend_do_not_unpack_with_eac(self):
        classification = {"packer": "upx", "confidence": 0.92, "fallback": None}
        drm = {
            "anti_cheat_modules": ["EasyAntiCheat:eac.dll"],
            "anti_cheat_strings": [],
            "indicators": ["anti_cheat_imports"],
            "note": "AC detected",
        }
        rec, warn = PACKER._recommend(classification, matched_count=3, drm=drm)
        self.assertEqual(rec, "do_not_unpack")
        self.assertIn("Anti-cheat", warn)

    def test_recommend_manual_only_low_confidence(self):
        classification = {"packer": "custom_or_unknown", "confidence": 0.3, "fallback": None}
        rec, warn = PACKER._recommend(classification, matched_count=1, drm={})
        self.assertEqual(rec, "manual_only")
        self.assertIsNotNone(warn)

    def test_recommend_none_when_clean(self):
        classification = {"packer": "none", "confidence": 0.0, "fallback": None}
        rec, warn = PACKER._recommend(classification, matched_count=0, drm={})
        self.assertEqual(rec, "none")
        self.assertIsNone(warn)


class TestWorkflowStructure(unittest.TestCase):
    """The workflow field replaces the old next_calls shotgun. It must
    contain only concrete tool_calls and external user actions."""

    def test_workflow_do_not_unpack_has_static_only(self):
        drm = {
            "anti_cheat_modules": ["BattlEye:BEService"],
            "anti_cheat_strings": [],
            "indicators": ["anti_cheat_imports"],
            "note": "AC detected",
        }
        wf = PACKER._workflow_for(
            {"packer": "upx", "confidence": 0.9, "fallback": None},
            drm, binary_path="/tmp/cheat.dll",
        )
        self.assertIn("static_steps", wf)
        self.assertIn("external_steps", wf)
        # No external steps when we say do_not_unpack
        self.assertEqual(wf["external_steps"], [])
        # Static steps must be tool calls with arguments
        for step in wf["static_steps"]:
            self.assertIn("tool", step)
            self.assertIn("arguments", step)
            # No <placeholder> in arguments
            for _k, v in step["arguments"].items():
                self.assertNotIn("<", str(v),
                                 f"placeholder leaked into {step}")

    def test_workflow_auto_unpack_has_external_step(self):
        wf = PACKER._workflow_for(
            {"packer": "upx", "confidence": 0.9, "fallback": None},
            drm={}, binary_path="/tmp/cheat.dll",
        )
        self.assertGreater(len(wf["external_steps"]), 0)
        ext = wf["external_steps"][0]
        self.assertTrue(ext.get("user_action"))
        self.assertIn("command_hint", ext)
        self.assertIn("upx -d", ext["command_hint"])
        self.assertIn("/tmp/cheat.dll", ext["command_hint"])

    def test_workflow_auto_unpack_no_path_no_hint(self):
        wf = PACKER._workflow_for(
            {"packer": "upx", "confidence": 0.9, "fallback": None},
            drm={}, binary_path="",
        )
        # No path = no fake command hint
        wf["workflow"]["external_steps"] if "workflow" in wf else wf["external_steps"]
        # workflow_for with empty binary returns a workflow with the
        # external step that has NO command_hint.
        self.assertGreater(len(wf["external_steps"]), 0)
        self.assertNotIn("command_hint", wf["external_steps"][0])

    def test_workflow_guided_unpack_uses_real_entry(self):
        # Patch _safe_start_ea to return a known value
        with mock.patch.object(PACKER, "_safe_start_ea", return_value=0x401000):
            wf = PACKER._workflow_for(
                {"packer": "vmprotect", "confidence": 0.85, "fallback": None},
                drm={}, binary_path="",
            )
        bp = next((s for s in wf["static_steps"]
                   if s.get("arguments", {}).get("type") == "execute"), None)
        self.assertIsNotNone(bp)
        self.assertEqual(bp["arguments"]["addr"], "0x401000")
        # No <placeholder>
        for s in wf["static_steps"]:
            for v in s.get("arguments", {}).values():
                self.assertNotIn("<", str(v))

    def test_workflow_manual_only_no_external(self):
        wf = PACKER._workflow_for(
            {"packer": "custom_or_unknown", "confidence": 0.3, "fallback": None},
            drm={}, binary_path="",
        )
        self.assertEqual(wf["external_steps"], [])
        # Has at least the entropy window step
        tools = {s["tool"] for s in wf["static_steps"]}
        self.assertIn("entropy", tools)

    def test_workflow_replaces_next_calls_string(self):
        """The new workflow must not contain a free-form next_calls field
        that mixes bash with tool calls. The old code had a list of mixed
        strings; the new code has structured static_steps + external_steps."""
        wf = PACKER._workflow_for(
            {"packer": "upx", "confidence": 0.9, "fallback": None},
            drm={}, binary_path="/tmp/cheat.dll",
        )
        self.assertNotIn("next_calls", wf)
        # Static steps and external steps are separate
        for s in wf["static_steps"]:
            self.assertNotIn("user_action", s)  # that's external only
        for s in wf["external_steps"]:
            self.assertTrue(s.get("user_action"))


class TestScriptAction(unittest.TestCase):
    def test_script_classify_helper_returns_dict(self):
        code = "_classify(_evaluate_signatures(['.UPX0', '.UPX1'], []), {})"
        result = PACKER._run_script(code, None)
        self.assertTrue(result["ok"])
        self.assertEqual(result["result"]["packer"], "upx")

    def test_script_rejects_empty(self):
        result = PACKER._run_script(None, None)
        self.assertFalse(result["ok"])

    def test_script_rejects_oversize(self):
        result = PACKER._run_script("a" * 20000, None)
        self.assertFalse(result["ok"])

    def test_script_rejects_open(self):
        result = PACKER._run_script("open('/etc/passwd')", None)
        self.assertFalse(result["ok"])
        self.assertIn("open", result["error"])

    def test_script_rejects_exec(self):
        result = PACKER._run_script("exec('print(1)')", None)
        self.assertFalse(result["ok"])

    def test_script_rejects_eval(self):
        result = PACKER._run_script("eval('1+1')", None)
        self.assertFalse(result["ok"])

    def test_script_rejects_import(self):
        result = PACKER._run_script("__import__('os').system('id')", None)
        self.assertFalse(result["ok"])

    def test_script_surfaces_exception(self):
        result = PACKER._run_script("1/0", None)
        self.assertFalse(result["ok"])
        self.assertIn("ZeroDivisionError", result["error"])

    def test_script_extra_globals_injected(self):
        code = "my_value * 2"
        result = PACKER._run_script(code, {"my_value": 21})
        self.assertTrue(result["ok"])
        self.assertEqual(result["result"], 42)

    def test_script_extra_globals_invalid_name_ignored(self):
        code = "1 + 1"
        result = PACKER._run_script(code, {"1bad-name": 99, "good": 7})
        # Only identifier names are injected; the rest are silently dropped.
        self.assertTrue(result["ok"])

    def test_script_returns_list(self):
        code = "list(_DISPLAY_NAME.keys())"
        result = PACKER._run_script(code, None)
        self.assertTrue(result["ok"])
        self.assertIn("upx", result["result"])


class TestEntropyIndicators(unittest.TestCase):
    def test_high_text_entropy_triggers(self):
        inds = PACKER._evaluate_entropy_indicators({
            ".text": 7.84,
            ".rdata": 5.2,
        })
        text_ind = next((i for i in inds if i["name"] == "text_segment_entropy"), None)
        self.assertIsNotNone(text_ind)
        self.assertTrue(text_ind["matched"])

    def test_normal_entropy_does_not_trigger(self):
        inds = PACKER._evaluate_entropy_indicators({
            ".text": 5.5,
            ".rdata": 4.8,
        })
        text_ind = next((i for i in inds if i["name"] == "text_segment_entropy"), None)
        self.assertIsNotNone(text_ind)
        self.assertFalse(text_ind["matched"])


class TestAntiAnalysis(unittest.TestCase):
    def test_anti_debug_imports_detected(self):
        inds = PACKER._evaluate_anti_analysis(
            imports=["IsDebuggerPresent", "CreateFileW"],
            strings=[],
        )
        names = [i["name"] for i in inds if i["matched"]]
        self.assertIn("anti_debug_imports", names)

    def test_anti_vm_strings_detected(self):
        inds = PACKER._evaluate_anti_analysis(
            imports=[],
            strings=["checking for vmtoolsd.exe presence", "sbiedll.dll loaded"],
        )
        names = [i["name"] for i in inds if i["matched"]]
        self.assertIn("anti_vm_strings", names)

    def test_clean_binary_no_indicators(self):
        inds = PACKER._evaluate_anti_analysis(
            imports=["CreateFileW", "WriteFile", "ReadFile"],
            strings=["normal application log message"],
        )
        matched = [i for i in inds if i["matched"]]
        self.assertEqual(matched, [])


if __name__ == "__main__":
    unittest.main()
