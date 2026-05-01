#!/usr/bin/env python3
"""
AST-level regression tests for vuln_scan surface/features.
These tests avoid importing IDA-only modules while still guarding API regressions.
"""

import ast
import unittest
from pathlib import Path


VULN_SCAN_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "ida_pro_mcp"
    / "ida_mcp"
    / "tools"
    / "vuln_scan.py"
)


class TestVulnScanAstSurface(unittest.TestCase):
    def setUp(self):
        self.module = ast.parse(VULN_SCAN_PATH.read_text(encoding="utf-8"))

    def _find_function(self, name):
        return next(
            (n for n in self.module.body if isinstance(n, ast.FunctionDef) and n.name == name),
            None,
        )

    def test_vuln_scan_has_analysis_actions_and_learning_params(self):
        fn = self._find_function("vuln_scan")
        self.assertIsNotNone(fn, "vuln_scan function missing")

        arg_names = [a.arg for a in fn.args.args]
        self.assertIn("action", arg_names)
        self.assertIn("limit", arg_names)
        self.assertIn("min_score", arg_names)
        self.assertIn("depth", arg_names)
        self.assertIn("finding_id", arg_names)
        self.assertIn("is_true_positive", arg_names)

        # Check defaults
        defaults = fn.args.defaults
        first_default_arg_idx = len(arg_names) - len(defaults)
        limit_idx = arg_names.index("limit")
        self.assertGreaterEqual(limit_idx, first_default_arg_idx)
        self.assertIsInstance(defaults[limit_idx - first_default_arg_idx], ast.Constant)

        action_arg = next((a for a in fn.args.args if a.arg == "action"), None)
        self.assertIsNotNone(action_arg, "action argument missing")
        ann = action_arg.annotation
        self.assertIsInstance(ann, ast.Subscript)
        # Annotated[Literal[...], "..."]
        literal = ann.slice.elts[0]
        self.assertIsInstance(literal, ast.Subscript)
        values = [
            e.value
            for e in literal.slice.elts
            if isinstance(e, ast.Constant) and isinstance(e.value, str)
        ]
        self.assertIn("scan", values)
        self.assertIn("analyze_function", values)
        self.assertIn("discover_surface", values)
        self.assertIn("taint_sources", values)
        self.assertIn("feedback", values)
        self.assertIn("learned_knowledge", values)
        self.assertIn("suggest_strategy", values)
        self.assertIn("reflect", values)

    def test_analysis_helpers_exist(self):
        helper_names = {
            "_discover_sinks",
            "_discover_sources",
            "_discover_sanitizers",
            "_analyze_sink_call",
            "_compute_risk_score",
            "_severity_from_score",
            "_get_callers",
            "_decompile_function",
            "_trace_arg_to_source",
            "_find_validation_for_arg",
            "_binary_fingerprint",
            "_load_vuln_knowledge",
            "_save_vuln_knowledge",
            "_get_or_create_binary_knowledge",
            "_voera_reflect",
            "_voera_learn_sources_sinks",
            "_voera_find_similar_strategy",
        }
        found = {
            n.name for n in self.module.body if isinstance(n, ast.FunctionDef) and n.name in helper_names
        }
        self.assertEqual(helper_names, found)

    def test_scan_branch_uses_dynamic_discovery(self):
        fn = self._find_function("vuln_scan")
        self.assertIsNotNone(fn)
        src = ast.get_source_segment(VULN_SCAN_PATH.read_text(encoding="utf-8"), fn) or ""
        self.assertIn('if action == "scan":', src)
        self.assertIn("_discover_sinks", src)
        self.assertIn("_discover_sources", src)
        self.assertIn("_discover_sanitizers", src)
        self.assertIn("_analyze_sink_call", src)
        self.assertIn("_compute_risk_score", src)
        self.assertIn("findings.sort(key=lambda x: -x[\"score\"])", src)

    def test_feedback_and_reflection_branches_exist(self):
        source = VULN_SCAN_PATH.read_text(encoding="utf-8")
        self.assertIn('elif action == "feedback":', source)
        self.assertIn('elif action == "reflect":', source)
        self.assertIn('elif action == "suggest_strategy":', source)
        self.assertIn('elif action == "learned_knowledge":', source)
        self.assertIn("_voera_reflect", source)
        self.assertIn("_voera_find_similar_strategy", source)

    def test_no_static_pattern_lists(self):
        """Ensure no old-style static vulnerability pattern lists exist."""
        source = VULN_SCAN_PATH.read_text(encoding="utf-8")
        # Old static lists that should NOT exist
        forbidden = [
            "_BUFFER_OVERFLOW_FUNCS",
            "_FORMAT_STRING_FUNCS",
            "_COMMAND_INJECTION_FUNCS",
            "_UAF_FREE_FUNCS",
            "_ALLOC_FUNCS",
            "_RACE_CONDITION_FUNCS",
            "_AUTH_FUNCS",
            "_INFO_LEAK_FUNCS",
            "_CREDENTIAL_PATTERNS",
            "_CWE_MAP",
        ]
        for pat in forbidden:
            self.assertNotIn(pat, source, f"Old static pattern list found: {pat}")

    def test_knowledge_persistence_path_exists(self):
        source = VULN_SCAN_PATH.read_text(encoding="utf-8")
        self.assertIn("_VULN_KNOWLEDGE_PATH", source)
        self.assertIn("_load_vuln_knowledge", source)
        self.assertIn("_save_vuln_knowledge", source)
        self.assertIn("vuln_knowledge.json", source)


if __name__ == "__main__":
    unittest.main()
