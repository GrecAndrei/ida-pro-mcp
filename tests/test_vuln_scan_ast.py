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

    def test_vuln_scan_has_intelligence_action_and_scan_profile(self):
        fn = self._find_function("vuln_scan")
        self.assertIsNotNone(fn, "vuln_scan function missing")

        arg_names = [a.arg for a in fn.args.args]
        self.assertIn("action", arg_names)
        self.assertIn("scan_profile", arg_names)

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
        self.assertIn("intelligence_report", values)

    def test_profile_and_attack_path_helpers_exist(self):
        helper_names = {
            "_normalize_scan_profile",
            "_profile_settings_for",
            "_iter_disasm_window",
            "_score_callsite_evidence",
            "_enrich_findings_with_risk",
            "_build_attack_paths",
            "_summarize_hotspots",
            "_build_recommendations",
            "_risk_histogram",
        }
        found = {
            n.name for n in self.module.body if isinstance(n, ast.FunctionDef) and n.name in helper_names
        }
        self.assertEqual(helper_names, found)

    def test_scan_all_branch_handles_intelligence_report(self):
        fn = self._find_function("vuln_scan")
        self.assertIsNotNone(fn)
        src = ast.get_source_segment(VULN_SCAN_PATH.read_text(encoding="utf-8"), fn) or ""
        self.assertIn("if action in (\"scan_all\", \"intelligence_report\"):", src)
        self.assertIn("\"attack_paths\": attack_paths", src)
        self.assertIn("\"hotspots\": hotspots", src)
        self.assertIn("\"recommendations\": recommendations", src)
        self.assertIn("\"scan_profile\": profile", src)


if __name__ == "__main__":
    unittest.main()
