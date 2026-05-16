"""Unit tests for build_signal_directives in response_enrichment.py."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class TestSignalDirectives(unittest.TestCase):
    def _get(self, tool, action, payload, addr=""):
        from ida_pro_mcp.host.response_enrichment import build_signal_directives
        return build_signal_directives(tool, action, payload, func_addr=addr)

    # ── code(decompile) ───────────────────────────────────────────────────────

    def test_network_plus_dangerous_sink_triggers_taint(self):
        d = self._get("code", "decompile",
                      {"pseudocode": "recv(buf); memcpy(dst, buf, len);",
                       "api_calls": ["recv", "memcpy"]},
                      addr="0x401000")
        calls = [x["call"] for x in d]
        self.assertTrue(any("taint" in c and "trace" in c for c in calls))
        high = [x for x in d if x["priority"] == "high"]
        self.assertTrue(any("taint" in x["call"] for x in high))

    def test_dangerous_pattern_triggers_explainer(self):
        d = self._get("code", "smart_decompile",
                      {"pseudocode": "strcpy(dst, src);",
                       "api_calls": ["strcpy"],
                       "dangerous_patterns": ["strcpy"]},
                      addr="0x401000")
        calls = [x["call"] for x in d]
        self.assertTrue(any("dangerous_pattern_explainer" in c for c in calls))

    def test_crypto_hints_trigger_crypto_id(self):
        d = self._get("code", "decompile",
                      {"pseudocode": "AES_encrypt(key, data);",
                       "api_calls": [],
                       "crypto_hints": ["AES"]},
                      addr="0x401000")
        calls = [x["call"] for x in d]
        self.assertTrue(any("crypto_id" in c for c in calls))

    def test_no_blackboard_entry_suggests_write(self):
        d = self._get("code", "decompile",
                      {"pseudocode": "foo();", "api_calls": [],
                       "blackboard_context": None},
                      addr="0x401000")
        calls = [x["call"] for x in d]
        self.assertTrue(any("blackboard" in c and "write" in c for c in calls))

    def test_blackboard_entry_present_no_write_suggestion(self):
        d = self._get("code", "decompile",
                      {"pseudocode": "foo();", "api_calls": [],
                       "blackboard_context": {"0x401000": [{"title": "known"}]}},
                      addr="0x401000")
        calls = [x["call"] for x in d]
        self.assertFalse(any("blackboard" in c and "write" in c for c in calls))

    def test_hot_function_suggests_api_contract(self):
        d = self._get("code", "decompile",
                      {"pseudocode": "foo();", "api_calls": [],
                       "callers": ["a", "b", "c", "d", "e", "f"]},
                      addr="0x401000")
        calls = [x["call"] for x in d]
        self.assertTrue(any("api_contract_extractor" in c for c in calls))

    def test_no_addr_no_taint_directive(self):
        d = self._get("code", "decompile",
                      {"pseudocode": "recv(buf); memcpy(dst, buf, len);",
                       "api_calls": ["recv", "memcpy"]},
                      addr="")
        calls = [x["call"] for x in d]
        self.assertFalse(any("taint" in c for c in calls))

    def test_no_dangerous_no_directives_for_clean_function(self):
        d = self._get("code", "decompile",
                      {"pseudocode": "return x + y;", "api_calls": [],
                       "dangerous_patterns": [], "crypto_hints": [],
                       "blackboard_context": {"0x401000": [{"title": "known"}]},
                       "callers": ["a"]},
                      addr="0x401000")
        self.assertEqual(len(d), 0)

    # ── taint results ─────────────────────────────────────────────────────────

    def test_taint_report_with_findings_triggers_explainer(self):
        d = self._get("taint", "report",
                      {"findings": [{"sink": "memcpy", "vuln_type": "buffer_overflow",
                                     "sink_addr": "0x401234"}]})
        calls = [x["call"] for x in d]
        self.assertTrue(any("dangerous_pattern_explainer" in c for c in calls))
        high = [x for x in d if x["priority"] == "high"]
        self.assertTrue(len(high) >= 1)

    def test_taint_report_empty_no_directives(self):
        d = self._get("taint", "report", {"findings": [], "total": 0})
        self.assertEqual(len(d), 0)

    def test_taint_trace_with_vulns_triggers_blackboard_write(self):
        d = self._get("taint", "trace",
                      {"vulns": [{"sink": "strcpy", "vuln_type": "buffer_overflow",
                                  "sink_addr": "0x401234"}]})
        calls = [x["call"] for x in d]
        self.assertTrue(any("blackboard" in c and "write" in c for c in calls))

    # ── search results ────────────────────────────────────────────────────────

    def test_search_find_with_items_suggests_smart_decompile(self):
        d = self._get("search", "find",
                      {"items": [{"addr": "0x401000", "name": "sub_401000"}]})
        calls = [x["call"] for x in d]
        self.assertTrue(any("smart_decompile" in c for c in calls))

    def test_search_nl_with_items_suggests_smart_decompile(self):
        d = self._get("search", "nl",
                      {"items": [{"addr": "0x401000", "name": "aes_encrypt"}]})
        calls = [x["call"] for x in d]
        self.assertTrue(any("smart_decompile" in c for c in calls))

    def test_search_no_items_no_directive(self):
        d = self._get("search", "find", {"items": []})
        self.assertEqual(len(d), 0)

    # ── blackboard frontier/coverage ─────────────────────────────────────────

    def test_frontier_top_item_suggests_smart_decompile(self):
        d = self._get("blackboard", "frontier",
                      {"items": [{"addr": "0x401000", "name": "sub_401000",
                                  "score": 0.85, "nearest_label_title": "AES"}]})
        calls = [x["call"] for x in d]
        self.assertTrue(any("smart_decompile" in c and "0x401000" in c for c in calls))
        high = [x for x in d if x["priority"] == "high"]
        self.assertTrue(len(high) >= 1)

    def test_coverage_low_suggests_frontier(self):
        d = self._get("blackboard", "coverage",
                      {"coverage_pct": 15.0, "unvisited": 200})
        calls = [x["call"] for x in d]
        self.assertTrue(any("frontier" in c for c in calls))
        high = [x for x in d if x["priority"] == "high"]
        self.assertTrue(len(high) >= 1)

    def test_coverage_high_no_directive(self):
        d = self._get("blackboard", "coverage",
                      {"coverage_pct": 80.0, "unvisited": 10})
        self.assertEqual(len(d), 0)

    # ── data(functions) ───────────────────────────────────────────────────────

    def test_data_functions_large_binary_suggests_coverage(self):
        d = self._get("data", "functions", {"total": 500})
        calls = [x["call"] for x in d]
        self.assertTrue(any("coverage" in c for c in calls))
        self.assertTrue(any("frontier" in c for c in calls))

    def test_data_functions_small_binary_no_directive(self):
        d = self._get("data", "functions", {"total": 10})
        self.assertEqual(len(d), 0)

    def test_idb_overview_firmware_suggests_triage_snapshot(self):
        d = self._get("idb", "overview", {"firmware_detected": True})
        calls = [x["call"] for x in d]
        self.assertTrue(any("triage_snapshot" in c for c in calls))
        self.assertTrue(any("guided_analysis" in c for c in calls))

    def test_idb_overview_non_firmware_no_triage_snapshot(self):
        d = self._get("idb", "overview", {"firmware_detected": False})
        calls = [x["call"] for x in d]
        self.assertFalse(any("triage_snapshot" in c for c in calls))

    # ── firmware_view ─────────────────────────────────────────────────────────

    def test_firmware_scan_region_suggests_carve_plan(self):
        d = self._get("firmware_view", "scan_region",
                      {"regions": [{"type": "code", "start": "0x0"}]})
        calls = [x["call"] for x in d]
        self.assertTrue(any("carve_plan" in c for c in calls))

    def test_firmware_carve_plan_suggests_smart_carve_dryrun(self):
        d = self._get("firmware_view", "carve_plan", {"plan": []})
        calls = [x["call"] for x in d]
        self.assertTrue(any("smart_carve" in c and "apply=false" in c for c in calls))

    def test_firmware_detect_load_address_found_suggests_vector_table(self):
        d = self._get("firmware_view", "detect_load_address",
                      {"candidates": [{"base": "0x8000000", "method": "cortex_m_vector_table",
                                       "confidence": 0.92}]})
        calls = [x["call"] for x in d]
        self.assertTrue(any("detect_vector_table" in c for c in calls))

    def test_firmware_detect_load_address_not_found_suggests_scan(self):
        d = self._get("firmware_view", "detect_load_address", {"candidates": []})
        calls = [x["call"] for x in d]
        self.assertTrue(any("scan_region" in c for c in calls))

    def test_firmware_detect_vector_table_suggests_smart_decompile_reset(self):
        d = self._get("firmware_view", "detect_vector_table",
                      {"vectors": [{"name": "Reset_Handler", "handler": "0x8000101",
                                    "type": "exception_vector"}],
                       "entry_points": ["0x8000101"]})
        calls = [x["call"] for x in d]
        self.assertTrue(any("smart_decompile" in c and "0x8000101" in c for c in calls))

    def test_firmware_detect_mmio_suggests_taint(self):
        d = self._get("firmware_view", "detect_mmio",
                      {"peripherals": [{"base": "0x40011000", "peripheral_name": "STM32_APB2"}],
                       "likely_chip_family": "STM32"})
        calls = [x["call"] for x in d]
        self.assertTrue(any("taint" in c for c in calls))

    def test_firmware_triage_snapshot_without_load_suggests_scan(self):
        d = self._get("firmware_view", "triage_snapshot",
                      {"summary": {"load_candidates": 0, "vector_entries": 0, "mmio_regions": 0}})
        calls = [x["call"] for x in d]
        self.assertTrue(any("scan_region" in c for c in calls))
        self.assertTrue(any("detect_mmio" in c for c in calls))

    def test_firmware_triage_snapshot_with_vectors_and_mmio_suggests_taint(self):
        d = self._get("firmware_view", "triage_snapshot",
                      {"summary": {"load_candidates": 1, "vector_entries": 5, "mmio_regions": 2}})
        calls = [x["call"] for x in d]
        self.assertTrue(any("func_by_sig" in c and "no_callers" in c for c in calls))
        self.assertTrue(any("taint(action='report')" in c for c in calls))

    # ── priority ordering ─────────────────────────────────────────────────────

    def test_high_priority_becomes_execution_directive(self):
        """High-priority directives should be usable as llm_execution_directive."""
        d = self._get("code", "decompile",
                      {"pseudocode": "recv(buf); memcpy(dst, buf, len);",
                       "api_calls": ["recv", "memcpy"]},
                      addr="0x401000")
        high = [x for x in d if x["priority"] == "high"]
        self.assertTrue(len(high) >= 1)
        # Each directive has required fields
        for h in high:
            self.assertIn("call", h)
            self.assertIn("reason", h)
            self.assertIsInstance(h["call"], str)
            self.assertGreater(len(h["call"]), 5)


if __name__ == "__main__":
    unittest.main()
