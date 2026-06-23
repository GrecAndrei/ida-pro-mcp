"""
Unit tests for the opt-in `intelligence(action="suggest")` action.

`suggest_next_steps` is a pure function with no IDA SDK dependency, but it
lives inside a 1100-line module whose other code requires IDA. We extract
the function by reading the source file, taking everything from
`def suggest_next_steps` to the next top-level `def`, and exec-ing it in
a controlled namespace.
"""
from __future__ import annotations

import os
import sys
import unittest


def _load_suggest_fn():
    """Extract suggest_next_steps from intelligence.py by source slicing.

    The function is a pure-Python dispatch table with no external deps; we
    avoid importing the rest of intelligence.py (which requires the full
    IDA SDK) by exec-ing just the function definition.
    """
    src_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "src", "ida_pro_mcp", "ida_mcp", "tools", "intelligence.py",
    )
    src_path = os.path.normpath(src_path)
    with open(src_path, encoding="utf-8") as f:
        text = f.read()
    lines = text.split("\n")

    # Find the function header. Look for `def suggest_next_steps(`
    start = None
    for i, line in enumerate(lines):
        if line.startswith("def suggest_next_steps("):
            start = i
            break
    if start is None:
        raise RuntimeError("suggest_next_steps not found in intelligence.py")

    # Walk forward, tracking indentation, until we hit a non-empty, non-
    # comment, non-docstring line that is less indented than the def.
    def_indent = len(lines[start]) - len(lines[start].lstrip())
    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Skip lines that are continuations of strings opened above
        if stripped.endswith("\\"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= def_indent:
            end = i
            break

    func_src = "\n".join(lines[start:end])
    namespace: dict = {"__builtins__": __builtins__}
    exec(compile(func_src, "<intelligence.suggest_next_steps>", "exec"),
         namespace)
    return namespace["suggest_next_steps"]


suggest_next_steps = _load_suggest_fn()


class TestSuggestEmpty(unittest.TestCase):
    def test_no_tool_returns_empty_with_hint(self):
        r = suggest_next_steps({}, None)
        self.assertTrue(r["ok"])
        self.assertEqual(r["suggestions"], [])
        self.assertIn("no obvious next step", r["reason"])

    def test_unrelated_tool_action_returns_empty(self):
        r = suggest_next_steps({"tool": "wiki", "action": "list_topics"}, None)
        self.assertEqual(r["suggestions"], [])
        self.assertIn("no obvious next step", r["reason"])


class TestSuggestCodeDecompile(unittest.TestCase):
    def test_dangerous_api_triggers_taint(self):
        r = suggest_next_steps({
            "tool": "code",
            "action": "decompile",
            "addr": "0x401000",
            "payload": {
                "api_calls": ["strcpy", "recv"],
                "behavior_tags": [],
            },
        }, None)
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["suggestions"]), 1)
        self.assertEqual(r["suggestions"][0]["tool"], "taint")
        self.assertEqual(r["suggestions"][0]["arguments"]["addr"], "0x401000")
        self.assertEqual(r["suggestions"][0]["arguments"]["source"], "strcpy")

    def test_process_injection_tag_triggers_taint(self):
        r = suggest_next_steps({
            "tool": "code",
            "action": "smart_decompile",
            "addr": "0x402000",
            "payload": {
                "api_calls": ["VirtualAllocEx", "WriteProcessMemory"],
                "behavior_tags": ["process_injection"],
            },
        }, None)
        self.assertEqual(r["suggestions"][0]["tool"], "taint")

    def test_network_plus_dangerous_sink_triggers_taint(self):
        r = suggest_next_steps({
            "tool": "code",
            "action": "decompile",
            "addr": "0x401000",
            "payload": {
                "api_calls": ["recv", "memcpy"],
                "behavior_tags": ["network"],
            },
        }, None)
        taint_calls = [s for s in r["suggestions"] if s["tool"] == "taint"]
        self.assertEqual(len(taint_calls), 1)
        self.assertEqual(taint_calls[0]["arguments"]["source"], "recv")

    def test_crypto_tag_triggers_crypto_id(self):
        r = suggest_next_steps({
            "tool": "code",
            "action": "decompile",
            "addr": "0x401000",
            "payload": {
                "api_calls": ["CryptEncrypt"],
                "behavior_tags": ["crypto"],
            },
        }, None)
        crypto_calls = [s for s in r["suggestions"] if s["tool"] == "crypto_id"]
        self.assertEqual(len(crypto_calls), 1)
        self.assertEqual(crypto_calls[0]["arguments"]["addr"], "0x401000")

    def test_clean_decompile_falls_back_to_xrefs(self):
        r = suggest_next_steps({
            "tool": "code",
            "action": "decompile",
            "addr": "0x401000",
            "payload": {
                "api_calls": ["malloc"],
                "behavior_tags": [],
            },
        }, None)
        self.assertEqual(len(r["suggestions"]), 1)
        self.assertEqual(r["suggestions"][0]["tool"], "code")
        self.assertEqual(r["suggestions"][0]["arguments"]["action"], "xrefs_to")
        self.assertEqual(r["suggestions"][0]["arguments"]["addr"], "0x401000")

    def test_capped_at_three(self):
        r = suggest_next_steps({
            "tool": "code",
            "action": "decompile",
            "addr": "0x401000",
            "payload": {
                "api_calls": ["strcpy", "recv"],
                "behavior_tags": ["process_injection", "network", "crypto"],
            },
        }, None)
        self.assertLessEqual(len(r["suggestions"]), 3)

    def test_addr_required_for_decompile_suggestion(self):
        r = suggest_next_steps({
            "tool": "code",
            "action": "decompile",
            "payload": {"api_calls": ["strcpy"]},
        }, None)
        self.assertEqual(r["suggestions"], [])


class TestSuggestTaint(unittest.TestCase):
    def test_taint_with_vuln_triggers_explainer(self):
        r = suggest_next_steps({
            "tool": "taint",
            "action": "report",
            "payload": {
                "vulns": [{
                    "sink_addr": "0x401234",
                    "vuln_type": "buffer_overflow",
                }],
            },
        }, None)
        self.assertEqual(len(r["suggestions"]), 1)
        self.assertEqual(r["suggestions"][0]["tool"], "llm_helpers")
        self.assertEqual(r["suggestions"][0]["arguments"]["addr"], "0x401234")
        self.assertEqual(
            r["suggestions"][0]["arguments"]["action"],
            "dangerous_pattern_explainer",
        )

    def test_taint_no_vulns_empty(self):
        r = suggest_next_steps({
            "tool": "taint",
            "action": "report",
            "payload": {"vulns": []},
        }, None)
        self.assertEqual(r["suggestions"], [])


class TestSuggestSearch(unittest.TestCase):
    def test_search_results_suggest_smart_decompile(self):
        r = suggest_next_steps({
            "tool": "search",
            "action": "find",
            "payload": {
                "items": [{"addr": "0x402000", "name": "aes_decrypt"}],
            },
        }, None)
        self.assertEqual(len(r["suggestions"]), 1)
        self.assertEqual(r["suggestions"][0]["tool"], "code")
        self.assertEqual(r["suggestions"][0]["arguments"]["addrs"], "0x402000")
        self.assertEqual(
            r["suggestions"][0]["arguments"]["action"],
            "smart_decompile",
        )

    def test_search_no_items_empty(self):
        r = suggest_next_steps({
            "tool": "search",
            "action": "find",
            "payload": {"items": []},
        }, None)
        self.assertEqual(r["suggestions"], [])


class TestSuggestBlackboard(unittest.TestCase):
    def test_frontier_suggests_top_target(self):
        r = suggest_next_steps({
            "tool": "blackboard",
            "action": "frontier",
            "payload": {
                "items": [{"addr": "0x403000", "name": "sub_403000",
                            "score": 0.91}],
            },
        }, None)
        self.assertEqual(r["suggestions"][0]["arguments"]["addrs"], "0x403000")

    def test_low_coverage_suggests_frontier(self):
        r = suggest_next_steps({
            "tool": "blackboard",
            "action": "coverage",
            "payload": {"coverage_pct": 12, "unvisited": 200},
        }, None)
        self.assertEqual(r["suggestions"][0]["tool"], "blackboard")
        self.assertEqual(r["suggestions"][0]["arguments"]["action"], "frontier")

    def test_high_coverage_empty(self):
        r = suggest_next_steps({
            "tool": "blackboard",
            "action": "coverage",
            "payload": {"coverage_pct": 85, "unvisited": 5},
        }, None)
        self.assertEqual(r["suggestions"], [])


class TestSuggestFirmware(unittest.TestCase):
    def test_idb_overview_firmware_suggests_triage(self):
        r = suggest_next_steps({
            "tool": "idb",
            "action": "overview",
            "payload": {"firmware_detected": True},
        }, None)
        self.assertEqual(r["suggestions"][0]["tool"], "firmware_view")
        self.assertEqual(
            r["suggestions"][0]["arguments"]["action"], "triage_snapshot")

    def test_idb_overview_no_firmware_empty(self):
        r = suggest_next_steps({
            "tool": "idb",
            "action": "overview",
            "payload": {"firmware_detected": False},
        }, None)
        self.assertEqual(r["suggestions"], [])

    def test_firmware_scan_region_suggests_carve_plan(self):
        r = suggest_next_steps({
            "tool": "firmware_view",
            "action": "scan_region",
            "payload": {"regions": [{"type": "code"}]},
        }, None)
        self.assertEqual(r["suggestions"][0]["arguments"]["action"], "carve_plan")

    def test_firmware_carve_plan_suggests_smart_carve_dryrun(self):
        r = suggest_next_steps({
            "tool": "firmware_view",
            "action": "carve_plan",
            "payload": {"plan": []},
        }, None)
        self.assertEqual(r["suggestions"][0]["arguments"]["action"], "smart_carve")
        self.assertEqual(r["suggestions"][0]["arguments"]["apply"], False)

    def test_firmware_smart_carve_applied_suggests_no_callers(self):
        r = suggest_next_steps({
            "tool": "firmware_view",
            "action": "smart_carve",
            "payload": {"applied": True},
        }, None)
        self.assertEqual(r["suggestions"][0]["tool"], "search")
        self.assertEqual(
            r["suggestions"][0]["arguments"]["action"], "func_by_sig")

    def test_firmware_smart_carve_not_applied_empty(self):
        r = suggest_next_steps({
            "tool": "firmware_view",
            "action": "smart_carve",
            "payload": {"applied": False},
        }, None)
        self.assertEqual(r["suggestions"], [])


class TestSuggestPacker(unittest.TestCase):
    def test_packer_do_not_unpack_suggests_string_ops_indicators(self):
        r = suggest_next_steps({
            "tool": "packer",
            "action": "detect",
            "payload": {"recommendation": "do_not_unpack"},
        }, None)
        self.assertEqual(r["suggestions"][0]["tool"], "string_ops")
        self.assertEqual(
            r["suggestions"][0]["arguments"]["action"], "indicators")

    def test_packer_auto_unpack_empty(self):
        r = suggest_next_steps({
            "tool": "packer",
            "action": "detect",
            "payload": {"recommendation": "auto_unpack"},
        }, None)
        self.assertEqual(r["suggestions"], [])


class TestSuggestSanity(unittest.TestCase):
    def test_based_on_present_when_suggestion_fired(self):
        r = suggest_next_steps({
            "tool": "search",
            "action": "find",
            "payload": {"items": [{"addr": "0x401000"}]},
        }, None)
        self.assertIn("based_on", r)
        self.assertEqual(r["based_on"]["tool"], "search")
        self.assertEqual(r["based_on"]["action"], "find")

    def test_no_placeholder_in_suggestion_args(self):
        r = suggest_next_steps({
            "tool": "code",
            "action": "decompile",
            "addr": "0x401000",
            "payload": {
                "api_calls": ["strcpy"],
                "behavior_tags": ["network", "process_injection", "crypto"],
            },
        }, None)
        for s in r["suggestions"]:
            args = s.get("arguments", {})
            for k, v in args.items():
                self.assertNotIn("<", str(v),
                                 f"placeholder leaked into {s['tool']}.{k}")


if __name__ == "__main__":
    unittest.main()
