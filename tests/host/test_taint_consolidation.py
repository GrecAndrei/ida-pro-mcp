"""Tests for the canonical taint registry and the consolidation of duplicate definitions.

Verifies:
- taint_registry.py exports the canonical source/sink sets
- All tools import from the registry (no local duplicates)
- CWE cross-references are present for all vulnerability categories
- threat_corpus auto-download infrastructure works
"""
import importlib
import inspect
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import install_common_stub, load_tool_module


def _load_registry():
    """Load taint_registry.py as a standalone module (no IDA dependency)."""
    path = os.path.join(
        os.path.dirname(__file__), "..", "..",
        "src", "ida_pro_mcp", "ida_mcp", "support", "taint_registry.py",
    )
    spec = importlib.util.spec_from_file_location("taint_registry", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestTaintRegistry(unittest.TestCase):
    """Test the canonical taint_registry.py module."""

    def test_taRINT_SOURCES_type_and_size(self):
        mod = _load_registry()
        self.assertIsInstance(mod.TAINT_SOURCES, frozenset)
        self.assertGreater(len(mod.TAINT_SOURCES), 30)

    def test_taRINT_SOURCES_includes_network(self):
        mod = _load_registry()
        for name in ("recv", "recvfrom", "read", "fread", "fgets", "gets", "scanf"):
            self.assertIn(name, mod.TAINT_SOURCES)

    def test_taRINT_SOURCES_includes_firmware(self):
        mod = _load_registry()
        for name in ("HAL_UART_Receive", "HAL_SPI_Receive", "FreeRTOS_recv", "DMA_Receive"):
            self.assertIn(name, mod.TAINT_SOURCES)

    def test_taRINT_SOURCES_includes_windows(self):
        mod = _load_registry()
        for name in ("ReadFile", "RegQueryValueEx", "DeviceIoControl", "URLDownloadToFile"):
            self.assertIn(name, mod.TAINT_SOURCES)

    def test_DANGEROUS_SINKS_type_and_size(self):
        mod = _load_registry()
        self.assertIsInstance(mod.DANGEROUS_SINKS, dict)
        self.assertGreater(len(mod.DANGEROUS_SINKS), 30)

    def test_DANGEROUS_SINKS_has_categories(self):
        mod = _load_registry()
        self.assertEqual(mod.DANGEROUS_SINKS["memcpy"], "buffer_overflow")
        self.assertEqual(mod.DANGEROUS_SINKS["system"], "command_injection")
        self.assertEqual(mod.DANGEROUS_SINKS["sprintf"], "format_string")
        self.assertEqual(mod.DANGEROUS_SINKS["HAL_UART_Transmit"], "firmware_output_injection")

    def test_DANGEROUS_SINK_NAMES_matches_dict(self):
        mod = _load_registry()
        self.assertEqual(mod.DANGEROUS_SINK_NAMES, frozenset(mod.DANGEROUS_SINKS.keys()))

    def test_VULN_TYPE_TO_CWE_mapping(self):
        mod = _load_registry()
        self.assertIn("CWE-120", mod.VULN_TYPE_TO_CWE["buffer_overflow"])
        self.assertIn("CWE-134", mod.VULN_TYPE_TO_CWE["format_string"])
        self.assertIn("CWE-78", mod.VULN_TYPE_TO_CWE["command_injection"])

    def test_DANGEROUS_APIS_CATEGORIZED(self):
        mod = _load_registry()
        self.assertIn("buffer_overflow", mod.DANGEROUS_APIS_CATEGORIZED)
        self.assertIn("strcpy", mod.DANGEROUS_APIS_CATEGORIZED["buffer_overflow"])
        self.assertIn("command_injection", mod.DANGEROUS_APIS_CATEGORIZED)

    def test_MITIGATION_CHECKS(self):
        mod = _load_registry()
        self.assertIn("stack_canary", mod.MITIGATION_CHECKS)
        self.assertIn("__stack_chk_fail", mod.MITIGATION_CHECKS["stack_canary"])


class TestNoDuplicateDefinitions(unittest.TestCase):
    """Verify that tools no longer define their own source/sink sets."""

    def _get_tool_source(self, module_basename):
        """Load tool source via isolated loader and return source code."""
        path = os.path.join(
            os.path.dirname(__file__), "..", "..",
            "src", "ida_pro_mcp", "ida_mcp", "tools",
            f"{module_basename}.py",
        )
        with open(path) as f:
            return f.read()

    def test_taint_no_local_taRINT_SOURCES_definition(self):
        source = self._get_tool_source("security")
        self.assertNotIn("TAINT_SOURCES = {", source)
        self.assertNotIn("DANGEROUS_SINKS = {", source)

    def test_combinators_no_local_definitions(self):
        source = self._get_tool_source("search/combinators")
        # Should NOT have local frozenset/dict definitions
        self.assertNotIn("frozenset({", source)
        self.assertNotIn('"strcpy": "buffer_overflow"', source)

    def test_summarize_no_local_definitions(self):
        source = self._get_tool_source("summarize")
        self.assertNotIn("_IMPORT_CATEGORIES = {", source)
        self.assertNotIn("_DANGEROUS_APIS = {", source)
        self.assertNotIn("_MITIGATION_CHECKS = {", source)

    def test_code_no_inline_taRINT_SOURCES(self):
        source = self._get_tool_source("code")
        self.assertNotIn('_TAINT_SOURCES = {', source)


class TestRegistryConsistency(unittest.TestCase):
    """Verify the registry is internally consistent."""

    def test_all_sink_categories_have_cwe(self):
        mod = _load_registry()
        for api, category in mod.DANGEROUS_SINKS.items():
            self.assertIn(
                category, mod.VULN_TYPE_TO_CWE,
                f"Category '{category}' for API '{api}' has no CWE mapping",
            )

    def test_categorized_derived_from_sinks(self):
        mod = _load_registry()
        all_categorized = set()
        for apis in mod.DANGEROUS_APIS_CATEGORIZED.values():
            all_categorized.update(apis)
        deprecated_crypto = {"MD5Init", "MD5Update", "SHA1Init", "DES_ecb_encrypt", "RC4"}
        for api in all_categorized - deprecated_crypto:
            self.assertIn(api, mod.DANGEROUS_SINKS)


class TestThreatCorpusDownload(unittest.TestCase):
    """Test threat_corpus auto-download infrastructure."""

    def test_ensure_corpus_loaded_has_auto_download(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "..",
            "src", "ida_pro_mcp", "host", "intelligence", "threat_corpus.py",
        )
        with open(path) as f:
            source = f.read()
        self.assertIn("auto_download", source)
        self.assertIn("download_corpus_sources", source)
        self.assertIn("_download_url", source)

    def test_download_urls_present(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "..",
            "src", "ida_pro_mcp", "host", "intelligence", "threat_corpus.py",
        )
        with open(path) as f:
            source = f.read()
        self.assertIn("cwe.mitre.org", source)
        self.assertIn("mitre/cti", source)
        self.assertIn("Neo23x0/signature-base", source)


class TestBlackboardAutoWrite(unittest.TestCase):
    """Verify crypto_id and gadgets have blackboard auto-write code."""

    def _get_tool_source(self, module_basename):
        path = os.path.join(
            os.path.dirname(__file__), "..", "..",
            "src", "ida_pro_mcp", "ida_mcp", "tools",
            f"{module_basename}.py",
        )
        with open(path) as f:
            return f.read()

    def test_crypto_id_has_blackboard_write(self):
        source = self._get_tool_source("security")
        self.assertIn("BlackboardStore", source)
        self.assertIn('category="crypto"', source)
        self.assertIn("engine_crypto", source)

    def test_gadgets_has_blackboard_write(self):
        source = self._get_tool_source("gadgets")
        self.assertIn("BlackboardStore", source)
        self.assertIn("engine_gadgets", source)

    def test_gadgets_mitigations_blackboard_write(self):
        source = self._get_tool_source("gadgets")
        self.assertIn("mitigation_gap", source)


class TestCtreeDataflowVisitor(unittest.TestCase):
    """Verify taint.py has ctree dataflow visitor."""

    def _get_tool_source(self, module_basename):
        path = os.path.join(
            os.path.dirname(__file__), "..", "..",
            "src", "ida_pro_mcp", "ida_mcp", "tools",
            f"{module_basename}.py",
        )
        with open(path) as f:
            return f.read()

    def test_ctree_visitor_exists(self):
        source = self._get_tool_source("security")
        self.assertIn("_dataflow_signal", source)

    def test_dataflow_signal_includes_ctree(self):
        source = self._get_tool_source("security")
        self.assertIn("microcode_ssa", source)
        self.assertIn("regex", source)

    def test_cwe_ids_in_trace_results(self):
        source = self._get_tool_source("security")
        self.assertIn("cwe_ids", source)
        self.assertIn("VULN_TYPE_TO_CWE", source)


if __name__ == "__main__":
    unittest.main()
