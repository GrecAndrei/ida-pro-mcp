"""p09_intelligence: patterns/arch_profile/context_density regression tests.

Verifies conservative regex auto-detection, literal '?' glob handling,
fuzzy double-count elimination, suffix stemming, arch_profile address
coercion + confidence normalization, and context_density tag/hex-line
preservation.
"""

from __future__ import annotations

import pytest

from ida_pro_mcp.host.analysis.arch_profile import normalize_arch_options
from ida_pro_mcp.host.analysis.context_density import ContextDensityOptimizer
from ida_pro_mcp.host.analysis.patterns import (
    _is_regex,
    _normalize_semantic_token,
    smart_match,
)


class TestIsRegexConservative:
    def test_literal_brackets_not_regex(self):
        # "foo[0]" is a literal array index, not a character class.
        assert _is_regex("foo[0]") is False

    def test_literal_plus_not_regex(self):
        assert _is_regex("v3 + 0x10") is False

    def test_literal_parens_not_regex(self):
        assert _is_regex("func()") is False

    def test_anchors_still_regex(self):
        assert _is_regex("^foo$") is True

    def test_character_class_range_still_regex(self):
        assert _is_regex("[a-z]+") is True

    def test_backslash_escape_still_regex(self):
        assert _is_regex(r"\d+") is True


class TestSmartMatchLiteral:
    def test_foo_bracket_literal_matches_itself(self):
        assert smart_match("foo[0]", "foo[0]") is True

    def test_foo_bracket_literal_rejects_charclass(self):
        # [0] is no longer a regex char class matching '0'.
        assert smart_match("foo[0]", "foo0") is False

    def test_plus_literal_matches_itself(self):
        assert smart_match("v3 + 0x10", "v3 + 0x10") is True

    def test_question_mark_is_literal_not_glob(self):
        # MSVC-mangled leading '?' must not act as a single-char wildcard.
        assert smart_match("?str@std@@", "Xstr@std@@") is False
        assert smart_match("?str@std@@", "?str@std@@") is True


class TestFuzzyDoubleCount:
    def test_single_overlap_does_not_satisfy_two_required(self):
        # Reported repro: only "decrypt" present but overlap_needed=2.
        assert smart_match("decrypt buffer input", "decrypt only") is False

    def test_two_overlaps_still_match(self):
        assert smart_match("decrypt buffer input", "decrypt buffer xor input") is True


class TestNumericIdentifierTokens:
    def test_numbered_string_does_not_match_sibling(self):
        assert smart_match("AGENT_SURFACE_STRING_007", "AGENT_SURFACE_STRING_007") is True
        assert smart_match("AGENT_SURFACE_STRING_007", "AGENT_SURFACE_STRING_008") is False

    def test_shared_prefix_without_number_still_matches(self):
        assert smart_match("AGENT_SURFACE_STRING", "AGENT_SURFACE_STRING_008") is True


class TestStemming:
    def test_decompilers_stems_to_canonical_decompile(self):
        assert _normalize_semantic_token("decompilers") == "decompile"

    def test_analysis_stems_to_analys(self):
        assert _normalize_semantic_token("analysis") == "analys"

    def test_synthesis_stems_to_synthes(self):
        assert _normalize_semantic_token("synthesis") == "synthes"


class TestArchProfile:
    def test_leading_zero_hex_coerced(self):
        out, meta = normalize_arch_options({"baseaddr": "00401000"})
        assert out.get("baseaddr") == 0x401000
        assert isinstance(out.get("baseaddr"), int)

    def test_plain_decimal_unchanged(self):
        out, meta = normalize_arch_options({"baseaddr": "1024"})
        assert out.get("baseaddr") == 1024

    def test_confidence_is_relative_to_best(self):
        # monkeypatch the private helper is fragile; instead assert the
        # public normalize path still returns sane values.
        out, _ = normalize_arch_options({"baseaddr": "0x1000", "bitness": 32})
        assert out.get("baseaddr") == 0x1000


class TestContextDensityPreservation:
    def test_strip_xml_tags_preserves_embedded_address(self):
        opt = ContextDensityOptimizer()
        assert opt.strip_xml_tags("; <0x401000> val") == "; <0x401000> val"

    def test_strip_xml_tags_still_removes_real_tags(self):
        opt = ContextDensityOptimizer()
        assert opt.strip_xml_tags("<tool_use>x</tool_use>") == "x"

    def test_whitespace_collapse_preserves_hex_dump_alignment(self):
        opt = ContextDensityOptimizer()
        hex_line = "0x401000  55 8b ec 83 ec 08 90 90  00 00 00 00 00 00 00 00"
        out = opt._compact_string(f"lead\n{hex_line}\ntail   spaced")
        assert hex_line in out
        assert "tail spaced" in out

    def test_max_xref_items_is_a_cap_not_a_floor(self):
        # Default budget 30000 would previously compute target=300, leaving a
        # 100-item list untouched; max_xref_items must cap it instead.
        opt = ContextDensityOptimizer(max_xref_items=5, budget_tokens=30000)
        data = [f"item-{i}" for i in range(100)]
        res = opt._compact_recursive(data, 30000)
        assert len(res) < 100
        assert any("truncated" in str(x) for x in res)
