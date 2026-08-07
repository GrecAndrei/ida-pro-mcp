"""Tests for ContextDensityOptimizer and information density calculations."""

from ida_pro_mcp.host.analysis.context_density import (
    ContextDensityOptimizer,
    compact_response,
    measure_information_density,
)


def test_measure_information_density_returns_valid_metrics():
    text = "sub_401000: mov eax, [ebp+8]; ret"
    metrics = measure_information_density(text)

    assert "estimated_tokens" in metrics
    assert "useful_token_ratio" in metrics
    assert metrics["useful_token_ratio"] > 0
    assert 0 <= metrics["density_score"] <= 1.0


def test_compress_code_blocks_truncates_long_blocks():
    opt = ContextDensityOptimizer(max_code_preview=2)
    code = "```c\nline1\nline2\nline3\nline4\nline5\n```"
    compacted = opt.compress_code_blocks(code)

    assert "more lines" in compacted
    assert "line1" in compacted
    assert "line2" in compacted
    assert "line5" not in compacted


def test_compact_response_preserves_short_data():
    opt = ContextDensityOptimizer(compact_threshold=1000, budget_tokens=100)
    data = {"status": "ok", "addr": "0x401000"}
    res = opt.compact_response(data)

    assert res == data


def test_strip_xml_tags():
    opt = ContextDensityOptimizer()
    assert opt.strip_xml_tags("<tool_use>hello</tool_use> world") == "hello world"
    assert opt.strip_xml_tags("no tags") == "no tags"
    assert opt.strip_xml_tags(42) == 42


def test_compress_hex_dumps_truncates_long_blocks():
    opt = ContextDensityOptimizer(max_hex_preview=2)
    lines = [
        "  0x401000  de ad be ef 01 02 03 04  ff 00 11 22",
        "  0x401010  00 11 22 33 44 55 66 77  88 99 aa bb",
        "  0x401020  ff ee dd cc bb aa 99 88  77 66 55 44",
        "  0x401030  11 22 33 44 55 66 77 88  99 aa bb cc",
        "after",
    ]
    text = "\n".join(lines)
    compacted = opt.compress_hex_dumps(text)
    assert "0x401000" in compacted
    assert "truncated" in compacted
    assert "0x401030" in compacted  # last line kept as tail
    assert "after" in compacted


def test_compress_hex_dumps_keeps_short_blocks():
    opt = ContextDensityOptimizer(max_hex_preview=3)
    lines = ["  0x401000  de ad be ef 01 02 03 04", "  0x401010  00 11 22 33 44 55 66 77"]
    compacted = opt.compress_hex_dumps("\n".join(lines))
    assert compacted == "\n".join(lines)


def test_compress_xref_lists_string():
    opt = ContextDensityOptimizer(max_xref_items=2)
    xrefs = "xrefs: 0x401000, 0x401100, 0x402000, 0x500000"
    compacted = opt.compress_xref_lists(xrefs)
    assert "0x401000, 0x401100" in compacted
    assert "more" in compacted
    assert "groups:" in compacted


def test_compress_xref_lists_list_of_strings():
    opt = ContextDensityOptimizer(max_xref_items=2)
    xrefs = ["0x401000", "0x401100", "0x402000", "0x500000"]
    compacted = opt.compress_xref_lists(xrefs)
    assert compacted[:2] == xrefs[:2]
    assert "2 more xrefs" in compacted[-1]
    assert "groups:" in compacted[-1]


def test_compress_xref_lists_recursive_dict_and_short_list():
    opt = ContextDensityOptimizer(max_xref_items=5)
    obj = {"key": ["0x401000", "0x401100"], "nested": {"items": ["0x402000"]}}
    assert opt.compress_xref_lists(obj) == obj
    assert opt.compress_xref_lists([]) == []


def test_addr_to_segment_buckets():
    opt = ContextDensityOptimizer()
    cases = {
        "0x800": "below_0x1000",
        "0x70000": "0x1000-0xfffff",
        "0x150000": "0x100000-0x1fffff",
        "0x250000": "0x200000-0x2fffff",
        "0x350000": "0x300000-0x3fffff",
        "0x500000": "above_0x400000",
    }
    for addr, expected in cases.items():
        assert opt._addr_to_segment(addr) == expected
    assert opt._addr_to_segment("garbage") == "unknown"


def test_compact_response_respects_budget_and_preserves_keys():
    opt = ContextDensityOptimizer(max_xref_items=2, compact_threshold=10_000, budget_tokens=1000)
    big_list = [f"0x401{i:03d}" for i in range(100)]
    data = {"status": "ok", "addr": "0x401000", "xrefs": big_list}
    res = opt.compact_response(data, budget_tokens=200)
    assert res["status"] == "ok"
    assert res["addr"] == "0x401000"
    assert len(res["xrefs"]) < len(big_list)
    assert any("truncated" in str(x) for x in res["xrefs"])


def test_compact_response_skips_small_data():
    opt = ContextDensityOptimizer(compact_threshold=10_000, budget_tokens=10_000)
    data = {"status": "ok", "addr": "0x401000"}
    assert opt.compact_response(data) == data


def test_compact_string_applies_line_and_whitespace_rules():
    opt = ContextDensityOptimizer(max_line_length=20)
    text = "short line\n" + "x" * 40 + "\n\n\n   spaced    out  "
    compacted = opt._compact_string(text)
    lines = compacted.split("\n")
    assert lines[0] == "short line"
    assert lines[1].endswith("...")
    assert len(lines[1]) <= 20
    assert "\n\n\n" not in compacted
    assert "  " not in compacted


def test_compact_recursive_truncates_very_long_lists():
    opt = ContextDensityOptimizer(max_xref_items=3, budget_tokens=300)
    data = [f"item-{i}" for i in range(40)]
    res = opt._compact_recursive(data, 300)
    assert len(res) < 40
    assert any("truncated" in str(x) for x in res)


def test_optimize_legacy_shim():
    opt = ContextDensityOptimizer(budget_tokens=1000)
    result = opt.optimize("hello world " * 100, context_label="disasm")
    assert result["ok"] is True
    assert result["context_label"] == "disasm"
    assert result["compression_ratio"] >= 1.0
    assert "info_density_before" in result
    assert "info_density_after" in result

    empty = opt.optimize("")
    assert empty["compacted"] == ""
    assert empty["compression_ratio"] == 1.0


def test_measure_information_density_edge_cases():
    opt = ContextDensityOptimizer()
    empty = opt.measure_information_density("")
    assert empty["estimated_tokens"] == 0
    assert empty["density_score"] == 0.0
    whitespace = opt.measure_information_density("   \n  ")
    assert whitespace["estimated_tokens"] >= 1
    dense = opt.measure_information_density("sub_401000 mov eax, [rbp+8] ret")
    assert dense["useful_token_ratio"] > 0.5
