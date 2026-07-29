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
