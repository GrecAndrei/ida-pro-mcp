from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_query_contract_includes_nl_batch_and_min_confidence():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/query.py")
    assert '"nl_batch"' in src
    assert "min_confidence" in src
    assert 'action in ("nl", "nl_batch")' in src


def test_debug_contract_includes_trace_and_mem_diff_actions():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/debug.py")
    assert '"trace_start"' in src
    assert '"trace_stop"' in src
    assert '"trace_read"' in src
    assert '"mem_diff"' in src
    assert "_MAX_REG_SNAPSHOTS = 50" in src


def test_debug_conditional_breakpoint_hook_present():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/debug.py")
    assert "class _BreakpointHooks" in src
    assert "dbg_bpt" in src
    assert "_BP_CONDITIONS" in src
    assert "idc.eval_idc" in src


def test_compare_contract_has_changelog_and_find_clones_shapes():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/compare.py")
    assert '"added_apis"' in src
    assert '"removed_apis"' in src
    assert '"string_delta"' in src
    assert '"clones"' in src
    assert '"similarity"' in src


def test_compare_blocks_contract_has_cfg_edit_metrics():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/compare.py")
    assert '"cfg_edit_distance"' in src
    assert '"added_blocks"' in src
    assert '"removed_blocks"' in src
    assert '"structural_match_pct"' in src


def test_taint_contract_has_sanitizer_and_interprocedural_fields():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/taint.py")
    assert '"sanitized_by"' in src
    assert '"interprocedural_findings"' in src
    assert '"reachability_only"' in src


def test_types_contract_has_inferred_types_and_propagation_shape():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/types.py")
    assert '"inferred_types"' in src
    assert '"confidence"' in src
    assert '"applied"' in src
    assert '"propagated_to"' in src
    assert '"skipped"' in src
    assert '"fields"' in src


def test_intelligence_contract_has_anchor_coverage_and_thresholds():
    src = _read("src/ida_pro_mcp/host/intelligence.py")
    assert "def anchor_coverage_report" in src
    assert "ANCHOR_MIN_CONFIDENCE" in src
    assert "min_thr = max" in src


def test_classify_and_schema_expose_anchor_coverage():
    csrc = _read("src/ida_pro_mcp/ida_mcp/tools/classify.py")
    ssrc = _read("src/ida_pro_mcp/host/schemas.py")
    assert '"anchor_coverage"' in csrc
    assert '"anchor_coverage"' in ssrc


def test_nav_semantic_goto_uses_embeddings_path():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/nav.py")
    assert "FunctionEmbeddingIndex" in src
    assert "BgeCodeEmbedder" in src
    assert "matched_by" in src

