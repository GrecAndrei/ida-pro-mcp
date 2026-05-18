from pathlib import Path
import pytest


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


@pytest.mark.parametrize(
    "action,needles",
    [
        ("trace_start", ['elif action == "trace_start"', "output_file", "max_insns"]),
        ("trace_stop", ['elif action == "trace_stop"', "insn_count", "trace_file"]),
        ("trace_read", ['elif action == "trace_read"', "entries", "limit"]),
        ("mem_diff", ['elif action == "mem_diff"', "changed_offsets", "change_count"]),
    ],
)
def test_debug_new_actions_have_three_contract_markers(action, needles):
    src = _read("src/ida_pro_mcp/ida_mcp/tools/debug.py")
    for n in needles:
        assert n in src, f"{action} missing marker: {n}"


@pytest.mark.parametrize(
    "action,needles",
    [
        ("nl", ['elif action in ("nl", "nl_batch")', "min_confidence", "results"]),
        ("nl_batch", ['if action == "nl_batch"', "matched_queries", "deduplicate"]),
    ],
)
def test_query_new_actions_have_three_contract_markers(action, needles):
    src = _read("src/ida_pro_mcp/ida_mcp/tools/query.py")
    for n in needles:
        assert n in src, f"{action} missing marker: {n}"


@pytest.mark.parametrize(
    "action,needles",
    [
        ("infer", ['elif action == "infer"', '"inferred_types"', '"applied"']),
        ("read_struct", ['elif action == "read_struct"', '"fields"', "Struct range exceeds mapped segment bounds"]),
        ("propagate", ['elif action == "propagate"', '"propagated_to"', '"skipped"']),
    ],
)
def test_types_goal_actions_have_three_contract_markers(action, needles):
    src = _read("src/ida_pro_mcp/ida_mcp/tools/types.py")
    for n in needles:
        assert n in src, f"{action} missing marker: {n}"


@pytest.mark.parametrize(
    "action,needles",
    [
        ("find_clones", ['elif action == "find_clones"', '"clones"', '"similarity"']),
        ("changelog", ['elif action == "changelog"', '"added_apis"', '"string_delta"']),
        ("blocks_cfg", ['elif action == "blocks"', '"cfg_edit_distance"', '"structural_match_pct"']),
    ],
)
def test_compare_goal_actions_have_three_contract_markers(action, needles):
    src = _read("src/ida_pro_mcp/ida_mcp/tools/compare.py")
    for n in needles:
        assert n in src, f"{action} missing marker: {n}"


@pytest.mark.parametrize(
    "signal",
    [
        '"sanitized_by"',
        '"interprocedural_findings"',
        '"reachability_only"',
    ],
)
def test_taint_goal_signals_present(signal):
    src = _read("src/ida_pro_mcp/ida_mcp/tools/taint.py")
    assert signal in src


def test_query_nl_batch_preserves_previous_matched_queries_on_score_replacement():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/query.py")
    assert "prev_queries = list(cur.get(\"matched_queries\", []))" in src
    assert "list(dict.fromkeys(prev_queries + [str(qitem)]))" in src


def test_query_unknown_action_hint_lists_nl_actions():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/query.py")
    assert "nl, nl_batch" in src


def test_debug_trace_start_reports_active_trace_file_when_already_running():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/debug.py")
    assert "\"already_running\": True" in src
    assert "active_path = str(getattr(active_fh, \"name\", \"\") or \"\")" in src


def test_debug_trace_start_creates_output_directory_and_validates_max_insns():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/debug.py")
    assert "os.makedirs(out_dir, exist_ok=True)" in src
    assert "max_insns must be > 0" in src


def test_debug_del_bp_unhooks_conditional_hook_when_no_conditions_left():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/debug.py")
    assert "if not _BP_CONDITIONS and _BP_HOOK is not None" in src
    assert "_BP_HOOK.unhook()" in src


def test_query_nl_and_nl_batch_clamp_min_confidence():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/query.py")
    assert "def _normalize_conf(raw, default=0.25):" in src
    assert "return max(0.0, min(1.0, float(val)))" in src


def test_query_nl_batch_returns_failed_queries_and_min_confidence():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/query.py")
    assert "\"failed_queries\": failed_queries" in src
    assert "\"min_confidence\": min_conf" in src


def test_debug_trace_read_validates_and_caps_limit():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/debug.py")
    assert "limit must be > 0" in src
    assert "lim = min(lim, 5000)" in src


def test_debug_mem_diff_reports_baseline_creation():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/debug.py")
    assert "out[\"baseline_created\"] = True" in src


def test_types_read_struct_defines_struct_size_and_full_range_check():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/types.py")
    assert "struct_size = int(tif.get_size())" in src
    assert "if not _is_fully_mapped(ea, struct_size):" in src


def test_types_infer_heap_object_uses_allocator_calls_not_operand_size():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/types.py")
    assert "\"allocator_calls\"" in src
    assert "idc.get_operand_value(head, 0)" not in src


def test_query_min_confidence_normalization_preserves_zero():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/query.py")
    assert "def _normalize_conf(raw, default=0.25):" in src
    assert "val = default if raw is None else float(raw)" in src


def test_classify_anchor_coverage_honors_small_limits():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/classify.py")
    assert "max_funcs = max(1, int(limit))" in src


def test_debug_mem_diff_has_size_cap_and_snapshot_eviction():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/debug.py")
    assert "_MAX_MEM_DIFF_SPAN = 0x10000" in src
    assert "_MAX_MEM_DIFF_SNAPSHOTS = 128" in src
    assert "size too large (max" in src
    assert "if len(_MEM_DIFF_SNAPSHOTS) > _MAX_MEM_DIFF_SNAPSHOTS" in src


def test_debug_add_bp_exposes_idc_condition_language():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/debug.py")
    assert "idc_condition = kwargs.get(\"idc_condition\")" in src
    assert "\"condition_language\": \"idc\" if bp_cond else None" in src


def test_static_trace_eval_expr_marks_idc_language():
    src = _read("src/ida_pro_mcp/ida_mcp/tools/static_trace.py")
    assert "\"language\": \"idc\"" in src
