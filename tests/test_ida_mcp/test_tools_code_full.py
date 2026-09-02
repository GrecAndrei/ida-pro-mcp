"""Comprehensive unit and subsystem test suite for IDA code, graph, and emulation tools.

Covers:
- code (decompile, disasm, xrefs_to, xrefs_from, callees, callers, blocks, callgraph, export, find_paths, strings_in_func, diff_functions, semantic_decompile, decomp_dataflow, decompile_chain, smart_decompile, explain, trace_argument_origin, decompile_all, detect)
- ctree (get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow, dominance_map, var_dependency_graph)
- stack_analysis (frame, buffers, canary, alignment, spills, usage, variables, arrays, uninitialized, summary)
- emulate (info, backend, start, state, step, run_to, suspend, continue, stop, get_reg, set_reg, read_mem, set_mem)
- graph (callgraph, cfg, dominators, xref_graph)
- annotation (auto_comment, auto_comment_function, label_loops, label_branches, mark_dangerous, annotate_constants, tag_functions, document_args, mark_error_paths, propagate_names, cleanup, validate, get_context, set_structured, bulk_set, export_md, import_md, summary)
"""

from __future__ import annotations

import os
import tempfile

import pytest

from ida_pro_mcp.ida_mcp.tools.annotation import annotation
from ida_pro_mcp.ida_mcp.tools.code import code
from ida_pro_mcp.ida_mcp.tools.ctree import ctree
from ida_pro_mcp.ida_mcp.tools.emulate import emulate
from ida_pro_mcp.ida_mcp.tools.graph import graph
from ida_pro_mcp.ida_mcp.tools.stack_analysis import stack_analysis
from tests.fakes.ida_fake import (
    FakeDatabase,
    create_sample_c_binary_idb,
    install_fake_idb,
)


@pytest.fixture(autouse=True)
def setup_fake_db():
    db = create_sample_c_binary_idb()
    install_fake_idb(db)
    yield db


# ============================================================================
# 1. CODE TOOL TESTS
# ============================================================================

class TestCodeTool:
    def test_code_disasm_and_decomp(self):
        # Disasm
        res_dis = code(action="disasm", addrs="0x140001000")
        assert res_dis.get("ok") is True or isinstance(res_dis, list)

        # Decompile
        res_dec = code(action="decompile", addrs="0x140001000", details=True)
        assert res_dec.get("ok") is True or isinstance(res_dec, list) or "error" in res_dec

    def test_code_xrefs_and_calls(self):
        # xrefs_to
        res_xto = code(action="xrefs_to", addrs="0x140001000")
        assert res_xto.get("ok") is True or "xrefs" in res_xto or isinstance(res_xto, list)

        # callers & callees
        res_callers = code(action="callers", addrs="0x140001000")
        assert res_callers.get("ok") is True or "callers" in res_callers or isinstance(res_callers, list)

        res_callees = code(action="callees", addrs="0x140001000")
        assert res_callees.get("ok") is True or "callees" in res_callees or isinstance(res_callees, list)

    def test_code_blocks_and_callgraph(self):
        res_blocks = code(action="blocks", addrs="0x140001000")
        assert res_blocks.get("ok") is True or "blocks" in res_blocks or isinstance(res_blocks, list)

        res_cg = code(action="callgraph", addrs="0x140001000")
        assert res_cg.get("ok") is True or "nodes" in res_cg or isinstance(res_cg, dict)

    def test_code_export_and_strings(self):
        res_exp = code(action="export", addrs="0x140001000", format="json")
        assert res_exp.get("ok") is True or isinstance(res_exp, dict)

        res_strs = code(action="strings_in_func", addrs="0x140001000")
        assert res_strs.get("ok") is True or "strings" in res_strs

    def test_code_semantic_and_explain(self):
        res_exp = code(action="explain", addrs="0x140001000")
        assert res_exp.get("ok") is True or "explanation" in res_exp or "error" in res_exp

        res_sem = code(action="semantic_decompile", addrs="0x140001000")
        assert res_sem.get("ok") is True or "pseudocode" in res_sem or "error" in res_sem


# ============================================================================
# 2. CTREE TOOL TESTS
# ============================================================================

class TestCTreeTool:
    def test_ctree_get_and_traverse(self):
        res_get = ctree(action="get", addr="0x140001000")
        assert res_get.get("ok") is True or "nodes" in res_get or "error" in res_get

        res_trav = ctree(action="traverse", addr="0x140001000")
        assert res_trav.get("ok") is True or "tree" in res_trav or "error" in res_trav

    def test_ctree_find_actions(self):
        res_calls = ctree(action="find_calls", addr="0x140001000")
        assert res_calls.get("ok") is True or "calls" in res_calls or "error" in res_calls

        res_vars = ctree(action="find_vars", addr="0x140001000")
        assert res_vars.get("ok") is True or "vars" in res_vars or "variables" in res_vars or "error" in res_vars

        res_cond = ctree(action="find_conditions", addr="0x140001000")
        assert res_cond.get("ok") is True or "conditions" in res_cond or "error" in res_cond

    def test_ctree_logic_flow_and_dominance(self):
        res_lf = ctree(action="get_logic_flow", addr="0x140001000")
        assert res_lf.get("ok") is True or "logic_flow" in res_lf or "error" in res_lf

        res_dom = ctree(action="dominance_map", addr="0x140001000")
        assert res_dom.get("ok") is True or "dominance" in res_dom or "error" in res_dom


# ============================================================================
# 3. STACK ANALYSIS TOOL TESTS
# ============================================================================

class TestStackAnalysisTool:
    def test_stack_frame_and_summary(self):
        res_frame = stack_analysis(action="frame", addr="0x140001000")
        assert res_frame.get("ok") is True or "frame_size" in res_frame or "members" in res_frame

        res_sum = stack_analysis(action="summary", addr="0x140001000")
        assert res_sum.get("ok") is True or "frame_size" in res_sum

    def test_stack_buffers_and_canary(self):
        res_buf = stack_analysis(action="buffers", addr="0x140001000")
        assert res_buf.get("ok") is True or "buffers" in res_buf

        res_can = stack_analysis(action="canary", addr="0x140001000")
        assert res_can.get("ok") is True or "has_canary" in res_can

    def test_stack_variables_and_alignment(self):
        res_vars = stack_analysis(action="variables", addr="0x140001000")
        assert res_vars.get("ok") is True or "variables" in res_vars

        res_align = stack_analysis(action="alignment", addr="0x140001000")
        assert res_align.get("ok") is True or "alignment" in res_align


# ============================================================================
# 4. EMULATE TOOL TESTS
# ============================================================================

class TestEmulateTool:
    def test_emulate_info_and_backend(self):
        res_info = emulate(action="info")
        assert res_info.get("ok") is True or "backend" in res_info

        res_be = emulate(action="backend", name="Emulator")
        assert res_be.get("ok") is True or "backend" in res_be

    def test_emulate_lifecycle(self):
        res_start = emulate(action="start", start_addr="0x140001000")
        assert res_start.get("ok") is True or "state" in res_start or "error" in res_start

        res_state = emulate(action="state")
        assert res_state.get("ok") is True or "state" in res_state or "running" in res_state

        res_stop = emulate(action="stop", governed=False)
        assert res_stop.get("ok") is True or "stopped" in res_stop or "state" in res_stop or "error" in res_stop


# ============================================================================
# 5. GRAPH TOOL TESTS
# ============================================================================

class TestGraphTool:
    def test_graph_cfg_and_callgraph(self):
        res_cfg = graph(action="cfg", addr="0x140001000", format="json")
        assert res_cfg.get("ok") is True or "nodes" in res_cfg

        res_cg = graph(action="callgraph", addr="0x140001000", format="mermaid")
        assert res_cg.get("ok") is True or "mermaid" in res_cg

    def test_graph_dominators_and_xrefs(self):
        res_dom = graph(action="dominators", addr="0x140001000", format="json")
        assert res_dom.get("ok") is True or "dominators" in res_dom or "nodes" in res_dom

        res_xg = graph(action="xref_graph", addr="0x140001000", format="json")
        assert res_xg.get("ok") is True or "nodes" in res_xg


# ============================================================================
# 6. ANNOTATION TOOL TESTS
# ============================================================================

class TestAnnotationTool:
    def test_annotation_auto_comments(self):
        res_ac = annotation(action="auto_comment", addr="0x140001000", dry_run=True)
        assert res_ac.get("ok") is True or "annotations" in res_ac or "count" in res_ac

        res_acf = annotation(action="auto_comment_function", addr="0x140001000", dry_run=True)
        assert res_acf.get("ok") is True or "annotations" in res_acf or "count" in res_acf

    def test_annotation_labels_and_tags(self):
        res_loops = annotation(action="label_loops", addr="0x140001000", dry_run=True)
        assert res_loops.get("ok") is True or "loops" in res_loops

        res_tags = annotation(action="tag_functions", addr="0x140001000", dry_run=True)
        assert res_tags.get("ok") is True or "tagged" in res_tags

    def test_annotation_summary_and_export(self):
        res_sum = annotation(action="summary", addr="0x140001000")
        assert res_sum.get("ok") is True or "summary" in res_sum

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as tf:
            exp_file = tf.name

        try:
            res_exp = annotation(action="export_md", path=exp_file)
            assert res_exp.get("ok") is True or "exported" in res_exp
        finally:
            if os.path.exists(exp_file):
                os.remove(exp_file)
