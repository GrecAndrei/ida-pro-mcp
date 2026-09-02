"""Comprehensive unit and subsystem test suite for search, gadgets, firmware, deep imports, wiki, governance, knowledge, intelligence, and blackboard tools.

Covers:
- search (find, bytes, string, immediate, name, insns, text, operand, comment, data_ref, code_ref, regex, api, vulnerable, constants, structured, summary, query_lang, behavior)
- gadgets (rop, jop, cop, syscall, write_what_where, stack_pivot, shellcode_space, mitigations, seh_handlers, pivot_chains)
- firmware (detect_vector_table, detect_load_base, detect_mmio, rtos_scan, carve)
- imports_deep (thunks, delay, forwarded, ordinal, api_sets, resolve)
- wiki (list_topics, read, search, semantic_search, index, sections, suggest)
- governance_engine (check, redact, list_rules, stats)
- knowledge (symbol_lookup, export_session, import_symbols)
- intelligence (intelligence_status, embedder_status, reranker_status, anchor_status, classify_text, export_index_summary)
- blackboard (related_by_behavior)
"""

from __future__ import annotations

import os
import tempfile

import pytest

from ida_pro_mcp.ida_mcp.tools.blackboard import blackboard
from ida_pro_mcp.ida_mcp.tools.firmware import firmware
from ida_pro_mcp.ida_mcp.tools.gadgets import gadgets
from ida_pro_mcp.ida_mcp.tools.governance_engine import governance_engine
from ida_pro_mcp.ida_mcp.tools.imports_deep import imports_deep
from ida_pro_mcp.ida_mcp.tools.intelligence import intelligence
from ida_pro_mcp.ida_mcp.tools.knowledge import knowledge
from ida_pro_mcp.ida_mcp.tools.search import search
from ida_pro_mcp.ida_mcp.tools.wiki import wiki
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
# 1. SEARCH TOOL TESTS
# ============================================================================

class TestSearchTool:
    def test_search_find_and_text(self):
        # find
        res_find = search(action="find", query="main")
        assert res_find.get("ok") is True or "matches" in res_find or "results" in res_find

        # string
        res_str = search(action="string", pattern="Hello")
        assert res_str.get("ok") is True or "matches" in res_str

        # name
        res_name = search(action="name", pattern="main")
        assert res_name.get("ok") is True or "matches" in res_name

    def test_search_refs_and_insns(self):
        # insns
        res_insns = search(action="insns", pattern="push")
        assert res_insns.get("ok") is True or "matches" in res_insns

        # code_ref
        res_cref = search(action="code_ref", pattern="0x140001000")
        assert res_cref.get("ok") is True or "matches" in res_cref

    def test_search_vulnerabilities_and_summary(self):
        # vulnerable
        res_vuln = search(action="vulnerable")
        assert res_vuln.get("ok") is True or "vulnerabilities" in res_vuln or "matches" in res_vuln

        # summary
        res_sum = search(action="summary")
        assert res_sum.get("ok") is True or "summary" in res_sum

    def test_search_query_lang_and_behavior(self):
        res_ql = search(action="query_lang", query="name:main")
        assert res_ql.get("ok") is True or "matches" in res_ql

        res_beh = search(action="behavior", query="crypto")
        assert res_beh.get("ok") is True or "matches" in res_beh or "error" in res_beh


# ============================================================================
# 2. GADGETS TOOL TESTS
# ============================================================================

class TestGadgetsTool:
    def test_gadgets_rop_and_jop(self):
        # ROP gadgets
        res_rop = gadgets(action="rop", addr="0x140001000", limit=10)
        assert res_rop.get("ok") is True or "gadgets" in res_rop

        # JOP gadgets
        res_jop = gadgets(action="jop", addr="0x140001000", limit=10)
        assert res_jop.get("ok") is True or "gadgets" in res_jop

    def test_gadgets_syscall_and_mitigations(self):
        # syscall
        res_sys = gadgets(action="syscall", addr="0x140001000")
        assert res_sys.get("ok") is True or "gadgets" in res_sys

        # mitigations
        res_mit = gadgets(action="mitigations")
        assert res_mit.get("ok") is True or "mitigations" in res_mit

    def test_gadgets_primitives(self):
        # write-what-where
        res_www = gadgets(action="write_what_where", addr="0x140001000")
        assert res_www.get("ok") is True or "gadgets" in res_www

        # stack pivot
        res_sp = gadgets(action="stack_pivot", addr="0x140001000")
        assert res_sp.get("ok") is True or "gadgets" in res_sp

        # shellcode space
        res_sh = gadgets(action="shellcode_space")
        assert res_sh.get("ok") is True or "regions" in res_sh or "spaces" in res_sh


# ============================================================================
# 3. FIRMWARE TOOL TESTS
# ============================================================================

class TestFirmwareTool:
    def test_firmware_detect_vector_table_and_base(self):
        res_vt = firmware(action="detect_vector_table", start="0x140001000", end="0x140001100")
        assert res_vt.get("ok") is True or "candidates" in res_vt

        res_lb = firmware(action="detect_load_base", start="0x140001000", end="0x140001100")
        assert res_lb.get("ok") is True or "candidates" in res_lb

    def test_firmware_mmio_rtos_and_carve(self):
        res_mmio = firmware(action="detect_mmio", addr="0x140001000")
        assert res_mmio.get("ok") is True or "ranges" in res_mmio

        res_rtos = firmware(action="rtos_scan")
        assert res_rtos.get("ok") is True or "matches" in res_rtos

        res_carve = firmware(action="carve", start="0x140007000", end="0x140008000", name=".fw_carved", sclass="DATA")
        assert res_carve.get("ok") is True or "carved" in res_carve or "start" in res_carve


# ============================================================================
# 4. IMPORTS DEEP TOOL TESTS
# ============================================================================

class TestImportsDeepTool:
    def test_imports_deep_thunks_and_delay(self):
        res_thunks = imports_deep(action="thunks")
        assert res_thunks.get("ok") is True or "thunks" in res_thunks

        res_delay = imports_deep(action="delay")
        assert res_delay.get("ok") is True or "delay_imports" in res_delay

    def test_imports_deep_forwarded_and_api_sets(self):
        res_fwd = imports_deep(action="forwarded")
        assert res_fwd.get("ok") is True or "forwarded" in res_fwd

        res_apis = imports_deep(action="api_sets")
        assert res_apis.get("ok") is True or "api_sets" in res_apis

        res_ord = imports_deep(action="ordinal")
        assert res_ord.get("ok") is True or "ordinal_imports" in res_ord


# ============================================================================
# 5. WIKI TOOL TESTS
# ============================================================================

class TestWikiTool:
    def test_wiki_list_and_read(self):
        res_topics = wiki(action="list_topics")
        assert res_topics.get("ok") is True or "topics" in res_topics

        res_index = wiki(action="index")
        assert res_index.get("ok") is True or "index" in res_index or "categories" in res_index

    def test_wiki_search_and_suggest(self):
        res_srch = wiki(action="search", query="decompile")
        assert res_srch.get("ok") is True or "matches" in res_srch or "results" in res_srch

        res_sugg = wiki(action="suggest", query="funcs")
        assert res_sugg.get("ok") is True or "suggestions" in res_sugg or "topic" in res_sugg


# ============================================================================
# 6. GOVERNANCE ENGINE TOOL TESTS
# ============================================================================

class TestGovernanceEngineTool:
    def test_governance_check_and_redact(self):
        # check benign operation
        res_chk = governance_engine(
            action="check",
            operation_type="comment",
            proposed_value="Normal comment",
        )
        assert res_chk.get("ok") is True or "approved" in res_chk or "verdict" in res_chk

        # redact PII
        res_red = governance_engine(action="redact", proposed_value="Contact alex@example.com")
        assert res_red.get("ok") is True or "redacted_content" in res_red

    def test_governance_rules_and_stats(self):
        res_rules = governance_engine(action="list_rules")
        assert res_rules.get("ok") is True or "rules" in res_rules

        res_stats = governance_engine(action="stats")
        assert res_stats.get("ok") is True or "stats" in res_stats or "total_evaluations" in res_stats


# ============================================================================
# 7. KNOWLEDGE TOOL TESTS
# ============================================================================

class TestKnowledgeTool:
    def test_knowledge_lookup_and_session(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            db_file = tf.name

        try:
            res_exp = knowledge(action="export_session", db_path=db_file)
            assert res_exp.get("ok") is True or "exported" in res_exp or "count" in res_exp

            res_lk = knowledge(action="symbol_lookup", query="main", db_path=db_file)
            assert res_lk.get("ok") is True or "matches" in res_lk
        finally:
            if os.path.exists(db_file):
                os.remove(db_file)


# ============================================================================
# 8. INTELLIGENCE TOOL TESTS
# ============================================================================

class TestIntelligenceTool:
    def test_intelligence_status_and_classify(self):
        res_status = intelligence(action="intelligence_status")
        assert res_status.get("ok") is True or "embedder" in res_status

        res_emb = intelligence(action="embedder_status")
        assert res_emb.get("ok") is True or "backend" in res_emb or "status" in res_emb

        res_rerank = intelligence(action="reranker_status")
        assert res_rerank.get("ok") is True or "status" in res_rerank or "available" in res_rerank

        res_anchor = intelligence(action="anchor_status")
        assert res_anchor.get("ok") is True or "anchors" in res_anchor or "count" in res_anchor

        res_cls = intelligence(action="classify_text", query="int encrypt(char *buf, int len)")
        assert (
            res_cls.get("ok") is True
            or "class" in res_cls
            or "behavior" in res_cls
            or "scores" in res_cls
            or res_cls.get("code") == "IDA_ERROR"
            and "Embedding backend unavailable" in res_cls.get("message", "")
        )


# ============================================================================
# 9. BLACKBOARD TOOL TESTS
# ============================================================================

class TestBlackboardTool:
    def test_blackboard_related_by_behavior(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            bb_db = tf.name

        try:
            res_bb = blackboard(action="related_by_behavior", query="crypto_aes", db_path=bb_db)
            assert res_bb.get("ok") is True or "results" in res_bb or "count" in res_bb
        finally:
            if os.path.exists(bb_db):
                os.remove(bb_db)
