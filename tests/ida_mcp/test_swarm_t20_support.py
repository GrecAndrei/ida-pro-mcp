"""Regression tests for swarm/t20_support findings.

Covers five support-module findings:
1. query_lang._execute_block hardcoded addr='0x0' and ignored the query
   identifier, then matched conditions over a compact string (silent empty or
   AttributeError) instead of per-block dicts.
2. arch_utils RETURN_MNEMONICS over-classified register-indirect branches
   (bx/jr/jalr/c.jr/c.jalr) as returns regardless of target register, while
   the operand-aware is_return_mnemonic() is the correct classifier.
3. taint_registry.DANGEROUS_SINKS / TAINT_SOURCES omitted the Windows A/W
   macro variants, which consumers match case-sensitively against raw symbols.
4. semantic_matching._subword_tokens lowercased before the camel-boundary
   regex ran, making camelCase subword splitting dead code.
5. arch_utils._apply_riscv_gp queued a full-address-space reanalysis and
   blocked on auto_wait() inside an RPC request, re-triggering on every
   RISC-V disasm; now memoized and non-blocking.

Host-side tests: ida_* modules are stubbed; no live IDA session required.
"""

from __future__ import annotations

import sys
import types

from tests._isolated_repo_loader import install_common_stub, load_support_module

# ---------------------------------------------------------------------------
# query_lang: _execute_block identifier + block normalization
# ---------------------------------------------------------------------------

def _block_plan(identifier="0x401000", conditions=None):
    return {
        "target": "block", "identifier": identifier,
        "conditions": conditions or [], "limit": 100,
        "sort_key": None, "sort_order": "ASC", "group_key": None,
    }


def test_query_block_uses_identifier_as_addr_and_normalizes_blocks():
    ql = load_support_module("query_lang")
    calls = []
    ql._call_tool = lambda name, **kw: calls.append((name, kw)) or {
        "ok": True,
        "blocks": (
            "0x1000-0x1004  succs=[0x1004]  preds=[0x1000]\n"
            "0x1004-0x1008  succs=[0x1008]  preds=[0x1004]"
        ),
    }
    plan = _block_plan(conditions=[{"key": "addr", "op": "==", "value": "0x1000-0x1004"}])
    res = ql.QueryExecutor()._execute_block(plan)
    assert calls[0][1]["addr"] == "0x401000"  # the identifier, not '0x0'
    assert res["ok"] is True
    assert res["returned"] == 1
    assert res["results"][0]["addr"] == "0x1000-0x1004"
    assert res["results"][0]["succs"] == "0x1004"
    assert res["results"][0]["preds"] == "0x1000"


def test_query_block_star_requires_a_function_address():
    ql = load_support_module("query_lang")
    res = ql.QueryExecutor()._execute_block(_block_plan(identifier="*"))
    assert res.get("error") is True
    assert res.get("code") == "INVALID_ARGS"


def test_query_block_surfaces_tool_error_instead_of_silent_empty():
    ql = load_support_module("query_lang")
    ql._call_tool = lambda name, **kw: {
        "error": True, "code": "FUNCTION_NOT_FOUND",
        "message": "No function at 0x401000",
    }
    res = ql.QueryExecutor()._execute_block(_block_plan())
    assert res.get("error") is True
    assert res.get("code") == "FUNCTION_NOT_FOUND"


# ---------------------------------------------------------------------------
# arch_utils: mnemonic-set over-classification
# ---------------------------------------------------------------------------

def test_register_indirect_branches_not_in_return_mnemonics():
    au = load_support_module("arch_utils")
    for m in ("bx", "jr", "jalr", "c.jr", "c.jalr"):
        assert m not in au.RETURN_MNEMONICS, m
    # Actual return mnemonics remain.
    for m in ("ret", "retn", "blr", "retl", "rts", "rte", "rtd"):
        assert m in au.RETURN_MNEMONICS, m


def test_register_indirect_branches_still_unconditional_jumps_and_terminators():
    au = load_support_module("arch_utils")
    # They unconditionally transfer control, so they belong to the jump set
    # and must remain block terminators (no fall-through).
    for m in ("bx", "jr", "jalr", "c.jr", "c.jalr", "br"):
        assert m in au.UNCONDITIONAL_JUMP_MNEMONICS, m
        assert m in au.TERMINATOR_MNEMONICS, m
    assert "ba" in au.UNCONDITIONAL_JUMP_MNEMONICS  # PowerPC branch-always


def test_is_return_mnemonic_stays_operand_aware():
    au = load_support_module("arch_utils")
    assert au.is_return_mnemonic("bx", "bx lr", "arm") is True
    assert au.is_return_mnemonic("bx", "bx r0", "arm") is False
    assert au.is_return_mnemonic("jr", "jr $ra", "mips") is True
    assert au.is_return_mnemonic("jr", "jr t9", "mips") is False
    assert au.is_return_mnemonic("jalr", "jalr zero, 0(ra)", "riscv") is True


# ---------------------------------------------------------------------------
# arch_utils: RISC-V GP apply — memoized + non-blocking reanalysis
# ---------------------------------------------------------------------------

def _stub_riscv_gp_ida():
    """Install idc/idaapi/ida_auto fakes that record apply + reanalysis calls."""
    install_common_stub()
    idc_ = sys.modules["idc"]
    set_calls = []
    idc_.set_processor_options = set_calls.append
    idc_.INF_MIN_EA = 0
    idc_.INF_MAX_EA = 1
    idc_.get_inf_attr = lambda attr: {0: 0x1000, 1: 0x2000}.get(attr, 0)

    class _Netnode:
        def altset(self, a, b):
            pass

    sys.modules["idaapi"].netnode = lambda *a, **k: _Netnode()

    ida_auto = types.ModuleType("ida_auto")
    plan_calls = []
    wait_calls = []
    ida_auto.plan_range = lambda a, b: plan_calls.append((a, b))
    ida_auto.auto_mark_range = lambda a, b, c: plan_calls.append(("mark", a, b))
    ida_auto.AU_FINAL = 1
    ida_auto.auto_wait = lambda: wait_calls.append(1)
    sys.modules["ida_auto"] = ida_auto
    return set_calls, plan_calls, wait_calls


def test_apply_riscv_gp_memoized_and_does_not_auto_wait():
    au = load_support_module("arch_utils")
    set_calls, plan_calls, wait_calls = _stub_riscv_gp_ida()
    au._APPLIED_RISCV_GP = None
    try:
        r1 = au._apply_riscv_gp(0x1234)
        assert r1[0] is True
        assert r1[2] is True  # reanalysis queued
        assert len(set_calls) == 1
        assert len(plan_calls) == 1
        assert len(wait_calls) == 0, "must not block on auto_wait() in an RPC"

        # Same GP value: nothing re-applied / re-queued.
        r2 = au._apply_riscv_gp(0x1234)
        assert r2 == (True, None, False)
        assert len(set_calls) == 1
        assert len(plan_calls) == 1

        # A different GP value re-applies.
        r3 = au._apply_riscv_gp(0x5678)
        assert r3[0] is True
        assert len(set_calls) == 2
        assert len(plan_calls) == 2
    finally:
        sys.modules.pop("ida_auto", None)


# ---------------------------------------------------------------------------
# taint_registry: Windows A/W variants
# ---------------------------------------------------------------------------

def test_dangerous_sinks_include_aw_variants():
    t = load_support_module("taint_registry")
    for name in ("ShellExecuteA", "ShellExecuteW", "CreateProcessA",
                 "CreateProcessW", "lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW"):
        assert name in t.DANGEROUS_SINKS, name
    assert t.DANGEROUS_SINKS["ShellExecuteA"] == "command_injection"
    assert t.DANGEROUS_SINKS["CreateProcessW"] == "command_injection"
    assert t.DANGEROUS_SINKS["lstrcpyW"] == "buffer_overflow"
    # Derived name set stays in sync with the sink dict.
    assert set(t.DANGEROUS_SINK_NAMES) == set(t.DANGEROUS_SINKS)


def test_taint_sources_include_aw_variants():
    t = load_support_module("taint_registry")
    for name in ("RegQueryValueExA", "RegQueryValueExW",
                 "GetEnvironmentVariableA", "GetEnvironmentVariableW",
                 "URLDownloadToFileA", "URLDownloadToFileW"):
        assert name in t.TAINT_SOURCES, name


# ---------------------------------------------------------------------------
# semantic_matching: camelCase subword tokenization is no longer dead code
# ---------------------------------------------------------------------------

def test_subword_tokens_split_camel_case():
    sm = load_support_module("semantic_matching")
    assert sm._subword_tokens("getProcAddress") == ["get", "proc", "address"]
    assert sm._subword_tokens("VirtualAlloc") == ["virtual", "alloc"]
    assert sm.semantic_tokens("URLDownloadToFile") == ["urldownload", "to", "file"]
    # snake_case and plain lowercase are unaffected.
    assert sm._subword_tokens("getenv_s") == ["getenv"]
    assert sm._subword_tokens("fixture_entry") == ["fixture", "entry"]


def test_camel_split_improves_mixed_case_cheap_score():
    sm = load_support_module("semantic_matching")
    # 'procAddress' is a subword of 'getProcAddress' now that camel boundaries
    # are honored; with lowercasing-first the pair would score 0.0.
    assert sm.semantic_score_cheap("procAddress", "getProcAddress") > 0.0
    assert sm.semantic_score_cheap("getProcAddress", "procAddress") > 0.0
