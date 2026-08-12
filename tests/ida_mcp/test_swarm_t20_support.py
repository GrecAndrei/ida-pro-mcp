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


def test_query_block_propagates_backend_truncation():
    """A capped blocks response surfaces truncated + total_matches instead of
    a silently-under-reported total (WO-Q1 promotion of the query DSL)."""
    ql = load_support_module("query_lang")
    ql._call_tool = lambda name, **kw: {
        "ok": True,
        "truncated": True,
        "blocks": (
            "0x1000-0x1004  succs=[0x1004]  preds=[0x1000]\n"
            "0x1004-0x1008  succs=[0x1008]  preds=[0x1004]"
        ),
    }
    res = ql.QueryExecutor()._execute_block(_block_plan())
    assert res["ok"] is True
    assert res["truncated"] is True
    assert res["total_matches"] == res["total"] == 2


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


def test_riscv_c_jr_ra_and_numeric_jalr_return_classification():
    """Register-indirect branches are returns only for the RA target (q01).

    ``c.jr ra`` returns while ``c.jr t0`` is an indirect jump; the numeric
    ``jalr x0, x1, 0`` form classifies identically to the ABI-name forms
    regardless of how IDA renders the operands (imm(rs1) vs rs1, imm).
    """
    au = load_support_module("arch_utils")
    # c.jr: RA-only return (ABI and numeric x1 names).
    assert au.is_return_mnemonic("c.jr", "c.jr ra", "riscv") is True
    assert au.is_return_mnemonic("c.jr", "c.jr x1", "riscv") is True
    assert au.is_return_mnemonic("c.jr", "c.jr t0", "riscv") is False
    assert au.is_return_mnemonic("c.jr", "c.jr a0", "riscv") is False
    # jalr: return only when rd==x0/zero AND rs1==ra/x1, in both operand shapes.
    for disasm in (
        "jalr zero, 0(ra)",
        "jalr x0, 0(x1)",
        "jalr zero, ra, 0",
        "jalr x0, x1, 0",
    ):
        assert au.is_return_mnemonic("jalr", disasm, "riscv") is True, disasm
    assert au.is_return_mnemonic("jalr", "jalr ra, 0(t0)", "riscv") is False
    assert au.is_return_mnemonic("jalr", "jalr x0, 0(t0)", "riscv") is False
    # c.jalr always links to ra — a call, never a return.
    assert au.is_return_mnemonic("c.jalr", "c.jalr ra", "riscv") is False
    assert au.is_call_mnemonic("c.jalr", "riscv") is True


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
        assert r2 == (True, None, False, {})
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


# ---------------------------------------------------------------------------
# arch_utils: RISC-V GP-relative ref re-pointing (headless set_gp)
#
# In idat the processor-option mechanism does not exist (9.3/9.4 live
# probes), so IDA decodes gp-relative loads/stores as o_displ(reg=GP) and
# creates data refs against an implicit GP of 0 — the raw displacement.
# _riscv_gp_fix_refs re-points those refs at GP + disp; these tests pin the
# scan semantics against scripted IDA modules.
# ---------------------------------------------------------------------------

O_DISPL = 2
O_VOID = 0
O_REG = 1


class _Op:
    def __init__(self, type_, reg=0, addr=0):
        self.type = type_
        self.reg = reg
        self.addr = addr


class _Insn:
    def __init__(self, mnem, ops):
        self._mnem = mnem
        self.ops = list(ops) + [_Op(O_VOID)] * (6 - len(ops))

    def get_canon_mnem(self):
        return self._mnem


class _InsnHolder:
    """Mutable insn slot: real decode_insn(insn, ea) mutates the passed
    insn in place, so the fake must copy scripted fields into it."""

    def __init__(self, src=None):
        if src is not None:
            self.ops = src.ops
            self._mnem = src._mnem
        else:
            self.ops = [_Op(O_VOID)] * 6
            self._mnem = ""

    def get_canon_mnem(self):
        return self._mnem


class _GpRefFixIda:
    """Scripted IDA fakes for _riscv_gp_fix_refs (9.4-style inf API)."""

    def __init__(self, insns, drefs, *, procname="riscv", bitness=64, seg_range=(0x0, 0x100), mapped=()):
        install_common_stub()
        self._insns = insns
        self._drefs = {ea: list(v) for ea, v in drefs.items()}
        self._seg_range = seg_range
        self._mapped = set(mapped) if mapped else set(range(*seg_range))
        self.del_calls = []
        self.add_calls = []

        ida_ida = types.ModuleType("ida_ida")
        ida_ida.inf_get_procname = lambda: procname
        ida_ida.inf_get_app_bitness = lambda: bitness
        sys.modules["ida_ida"] = ida_ida

        ida_idp = types.ModuleType("ida_idp")
        ida_idp.str2reg = lambda name: 3 if str(name).upper() == "GP" else 0
        sys.modules["ida_idp"] = ida_idp

        ida_xref = sys.modules.setdefault("ida_xref", types.ModuleType("ida_xref"))
        ida_xref.dr_R = 0
        ida_xref.dr_W = 1
        ida_xref.del_dref = self._del_dref
        ida_xref.add_dref = self._add_dref
        ida_xref.get_first_dref_from = self._first_dref
        ida_xref.get_next_dref_from = self._next_dref

        ida_ua = sys.modules["ida_ua"]
        ida_ua.insn_t = _InsnHolder

        def _decode(insn, ea):
            src = self._insns.get(ea)
            if src is None:
                return False
            insn.ops = src.ops
            insn._mnem = src._mnem
            return True
        ida_ua.decode_insn = _decode

        idc_ = sys.modules["idc"]
        idc_.BADADDR = -1
        idc_.next_head = lambda ea, end=-1: ea + 4

        seg = sys.modules["ida_segment"]
        seg.get_first_segment_ea = lambda: self._seg_range[0]
        seg.get_next_segment_ea = lambda ea: -1
        seg.getseg = lambda ea: (
            types.SimpleNamespace(start_ea=self._seg_range[0], end_ea=self._seg_range[1])
            if self._seg_range[0] <= ea < self._seg_range[1] else None
        )

    # -- xref plumbing -------------------------------------------------------
    def _first_dref(self, ea):
        return self._drefs.get(ea, [])[0] if self._drefs.get(ea) else -1

    def _next_dref(self, ea, cur):
        lst = self._drefs.get(ea, [])
        try:
            idx = lst.index(cur)
        except ValueError:
            return -1
        return lst[idx + 1] if idx + 1 < len(lst) else -1

    def _del_dref(self, frm, to):
        self.del_calls.append((frm, to))
        if frm in self._drefs and to in self._drefs[frm]:
            self._drefs[frm].remove(to)

    def _add_dref(self, frm, to, dtp):
        self.add_calls.append((frm, to, dtp))
        self._drefs.setdefault(frm, []).append(to)
        return True

    # -- convenience ----------------------------------------------------------


def _fix_ida(insns, drefs, **kw):
    fake = _GpRefFixIda(insns, drefs, **kw)
    fake.ida_xref = sys.modules["ida_xref"]
    fake.ida_segment = sys.modules["ida_segment"]
    return fake


def _gprel_insn(ea, mnem="ld", reg=3, disp=0xFFFFFFFF80000020):
    return {ea: _Insn(mnem, [_Op(O_REG, 13), _Op(O_DISPL, reg, disp)])}


def test_riscv_gp_fix_refs_repoints_stale_raw_refs():
    fake = _fix_ida(
        _gprel_insn(0x0, "ld") | _gprel_insn(0x4, "sd", disp=0xFFFFFFFF80000030),
        {0x0: [0xFFFFFFFF80000020], 0x4: [0xFFFFFFFF80000030]},
    )
    au = load_support_module("arch_utils")
    res = au._riscv_gp_fix_refs(0x80000020)
    assert res["fixed"] == 2, res
    # ld -> dr_R (0), sd -> dr_W (1), both re-pointed to GP + disp
    assert sorted(fake.add_calls) == sorted([
        (0x0, 0x40, 0), (0x4, 0x50, 1),
    ]), fake.add_calls
    # stale raw-target refs deleted
    assert sorted(fake.del_calls) == sorted([
        (0x0, 0xFFFFFFFF80000020), (0x4, 0xFFFFFFFF80000030),
    ]), fake.del_calls


def test_riscv_gp_fix_refs_skips_unmapped_targets():
    fake = _fix_ida(
        _gprel_insn(0x0),
        {0x0: [0xFFFFFFFF80000020]},
        seg_range=(0x0, 0x10),  # computed target 0x40 is outside
    )
    au = load_support_module("arch_utils")
    res = au._riscv_gp_fix_refs(0x80000020)
    assert res["fixed"] == 0, res
    assert res["skipped"] == 1, res
    assert fake.add_calls == []
    assert fake.del_calls == []


def test_riscv_gp_fix_refs_idempotent_when_correct_ref_exists():
    fake = _fix_ida(
        _gprel_insn(0x0),
        {0x0: [0x40]},  # already correct — GUI-style resolution
    )
    au = load_support_module("arch_utils")
    res = au._riscv_gp_fix_refs(0x80000020)
    assert res["fixed"] == 0, res
    assert fake.add_calls == []
    assert fake.del_calls == []


def test_riscv_gp_fix_refs_ignores_non_gp_operands():
    # sp-based displacement (reg=2) and plain x3 register operand (type=1)
    insns = {0x0: _Insn("c.sd", [_Op(O_REG, 1), _Op(O_DISPL, 2, 0x8)])}
    fake = _fix_ida(insns, {})
    au = load_support_module("arch_utils")
    res = au._riscv_gp_fix_refs(0x80000020)
    assert res["fixed"] == 0, res
    assert fake.add_calls == []
    assert fake.del_calls == []


def test_riscv_gp_fix_refs_cleans_previous_gp_refs():
    # refs from an earlier GP value (0x40) plus the plugin's raw ref
    fake = _fix_ida(
        _gprel_insn(0x0),
        {0x0: [0xFFFFFFFF80000020, 0x40]},
    )
    au = load_support_module("arch_utils")
    res = au._riscv_gp_fix_refs(0x80000000, old_gp=0x80000020)
    assert res["fixed"] == 1, res
    assert (0x0, 0x20, 0) in fake.add_calls, fake.add_calls
    assert (0x0, 0x40) in fake.del_calls, fake.del_calls   # stale old-gp ref
    assert (0x0, 0xFFFFFFFF80000020) in fake.del_calls, fake.del_calls  # raw ref


def test_riscv_gp_fix_refs_masks_to_xlen():
    fake = _fix_ida(
        _gprel_insn(0x0),
        {0x0: [0xFFFFFFFF80000020]},
        bitness=32,
    )
    au = load_support_module("arch_utils")
    res = au._riscv_gp_fix_refs(0x80000020)
    assert res["fixed"] == 1, res
    assert (0x0, 0x40, 0) in fake.add_calls, fake.add_calls


def test_riscv_gp_fix_refs_noop_on_non_riscv():
    fake = _fix_ida(_gprel_insn(0x0), {0x0: [0xFFFFFFFF80000020]}, procname="metapc")
    au = load_support_module("arch_utils")
    res = au._riscv_gp_fix_refs(0x80000020)
    assert res == {"fixed": 0, "skipped": 0}, res
    assert fake.add_calls == []
    assert fake.del_calls == []


def test_get_arch_uses_9_4_inf_api_when_structure_removed():
    # 9.4 removed idaapi.get_inf_structure; get_arch must fall back to
    # ida_ida.inf_get_procname/inf_get_app_bitness (probed live on 9.4).
    install_common_stub()
    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_procname = lambda: "riscv"
    ida_ida.inf_get_app_bitness = lambda: 64
    sys.modules["ida_ida"] = ida_ida
    assert not hasattr(sys.modules["idaapi"], "get_inf_structure")
    au = load_support_module("arch_utils")
    assert au.get_arch() == "riscv64"
    assert au.is_riscv_family() is True

    ida_ida.inf_get_procname = lambda: "metapc"
    ida_ida.inf_get_app_bitness = lambda: 32
    assert au.get_arch() == "x86"


def test_apply_riscv_gp_headless_path_uses_ref_fix():
    # No idc.set_processor_options and no verifiable directive (9.3/9.4 idat
    # probe: process_config_directive prints "Illegal keyword" for gp=):
    # applied must come from the ref-fix scan, and no reanalysis queued.
    _fix_ida(
        _gprel_insn(0x0),
        {0x0: [0xFFFFFFFF80000020]},
    )
    au = load_support_module("arch_utils")
    idaapi = sys.modules["idaapi"]
    netnode_calls = []

    class _NN:
        def altset(self, a, b):
            netnode_calls.append((a, b))

    idaapi.netnode = lambda *a, **k: _NN()
    sys.modules["ida_idp"].process_config_directive = lambda d: None  # rejects silently
    # Other tests in this file install idc.set_processor_options / ida_auto
    # on the same module objects — scrub them so this really is the headless
    # path (no directive, no reanalysis plumbing).
    idc_ = sys.modules["idc"]
    if hasattr(idc_, "set_processor_options"):
        delattr(idc_, "set_processor_options")
    sys.modules.pop("ida_auto", None)
    au._APPLIED_RISCV_GP = None
    try:
        applied, apply_error, reanalysis_queued, refs = au._apply_riscv_gp(0x80000020)
        assert applied is True, apply_error
        assert apply_error is None
        assert reanalysis_queued is False, "no reanalysis on the ref-fix path"
        assert refs["fixed"] == 1, refs
        assert (1, 0x80000020) in netnode_calls, netnode_calls  # persisted
        assert au._APPLIED_RISCV_GP == 0x80000020
        # memoized repeat: no second scan / no second netnode write
        applied2, _, queued2, refs2 = au._apply_riscv_gp(0x80000020)
        assert applied2 is True and queued2 is False
        assert refs2 == {}
        assert len(netnode_calls) == 1
    finally:
        au._APPLIED_RISCV_GP = None
