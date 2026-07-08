"""Regression: the IDA-side analysis helpers must detect the "loader finished
but ``.text`` was never analyzed" failure mode and surface it as a
reanalysis that actually creates real functions.

The bug surfaced against ``libidmservicemgr.so`` (Android NDK arm64-v8a
stripped library). The ELF loader creates 8-byte PLT stubs for the
dynamic symbols but never enqueues work for ``.text``. After
``idapro.open_database(run_auto_analysis=True)`` + ``ida_auto.auto_wait()``
the queue is empty, ``analysis_complete`` reports True, and
``defined_code_bytes == 0`` for the 1.5 MB ``.text`` segment. From the
host's point of view the IDB is "fully analyzed" but it actually
contains nothing useful.

The fix:
1. ``_auto_reanalyze_text_segments`` walks executable segments, skips
   PLT/INIT/FINI/GOT/small trampolines, and schedules
   ``ida_auto.plan_range`` for each. Returns a dict with the
   before/after coverage so the caller can see the upgrade.
2. ``_ensure_entry_point_functions`` creates functions for any ELF
   entry point the auto-analyzer missed (e.g. JNI exports).
3. ``analysis(action='state')`` reports ``analysis_complete`` so
   the host/MCP caller can detect incomplete analysis and trigger
   a reanalysis.

These tests are unit tests with the IDA SDK mocked out — no real IDA
process required. They pin the contract for ``.text`` reanalysis.

Implementation note: the helpers live in
``ida_pro_mcp.ida_mcp.tools.analysis`` and importing that module triggers
the full tool import chain (``zeromcp``, ``ida_kernwin``, etc.). The tests
extract the helper source verbatim into a stand-alone test module so they
run without booting the rest of the tool layer. This is brittle if the
helpers change shape, but the existing test suite follows the same pattern
(e.g. ``test_var_rename_hints_no_hex_leak.py``).
"""
from __future__ import annotations

import os
import sys
import textwrap
import time
from unittest.mock import MagicMock

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


_HELPERS_SRC = textwrap.dedent('''
    _BADADDR = 0xFFFFFFFFFFFFFFFF

    _SKIP_SEGMENT_NAMES = {
        ".plt", ".plt.got", ".plt.sec", ".plt.bnd",
        ".init", ".fini", ".init_array", ".fini_array",
        ".plt_indirect", ".plt_resolve",
        ".got", ".got.plt", ".got.off", ".got.sec",
    }


    def _segment_code_score(seg, idaapi, ida_bytes, idc):
        """Return (defined_code_bytes, total_code_bytes, code_head_count)."""
        defined = 0
        total = 0
        heads = 0
        if seg is None:
            return 0, 0, 0
        try:
            if not (seg.perm & idaapi.SEGPERM_EXEC):
                return 0, 0, 0
        except Exception:
            return 0, 0, 0
        total = int(seg.end_ea) - int(seg.start_ea)
        if total <= 0:
            return 0, 0, 0
        head = int(seg.start_ea)
        end_ea = int(seg.end_ea)
        while head < end_ea:
            try:
                flags = ida_bytes.get_flags(head)
            except Exception:
                break
            try:
                if ida_bytes.is_code(flags):
                    defined += int(idc.get_item_size(head))
                    heads += 1
            except Exception:
                pass
            try:
                nxt = idc.next_head(head, end_ea)
            except Exception:
                break
            if nxt == idaapi.BADADDR or nxt <= head:
                break
            head = int(nxt)
        return defined, total, heads


    def _find_text_segments(idaapi, idautils, ida_segment):
        """Return [(start, end, name), ...] for segments to re-analyze."""
        out = []
        seen = set()
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg:
                continue
            try:
                if not (seg.perm & idaapi.SEGPERM_EXEC):
                    continue
            except Exception:
                continue
            s = int(seg.start_ea)
            e = int(seg.end_ea)
            if e - s < 0x100:
                continue
            name = ""
            try:
                name = ida_segment.get_segm_name(seg)
            except Exception:
                name = ""
            if name in _SKIP_SEGMENT_NAMES:
                continue
            key = (s, e)
            if key in seen:
                continue
            seen.add(key)
            out.append((s, e, name))
        out.sort(key=lambda t: t[0])
        return out


    def _auto_reanalyze_text_segments(
        wait_seconds,
        *,
        idaapi,
        idautils,
        ida_bytes,
        idc,
        ida_segment,
        ida_funcs,
        ida_auto,
        time_mod,
        log,
    ):
        ranges = _find_text_segments(idaapi, idautils, ida_segment)
        before_funcs = 0
        before_defined = 0
        before_total = 0
        try:
            before_funcs = int(idaapi.get_func_qty())
        except Exception:
            pass
        for s, e, _name in ranges:
            try:
                d, t, _h = _segment_code_score(idaapi.getseg(s), idaapi, ida_bytes, idc)
                before_defined += d
                before_total += t
            except Exception:
                pass
        scheduled = 0
        for s, e, _name in ranges:
            try:
                if hasattr(ida_auto, "plan_range"):
                    ida_auto.plan_range(s, e)
                elif hasattr(ida_auto, "auto_mark_range"):
                    ida_auto.auto_mark_range(s, e, getattr(ida_auto, "AU_FINAL", 0))
                elif hasattr(idaapi, "auto_mark_range"):
                    idaapi.auto_mark_range(s, e, idaapi.AU_FINAL)
                else:
                    continue
                scheduled += 1
            except Exception:
                continue
        waited = 0.0
        started = time_mod.time()
        if scheduled > 0 and wait_seconds > 0:
            try:
                if hasattr(ida_auto, "auto_wait"):
                    ida_auto.auto_wait()
                waited = time_mod.time() - started
            except Exception:
                waited = time_mod.time() - started
        after_funcs = 0
        after_defined = 0
        after_total = 0
        after_heads = 0
        try:
            after_funcs = int(idaapi.get_func_qty())
        except Exception:
            pass
        for s, e, _name in ranges:
            try:
                d, t, h = _segment_code_score(idaapi.getseg(s), idaapi, ida_bytes, idc)
                after_defined += d
                after_total += t
                after_heads += h
            except Exception:
                pass
        coverage_before = (
            round(before_defined / before_total * 100, 2) if before_total else 0.0
        )
        coverage_after = (
            round(after_defined / after_total * 100, 2) if after_total else 0.0
        )
        eligible = [
            {"start": hex(s), "end": hex(e), "name": name}
            for s, e, name in ranges
        ]
        return {
            "eligible_ranges": eligible,
            "scheduled": scheduled,
            "functions_before": before_funcs,
            "functions_after": after_funcs,
            "functions_added": max(0, after_funcs - before_funcs),
            "defined_code_bytes_before": before_defined,
            "defined_code_bytes_after": after_defined,
            "total_code_bytes": after_total,
            "code_heads_after": after_heads,
            "coverage_pct_before": coverage_before,
            "coverage_pct_after": coverage_after,
            "waited_seconds": round(waited, 2),
            "reanalysis_triggered": (
                after_funcs > before_funcs or after_defined > before_defined
            ),
        }


    def _entry_point_addrs(ida_entry, idaapi):
        out = set()
        try:
            qty = int(ida_entry.get_entry_qty())
            for i in range(qty):
                ord_val = ida_entry.get_entry_ordinal(i)
                ea = int(ida_entry.get_entry(ord_val))
                if ea and ea != idaapi.BADADDR:
                    out.add(ea)
        except Exception:
            pass
        return sorted(out)


    def _ensure_entry_point_functions(
        *,
        ida_entry,
        idaapi,
        ida_funcs,
    ):
        created = []
        skipped = []
        failed = []
        for ea in _entry_point_addrs(ida_entry, idaapi):
            try:
                if idaapi.get_func(ea):
                    skipped.append(hex(ea))
                    continue
                ok = False
                try:
                    ok = bool(ida_funcs.add_func(ea))
                except Exception:
                    ok = False
                if ok:
                    created.append(hex(ea))
                else:
                    failed.append(hex(ea))
            except Exception:
                failed.append(hex(ea))
        return {
            "entry_points_total": len(created) + len(skipped) + len(failed),
            "created": created,
            "skipped_already_func": skipped,
            "failed": failed,
        }
''')


def _build_namespace():
    """Build a namespace with the IDA SDK stubs so the helpers can run."""
    import types
    ns: dict = {"__name__": "fake_analysis_module"}
    # IDA SDK stubs
    idaapi = types.SimpleNamespace(
        BADADDR=0xFFFFFFFFFFFFFFFF,
        SEGPERM_EXEC=4,
        AU_NONE=0,
        AU_FINAL=0,
        f_BIN=0,
        f_BINARY=0,
        f_BIN_FTYPE=0,
        plan_range=lambda *a, **k: None,
        auto_mark_range=lambda *a, **k: None,
        get_func=lambda _ea: None,
        get_func_qty=lambda: 0,
        getseg=lambda _ea: None,
        auto_is_ok=lambda: True,
        get_auto_state=lambda: 0,
        get_strlist_qty=lambda: 0,
    )
    idautils = types.SimpleNamespace(
        Segments=lambda: iter([]),
        Functions=lambda: iter([]),
    )
    ida_bytes = types.SimpleNamespace(
        get_flags=lambda _ea: 0,
        is_code=lambda _f: False,
        is_data=lambda _f: False,
        get_wide_dword=lambda _ea: 0,
        get_bytes=lambda *a, **k: b"",
    )
    idc = types.SimpleNamespace(
        get_item_size=lambda _ea: 4,
        next_head=lambda ea, _e: ea + 4,
        get_cmt=lambda *a, **k: "",
        get_func_name=lambda _ea: "",
        set_name=lambda *a, **k: True,
        get_bookmark=lambda _i: 0xFFFFFFFFFFFFFFFF,
        get_bookmark_desc=lambda _i: "",
        create_insn=lambda _ea: 4,
        split_sreg_range=lambda *a, **k: True,
        SR_auto=2,
    )
    ida_segment = types.SimpleNamespace(
        getseg=lambda _ea: None,
        get_segm_name=lambda _s: "",
        set_segm_class=lambda *a, **k: None,
        update_segm=lambda _s: None,
    )
    ida_funcs = types.SimpleNamespace(
        add_func=lambda *a, **k: True,
        get_func=lambda _ea: None,
        update_func=lambda _f: None,
    )
    ida_auto = types.SimpleNamespace(
        plan_range=lambda *a, **k: None,
        auto_mark_range=lambda *a, **k: None,
        auto_wait=lambda: None,
        AU_FINAL=0,
    )
    ida_entry = types.SimpleNamespace(
        get_entry_qty=lambda: 0,
        get_entry_ordinal=lambda _i: 0,
        get_entry=lambda _o: 0,
        get_entry_name=lambda _o: "",
    )
    time_mod = types.SimpleNamespace(time=time.time)
    log = types.SimpleNamespace(info=lambda *a, **k: None, debug=lambda *a, **k: None)

    ns.update(
        idaapi=idaapi,
        idautils=idautils,
        ida_bytes=ida_bytes,
        idc=idc,
        ida_segment=ida_segment,
        ida_funcs=ida_funcs,
        ida_auto=ida_auto,
        ida_entry=ida_entry,
        time_mod=time_mod,
        log=log,
    )

    exec(compile(_HELPERS_SRC, "<analysis.py:helpers>", "exec"), ns)
    return ns


_NS = _build_namespace()

# Pull the helper functions out of the namespace.
_SKIP_SEGMENT_NAMES = _NS["_SKIP_SEGMENT_NAMES"]
_find_text_segments = _NS["_find_text_segments"]
_auto_reanalyze_text_segments = _NS["_auto_reanalyze_text_segments"]
_ensure_entry_point_functions = _NS["_ensure_entry_point_functions"]
_entry_point_addrs = _NS["_entry_point_addrs"]
_segment_code_score = _NS["_segment_code_score"]


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


class _Seg:
    """Mock segment with the attributes the helpers actually read."""
    def __init__(self, start, end, name, perm):
        self.start_ea = start
        self.end_ea = end
        self.size = end - start
        self.perm = perm
        self.name = name


def _make_getseg(segmap):
    """Return a getseg-like function for a {ea: seg} map."""

    def getseg(ea):
        return segmap.get(ea)

    return getseg


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_skip_segment_names_includes_plt_and_got():
    """PLT / INIT / FINI / GOT variants must all be in the skip set."""
    required = {".plt", ".init", ".fini", ".got", ".got.plt", ".init_array", ".fini_array"}
    missing = required - _SKIP_SEGMENT_NAMES
    assert not missing, f"missing skip entries: {missing}"


def test_find_text_segments_skips_plt_and_tiny_trampolines():
    """``.plt`` and small (<0x100 bytes) LOAD trampolines are excluded."""
    segmap = {
        0x0: _Seg(0x0, 0x35070, "LOAD", 4),       # huge exec, kept
        0x35070: _Seg(0x35070, 0x35EB0, ".plt", 4),  # skipped by name
        0x35EB0: _Seg(0x35EB0, 0x35EC0, "LOAD", 4),  # 16 bytes, skipped
        0x35EC0: _Seg(0x35EC0, 0x1A1980, ".text", 4),  # real .text, kept
        0x1A1980: _Seg(0x1A1980, 0x1D0CD9, ".rodata", 1),  # r only, not exec
        0x1D0CD9: _Seg(0x1D0CD9, 0x1D0CDC, "LOAD", 4),  # 3 bytes, skipped
    }
    idaapi = _NS["idaapi"]
    idautils = _NS["idautils"]
    ida_segment = _NS["ida_segment"]
    getseg = _make_getseg(segmap)

    idautils.Segments = lambda: iter(segmap.keys())
    idaapi.getseg = getseg
    # Wire get_segm_name through the segmap's name attribute
    ida_segment.get_segm_name = lambda s: s.name

    ranges = _find_text_segments(idaapi, idautils, ida_segment)

    starts = [r[0] for r in ranges]
    names = [r[2] for r in ranges]

    # .plt is excluded
    assert 0x35070 not in starts, f".plt should be skipped: {ranges}"
    # 16-byte trampoline excluded
    assert 0x35EB0 not in starts, f"16-byte trampoline should be skipped: {ranges}"
    # .rodata excluded (not exec)
    assert 0x1A1980 not in starts, f".rodata is r-only, should be skipped: {ranges}"
    # 3-byte LOAD trampoline excluded
    assert 0x1D0CD9 not in starts, f"3-byte LOAD should be skipped: {ranges}"
    # .text is kept
    assert 0x35EC0 in starts, f".text must be kept: {ranges}"
    # The huge first LOAD (0x0-0x35070, has EXEC) is kept
    assert 0x0 in starts, f"big first LOAD must be kept: {ranges}"

    # Results are sorted by start address
    assert starts == sorted(starts), f"ranges must be sorted: {ranges}"
    # Names returned for each range
    assert ".text" in names
    # No .plt in the returned names
    assert ".plt" not in names


def test_auto_reanalyze_text_segments_schedules_per_range():
    """Each eligible range gets a plan_range call; entry points get funcs."""
    segmap = {
        0x35EC0: _Seg(0x35EC0, 0x1A1980, ".text", 4),
        0x0: _Seg(0x0, 0x35070, "LOAD", 4),
    }
    idaapi = _NS["idaapi"]
    idautils = _NS["idautils"]
    ida_segment = _NS["ida_segment"]
    ida_bytes = _NS["ida_bytes"]
    idc = _NS["idc"]
    ida_funcs = _NS["ida_funcs"]
    ida_auto = _NS["ida_auto"]
    time_mod = _NS["time_mod"]
    log = _NS["log"]

    idautils.Segments = lambda: iter(segmap.keys())
    idaapi.getseg = _make_getseg(segmap)
    ida_segment.get_segm_name = lambda s: s.name

    plan_calls = []
    def fake_plan(s, e):
        plan_calls.append((s, e))
    ida_auto.plan_range = fake_plan

    # Simulate the work landing: bump func count after plan_range.
    _state = {"fc": 219}

    def fake_auto_wait():
        # Simulate that 8846 functions got created
        _state["fc"] = 9065

    def fake_get_func_qty():
        return _state["fc"]

    ida_auto.auto_wait = fake_auto_wait
    idaapi.get_func_qty = fake_get_func_qty

    result = _auto_reanalyze_text_segments(
        wait_seconds=0.1,
        idaapi=idaapi,
        idautils=idautils,
        ida_bytes=ida_bytes,
        idc=idc,
        ida_segment=ida_segment,
        ida_funcs=ida_funcs,
        ida_auto=ida_auto,
        time_mod=time_mod,
        log=log,
    )

    # Two eligible ranges were scheduled
    assert len(plan_calls) == 2, f"expected 2 plan_range calls, got {plan_calls}"
    assert (0x35EC0, 0x1A1980) in plan_calls
    assert (0x0, 0x35070) in plan_calls

    # Returned metadata reflects the upgrade
    assert result["scheduled"] == 2
    assert result["functions_before"] == 219
    assert result["functions_after"] == 9065
    assert result["functions_added"] == 9065 - 219
    assert result["reanalysis_triggered"] is True
    # coverage_pct_after is computed from the segment sizes; pre was 0
    assert result["coverage_pct_before"] == 0.0
    assert result["coverage_pct_after"] >= 0.0
    # Eligible ranges are reported
    assert "eligible_ranges" in result
    assert len(result["eligible_ranges"]) == 2
    assert result["eligible_ranges"][0]["name"] == "LOAD"
    assert result["eligible_ranges"][1]["name"] == ".text"


def test_auto_reanalyze_text_segments_handles_no_eligible_ranges():
    """If there are no eligible segments, no plan_range calls happen."""
    idaapi = _NS["idaapi"]
    idautils = _NS["idautils"]
    ida_segment = _NS["ida_segment"]
    ida_bytes = _NS["ida_bytes"]
    idc = _NS["idc"]
    ida_funcs = _NS["ida_funcs"]
    ida_auto = _NS["ida_auto"]
    time_mod = _NS["time_mod"]
    log = _NS["log"]

    idautils.Segments = lambda: iter([])
    idaapi.getseg = lambda _ea: None
    idaapi.get_func_qty = lambda: 0

    plan_calls = []
    ida_auto.plan_range = lambda *a, **k: plan_calls.append(a)

    result = _auto_reanalyze_text_segments(
        wait_seconds=0.0,
        idaapi=idaapi,
        idautils=idautils,
        ida_bytes=ida_bytes,
        idc=idc,
        ida_segment=ida_segment,
        ida_funcs=ida_funcs,
        ida_auto=ida_auto,
        time_mod=time_mod,
        log=log,
    )

    assert result["scheduled"] == 0
    assert result["functions_before"] == 0
    assert result["functions_after"] == 0
    assert result["reanalysis_triggered"] is False
    assert result["eligible_ranges"] == []
    assert plan_calls == []


def test_ensure_entry_point_functions_creates_missing():
    """Entry points that don't have a function yet must get one."""
    idaapi = _NS["idaapi"]
    ida_entry = _NS["ida_entry"]
    ida_funcs = _NS["ida_funcs"]

    # Use list-backed state so multiple calls return the right value.
    ordinals_iter = iter([0, 1, 2])
    entries_iter = iter([0x39E60, 0x431F4, 0x3BAD0])

    ida_entry.get_entry_qty = lambda: 3
    ida_entry.get_entry_ordinal = lambda _i: next(ordinals_iter)
    ida_entry.get_entry = lambda _o: next(entries_iter)
    idaapi.get_func = lambda _ea: None

    add_func_calls = []
    def fake_add_func(ea, *args, **kwargs):
        add_func_calls.append(ea)
        return True
    ida_funcs.add_func = fake_add_func

    result = _ensure_entry_point_functions(
        ida_entry=ida_entry, idaapi=idaapi, ida_funcs=ida_funcs
    )

    # _entry_point_addrs sorts the deduped EAs ascending; add_func calls
    # follow that sort order.
    assert add_func_calls == [0x39E60, 0x3BAD0, 0x431F4]
    assert result["entry_points_total"] == 3
    assert result["created"] == [hex(0x39E60), hex(0x3BAD0), hex(0x431F4)]
    assert result["skipped_already_func"] == []
    assert result["failed"] == []


def test_ensure_entry_point_functions_skips_existing():
    """Entry points that already have a function are not re-created."""
    idaapi = _NS["idaapi"]
    ida_entry = _NS["ida_entry"]
    ida_funcs = _NS["ida_funcs"]

    existing_func = MagicMock()
    existing_func.start_ea = 0x39E60

    ida_entry.get_entry_qty = lambda: 1
    ida_entry.get_entry_ordinal = lambda _i: 0
    ida_entry.get_entry = lambda _o: 0x39E60
    idaapi.get_func = lambda _ea: existing_func

    add_func_calls = []
    ida_funcs.add_func = lambda *a, **k: add_func_calls.append(a) or True

    result = _ensure_entry_point_functions(
        ida_entry=ida_entry, idaapi=idaapi, ida_funcs=ida_funcs
    )

    assert result["created"] == []
    assert result["skipped_already_func"] == [hex(0x39E60)]
    assert add_func_calls == []


def test_ensure_entry_point_functions_records_failures():
    """A failed add_func must be reported in 'failed', not 'created'."""
    idaapi = _NS["idaapi"]
    ida_entry = _NS["ida_entry"]
    ida_funcs = _NS["ida_funcs"]

    ida_entry.get_entry_qty = lambda: 1
    ida_entry.get_entry_ordinal = lambda _i: 0
    ida_entry.get_entry = lambda _o: 0x39E60
    idaapi.get_func = lambda _ea: None
    ida_funcs.add_func = lambda *a, **k: False

    result = _ensure_entry_point_functions(
        ida_entry=ida_entry, idaapi=idaapi, ida_funcs=ida_funcs
    )

    assert result["created"] == []
    assert result["failed"] == [hex(0x39E60)]


def test_entry_point_addrs_dedupes_and_sorts():
    """Duplicate entry EAs collapse; result is sorted ascending."""
    idaapi = _NS["idaapi"]
    ida_entry = _NS["ida_entry"]

    ida_entry.get_entry_qty = lambda: 4
    ida_entry.get_entry_ordinal = lambda i: [0, 1, 2, 3][i]
    ida_entry.get_entry = lambda o: [0x431F4, 0x39E60, 0x431F4, 0x3BAD0][o]

    addrs = _entry_point_addrs(ida_entry, idaapi)

    assert addrs == [0x39E60, 0x3BAD0, 0x431F4]


def test_segment_code_score_skips_non_exec_segments():
    """A segment without SEGPERM_EXEC must score 0/0/0 even if huge."""
    idaapi = _NS["idaapi"]
    ida_bytes = _NS["ida_bytes"]
    idc = _NS["idc"]

    # .rodata: large but read-only
    rodata = _Seg(0x1A1980, 0x1D0CD9, ".rodata", 1)  # SEGPERM_READ=1, no EXEC
    d, t, h = _segment_code_score(rodata, idaapi, ida_bytes, idc)
    assert d == 0
    assert t == 0
    assert h == 0


def test_segment_code_score_counts_code_heads():
    """Defined bytes = sum of get_item_size() for code heads."""
    idaapi = _NS["idaapi"]
    ida_bytes = _NS["ida_bytes"]
    idc = _NS["idc"]

    text = _Seg(0x1000, 0x2000, ".text", 4)

    # Simulate 4 code heads of size 4 each (16 bytes total)
    code_heads = {0x1000, 0x1004, 0x1008, 0x100C}
    sizes = dict.fromkeys(code_heads, 4)

    def fake_get_flags(ea):
        return 0x40000 if ea in code_heads else 0  # MS_CODE bit

    def fake_is_code(flags):
        return bool(flags & 0x40000)

    def fake_get_item_size(ea):
        return sizes.get(ea, 4)

    heads = []
    def fake_next_head(ea, end):
        next_ea = ea + 4
        if next_ea >= end:
            return idaapi.BADADDR
        heads.append(next_ea)
        return next_ea

    ida_bytes.get_flags = fake_get_flags
    ida_bytes.is_code = fake_is_code
    idc.get_item_size = fake_get_item_size
    idc.next_head = fake_next_head

    d, t, h = _segment_code_score(text, idaapi, ida_bytes, idc)

    # Total: 0x2000 - 0x1000 = 0x1000
    assert t == 0x1000
    # Defined: 4 heads × 4 bytes = 16
    assert d == 16
    assert h == 4
