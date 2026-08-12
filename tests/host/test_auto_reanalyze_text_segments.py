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
exec the *live* helper source sliced out of ``analysis.py`` at import time
(see ``_extract_helpers_src``), so they run without booting the rest of the
tool layer while still exercising the shipped code — a frozen copy of the
helpers drifted from production and let these tests pass against stale
logic.
"""
from __future__ import annotations

import ast
import importlib.util
import os
import time
from unittest.mock import MagicMock


def _analysis_helpers_path() -> str:
    """Locate the installed analysis.py without importing the IDA tool chain."""
    spec = importlib.util.find_spec("ida_pro_mcp")
    if spec is None or not spec.submodule_search_locations:
        raise RuntimeError("could not resolve the installed ida_pro_mcp package")
    root = spec.submodule_search_locations[0]
    return os.path.join(root, "ida_mcp", "tools", "analysis.py")


def _extract_helpers_src() -> str:
    """Slice the live helper source out of production analysis.py.

    The helpers run inside IDA's SDK, so importing the module in a plain
    pytest process is impossible.  Instead of a hand-maintained frozen copy,
    exec the actual production source: any change to analysis.py is then
    exercised by these tests immediately (no drift window).
    """
    analysis_path = _analysis_helpers_path()
    with open(analysis_path, encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src)
    helper_names = {
        "_SKIP_SEGMENT_NAMES",
        "_segment_code_score",
        "_find_text_segments",
        "_auto_reanalyze_text_segments",
        "_entry_point_addrs",
        "_ensure_entry_point_functions",
    }
    spans: list[tuple[int, int]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = node.name
        elif isinstance(node, ast.Assign):
            name = next((t.id for t in node.targets if isinstance(t, ast.Name)), None)
        else:
            name = None
        if name in helper_names:
            spans.append((node.lineno, getattr(node, "end_lineno", node.lineno)))
    if len(spans) != len(helper_names):
        raise RuntimeError(
            f"could not locate all analysis helpers in {analysis_path}: found {spans}"
        )
    lines = src.splitlines()
    body = "\n".join(lines[min(s[0] for s in spans) - 1 : max(s[1] for s in spans)])
    # The helpers import IDA SDK modules from the running interpreter; in the
    # test namespace those resolve to the stubs built by _build_namespace.
    # Fail loudly if production changes these lines so the test is updated
    # with the shape change instead of silently passing stale logic.
    for old, new in (
        (
            "    import idc as _idc\n",
            "    _idc = globals()['idc']  # bound from test namespace\n",
        ),
        (
            "    import ida_auto as _ida_auto\n",
            "    _ida_auto = globals()['ida_auto']  # bound from test namespace\n",
        ),
        (
            "    import ida_funcs\n",
            "    ida_funcs = globals()['ida_funcs']  # bound from test namespace\n",
        ),
    ):
        if old not in body:
            raise RuntimeError(
                f"analysis.py helper shape changed; expected `{old.strip()}` "
                f"inside the sliced helpers of {analysis_path}"
            )
        body = body.replace(old, new)
    return body


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
        getseg=lambda _ea: idaapi.getseg(_ea),  # noqa: PLW0108 - defers to per-test override
        get_segm_name=lambda _s: "",
        set_segm_class=lambda *a, **k: None,
        update_segm=lambda _s: None,
    )
    # The sliced helpers call the compat shim (EA-based get_segment_name on
    # 9.4, get_segm_name(getseg(ea)) on <=9.3). Mirror the legacy fallback
    # against the namespace's own ida_segment stubs.
    _compat = types.SimpleNamespace(
        get_segment_name=lambda ea: ida_segment.get_segm_name(ida_segment.getseg(ea)),
        get_func_start=lambda ea: (
            idaapi.get_func(ea).start_ea if idaapi.get_func(ea) else None
        ),
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

    ns.update(
        time=time,
        idaapi=idaapi,
        idautils=idautils,
        ida_bytes=ida_bytes,
        idc=idc,
        ida_segment=ida_segment,
        ida_funcs=ida_funcs,
        ida_auto=ida_auto,
        ida_entry=ida_entry,
        _compat=_compat,
    )

    exec(compile(_extract_helpers_src(), "<analysis.py:helpers>", "exec"), ns)
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

    ranges = _find_text_segments()

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
    ida_auto = _NS["ida_auto"]

    idautils.Segments = lambda: iter(segmap.keys())
    idaapi.getseg = _make_getseg(segmap)
    ida_segment.get_segm_name = lambda s: s.name

    plan_calls = []
    def fake_plan(s, e):
        plan_calls.append((s, e))
    ida_auto.plan_range = fake_plan

    # Simulate the work landing: bump func count as the bounded pump loop
    # steps the analyzer. auto_wait() is never used — it drains the whole
    # queue with no timeout, which can blow the host RPC recv deadline on a
    # large binary, so the wait path must poll auto_is_ok() and pump
    # incrementally with auto_make_step() instead.
    _state = {"fc": 219, "steps": 0}
    auto_wait_calls = []

    def fake_auto_make_step(s, e):
        _state["steps"] += 1
        return True

    def fake_auto_wait():
        auto_wait_calls.append(True)
        _state["fc"] = 9065

    def fake_auto_is_ok():
        # The queue drains after two pump steps, creating the functions.
        if _state["steps"] >= 2:
            _state["fc"] = 9065
            return True
        return False

    def fake_get_func_qty():
        return _state["fc"]

    ida_auto.auto_make_step = fake_auto_make_step
    ida_auto.auto_wait = fake_auto_wait
    idaapi.get_func_qty = fake_get_func_qty
    idaapi.auto_is_ok = fake_auto_is_ok

    result = _auto_reanalyze_text_segments(wait_seconds=0.5)

    # The bounded pump drives completion; the unbounded queue-drain is never
    # invoked.
    assert auto_wait_calls == []

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
    ida_auto = _NS["ida_auto"]

    idautils.Segments = lambda: iter([])
    idaapi.getseg = lambda _ea: None
    idaapi.get_func_qty = lambda: 0

    plan_calls = []
    ida_auto.plan_range = lambda *a, **k: plan_calls.append(a)

    result = _auto_reanalyze_text_segments(wait_seconds=0.0)

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

    result = _ensure_entry_point_functions()

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

    result = _ensure_entry_point_functions()

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

    result = _ensure_entry_point_functions()

    assert result["created"] == []
    assert result["failed"] == [hex(0x39E60)]


def test_entry_point_addrs_dedupes_and_sorts():
    """Duplicate entry EAs collapse; result is sorted ascending."""
    ida_entry = _NS["ida_entry"]

    ida_entry.get_entry_qty = lambda: 4
    ida_entry.get_entry_ordinal = lambda i: [0, 1, 2, 3][i]
    ida_entry.get_entry = lambda o: [0x431F4, 0x39E60, 0x431F4, 0x3BAD0][o]

    addrs = _entry_point_addrs()

    assert addrs == [0x39E60, 0x3BAD0, 0x431F4]


def test_segment_code_score_skips_non_exec_segments():
    """A segment without SEGPERM_EXEC must score 0/0/0 even if huge."""
    # .rodata: large but read-only
    rodata = _Seg(0x1A1980, 0x1D0CD9, ".rodata", 1)  # SEGPERM_READ=1, no EXEC
    d, t, h = _segment_code_score(rodata)
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

    d, t, h = _segment_code_score(text)

    # Total: 0x2000 - 0x1000 = 0x1000
    assert t == 0x1000
    # Defined: 4 heads × 4 bytes = 16
    assert d == 16
    assert h == 4
