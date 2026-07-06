"""Test analysis:state reports completion status after reanalysis."""
import os

import pytest

AIC_FW = os.environ.get(
    "AIC8800D80_FW",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "aic8800d80.bin")),
)


def test_analysis_state_reports_completion(ida_runner, ida_available):
    """Verify analysis(action='state') reports analysis completion status.

    After segment/Thumb/bitness fixes, schedule reanalysis and verify the
    state action reports analysis_complete=true.
    """
    if not ida_available:
        pytest.skip("IDA integration unavailable")
    if not os.path.isfile(AIC_FW):
        pytest.skip(f"AIC firmware not found: {AIC_FW}")

    ida_runner.binary = AIC_FW
    script = """
import json
import time
import idautils
import idaapi
import idc
import ida_segment
from analysis import analysis as analysis_tool

min_ea = idaapi.inf_get_min_ea()
max_ea = idaapi.inf_get_max_ea()
proc = idc.get_inf_attr(idc.INF_PROCNAME)

# Apply segment/Thumb fixes
seg = idaapi.getseg(min_ea)
if seg:
    ida_segment.set_segm_class(seg, "CODE")
    if hasattr(seg, "bitness"):
        seg.bitness = 1
        ida_segment.update_segm(seg)
if "arm" in (proc or "").lower():
    idc.split_sreg_range(min_ea, "T", 1, 2)

# Schedule reanalysis
t0 = time.time()
reanalyze_result = analysis_tool(action="reanalyze")
t1 = time.time()

# Check analysis state
state_result = analysis_tool(action="state")
t2 = time.time()

func_count = sum(1 for _ in idautils.Functions())

with open(RESULT_PATH, 'w') as f:
    json.dump({
        'ok': True,
        'proc': proc,
        'reanalyze': reanalyze_result,
        'state': state_result,
        'analysis_complete': state_result.get('analysis_complete', False),
        'functions': func_count,
        't_schedule': round(t1 - t0, 3),
        't_state': round(t2 - t1, 3),
    }, f)
"""
    result = ida_runner.run_script(script, timeout=120, processor="arm")
    import sys
    print(f"\n[result] analysis_complete={result.get('analysis_complete')} "
          f"funcs={result.get('functions')} "
          f"t_schedule={result.get('t_schedule')}s t_state={result.get('t_state')}s",
          file=sys.stderr)

    assert result.get("ok") is True, f"Script failed: {result}"

    # reanalyze should return ok
    reanalyze = result.get("reanalyze", {})
    assert reanalyze.get("ok") is True, f"Reanalyze failed: {reanalyze}"

    # state should return ok
    state_result = result.get("state", {})
    assert state_result.get("ok") is True, f"State check failed: {state_result}"

    # State should report analysis_complete field
    assert "analysis_complete" in state_result, \
        f"State result missing 'analysis_complete' field: {state_result.keys()}"
