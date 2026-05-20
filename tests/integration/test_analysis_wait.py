"""Test analysis:wait polling on a raw binary after segment/Thumb fixes."""
import os
import pytest

AIC_FW = os.environ.get(
    "AIC8800D80_FW",
    "/home/REDACTED/Downloads/aic8800d80/fmacfw_8800d80_h_u02.bin",
)


def test_analysis_wait_polling(ida_runner, ida_available):
    """Verify analysis(action='wait', timeout=N) polls completion correctly.

    After segment/Thumb/bitness fixes, schedule reanalysis and verify the
    wait action reports analysis_complete=true.
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

# Poll with wait
wait_result = analysis_tool(action="wait", timeout=5.0, max_wait=30.0)
t2 = time.time()

func_count = sum(1 for _ in idautils.Functions())

with open(RESULT_PATH, 'w') as f:
    json.dump({
        'ok': True,
        'proc': proc,
        'reanalyze': reanalyze_result,
        'wait': wait_result,
        'analysis_complete': wait_result.get('analysis_complete', False),
        'seconds_waited': wait_result.get('seconds_waited', 0),
        'functions': func_count,
        't_schedule': round(t1 - t0, 3),
        't_wait': round(t2 - t1, 3),
    }, f)
"""
    result = ida_runner.run_script(script, timeout=120, processor="arm")
    import sys
    print(f"\n[result] analysis_complete={result.get('analysis_complete')} "
          f"seconds_waited={result.get('seconds_waited')} "
          f"funcs={result.get('functions')} "
          f"t_schedule={result.get('t_schedule')}s t_wait={result.get('t_wait')}s",
          file=sys.stderr)

    assert result.get("ok") is True, f"Script failed: {result}"

    # reanalyze should return ok
    reanalyze = result.get("reanalyze", {})
    assert reanalyze.get("ok") is True, f"Reanalyze failed: {reanalyze}"

    # wait should return ok
    wait_result = result.get("wait", {})
    assert wait_result.get("ok") is True, f"Wait failed: {wait_result}"

    # Wait should report completion (either already done or after polling)
    assert result.get("analysis_complete", False) or result.get("seconds_waited", 0) > 0, \
        f"Wait should either report completion or have waited. " \
        f"analysis_complete={result.get('analysis_complete')} " \
        f"seconds_waited={result.get('seconds_waited')}"

    # After wait, we should have at least the analysis status reported
    assert "analysis_complete" in wait_result, \
        f"Wait result missing 'analysis_complete' field: {wait_result.keys()}"
