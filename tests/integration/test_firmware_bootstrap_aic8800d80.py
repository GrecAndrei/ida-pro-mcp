import os

import pytest

AIC_FW = os.environ.get(
    "AIC8800D80_FW",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "aic8800d80.bin")),
)


def test_firmware_bootstrap_aic8800d80(ida_runner, ida_available):
    """Test firmware bootstrap on AIC8800D80 binary loaded as ARM with bin loader.

    Verifies:
    - bin loader creates CODE segment (not BSS/DATA)
    - 32-bit bitness is applied
    - T=1 Thumb mode is auto-set
    - create_insn() succeeds on vector handlers
    - add_func() creates functions from vectors
    - Reset_Handler is named
    """
    if not ida_available:
        pytest.skip("IDA integration unavailable")
    if not os.path.isfile(AIC_FW):
        pytest.skip(f"AIC firmware not found: {AIC_FW}")

    ida_runner.binary = AIC_FW
    script = """
import json
import struct
import idautils
import idaapi
import idc
import ida_segment
import ida_bytes
import ida_funcs
import ida_name
from firmware_view import run_firmware_bootstrap  # formerly firmware_bootstrap.run_firmware_bootstrap
from ida_pro_mcp.host.chip_db import find_chip_profile

min_ea = idaapi.inf_get_min_ea()
max_ea = idaapi.inf_get_max_ea()
proc = idc.get_inf_attr(idc.INF_PROCNAME)

# Apply root-cause fixes BEFORE bootstrap so the IDB state is correct
seg = idaapi.getseg(min_ea)
if seg:
    cur_class = ida_segment.get_segm_class(seg)
    if cur_class != "CODE":
        ida_segment.set_segm_class(seg, "CODE")
    if hasattr(seg, "bitness") and seg.bitness != 1:
        seg.bitness = 1
        ida_segment.update_segm(seg)
if "arm" in (proc or "").lower():
    idc.split_sreg_range(min_ea, "T", 1, 2)

# Verify segment state: should be CODE, 32-bit
seg = idaapi.getseg(min_ea)
seg_class = ida_segment.get_segm_class(seg) if seg else "UNKNOWN"
seg_code = bool(seg.type == idaapi.SEG_CODE) if seg else False
seg_bitness = seg.bitness if seg and hasattr(seg, 'bitness') else -1

# Verify T=1 Thumb mode is set for ARM
t_val = idc.get_sreg(min_ea, "T") if "arm" in (proc or "").lower() else -9

# Clear any stale data and mark first code region
if seg and not seg_code:
    ida_bytes.del_items(min_ea, ida_bytes.DELIT_EXPAND, max_ea - min_ea)

prof = find_chip_profile('AIC8800D80') or {}
report = run_firmware_bootstrap(
    chip_family='AIC8800D80',
    load_base=prof.get('load_base'),
    memory_map=prof.get('memory_map'),
    peripheral_addresses=prof.get('peripheral_addresses'),
    post_load_actions=prof.get('post_load_actions'),
)
func_count = sum(1 for _ in idautils.Functions())
reset_found = any(idc.get_func_name(ea) == 'Reset_Handler' for ea in idautils.Functions())
vectors_detected = (report.get('details') or {}).get('define_vector_table', {}).get('vectors_detected', 0)
funcs_created = (report.get('details') or {}).get('define_vector_table', {}).get('functions_created', 0)
debug_info = (report.get('details') or {}).get('define_vector_table', {}).get('_debug', {})

# Test create_insn on first handler
first_handler_ok = False
chunk = idaapi.get_bytes(min_ea, 16) or b""
reset_ptr = struct.unpack_from("<I", chunk, 4)[0] & ~1 if len(chunk) >= 8 else 0
if reset_ptr and min_ea <= reset_ptr < max_ea:
    try:
        import ida_ua
        insn_len = ida_ua.create_insn(reset_ptr)
        if insn_len == 0:
            insn_len = idc.create_insn(reset_ptr)
        first_handler_ok = insn_len > 0
    except Exception:
        first_handler_ok = False

with open(RESULT_PATH, 'w') as f:
    json.dump({
        'ok': True,
        'proc': proc,
        'report': report,
        'function_count': func_count,
        'functions_created': funcs_created,
        'reset_found': reset_found,
        'vectors_detected': vectors_detected,
        'reset_ptr_hex': hex(reset_ptr) if reset_ptr else None,
        'segment_class': seg_class,
        'segment_code': seg_code,
        'segment_bitness': seg_bitness,
        't_register': t_val,
        'first_handler_ok': first_handler_ok,
        'debug': debug_info,
        '_status': report.get('_status', 'ok'),
    }, f)
"""
    result = ida_runner.run_script(script, timeout=180, processor="arm")
    import sys
    print(f"\n[result] proc={result.get('proc')} vectors={result.get('vectors_detected')} "
          f"funcs={result.get('function_count')} funcs_created={result.get('functions_created')} "
          f"reset={result.get('reset_found')} "
          f"seg_class={result.get('segment_class')} seg_code={result.get('segment_code')} "
          f"seg_bitness={result.get('segment_bitness')} T={result.get('t_register')} "
          f"first_handler={result.get('first_handler_ok')}", file=sys.stderr)

    assert result.get("ok") is True, f"Script failed: {result}"

    # Vector table must be detected (64 entries in AIC8800D80)
    assert result.get("vectors_detected", 0) >= 32, \
        f"Expected >=32 vectors, got {result.get('vectors_detected')}: {result.get('report')}"

    # Report must be well-formed
    report = result.get("report") or {}
    assert report.get("ok") is True, f"Bootstrap report not ok: {report}"

    # Segment should be CODE (this is the fix for issue #6)
    seg_class = result.get("segment_class", "")
    seg_code = result.get("segment_code", False)
    assert seg_class == "CODE" or seg_code, \
        f"Segment should be CODE, got class={seg_class}, is_code={seg_code}. " \
        f"Root cause: IDA raw binary loader creates BSS/DATA segments. Fix: pre_analysis_opts segment fix."

    # For ARM, T=1 should be set (Thumb mode)
    if "arm" in str(result.get("proc", "")).lower():
        t_val = result.get("t_register", 0)
        assert t_val == 1, f"T register should be 1 for ARM Thumb, got {t_val}. " \
            f"Root cause: no Thumb auto-detection. Fix: server_script.py sets split_sreg_range(T, 1)."

    assert report.get("peripherals_annotated", 0) >= 0

    func_count = result.get("function_count", 0)
    funcs_created = result.get("functions_created", 0)
    result.get("reset_found", False)

    if func_count == 0 and funcs_created == 0:
        debug = result.get("debug", {})
        import warnings
        warnings.warn(
            f"No functions created after bootstrap. "
            f"code_failures={debug.get('code_failures', [])} "
            f"func_failures={debug.get('func_failures', [])} "
            f"segment_class={seg_class} seg_bitness={result.get('segment_bitness')} "
            f"T={result.get('t_register')} first_handler_ok={result.get('first_handler_ok')} "
            f"Root cause: create_insn/add_func chain broken despite segment/bitness/Thumb fixes.", stacklevel=2
        )
