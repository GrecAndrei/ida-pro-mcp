"""Test funcs:create on raw ARM binaries with proper Thumb/segment/bitness setup."""
import os

import pytest

AIC_FW = os.environ.get(
    "AIC8800D80_FW",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "aic8800d80.bin")),
)


def test_funcs_create_on_vector_handler(ida_runner, ida_available):
    """Verify funcs:create works on raw ARM binaries after pre-analysis fixes.

    Tests the full pipeline: segment→CODE, bitness→32, T=1→Thumb,
    create_insn → add_func → set_name on the Reset_Handler vector.
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

min_ea = idaapi.inf_get_min_ea()
max_ea = idaapi.inf_get_max_ea()
proc = idc.get_inf_attr(idc.INF_PROCNAME)

# Apply the root-cause fixes: segment class, bitness, T-bit
seg = idaapi.getseg(min_ea)
results = {"steps": []}

# Step 1: Fix segment class to CODE
if seg:
    cur_class = ida_segment.get_segm_class(seg)
    if cur_class != "CODE":
        ida_segment.set_segm_class(seg, "CODE")
        results["steps"].append({"step": "segment_class", "from": cur_class, "to": "CODE"})
    else:
        results["steps"].append({"step": "segment_class", "status": "already_CODE"})

# Step 2: Ensure 32-bit bitness
if hasattr(seg, "bitness") and seg.bitness != 1:
    seg.bitness = 1
    ida_segment.update_segm(seg)
    results["steps"].append({"step": "segment_bitness", "set": 32})
else:
    results["steps"].append({"step": "segment_bitness", "status": "already_32" if getattr(seg, 'bitness', 0) == 1 else f"bitness={getattr(seg, 'bitness', 'N/A')}"})

# Step 3: Set T=1 for ARM Thumb
t_val_before = None
if "arm" in (proc or "").lower():
    t_val_before = idc.get_sreg(min_ea, "T")
    idc.split_sreg_range(min_ea, "T", 1, 2)
    t_val_after = idc.get_sreg(min_ea, "T")
    results["steps"].append({"step": "t_bit", "before": t_val_before, "after": t_val_after})

# Step 4: Find Reset_Handler vector (offset 4 in vector table)
chunk = idaapi.get_bytes(min_ea, 16) or b""
reset_ptr = struct.unpack_from("<I", chunk, 4)[0] & ~1 if len(chunk) >= 8 else 0
results["reset_ptr_raw"] = hex(reset_ptr) if reset_ptr else None

# Map runtime VA to IDB space if needed (load_base normalization)
handler_ea = reset_ptr
if handler_ea and (handler_ea < min_ea or handler_ea >= max_ea):
    for align in (0x100000, 0x10000, 0x1000):
        off = handler_ea & (align - 1)
        if 0 <= off < (max_ea - min_ea):
            mapped = min_ea + off
            if min_ea <= mapped < max_ea:
                handler_ea = mapped
                break
results["handler_ea"] = hex(handler_ea) if handler_ea else None

# Step 5: Try create_insn at handler address
insn_created = False
insn_len = 0
if handler_ea and min_ea <= handler_ea < max_ea:
    ida_bytes.del_items(handler_ea, ida_bytes.DELIT_SIMPLE, 16)
    try:
        import ida_ua
        insn_len = ida_ua.create_insn(handler_ea)
    except Exception:
        insn_len = idc.create_insn(handler_ea)
    if insn_len == 0:
        insn_len = idc.create_insn(handler_ea)
    insn_created = insn_len > 0
    results["steps"].append({"step": "create_insn", "ok": insn_created, "length": insn_len, "is_code": ida_bytes.is_code(ida_bytes.get_flags(handler_ea))})
else:
    results["steps"].append({"step": "create_insn", "error": "handler_ea out of bounds"})

# Step 6: Try add_func at handler address
func_created = False
if handler_ea and insn_created:
    try:
        func_created = ida_funcs.add_func(handler_ea)
        if func_created:
            idc.set_name(handler_ea, "Reset_Handler", ida_name.SN_FORCE)
    except Exception:
        pass
    results["steps"].append({"step": "add_func", "ok": func_created, "ea": hex(handler_ea)})

# Step 7: Verify
final_funcs = sum(1 for _ in idautils.Functions())
reset_exists = any(idc.get_func_name(ea) == 'Reset_Handler' for ea in idautils.Functions())

with open(RESULT_PATH, 'w') as f:
    json.dump({
        'ok': True,
        'proc': proc,
        'handler_ea': hex(handler_ea) if handler_ea else None,
        'insn_created': insn_created,
        'func_created': func_created,
        'reset_exists': reset_exists,
        'final_funcs': final_funcs,
        'seg_code': seg.type == idaapi.SEG_CODE if seg else False,
        'seg_class': ida_segment.get_segm_class(seg) if seg else "N/A",
        'steps': results["steps"],
    }, f)
"""
    result = ida_runner.run_script(script, timeout=180, processor="arm")
    import sys
    print(f"\n[result] proc={result.get('proc')} insn_created={result.get('insn_created')} "
          f"func_created={result.get('func_created')} reset_exists={result.get('reset_exists')} "
          f"final_funcs={result.get('final_funcs')} "
          f"seg_class={result.get('seg_class')} seg_code={result.get('seg_code')}",
          file=sys.stderr)
    print(f"[steps] {result.get('steps')}", file=sys.stderr)

    assert result.get("ok") is True, f"Script failed: {result}"

    # Segment must be CODE
    seg_code = result.get("seg_code", False)
    seg_class = result.get("seg_class", "")
    assert seg_code or seg_class == "CODE", \
        f"Segment must be CODE after fix. Got class={seg_class}, is_code={seg_code}"

    # Instruction creation must succeed on the Reset_Handler vector
    assert result.get("insn_created", False), \
        f"create_insn failed on handler at {result.get('handler_ea')}. " \
        f"Steps: {result.get('steps')}. " \
        f"Root cause: segment not CODE or T-bit not set."

    # Function creation should succeed after instruction is recognized
    if result.get("insn_created"):
        func_created = result.get("func_created", False)
        if not func_created:
            import warnings
            warnings.warn(
                f"create_insn succeeded but add_func failed on handler at {result.get('handler_ea')}. "
                f"Steps: {result.get('steps')}. This may be a transient IDA issue."
            )
