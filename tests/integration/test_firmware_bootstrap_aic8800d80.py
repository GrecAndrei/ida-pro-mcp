import os
import pytest

AIC_FW = os.environ.get(
    "AIC8800D80_FW",
    "/home/REDACTED/Downloads/aic8800d80/fmacfw_8800d80_h_u02.bin",
)


@pytest.mark.integration
def test_firmware_bootstrap_aic8800d80(ida_runner, ida_available):
    if not ida_available:
        pytest.skip("IDA integration unavailable")
    if not os.path.isfile(AIC_FW):
        pytest.skip(f"AIC firmware not found: {AIC_FW}")

    ida_runner.binary = AIC_FW
    script = """
import json
import idautils
from firmware_bootstrap import run_firmware_bootstrap
from ida_pro_mcp.host.chip_db import find_chip_profile

prof = find_chip_profile('AIC8800D80') or {}
report = run_firmware_bootstrap(
    chip_family='AIC8800D80',
    load_base=prof.get('load_base'),
    memory_map=prof.get('memory_map'),
    peripheral_addresses=prof.get('peripheral_addresses'),
    post_load_actions=prof.get('post_load_actions'),
)
func_count = sum(1 for _ in idautils.Functions())
reset_found = any((name == 'Reset_Handler') for _, name in [(ea, __import__('idc').get_func_name(ea)) for ea in idautils.Functions()])
with open(RESULT_PATH, 'w') as f:
    json.dump({
        'ok': True,
        'report': report,
        'function_count': func_count,
        'reset_defined': bool(reset_found),
    }, f)
"""
    result = ida_runner.run_script(script, timeout=180)
    assert result.get("ok") is True
    assert int(result.get("function_count", 0)) > 0
    assert bool(result.get("reset_defined")) is True
