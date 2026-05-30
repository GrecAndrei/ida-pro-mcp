import json
import os

import pytest

import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(__file__))
from conftest import IDARunner, ida_is_available

AIC_FW = os.environ.get(
    "AIC8800D80_FW",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "aic8800d80.bin")),
)
TEST_BINARY = "tests/data/test_binary.exe"


pytestmark = pytest.mark.skipif(not ida_is_available(), reason="IDA integration tests require licensed IDA Pro")


def _run_with_binary(binary_path: str, script_body: str, timeout: int = 150) -> dict:
    runner = IDARunner(binary=binary_path)
    return runner.run_script(script_body, timeout=timeout)


def test_tool_loading():
    # Inject the project root as a literal string so the script can find server_script.py
    import os as _os
    _project_root = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    script = f'''
import os
import sys
import json
import importlib.util

project_root = {repr(_project_root)}
script_path = os.path.join(project_root, "src", "ida_pro_mcp", "server_script.py")
spec = importlib.util.spec_from_file_location("server_script_under_test", script_path)
mod = importlib.util.module_from_spec(spec)
sys.modules["server_script_under_test"] = mod
spec.loader.exec_module(mod)

mod.TOOLS.clear()
mod.load_tools()
loaded_tools = sorted(mod.TOOLS.keys())
search_loaded = mod._try_load_single_tool("search")

firmware_import_errors = []
try:
    for line in open(mod.ALIVE_FILE, "r", encoding="utf-8", errors="replace"):
        if "firmware_bootstrap" in line and "No module named" in line:
            firmware_import_errors.append(line.strip())
except Exception as e:
    firmware_import_errors.append(f"Could not read alive file: {{e}}")

result = {{
    "ok": True,
    "tool_count": len(loaded_tools),
    "tools": loaded_tools,
    "search_loaded": {{
        "loaded": bool(search_loaded[0]),
        "name": search_loaded[1],
        "error": search_loaded[2],
    }},
    "firmware_bootstrap_loaded": "firmware_bootstrap" in loaded_tools,
    "firmware_import_errors": firmware_import_errors,
}}

with open(RESULT_PATH, "w") as f:
    json.dump(result, f)
'''
    result = _run_with_binary(TEST_BINARY, script, timeout=180)
    assert result.get("ok") is True, result
    assert isinstance(result.get("tools"), list), result
    assert not result.get("firmware_import_errors"), result
    assert result.get("search_loaded", {}).get("loaded") is True, result
    assert result.get("search_loaded", {}).get("name") == "search", result
    assert result.get("search_loaded", {}).get("error") is None, result
    assert int(result.get("tool_count", 0)) >= 10, result


def test_inf_readiness_pe():
    # IDA 9.x API: idaapi.get_inf_structure() and ida_ida.cvar are REMOVED.
    # The correct APIs are: ida_ida.inf_get_min_ea() and idc.get_inf_attr(idc.INF_MIN_EA)
    script = r'''
import json
import ida_ida
import idc

errors = []
min_ea_ida_ida = None
min_ea_idc = None

try:
    min_ea_ida_ida = int(ida_ida.inf_get_min_ea())
except Exception as e:
    errors.append(f"ida_ida.inf_get_min_ea failed: {e}")

try:
    min_ea_idc = int(idc.get_inf_attr(idc.INF_MIN_EA))
except Exception as e:
    errors.append(f"idc.get_inf_attr failed: {e}")

with open(RESULT_PATH, "w") as f:
    json.dump(
        {
            "ok": True,
            "min_ea_ida_ida": min_ea_ida_ida,
            "min_ea_idc": min_ea_idc,
            "errors": errors,
        },
        f,
    )
'''
    result = _run_with_binary(TEST_BINARY, script, timeout=120)
    assert result.get("ok") is True, result
    assert result.get("min_ea_ida_ida") is not None, f"ida_ida.inf_get_min_ea() failed: {result}"
    assert result.get("min_ea_idc") is not None, f"idc.get_inf_attr(INF_MIN_EA) failed: {result}"
    assert not result.get("errors"), f"Unexpected errors: {result['errors']}"


def test_inf_readiness_raw():
    if not os.path.isfile(AIC_FW):
        pytest.skip(f"AIC firmware not found: {AIC_FW}")

    script = r'''
import json
import ida_ida
import idc

errors = []
min_ea_ida_ida = None
min_ea_idc = None

try:
    min_ea_ida_ida = int(ida_ida.inf_get_min_ea())
except Exception as e:
    errors.append(f"ida_ida.inf_get_min_ea failed: {e}")

try:
    min_ea_idc = int(idc.get_inf_attr(idc.INF_MIN_EA))
except Exception as e:
    errors.append(f"idc.get_inf_attr failed: {e}")

with open(RESULT_PATH, "w") as f:
    json.dump(
        {
            "ok": True,
            "min_ea_ida_ida": min_ea_ida_ida,
            "min_ea_idc": min_ea_idc,
            "errors": errors,
        },
        f,
    )
'''
    result = _run_with_binary(AIC_FW, script, timeout=180)
    assert result.get("ok") is True, result
    assert result.get("min_ea_ida_ida") is not None, f"ida_ida.inf_get_min_ea() failed: {result}"
    assert result.get("min_ea_idc") is not None, f"idc.get_inf_attr(INF_MIN_EA) failed: {result}"
    assert not result.get("errors"), f"Unexpected errors: {result['errors']}"
