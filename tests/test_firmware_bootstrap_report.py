import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
TOOLS = os.path.join(ROOT, "src", "ida_pro_mcp", "ida_mcp", "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

from firmware_bootstrap import _base_bootstrap_report


def test_bootstrap_report_structure():
    actions = ["define_vector_table", "annotate_mmio", "reanalyze", "define_strings"]
    r = _base_bootstrap_report("AIC8800D80", 0x120000, actions)
    assert r["ok"] is True
    assert r["chip_family"] == "AIC8800D80"
    assert r["load_base"] == "0x120000"
    assert r["actions"] == actions
    assert r["functions_created"] == 0
    assert r["entry_points_defined"] == 0
    assert r["peripherals_annotated"] == 0
    assert r["strings_defined"] == 0
    assert r["reset_handler"] is None
    assert isinstance(r["details"], dict)
