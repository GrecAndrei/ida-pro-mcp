"""Regression test for the bootstrap report helper (formerly in
firmware_bootstrap.py, now lives in firmware_view.py as
_fwb_base_bootstrap_report).

We load just the helper function by reading the file source, extracting
the function definition, and exec'ing it in a stubbed namespace — the
rest of firmware_view.py can't be imported in CI because it pulls in the
IDA SDK (idaapi, idautils, idc, ...) at module load.
"""

from __future__ import annotations

import os
import re
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(__file__))
FIRMWARE_VIEW_PATH = os.path.join(
    ROOT, "src", "ida_pro_mcp", "ida_mcp", "tools", "firmware_view.py"
)


def _load_fwb_base_bootstrap_report():
    src = open(FIRMWARE_VIEW_PATH).read()
    # Extract the function definition (with any decorator-less def).
    m = re.search(
        r"^def _fwb_base_bootstrap_report\(.*?(?=^def |\nclass |\Z)",
        src,
        re.MULTILINE | re.DOTALL,
    )
    if not m:
        raise RuntimeError("could not locate _fwb_base_bootstrap_report in firmware_view.py")
    fn_src = m.group(0)
    ns: dict = {"__name__": "fwb_test_stub"}
    exec(fn_src, ns)
    return ns["_fwb_base_bootstrap_report"]


def test_bootstrap_report_structure():
    fn = _load_fwb_base_bootstrap_report()
    actions = ["define_vector_table", "annotate_mmio", "reanalyze", "define_strings"]
    r = fn("AIC8800D80", 0x120000, actions)
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


def test_bootstrap_report_accepts_str_load_base():
    """load_base may be passed as a string (already-hex); the function
    must not crash and should preserve it verbatim when not an int."""
    fn = _load_fwb_base_bootstrap_report()
    r = fn("AIC8800D80", "0x80000", [])
    assert r["ok"] is True
    # String load_base is preserved as-is (caller is responsible for
    # formatting).
    assert r["load_base"] == "0x80000"


def test_bootstrap_report_actions_copied_not_aliased():
    """Mutating the caller's actions list after the call must not
    change the report's stored actions."""
    fn = _load_fwb_base_bootstrap_report()
    actions = ["define_vector_table"]
    r = fn("AIC8800D80", 0x0, actions)
    actions.append("EXTRA_MUTATION")
    assert "EXTRA_MUTATION" not in r["actions"]
