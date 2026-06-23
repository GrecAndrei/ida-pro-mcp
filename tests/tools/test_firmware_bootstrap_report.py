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

