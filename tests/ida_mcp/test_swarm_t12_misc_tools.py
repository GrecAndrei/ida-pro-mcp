"""Regression tests for swarm/t12_misc_tools findings.

Covers:
- symbols.load_dwarf: returns an IDA_ERROR envelope when the dwarf plugin
  fails to load/run, matching load_pdb (previously ok:true-on-failure).
- imports_deep.delay / forwarded / api_sets: honor the query filter.
- imports_deep.api_sets: the hardcoded redirection guess no longer reports
  kernel32.dll for generic api-ms-* names (they resolve to kernelbase), and
  the response labels the target as a heuristic.

Host-side tests: ida_* modules are stubbed via tests._isolated_repo_loader;
no live IDA session is required.
"""

from __future__ import annotations

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_module  # noqa: E402

# ---------------------------------------------------------------------------
# symbols.load_dwarf — error envelope on plugin failure
# ---------------------------------------------------------------------------

def test_load_dwarf_error_envelope_on_plugin_failure(monkeypatch):
    mod = load_tool_module("symbols")
    monkeypatch.setattr(sys.modules["ida_loader"], "load_and_run_plugin", lambda name, arg: False, raising=False)
    res = mod.symbols(action="load_dwarf")
    # Pre-fix this returned {"ok": True, "note": "DWARF processing handled
    # by IDA during analysis"} — ok:true on a load failure.
    assert res.get("ok") is False
    assert res.get("code") == "IDA_ERROR"


def test_load_dwarf_ok_on_plugin_success(monkeypatch):
    mod = load_tool_module("symbols")
    monkeypatch.setattr(sys.modules["ida_loader"], "load_and_run_plugin", lambda name, arg: True, raising=False)
    res = mod.symbols(action="load_dwarf")
    assert res["ok"] is True
    assert res["loaded"] is True


# ---------------------------------------------------------------------------
# imports_deep — query filter honored by delay/forwarded/api_sets
# ---------------------------------------------------------------------------

class _Seg:
    def __init__(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea


def _load_imports_deep():
    mod = load_tool_module("imports_deep")
    mod.idaapi.BADADDR = -1
    return mod


def test_delay_honors_query_filter(monkeypatch):
    mod = _load_imports_deep()

    monkeypatch.setattr(sys.modules["idautils"], "Segments", lambda: [0x1000], raising=False)
    monkeypatch.setattr(sys.modules["idc"], "get_segm_name", lambda ea: ".didat", raising=False)
    monkeypatch.setattr(sys.modules["ida_segment"], "getseg", lambda ea: _Seg(0x1000, 0x1010), raising=False)
    names = {
        0x1000: "KERNEL32_LoadLibraryA",
        0x1001: "KERNEL32_GetProcAddress",
        0x1002: "USER32_MessageBoxW",
    }
    monkeypatch.setattr(sys.modules["idc"], "get_name", lambda ea: names.get(ea, ""), raising=False)
    monkeypatch.setattr(sys.modules["idc"], "next_head", lambda ea, end: ea + 1, raising=False)

    filtered = mod.imports_deep(action="delay", query="kernel32", offset=0, count=100)
    assert filtered["ok"] is True
    assert "KERNEL32_LoadLibraryA" in filtered["delay_imports"]
    assert "KERNEL32_GetProcAddress" in filtered["delay_imports"]
    assert "USER32_MessageBoxW" not in filtered["delay_imports"]
    assert filtered["total"] == 3  # [KERNEL32] header + 2 funcs

    unfiltered = mod.imports_deep(action="delay", query=None, offset=0, count=100)
    assert "USER32_MessageBoxW" in unfiltered["delay_imports"]
    assert unfiltered["total"] == 5  # KERNEL32 group (3) + USER32 group (2)


def test_forwarded_honors_query_filter(monkeypatch):
    mod = _load_imports_deep()

    nalt = sys.modules["ida_nalt"]
    monkeypatch.setattr(nalt, "get_import_module_qty", lambda: 1, raising=False)
    monkeypatch.setattr(nalt, "get_import_module_name", lambda i: "kernel32.dll", raising=False)

    def _enum(_module_idx, cb):
        cb(0x1000, "kernel32.CreateFileW", 0)
        cb(0x1001, "ntdll.NtCreateFile", 0)
        return True

    monkeypatch.setattr(nalt, "enum_import_names", _enum, raising=False)

    filtered = mod.imports_deep(action="forwarded", query="ntdll", offset=0, count=100)
    assert filtered["ok"] is True
    assert "ntdll.NtCreateFile" in filtered["forwarded"]
    assert "kernel32.CreateFileW" not in filtered["forwarded"]
    assert filtered["total"] == 1

    unfiltered = mod.imports_deep(action="forwarded", query=None, offset=0, count=100)
    assert "kernel32.CreateFileW" in unfiltered["forwarded"]
    assert unfiltered["total"] == 2


def _configure_api_sets(monkeypatch, names):
    nalt = sys.modules["ida_nalt"]
    monkeypatch.setattr(nalt, "get_import_module_qty", lambda: len(names), raising=False)
    monkeypatch.setattr(nalt, "get_import_module_name", lambda i: names[i], raising=False)


def test_api_sets_heuristic_targets_are_kernelbase_not_kernel32(monkeypatch):
    mod = _load_imports_deep()
    _configure_api_sets(monkeypatch, [
        "api-ms-win-security-base-l1-1-0.dll",
        "api-ms-win-crt-runtime-l1-1-0.dll",
        "api-ms-win-core-file-l1-1-0.dll",
    ])

    res = mod.imports_deep(action="api_sets", query=None, offset=0, count=100)
    assert res["ok"] is True
    text = res["api_sets"]
    # Pre-fix, api-ms-win-security-base-* (neither 'win-core' nor 'crt') was
    # reported as kernel32.dll — a wrong redirection target.
    assert "api-ms-win-security-base-l1-1-0.dll  -> kernelbase.dll" in text
    assert "api-ms-win-core-file-l1-1-0.dll  -> kernelbase.dll" in text
    assert "api-ms-win-crt-runtime-l1-1-0.dll  -> ucrtbase.dll" in text
    assert "kernel32" not in text
    # The guess must be labelled, not presented as an exact resolution.
    assert "heuristic" in res.get("note", "")


def test_api_sets_honors_query_filter(monkeypatch):
    mod = _load_imports_deep()
    _configure_api_sets(monkeypatch, [
        "api-ms-win-security-base-l1-1-0.dll",
        "api-ms-win-crt-runtime-l1-1-0.dll",
    ])

    res = mod.imports_deep(action="api_sets", query="crt", offset=0, count=100)
    assert res["ok"] is True
    assert "crt-runtime" in res["api_sets"]
    assert "security-base" not in res["api_sets"]
    assert res["total"] == 1
