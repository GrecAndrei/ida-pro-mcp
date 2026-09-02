"""Composed fake-IDA coverage for runtime discovery and symbol recovery."""

import sys

from tests._isolated_repo_loader import load_support_module


def _install_fake_ida(monkeypatch):
    from tests.ida_mcp.test_support_engines_and_integration import _make_fake_ida

    fakes = _make_fake_ida()
    for name, module in fakes.items():
        monkeypatch.setitem(sys.modules, name, module)
    return fakes


def test_runtime_detection_composes_go_and_rust_modes(monkeypatch):
    fakes = _install_fake_ida(monkeypatch)
    mod = load_support_module("runtime_engine")
    fakes["ida_funcs"].get_func_qty = lambda: 2
    fakes["ida_funcs"].get_nfn = lambda index: type(
        "Fn", (), {"start_ea": (0x401000, 0x401100)[index]}
    )()
    fakes["ida_name"].get_name = lambda _ea: "_Rfoo"

    env = mod.detect_runtime_environment()

    assert env["runtimes"] == [
        {"name": "Golang", "version_hint": "Go 1.20+", "pclntab_ea": "0x400000"},
            {"name": "Rust", "mangled_sample_count": 2},
    ]

    names = {0x401000: "_Rfoo", 0x401100: "normal"}
    fakes["ida_funcs"].get_func_qty = lambda: 2
    fakes["ida_funcs"].get_nfn = lambda index: type("Fn", (), {"start_ea": (0x401000, 0x401100)[index]})()
    fakes["ida_name"].get_name = lambda ea: names[ea]
    assert mod.detect_runtime_environment()["runtimes"] == [
        {"name": "Golang", "version_hint": "Go 1.20+", "pclntab_ea": "0x400000"}
    ]


def test_go_pclntab_scanner_handles_missing_segments_and_headers(monkeypatch):
    fakes = _install_fake_ida(monkeypatch)
    mod = load_support_module("runtime_engine")

    fakes["ida_segment"].get_segm_qty = lambda: 0
    assert mod.find_go_pclntab() == (None, "unknown")

    fakes["ida_segment"].get_segm_qty = lambda: 2
    fakes["ida_segment"].get_nseg = lambda index: None if index == 0 else type(
        "Segment", (), {"start_ea": 0x500000, "end_ea": 0x500010}
    )()
    fakes["ida_bytes"].get_bytes = lambda _ea, _size: b"not a pclntab"
    assert mod.find_go_pclntab() == (None, "unknown")
    assert mod.parse_go_pclntab(0x500000) == []


def test_go_pclntab_parser_recovers_bounded_function_records(monkeypatch):
    fakes = _install_fake_ida(monkeypatch)
    mod = load_support_module("runtime_engine")
    base = 0x600000

    header = bytearray(80)
    header[8:16] = (2).to_bytes(8, "little")
    header[32:40] = (0x100).to_bytes(8, "little")
    header[64:72] = (0x200).to_bytes(8, "little")
    fakes["ida_bytes"].get_bytes = lambda _ea, _size: bytes(header)

    offsets = {0x600200: 0x1234, 0x600204: 0, 0x600208: 0x5678, 0x60020C: 6}
    fakes["ida_bytes"].get_dword = lambda ea: offsets.get(ea, 0)
    strings = {base + 0x100: b"main.main", base + 0x106: b"runtime.goexit"}
    fakes["ida_bytes"].get_strlit_contents = lambda ea, _size, _stype: strings.get(ea)

    assert mod.parse_go_pclntab(base, max_funcs=1) == [
        {"entry_ea": "0x1234", "name": "main.main"}
    ]
    assert mod.parse_go_pclntab(base) == [
        {"entry_ea": "0x1234", "name": "main.main"},
        {"entry_ea": "0x5678", "name": "runtime.goexit"},
    ]


def test_runtime_parser_and_demangler_cover_fallbacks(monkeypatch):
    fakes = _install_fake_ida(monkeypatch)
    mod = load_support_module("runtime_engine")

    fakes["ida_bytes"].get_bytes = lambda _ea, _size: b"x" * 64
    assert mod.parse_go_pclntab(0x700000) == []

    fakes["ida_name"].demangle_name = lambda _name, flags=0: "" if flags == 0 else "legacy::name"
    fakes["idc"].INF_SHORT_DN = 1
    assert mod.demangle_rust_symbol("") == ""
    assert mod.demangle_rust_symbol("plain") == "plain"
    assert mod.demangle_rust_symbol("_Rsymbol") == "legacy::name"

    del fakes["ida_name"].demangle_name
    assert mod.demangle_rust_symbol("_ZNlegacy") == "_ZNlegacy"
    fakes["ida_name"] = None
    mod.ida_name = None
    assert mod.demangle_rust_symbol("_Rmissing") == "_Rmissing"
