"""Composed fake-IDA coverage for firmware vector and SVD helpers."""

import json
import sys

from tests._isolated_repo_loader import load_support_module


def _install_fake_ida(monkeypatch):
    from tests.ida_mcp.test_support_engines_and_integration import _make_fake_ida

    fakes = _make_fake_ida()
    for name, module in fakes.items():
        monkeypatch.setitem(sys.modules, name, module)
    return fakes


def test_vector_table_maps_arm_thumb_reserved_and_irq_entries(monkeypatch):
    fakes = _install_fake_ida(monkeypatch)
    mod = load_support_module("svd_engine")
    pointers = {
        0x80000004: 0x1001,
        0x80000008: 0x2000,
        0x8000001C: 0x3001,
        0x80000040: 0x4001,
        0x80000044: 0xFFFFFFFF,
    }
    fakes["ida_bytes"].get_dword = lambda ea: pointers.get(ea, 0)
    added = []
    renamed = []

    def add_func(ea):
        added.append(ea)

    fakes["ida_funcs"].add_func = add_func
    fakes["ida_name"].get_name = lambda _ea: "sub_existing"
    fakes["ida_name"].set_name = lambda ea, name, _flags=0: renamed.append((ea, name))

    mapped = mod.map_vector_table_isrs(0x80000000, arch="ARM", limit=18)

    assert [item["slot"] for item in mapped] == [1, 2, 7, 16]
    assert mapped[0]["target_ea"] == "0x1000"
    assert mapped[1]["target_ea"] == "0x2000"
    assert mapped[2]["vector_name"] == "Reserved_7"
    assert mapped[3]["vector_name"] == "IRQ_0_Handler"
    assert added == [0x1000, 0x2000, 0x4000]
    assert renamed == [(0x1000, "Reset_Handler"), (0x2000, "NMI_Handler"), (0x4000, "IRQ_0_Handler")]

    fakes["ida_bytes"].get_dword = lambda _ea: 0x5001
    assert mod.map_vector_table_isrs(0x90000000, arch="riscv", limit=1)[0]["target_ea"] == "0x5001"


def test_svd_application_accepts_json_dict_list_and_creates_segments(monkeypatch):
    fakes = _install_fake_ida(monkeypatch)
    mod = load_support_module("svd_engine")
    segments = {}
    added_segments = []
    named = []

    def getseg(ea):
        return segments.get(ea)

    fakes["ida_segment"].getseg = getseg

    def add_seg(start, end, *_args):
        added_segments.append((start, end))
        segments[start] = type("Segment", (), {})()
        return True

    fakes["ida_segment"].add_seg = add_seg
    fakes["ida_segment"].set_segm_name = lambda seg, name: setattr(seg, "name", name)
    fakes["ida_name"].set_name = lambda ea, name, _flags=0: named.append((ea, name))

    payload = json.dumps({"peripherals": [{"name": "UART", "base": "0x50000000", "size": 256}]})
    assert mod.apply_svd_peripherals(payload) == [
        {"peripheral": "UART", "base": "0x50000000", "size": 256}
    ]
    assert added_segments == [(0x50000000, 0x50000100)]
    assert named == [(0x50000000, "UART_BASE")]

    segments[0x60000000] = type("Existing", (), {})()
    assert mod.apply_svd_peripherals({"name": "GPIO", "base": 0x60000000}, limit=1) == [
        {"peripheral": "GPIO", "base": "0x60000000", "size": 0x1000}
    ]
    assert added_segments == [(0x50000000, 0x50000100)]


def test_svd_input_fallbacks_and_missing_ida_are_safe(monkeypatch):
    _install_fake_ida(monkeypatch)
    mod = load_support_module("svd_engine")

    assert mod.apply_svd_peripherals("not-json", base_override=0x70000000) == [
        {"peripheral": "PERIPH_0", "base": "0x70000000", "size": 0x1000}
    ]
    assert mod.apply_svd_peripherals([{"base": "0x71000000"}], limit=1) == [
        {"peripheral": "PERIPH", "base": "0x71000000", "size": 0x1000}
    ]

    mod.ida_bytes = None
    assert mod.map_vector_table_isrs(0x80000000) == []
    mod.ida_segment = None
    mod.ida_name = None
    assert mod.apply_svd_peripherals({"name": "TIMER", "base": "0x72000000"})[0]["peripheral"] == "TIMER"
