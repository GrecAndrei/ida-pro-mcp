"""Cross-mode coverage for memory metadata and failure handling."""

from __future__ import annotations

import struct

from tests.ida_mcp.test_memory_surface_modes import _full_error_envelope
from tests.ida_mcp.test_swarm_q05d_memory_misc import _load_memory


def test_fixup_metadata_and_pointer_relocation_modes(monkeypatch):
    mem = _load_memory(bitness=32)
    _full_error_envelope(mem)
    fixup = mem.ida_fixup
    fixup.FIXUP_OFF32 = 1
    fixup.FIXUP_REL32 = 0x42
    mem._FIXUP_MODULE_NAMES = None
    assert mem._fixup_type_name("1") is None
    assert mem._fixup_type_name(1) == "FIXUP_OFF32"
    assert mem._fixup_type_name(0x0E) == "FIXUP_OFF_OR_PTR"
    assert mem._fixup_type_name(0x42) == "FIXUP_REL32"
    assert mem._fixup_type_name(0x99) == "FIXUP_0x99"

    class FixupData:
        type = 1
        base = 0x1000
        off = 4
        displacement = 8

    fixup.fixup_data_t = FixupData
    fixup.get_fixup = lambda _data, _ea: True
    info = mem._fixup_info(0x1000)
    assert info["relocation"] is True
    assert info["fixup_name"] == "FIXUP_OFF32"
    assert info["fixup_base"] == 0x1000
    fixup.get_fixup = lambda _data, _ea: False
    assert mem._fixup_info(0x1000) is None
    fixup.get_fixup = lambda *_args: (_ for _ in ()).throw(RuntimeError("fixup api"))
    assert mem._fixup_info(0x1000) is None

    raw = struct.pack("<I", 0x2000) + b"\x00" * 4
    mem.ida_bytes.is_loaded = lambda value: value == 0x2000
    mem.idc.get_name = lambda value: "target" if value == 0x2000 else ""
    fixup.get_fixup = lambda _data, ea: ea == 0x1000
    mem.ida_bytes.get_bytes = lambda _ea, size: raw[:size]
    pointers = mem._find_pointers(raw, 0x1000)
    assert pointers[0]["relocation"] is True and pointers[0]["fixup_name"] == "FIXUP_OFF32"


def test_memory_parameter_and_governance_boundaries(monkeypatch):
    mem = _load_memory()
    _full_error_envelope(mem)
    assert mem._coerce_memory_params("read", "0x1000", "bad", 2)[1]["error"] is True
    monkeypatch.setattr(mem, "validate_addr", lambda _value: (None, {"error": True, "code": "bad"}))
    assert mem._coerce_memory_params("read", "not-an-address", 4, "bad")[1]["error"] is True
    assert mem._coerce_memory_params("read", None, 4, "bad")[1]["error"] is True
    assert mem._coerce_memory_params("search", None, 4, "bad")[0] == (None, 4, 2)
    assert mem._coerce_memory_params("compare", None, 4, 2)[0] == (None, 4, 2)

    monkeypatch.setattr(mem._compat, "get_segment_perm", lambda _ea: 1)
    monkeypatch.setattr(mem._compat, "get_segment_name", lambda _ea: ".text")
    assert mem._write_governance_metadata(0x1000) == {
        "section_type": ".text",
        "is_import_addr": False,
        "modifies_control_flow": True,
    }
    monkeypatch.setattr(mem._compat, "get_segment_perm", lambda _ea: None)
    assert mem._write_governance_metadata(0x1000) == {}

    mem.ida_bytes.get_bytes = lambda _ea, size: b"\x00" * size
    assert mem.memory(action="read", address="0x1000", type="f32")["error"] is True
    assert mem.memory(action="read", address="0x1000", type="f64")["error"] is True
    assert mem.memory(action="read", address="0x1000", type="bytes", size="bad")["error"] is True


def test_memory_big_endian_float_struct_walk_and_write_failures(monkeypatch):
    mem = _load_memory(bitness=32)
    _full_error_envelope(mem)
    monkeypatch.setattr(mem, "_inf_is_be", lambda: True)
    mem.ida_bytes.get_bytes = lambda _ea, size: struct.pack(">f", 1.25)[:size]
    assert mem.memory(action="read", address="0x1000", type="f32")["value"] == 1.25
    mem.ida_bytes.get_bytes = lambda _ea, size: struct.pack(">d", 2.5)[:size]
    assert mem.memory(action="read", address="0x1000", type="f64")["value"] == 2.5

    raw = struct.pack(">I", 0x2000)
    mem.ida_bytes.get_bytes = lambda _ea, size: raw[:size]
    mem.ida_bytes.is_loaded = lambda value: value == 0x2000
    mem.idc.get_name = lambda value: "target" if value == 0x2000 else ""
    mem.ida_nalt.get_tinfo = lambda _tinfo, value: value == 0x2000
    mem.ida_typeinf.tinfo_t = lambda: "struct node *"
    assert mem.memory(action="struct_walk", address="0x1000", depth=1)["nodes"][0]["type"] == "struct node *"

    monkeypatch.setattr(mem._compat, "get_segment_perm", lambda _ea: 1)
    monkeypatch.setattr(mem._compat, "get_segment_name", lambda _ea: ".text")
    mem.evaluate_operation = lambda **_kwargs: {"approved": False, "verdict": "blocked", "violations": ["text"]}
    assert mem.memory(action="write", address="0x1000", data="90")["code"] == "GOVERNANCE_BLOCKED"
    mem.evaluate_operation = lambda **_kwargs: {"approved": True, "verdict": "ok", "violations": []}
    mem.ida_bytes.patch_bytes = lambda _ea, _data: 0
    partial = mem.memory(action="write", address="0x1000", data="90")
    assert partial["error"] is True and partial["code"] == "IDA_ERROR"
    mem.ida_bytes.patch_bytes = lambda _ea, _data: (_ for _ in ()).throw(RuntimeError("patch failed"))
    failed = mem.memory(action="write", address="0x1000", data="90", governed=False)
    assert failed["error"]
    assert "patch failed" in str(failed["error"])
