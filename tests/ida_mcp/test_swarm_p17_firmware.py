"""Regression tests for the resurrected firmware-shaping tool (WO-F1).

WO-F1 rebuilds the deleted ``firmware_view`` capability as an IDA-side
``firmware`` tool — the mission differentiator vs radare2.  ``pointer_sweep``
is folded into ``search(action='data_value')`` (WO-S6); ``auto_retype`` is
deferred.  This file pins the five rebuilt actions on the shared raw-blob fake
(``tests/ida_mcp/raw_blob_fake.py``), no live IDA required:

- detect_vector_table returns the committed RISC-V fixture's LE u32 ISR table
  (4 handlers at 0x80000008), ranks it above incidental pointer runs, and
  honors ``word`` / ``endian`` / ``base``.
- detect_load_base validates the known load base (0x80000000) by decoding the
  reset-vector ``j`` and the reset-handler GP-init prologue, and ranks it above
  a wrong hypothesis.
- detect_mmio surfaces the fixture's UART base (0x10003000) as an MMIO page.
- rtos_scan detects FreeRTOS signatures in raw bytes and returns no matches on
  the bare fixture.
- carve defines a segment (mirroring ``segments`` add) and rejects overlap.
- Tool-level error paths: unknown action, missing bounds.
"""

import os
import sys

from tests._isolated_repo_loader import load_tool_module
from tests.ida_mcp.raw_blob_fake import (
    RISCV_ISR_DEFAULT,
    RISCV_ISR_TIMER,
    RISCV_ISR_UART,
    RISCV_RESET_HANDLER,
    RISCV_UART_BASE,
    RISCV_VECTOR_TABLE,
    fixture_bytes,
    install_raw_blob,
)

LOAD_BASE = 0x80000000
# Fixture rodata stores a `.word 0x10003000` UART base at blob offset
# RISCV_UART_BASE (0xA4); the peripheral address itself is 0x10003000.
UART_ADDR = 0x10003000


def _vector_ptr(off: int) -> int:
    return LOAD_BASE + off


def _load_fixture(**kwargs):
    """Install the committed RISC-V blob and load the real firmware tool."""
    blob = install_raw_blob(fixture_bytes(), processor="riscv", bitness=64,
                            base=LOAD_BASE, **kwargs)
    return blob, blob.load_tool("firmware")


# ---------------------------------------------------------------------------
# detect_vector_table
# ---------------------------------------------------------------------------

def test_vector_table_detects_fixture_isr_table():
    blob, mod = _load_fixture()
    resp = mod.firmware(action="detect_vector_table", word="u32", endian="le")
    assert resp["ok"] is True, resp
    cands = resp["candidates"]
    assert cands, resp
    # The LE u32 ISR table at 0x80000008 is the longest pointer run in the image.
    top = cands[0]
    assert top["base"] == hex(_vector_ptr(RISCV_VECTOR_TABLE)), cands
    assert top["count"] >= 4, top
    assert top["endian"] == "le"
    first = top["first_entries"]
    assert hex(_vector_ptr(RISCV_RESET_HANDLER)) in first, first
    assert hex(_vector_ptr(RISCV_ISR_TIMER)) in first, first
    assert hex(_vector_ptr(RISCV_ISR_UART)) in first, first
    assert hex(_vector_ptr(RISCV_ISR_DEFAULT)) in first, first
    assert 0.5 <= top["confidence"] <= 0.98


def test_vector_table_auto_width_falls_back_to_u32_on_64bit_blob():
    # 64-bit processor -> auto would pick u64 and miss the u32 table; the
    # auto path must fall back to u32 when the wider scan finds no runs.
    blob, mod = _load_fixture()
    resp = mod.firmware(action="detect_vector_table", word="auto", endian="le")
    assert resp["ok"] is True, resp
    assert resp["candidates"][0]["base"] == hex(_vector_ptr(RISCV_VECTOR_TABLE)), resp["candidates"]
    assert resp["candidates"][0]["word_size"] == 4


def test_vector_table_respects_base_anchor():
    blob, mod = _load_fixture()
    resp = mod.firmware(action="detect_vector_table", word="u32", endian="le",
                        base=hex(_vector_ptr(RISCV_VECTOR_TABLE)))
    assert resp["ok"] is True, resp
    assert resp["candidates"][0]["base"] == hex(_vector_ptr(RISCV_VECTOR_TABLE))
    assert resp["candidates"][0]["count"] >= 4


def test_vector_table_big_endian_does_not_hit_le_table():
    # The LE table bytes decode to unmapped values under big-endian reads.
    blob, mod = _load_fixture()
    resp = mod.firmware(action="detect_vector_table", word="u32", endian="be")
    assert resp["ok"] is True, resp
    bases = [c["base"] for c in resp["candidates"]]
    assert hex(_vector_ptr(RISCV_VECTOR_TABLE)) not in bases, bases


def test_vector_table_invalid_word_and_endian_error():
    blob, mod = _load_fixture()
    r1 = mod.firmware(action="detect_vector_table", word="u64", endian="le")
    assert r1["ok"] is False and r1["code"] == "INVALID_ARGS", r1
    r2 = mod.firmware(action="detect_vector_table", word="u32", endian="sideways")
    assert r2["ok"] is False and r2["code"] == "INVALID_ARGS", r2


# ---------------------------------------------------------------------------
# detect_load_base
# ---------------------------------------------------------------------------

def _load_fixture_with_insn_map():
    """Seed disasm so the reset vector and GP-init prologue decode."""
    insn_map = {
        LOAD_BASE: ("j", [_vector_ptr(RISCV_RESET_HANDLER)]),
        _vector_ptr(RISCV_RESET_HANDLER): ("auipc", ["gp", 0x80000]),
        _vector_ptr(RISCV_RESET_HANDLER) + 4: ("addi", ["gp", "gp", 0]),
    }
    return _load_fixture(insn_map=insn_map)


def test_detect_load_base_validates_known_base():
    blob, mod = _load_fixture_with_insn_map()
    resp = mod.firmware(action="detect_load_base")
    assert resp["ok"] is True, resp
    assert resp["recommended_base"] == hex(LOAD_BASE), resp
    top = resp["candidates"][0]
    assert top["base"] == hex(LOAD_BASE)
    assert top["confidence"] >= 0.8, top
    evidence = "\n".join(top["evidence"])
    assert "reset vector" in evidence and "jumps" in evidence, top
    assert "GP init" in evidence, top


def test_detect_load_base_explicit_candidates_rank_known_base_first():
    blob, mod = _load_fixture_with_insn_map()
    resp = mod.firmware(action="detect_load_base",
                        base_candidates=[hex(LOAD_BASE), "0x08000000"])
    assert resp["ok"] is True, resp
    assert resp["candidates"][0]["base"] == hex(LOAD_BASE)
    assert resp["candidates"][0]["confidence"] > resp["candidates"][1]["confidence"]


def test_detect_load_base_invalid_candidate_errors():
    blob, mod = _load_fixture_with_insn_map()
    resp = mod.firmware(action="detect_load_base", base_candidates=["not-an-addr"])
    assert resp["ok"] is False and resp["code"] == "INVALID_ARGS", resp


# ---------------------------------------------------------------------------
# detect_mmio
# ---------------------------------------------------------------------------

def test_detect_mmio_surfaces_uart_base():
    blob, mod = _load_fixture()
    resp = mod.firmware(action="detect_mmio")
    assert resp["ok"] is True, resp
    assert resp["registers_hint"]["distinct_pages"] >= 1, resp
    uart_page = hex(UART_ADDR & ~0xFFF)
    assert uart_page in [r["base"] for r in resp["ranges"]], resp
    uart_range = next(r for r in resp["ranges"] if r["base"] == uart_page)
    assert hex(UART_ADDR) in uart_range["example_registers"], uart_range
    assert uart_range["peripheral_name"], uart_range
    # The image's own page must not be reported as an MMIO window.
    assert "0x80000000" not in [r["base"] for r in resp["ranges"]], resp


def test_detect_mmio_addr_radius_narrows_window():
    blob, mod = _load_fixture()
    # Anchor at the blob offset that stores the UART base (0x800000A4) so the
    # radius genuinely narrows the window to a 128-byte slice.
    resp = mod.firmware(action="detect_mmio",
                        addr=hex(_vector_ptr(RISCV_UART_BASE)), addr_radius=64)
    assert resp["ok"] is True, resp
    assert hex(UART_ADDR & ~0xFFF) in [r["base"] for r in resp["ranges"]], resp
    assert resp["scan_window"]["start"] >= hex(_vector_ptr(RISCV_UART_BASE) - 64), resp


# ---------------------------------------------------------------------------
# rtos_scan
# ---------------------------------------------------------------------------

def test_rtos_scan_bare_fixture_has_no_matches():
    blob, mod = _load_fixture()
    resp = mod.firmware(action="rtos_scan")
    assert resp["ok"] is True, resp
    assert resp["matches"] == []
    assert resp["detected"] is None


def test_rtos_scan_detects_freertos_from_raw_bytes():
    data = bytearray(b"\x00\x00\x00\x00")
    data += b"FreeRTOS xTaskCreate vTaskDelay 0x00"
    data += bytes(16)
    blob = install_raw_blob(bytes(data), processor="riscv", bitness=32, base=0x1000)
    mod = blob.load_tool("firmware")
    resp = mod.firmware(action="rtos_scan")
    assert resp["ok"] is True, resp
    assert resp["detected"] == "FreeRTOS", resp
    freertos = next(m for m in resp["matches"] if m["rtos"] == "FreeRTOS")
    assert any("xtaskcreate" in e for e in freertos["evidence"]), freertos


def test_rtos_scan_query_filters_matches():
    data = bytearray(b"\x00\x00\x00\x00")
    data += b"FreeRTOS xTaskCreate 0x00"
    data += bytes(16)
    blob = install_raw_blob(bytes(data), processor="riscv", bitness=32, base=0x1000)
    mod = blob.load_tool("firmware")
    resp = mod.firmware(action="rtos_scan", query="freertos")
    assert resp["ok"] is True, resp
    assert resp["matches"], resp
    assert all("freertos" in m["rtos"].lower() for m in resp["matches"]), resp["matches"]


# ---------------------------------------------------------------------------
# carve
# ---------------------------------------------------------------------------

def _install_carve_stubs(blob):
    """Give the fake idaapi the segment_t/add_segm_ex surface carve needs."""
    idaapi = blob.module("idaapi")
    created = []

    class _Seg:
        def __init__(self):
            self.start_ea = 0
            self.end_ea = 0
            self.perm = 0

    def _add_segm_ex(seg, name, sclass, flags):
        created.append({"seg": seg, "name": name, "sclass": sclass, "flags": flags})
        return True

    idaapi.segment_t = _Seg
    idaapi.add_segm_ex = _add_segm_ex
    return created


def test_carve_defines_segment():
    blob, mod = _load_fixture()
    created = _install_carve_stubs(blob)
    resp = mod.firmware(action="carve", start="0x40000000", end="0x40001000",
                        name=".mmio", sclass="DATA")
    assert resp["ok"] is True, resp
    assert resp["start"] == "0x40000000"
    assert resp["end"] == "0x40001000"
    assert resp["name"] == ".mmio"
    assert resp["class"] == "DATA"
    assert resp["size"] == 0x1000
    assert created and created[0]["name"] == ".mmio"
    assert created[0]["seg"].start_ea == 0x40000000
    assert created[0]["seg"].end_ea == 0x40001000


def test_carve_code_class_sets_exec_perm():
    blob, mod = _load_fixture()
    created = _install_carve_stubs(blob)
    resp = mod.firmware(action="carve", start="0x40001000", end="0x40002000",
                        sclass="CODE")
    assert resp["ok"] is True, resp
    assert resp["perms"] == "rx", resp
    assert created[0]["seg"].perm & blob.module("idaapi").SEGPERM_EXEC


def test_carve_rejects_overlap():
    blob, mod = _load_fixture()
    _install_carve_stubs(blob)
    resp = mod.firmware(action="carve", start="0x80000000", end="0x80000100",
                        name="clash")
    assert resp["ok"] is False
    assert resp["code"] == "SEGMENT_OVERLAP"


def test_carve_requires_start_and_end():
    blob, mod = _load_fixture()
    resp = mod.firmware(action="carve", start="0x40000000")
    assert resp["ok"] is False and resp["code"] == "INVALID_ARGS", resp


# ---------------------------------------------------------------------------
# tool-level error paths
# ---------------------------------------------------------------------------

def test_unknown_action_errors():
    blob, mod = _load_fixture()
    resp = mod.firmware(action="retype_all")
    assert resp["ok"] is False and resp["code"] == "INVALID_ARGS", resp
    assert "detect_vector_table" in resp["message"]


def test_detection_without_mapped_bounds_errors():
    # No ida_ida/idaapi bounds in the bare stub -> IDA_ERROR with a clear hint.
    mod = load_tool_module("firmware")
    resp = mod.firmware(action="detect_vector_table", word="u32", endian="le")
    assert resp["ok"] is False and resp["code"] == "IDA_ERROR", resp
    assert "bounds" in resp["message"]
