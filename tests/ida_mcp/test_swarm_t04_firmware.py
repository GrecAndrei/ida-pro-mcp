"""Regression tests for t04_firmware swarm audit fixes.

Covers (each maps to a confirmed finding in the t04 audit):
- firmware_view endianness: detect_* actions now unpack words with the IDB's
  native endianness via _inf_is_be() instead of hardcoded little-endian '<I'.
- rollback_last: del_items is a C void API, so a clean call is reported as
  rolled_back:1 instead of being read in a boolean context (always 0).
- detect_mmio: all-ones (-1 / 0xFFFFFFFF) values are rejected as MMIO hits
  instead of false-positiving against ARM_system_space.
- _fwb_run_vector_bootstrap: only segments that were actually mutated count
  toward segments_fixed, and segments carrying defined items (.rodata/.data
  on a real ELF/PE) are no longer force-reclassified to executable CODE.
- governance: firmware_view renames/comments now route through
  evaluate_operation (blocked renames skipped, PII redacted) like the sibling
  modify/annotation write tools.
"""
import os
import struct
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import load_tool_module


def _load(overrides=None):
    m = load_tool_module("firmware_view", common_overrides=overrides or {})
    # The test _common stub does not export underscore-prefixed helpers through
    # `from ._common import *` (the real module does, via __all__), so tests
    # set the ones they need directly on the loaded module.
    m._inf_is_be = lambda: False
    m._inf_is_64bit = lambda: False
    m._inf_min_ea = lambda: 0x1000
    m._inf_max_ea = lambda: 0x2000
    m._inf_procname = lambda: "arm"
    m._inf_filetype_id = lambda: 0
    m.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    return m


class _Seg:
    def __init__(self, start, end, stype, perm, cls):
        self.start_ea = start
        self.end_ea = end
        self.type = stype
        self.perm = perm
        self._class = cls

    def __repr__(self):
        return f"_Seg({hex(self.start_ea)}, class={self._class}, type={self.type})"


class TestEndiannessHelpers(unittest.TestCase):
    """_fw_u32_fmt/_fw_u64_fmt key off IDB endianness (finding: '<I' hardcode)."""

    def setUp(self):
        self.mod = _load()

    def test_little_endian_formats(self):
        self.mod._inf_is_be = lambda: False
        self.assertEqual(self.mod._fw_u32_fmt(), "<I")
        self.assertEqual(self.mod._fw_u64_fmt(), "<Q")

    def test_big_endian_formats(self):
        self.mod._inf_is_be = lambda: True
        self.assertEqual(self.mod._fw_u32_fmt(), ">I")
        self.assertEqual(self.mod._fw_u64_fmt(), ">Q")


class TestDetectLoadAddressBigEndian(unittest.TestCase):
    """detect_load_address reads SP/reset vector with native endianness."""

    def setUp(self):
        self.mod = _load()
        self.mod._inf_is_be = lambda: True
        # Big-endian Cortex-M vector table: SP=0x20000000, reset=0x08000401 (Thumb).
        self.mod.ida_bytes.get_bytes = lambda ea, size: struct.pack(">II", 0x20000000, 0x08000401)

    def test_big_endian_sp_and_reset_vector(self):
        result = self.mod.firmware_view(action="detect_load_address")
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["candidates"], result)
        cand = result["candidates"][0]
        self.assertEqual(cand["method"], "cortex_m_vector_table")
        self.assertEqual(cand["base"], "0x8000000")
        self.assertTrue(cand["thumb"])
        self.assertEqual(cand["reset_handler"], "0x8000400")


class TestDetectMmioAllOnesGuard(unittest.TestCase):
    """detect_mmio rejects 0xFFFFFFFF instead of matching ARM_system_space."""

    def setUp(self):
        self.mod = _load()
        self.mod.ida_bytes.get_bytes = lambda ea, size: b"\xff" * min(size, 4096)
        self.mod.idautils.Segments = lambda: iter([])

    def test_all_ones_words_are_not_mmio(self):
        result = self.mod.firmware_view(action="detect_mmio")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["peripheral_count"], 0)
        self.assertEqual(result["likely_chip_family"], "unknown")
        self.assertEqual(result["peripherals"], [])


class TestRollbackLastDelItemsVoid(unittest.TestCase):
    """rollback_last reports rolled_back:1 because del_items is void."""

    def setUp(self):
        self.mod = _load()
        self.del_items_calls = []
        self.mod.ida_bytes.DELIT_SIMPLE = 0
        # del_items is a C void API: it returns None on success. The old code
        # read it in a boolean context and always reported rolled_back:0.
        self.mod.ida_bytes.del_items = lambda ea, flags, size: self.del_items_calls.append((ea, flags, size))
        self.saved = {}
        self.mod._load_fw_state = lambda: {
            "history": [{"ea": "0x1234", "size": 4, "prev_kind": "unknown"}],
            "contradictions": [],
            "campaigns": {},
            "fingerprint_corpus": [],
        }
        self.mod._save_fw_state = self.saved.update

    def test_successful_del_items_is_rolled_back_1(self):
        result = self.mod.firmware_view(action="rollback_last")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["rolled_back"], 1)
        self.assertEqual(self.del_items_calls, [(0x1234, 0, 4)])
        self.assertEqual(result["remaining_history"], 0)


class TestVectorBootstrapSegmentsFixed(unittest.TestCase):
    """_fwb_run_vector_bootstrap only counts segments actually mutated and
    leaves segments that already carry defined items alone."""

    def setUp(self):
        self.mod = _load()
        self.mod.firmware_view = lambda **kw: {"vectors": []}
        self.segments = {
            0x1000: _Seg(0x1000, 0x1400, 0x02, 0x00, "DATA"),  # has defined items -> skipped
            0x2000: _Seg(0x2000, 0x2400, 0x02, 0x00, "DATA"),  # raw BSS/DATA -> fixed
            0x3000: _Seg(0x3000, 0x3400, 0x20, 0x04, "CODE"),  # already CODE/EXEC -> no fix
        }
        self.mod.idautils.Segments = lambda: iter(list(self.segments))
        self.mod.idaapi.getseg = self.segments.get
        self.mod.idaapi.SEG_CODE = 0x20
        self.mod.idaapi.SEGPERM_EXEC = 0x04
        # Only segment A (0x1000) carries defined items.
        self.mod.ida_bytes.get_flags = lambda ea: 0x10 if ea == 0x1000 else 0
        self.mod.ida_bytes.is_code = lambda f: bool(f & 0x10)
        self.mod.ida_bytes.is_data = lambda f: bool(f & 0x20)
        self.mod.idc.get_item_size = lambda ea: 1
        self.mod.ida_segment.get_segm_class = lambda seg: seg._class
        self.mod.ida_segment.set_segm_class = lambda seg, cls: setattr(seg, "_class", cls)
        self.mod.ida_segment.update_segm = lambda seg: None

    def test_segments_fixed_counts_only_mutated_segments(self):
        result = self.mod._fwb_run_vector_bootstrap()
        # Segment A had items -> skipped. Segment C needed no change -> not counted.
        # Only segment B was upgraded -> exactly 1.
        self.assertEqual(result["segments_fixed"], 1)
        self.assertEqual(self.segments[0x1000]._class, "DATA")  # untouched
        self.assertEqual(self.segments[0x2000]._class, "CODE")  # upgraded
        self.assertEqual(self.segments[0x2000].type, 0x20)
        self.assertEqual(self.segments[0x2000].perm & 0x04, 0x04)


class TestAnnotateMmioGovernance(unittest.TestCase):
    """_fwb_annotate_mmio routes renames/comments through the governance engine."""

    def setUp(self):
        self.mod = _load()
        self.mod._fwb_int_addr = lambda v: int(str(v), 0)
        self.name_calls = []
        self.cmt_calls = []
        self.mod.idc.set_name = lambda ea, name, flags: self.name_calls.append((ea, name, flags))
        self.mod.idc.set_cmt = lambda ea, cmt, rpt: self.cmt_calls.append((ea, cmt, rpt))
        self.mod.ida_name.SN_FORCE = 0x20

    def test_normal_peripheral_annotated(self):
        result = self.mod._fwb_annotate_mmio([{"name": "GPIOA", "addr": "0x40000000"}])
        self.assertEqual(result, {"peripherals_annotated": 1, "peripherals_blocked": 0})
        self.assertEqual(self.name_calls, [(0x40000000, "GPIOA_BASE", 0x20)])
        self.assertEqual(self.cmt_calls, [(0x40000000, "MMIO base for GPIOA", 1)])

    def test_blocked_rename_is_skipped(self):
        self.mod._govern_evaluate = lambda **kw: {
            "approved": False,
            "verdict": "blocked",
            "violations": [{"rule": "R003", "description": "blocked"}],
            "redacted_content": kw["proposed_value"],
        }
        result = self.mod._fwb_annotate_mmio([{"name": "GPIOA", "addr": "0x40000000"}])
        self.assertEqual(result, {"peripherals_annotated": 0, "peripherals_blocked": 1})
        self.assertEqual(self.name_calls, [])
        self.assertEqual(self.cmt_calls, [])

    def test_comment_pii_is_redacted(self):
        # Uses the real governance engine (PII redaction is on by default).
        # Note: the IP must be word-boundary-delimited in the comment (an
        # underscore prefix would suppress the regex's \\b match).
        result = self.mod._fwb_annotate_mmio([{"name": "iface 10.0.0.1", "addr": "0x40000000"}])
        self.assertEqual(result["peripherals_annotated"], 1)
        self.assertEqual(result["peripherals_blocked"], 0)
        # Comment carrying the IP address is redacted before set_cmt.
        self.assertEqual(len(self.cmt_calls), 1)
        self.assertIn("[IP_REDACTED]", self.cmt_calls[0][1])

    def test_govern_degrades_to_allowed_when_engine_unavailable(self):
        self.mod._govern_evaluate = None
        ok, value = self.mod._fwb_govern("rename", 0x4000, "GPIOA_BASE")
        self.assertTrue(ok)
        self.assertEqual(value, "GPIOA_BASE")


if __name__ == "__main__":
    unittest.main()
