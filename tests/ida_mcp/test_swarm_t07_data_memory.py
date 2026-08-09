"""Regression tests for the t07_data_memory audit fixes.

Covers (each maps to a confirmed finding in the t07 audit):
- memory(write) runs the deterministic governance pre-check by default, the
  same layer modify(patch_bytes) honors — an executable (.text) patch is
  blocked while a .data patch proceeds.
- memory(write) surfaces patch_bytes' real written count: a failed/partial
  patch returns IDA_ERROR instead of reporting the requested size as ok:true.
- memory(search) with an integer wider than int_width no longer degrades to a
  wrong UTF-8 text search: it widens to the pointer size when the value fits,
  and returns INVALID_ARGS when it cannot fit the effective width.
- memory(compare) accepts addr1/addr2 without a single `addr`.
- memory(read, type=string) falls back to the single-argument
  idc.get_strlit_contents form on IDA versions whose 3-arg form is unsupported.
"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import load_tool_module


def _blank_modules(names):
    for name in names:
        sys.modules.setdefault(name, types.ModuleType(name))


def _load_memory(bitness=64, ida_bytes=None, idc=None, ida_segment=None):
    if ida_bytes is None:
        ida_bytes = types.ModuleType("ida_bytes")
    if idc is None:
        idc = types.ModuleType("idc")
    if ida_segment is None:
        ida_segment = types.ModuleType("ida_segment")
    _blank_modules(["idaapi", "idautils", "ida_funcs", "ida_name", "ida_typeinf",
                    "ida_nalt", "ida_hexrays", "ida_frame", "ida_struct",
                    "ida_lines", "ida_ua", "ida_kernwin", "ida_loader",
                    "ida_dbg", "ida_fixup"])
    sys.modules["ida_bytes"] = ida_bytes
    sys.modules["idc"] = idc
    sys.modules["ida_segment"] = ida_segment
    overrides = {
        "ida_bytes": ida_bytes,
        "idc": idc,
        "ida_segment": ida_segment,
    }
    mem = load_tool_module("memory", common_overrides=overrides)
    mem.MCPError.GOVERNANCE_BLOCKED = "GOVERNANCE_BLOCKED"
    # The real _common re-exports these underscore helpers via __all__, so
    # `from ._common import *` picks them up in IDA; the test stub has no
    # __all__, so bind them on the loaded module explicitly.
    mem._inf_bitness = lambda: bitness
    mem._inf_is_be = lambda: False
    mem._inf_min_ea = lambda: 0x1000
    return mem


class _Seg:
    """Minimal segment mock carrying permissions."""

    def __init__(self, name, perm):
        self.name = name
        self.perm = perm


class TestMemoryWriteGovernance(unittest.TestCase):
    def setUp(self):
        self.mem = _load_memory()
        self.ida_bytes = self.mem.ida_bytes
        self.seg = self.mem.ida_segment
        self.seg.SEGPERM_X = 1
        # Default: a non-executable, non-import segment so governance approves.
        self.seg.getseg = lambda ea: _Seg(".data", 3)
        self.seg.get_segm_name = lambda seg: seg.name
        self.patched = []
        self.ida_bytes.patch_bytes = lambda ea, buf: (self.patched.append((ea, buf)) or len(buf))

    def test_write_to_executable_section_is_blocked(self):
        # Real governance engine + real metadata: patching .text must be blocked,
        # matching modify(patch_bytes), and patch_bytes must not be called.
        self.seg.getseg = lambda ea: _Seg(".text", 5)  # executable
        res = self.mem._memory_impl("write", "0x1000", "bytes", 16, "90 90", None, 2)
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "GOVERNANCE_BLOCKED")
        self.assertEqual(self.patched, [])

    def test_write_to_data_section_is_approved(self):
        res = self.mem._memory_impl("write", "0x1000", "bytes", 16, "90 90", None, 2)
        self.assertIs(res["ok"], True)
        self.assertEqual(res["size"], 2)
        self.assertEqual(self.patched, [(0x1000, bytes([0x90, 0x90]))])

    def test_write_governance_engine_block_respected(self):
        # Governance rejection short-circuits before patch_bytes.
        self.mem.evaluate_operation = lambda **kw: {
            "approved": False, "verdict": "blocked",
            "violations": [{"rule_id": "R001"}],
            "ontology_class": "PATCH", "axiom_score": 0.0,
        }
        res = self.mem._memory_impl("write", "0x1000", "bytes", 16, "90 90", None, 2)
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "GOVERNANCE_BLOCKED")
        self.assertEqual(self.patched, [])

    def test_write_governed_false_bypasses(self):
        # Explicit bypass (matches modify's governed=False escape hatch).
        self.mem.evaluate_operation = lambda **kw: (_ for _ in ()).throw(
            AssertionError("governance must be skipped when governed=False"))
        res = self.mem._memory_impl("write", "0x1000", "bytes", 16, "90 90", None, 2,
                                    governed=False)
        self.assertIs(res["ok"], True)
        self.assertEqual(self.patched, [(0x1000, bytes([0x90, 0x90]))])


class TestMemoryWritePartialPatch(unittest.TestCase):
    def setUp(self):
        self.mem = _load_memory()
        self.mem.evaluate_operation = lambda **kw: {"approved": True, "verdict": "approved", "violations": []}
        seg = self.mem.ida_segment
        seg.SEGPERM_X = 1
        seg.getseg = lambda ea: _Seg(".data", 3)
        seg.get_segm_name = lambda s: s.name

    def test_zero_bytes_written_reports_error(self):
        self.mem.ida_bytes.patch_bytes = lambda ea, buf: 0
        res = self.mem._memory_impl("write", "0x1000", "bytes", 16, "90 90", None, 2)
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "IDA_ERROR")

    def test_partial_write_reports_error(self):
        self.mem.ida_bytes.patch_bytes = lambda ea, buf: 1  # wrote 1 of 2
        res = self.mem._memory_impl("write", "0x1000", "bytes", 16, "90 90", None, 2)
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "IDA_ERROR")


class TestMemorySearchIntegerOverflow(unittest.TestCase):
    def setUp(self):
        self.mem = _load_memory(bitness=64)
        self.ida_bytes = self.mem.ida_bytes

    def test_wide_integer_widens_to_pointer_size(self):
        # 64-bit pointer value with default int_width=4: must widen to 8 bytes
        # and match, not degrade to a 0-hit UTF-8 text search.
        pat = bytes.fromhex("88 77 66 55 44 33 22 11")
        self.ida_bytes.get_bytes = lambda ea, n: pat + b"\x00" * (n - len(pat))
        res = self.mem._memory_impl("search", "0x1000", "bytes", 16, "0x1122334455667788", None, 2)
        self.assertIs(res["ok"], True)
        self.assertEqual(res["mode"], "integer")
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["hits"], ["0x1000"])

    def test_unfittable_integer_returns_invalid_args(self):
        # 32-bit binary: a 64-bit value cannot fit any width — loud error, not
        # a silent wrong 0-hit result.
        self.mem._inf_bitness = lambda: 32
        self.ida_bytes.get_bytes = lambda ea, n: b"\x00" * n
        res = self.mem._memory_impl("search", "0x1000", "bytes", 16, "0x1122334455667788", None, 2)
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "INVALID_ARGS")

    def test_integer_fitting_requested_width_still_matches(self):
        pat = bytes.fromhex("44 33 22 11")
        self.ida_bytes.get_bytes = lambda ea, n: pat + b"\x00" * (n - len(pat))
        res = self.mem._memory_impl("search", "0x1000", "bytes", 16, "0x11223344", None, 2)
        self.assertIs(res["ok"], True)
        self.assertEqual(res["mode"], "integer")
        self.assertEqual(res["count"], 1)


class TestMemoryCompareRegions(unittest.TestCase):
    def test_compare_with_addr1_addr2_only(self):
        # Documented schema form (addr1/addr2) must not hit the generic
        # "addr required" guard.
        mem = _load_memory()
        mem.ida_bytes.get_bytes = lambda ea, n: (
            bytes([1, 2, 3, 4]) if ea == 0x1000 else bytes([1, 9, 3, 4])
        )
        res = mem._memory_impl("compare", None, "bytes", 16, None, None, 2,
                               addr1="0x1000", addr2="0x2000")
        self.assertIs(res["ok"], True)
        self.assertEqual(res["addr1"], "0x1000")
        self.assertEqual(res["addr2"], "0x2000")
        self.assertEqual(res["diff_count"], 1)


class TestMemoryReadStringFallback(unittest.TestCase):
    def test_string_read_falls_back_to_single_arg_form(self):
        mem = _load_memory()

        def _get_strlit(*args):
            if len(args) == 3:
                raise TypeError("three-arg form unsupported on this IDA")
            return b"hello world"

        mem.idc.get_strlit_contents = _get_strlit
        res = mem._memory_impl("read", "0x1000", "string", 16, None, None, 2)
        self.assertIs(res["ok"], True)
        self.assertEqual(res["value"], "hello world")
        self.assertEqual(res["length"], 11)


if __name__ == "__main__":
    unittest.main()
