"""Regression tests for the ida_segregs segment-register seam (WO-S1).

Pins the three public sreg actions added to the segments tool:
- sreg_get: read a segment register value at an address plus its range and type.
- sreg_set: write a segment register value (governed write, mirrors set_attr).
- sreg_list: enumerate the sreg ranges overlapping the address's segment.

Everything runs on per-file _FakeIda-style fakes of ida_segregs / ida_idp /
ida_segments modeled on the IDA 9.x Python API (``split_sreg_range(ea, rg, v,
tag, silent)``, ``get_sreg_range(out, ea, rg)``, ``get_sreg_ranges_qty`` /
``getn_sreg_range``) — no live IDA is required. A RISC-V GP / opaque raw-blob
scenario covers the firmware case the paper's segment-register seam targets.
"""
import inspect
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import load_tool_module

# sreg range tags (ida_segregs.SR_*)
SR_INHERIT = 0
SR_USER = 1
SR_AUTO = 2
BADSEL = -1

# Processor register table used by the fake ida_idp.ph; the first/last
# segment-register indices bracket the sreg registers.
_REG_NAMES = ["T", "CS", "DS", "SS", "FS", "GS", "GP"]
_REG_MAP = {name: i for i, name in enumerate(_REG_NAMES)}


class _MCPError:
    """Extended MCPError with the codes the segments tool emits."""

    INVALID_ARGS = "INVALID_ARGS"
    INVALID_ARG_TYPE = "INVALID_ARG_TYPE"
    SEGMENT_NOT_FOUND = "SEGMENT_NOT_FOUND"
    ADDRESS_NOT_MAPPED = "ADDRESS_NOT_MAPPED"
    IDA_ERROR = "IDA_ERROR"
    SEGMENT_OVERLAP = "SEGMENT_OVERLAP"
    ACTION_NOT_FOUND = "ACTION_NOT_FOUND"


class _SregRange:
    """Minimal stand-in for ida_segregs.sreg_range_t (start_ea/end_ea/val/tag)."""

    def __init__(self):
        self.start_ea = 0
        self.end_ea = 0
        self.val = BADSEL
        self.tag = SR_INHERIT


class _FakeSegregs:
    """In-memory model of the ida_segregs Python API (IDA 9.x surface).

    Each register keeps a sorted, non-overlapping list of [start, end, val, tag]
    ranges seeded with one inherited range covering [0, max_ea).  split_sreg_range
    sets the value from ``ea`` to the end of the containing range, mirroring the
    real "split one range into two and set a new value for the second range".
    """

    SR_inherit = SR_INHERIT
    SR_user = SR_USER
    SR_auto = SR_AUTO

    def __init__(self, max_ea=0x90000000):
        self._max_ea = max_ea
        self._ranges = {}

    def _ensure(self, reg):
        if reg not in self._ranges:
            self._ranges[reg] = [[0, self._max_ea, BADSEL, SR_INHERIT]]
        return self._ranges[reg]

    def _range_containing(self, reg, ea):
        for s, e, v, t in self._ensure(reg):
            if s <= ea < e:
                return (s, e, v, t)
        return None

    def _split_at(self, reg, ea):
        lst = self._ensure(reg)
        for i, r in enumerate(lst):
            s, e, v, t = r
            if s < ea < e:
                lst[i] = [s, ea, v, t]
                lst.insert(i + 1, [ea, e, v, t])
                return

    def _overwrite(self, reg, ea1, ea2, val, tag):
        self._split_at(reg, ea1)
        self._split_at(reg, ea2)
        lst = self._ensure(reg)
        out = []
        for s, e, v, t in lst:
            if e <= ea1 or s >= ea2:
                out.append([s, e, v, t])
                continue
            if s < ea1:
                out.append([s, ea1, v, t])
            if e > ea2:
                out.append([ea2, e, v, t])
        out.append([ea1, ea2, val, tag])
        out.sort(key=lambda r: r[0])
        merged = []
        for r in out:
            if merged and merged[-1][1] == r[0] and merged[-1][2] == r[2] and merged[-1][3] == r[3]:
                merged[-1][1] = r[1]
            else:
                merged.append(r)
        self._ranges[reg] = merged

    # -- public ida_segregs surface ----------------------------------------
    def get_sreg(self, ea, rg):
        found = self._range_containing(rg, ea)
        return found[2] if found else BADSEL

    def split_sreg_range(self, ea, rg, v, tag=SR_USER, silent=False):
        if ea < 0:
            return False
        found = self._range_containing(rg, ea)
        end = found[1] if found else self._max_ea
        self._overwrite(rg, ea, end, v, tag)
        return True

    def get_sreg_range(self, out, ea, rg):
        found = self._range_containing(rg, ea)
        if not found:
            return False
        out.start_ea, out.end_ea, out.val, out.tag = found
        return True

    def sreg_range_t(self):
        return _SregRange()

    def get_sreg_ranges_qty(self, rg):
        return len(self._ensure(rg))

    def getn_sreg_range(self, out, rg, n):
        lst = self._ensure(rg)
        if not (0 <= n < len(lst)):
            return False
        out.start_ea, out.end_ea, out.val, out.tag = lst[n]
        return True


def _build(segment, *, reg_names=None, max_ea=0x90000000, mapped=None):
    """Build fake IDA modules and load the segments tool against them."""
    reg_names = reg_names or list(_REG_NAMES)

    segregs = _FakeSegregs(max_ea=max_ea)

    ida_idp = types.ModuleType("ida_idp")
    ida_idp.ph = types.SimpleNamespace(
        reg_names=list(reg_names),
        reg_first_sreg=0,
        reg_last_sreg=len(reg_names) - 1,
    )
    ida_idp.str2reg = lambda name: _REG_MAP.get(str(name), -1)

    idaapi = types.ModuleType("idaapi")
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi.BADSEL = BADSEL
    idaapi.SEGPERM_READ = 1
    idaapi.SEGPERM_WRITE = 2
    idaapi.SEGPERM_EXEC = 4

    def _in_segment(ea):
        return segment.start_ea <= ea < segment.end_ea

    if mapped is None:
        mapped = (segment.start_ea, segment.end_ea)
    mapped_start, mapped_end = mapped

    def _in_mapped(ea):
        return mapped_start <= ea < mapped_end

    idaapi.getseg = lambda ea: segment if _in_segment(ea) else None
    idaapi.is_mapped = _in_mapped

    ida_segment = types.ModuleType("ida_segment")
    ida_segment.getseg = idaapi.getseg
    ida_segment.get_segm_name = lambda seg, flags=0: getattr(seg, "name", "")
    ida_segment.get_segm_class = lambda seg: getattr(seg, "sclass", "DATA")

    def validate_addr(addr, *a, **kw):
        ea = int(str(addr), 0)
        if not idaapi.is_mapped(ea):
            return None, {
                "ok": False,
                "code": "ADDRESS_NOT_MAPPED",
                "message": f"Address {hex(ea)} is not mapped in the database",
            }
        return ea, None

    idc = types.ModuleType("idc")
    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.STRTYPE_C = 0
    idautils = types.ModuleType("idautils")

    sys.modules["idaapi"] = idaapi
    sys.modules["idc"] = idc
    sys.modules["ida_nalt"] = ida_nalt
    sys.modules["ida_segment"] = ida_segment
    sys.modules["idautils"] = idautils
    sys.modules["ida_idp"] = ida_idp
    sys.modules["ida_segregs"] = segregs

    mod = load_tool_module(
        "segments",
        common_overrides={
            "idaapi": idaapi,
            "idc": idc,
            "ida_nalt": ida_nalt,
            "ida_segment": ida_segment,
            "idautils": idautils,
            "validate_addr": validate_addr,
            "MCPError": _MCPError,
        },
    )
    return mod, segregs, ida_idp


# ---------------------------------------------------------------------------
# Thumb T round-trip: define a segment, set T for a range, read it back, list it
# ---------------------------------------------------------------------------
class TestSregThumbRoundTrip(unittest.TestCase):
    def setUp(self):
        self.segment = types.SimpleNamespace(
            start_ea=0x1000, end_ea=0x1100, name=".text", sclass="CODE"
        )
        self.mod, self.segregs, _ = _build(self.segment)

    def test_sreg_set_writes_and_get_reads_back(self):
        set_result = self.mod.segments(action="sreg_set", start="0x1000", reg="T", value=1)
        self.assertTrue(set_result["ok"], set_result)
        self.assertEqual(set_result["reg"], "T")
        self.assertEqual(set_result["value"], 1)
        self.assertEqual(set_result["sr_type"], "signed")

        get_result = self.mod.segments(action="sreg_get", start="0x1000", reg="T")
        self.assertTrue(get_result["ok"], get_result)
        self.assertEqual(get_result["value"], 1)
        self.assertEqual(get_result["sr_type"], "signed")
        self.assertEqual(get_result["reg"], "T")
        self.assertEqual(get_result["range"]["start"], "0x1000")
        # split_sreg_range carries the value to the end of the containing range.
        self.assertGreaterEqual(int(get_result["range"]["end"], 16), 0x1100)

    def test_sreg_set_accepts_hex_string_value(self):
        set_result = self.mod.segments(action="sreg_set", start="0x1000", reg="T", value="0x10")
        self.assertTrue(set_result["ok"], set_result)
        self.assertEqual(set_result["value"], 16)
        get_result = self.mod.segments(action="sreg_get", start="0x1000", reg="T")
        self.assertEqual(get_result["value"], 16)

    def test_sreg_get_untouched_register_returns_badsel(self):
        get_result = self.mod.segments(action="sreg_get", start="0x1000", reg="SS")
        self.assertTrue(get_result["ok"], get_result)
        self.assertEqual(get_result["value"], BADSEL)

    def test_sreg_list_enumerates_the_set_range(self):
        self.mod.segments(action="sreg_set", start="0x1000", reg="T", value=1)
        result = self.mod.segments(action="sreg_list", start="0x1000")
        self.assertTrue(result["ok"], result)
        self.assertIsNone(result["reg"])  # no filter -> every segment register
        self.assertEqual(result["segment"], ".text")
        t_entries = [r for r in result["ranges"] if r["reg"] == "T"]
        self.assertEqual(len(t_entries), 1)
        self.assertEqual(t_entries[0]["value"], 1)
        self.assertEqual(t_entries[0]["sr_type"], "signed")
        self.assertEqual(t_entries[0]["start"], "0x1000")
        self.assertGreaterEqual(int(t_entries[0]["end"], 16), 0x1100)
        # Every record carries the full public shape.
        for record in result["ranges"]:
            for key in ("reg", "value", "sr_type", "start", "end"):
                self.assertIn(key, record)
        self.assertGreaterEqual(result["count"], 1)

    def test_sreg_list_filtered_by_register(self):
        self.mod.segments(action="sreg_set", start="0x1000", reg="T", value=1)
        result = self.mod.segments(action="sreg_list", start="0x1000", reg="T")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["reg"], "T")
        self.assertEqual(len(result["ranges"]), 1)
        self.assertEqual(result["ranges"][0]["value"], 1)
        self.assertEqual(result["ranges"][0]["start"], "0x1000")

    def test_sreg_set_default_sr_type_stores_inherit_tag(self):
        self.mod.segments(action="sreg_set", start="0x1000", reg="T", value=1, sr_type="default")
        get_result = self.mod.segments(action="sreg_get", start="0x1000", reg="T")
        self.assertEqual(get_result["value"], 1)
        self.assertEqual(get_result["sr_type"], "default")

    def test_action_literal_includes_sreg_actions(self):
        param = inspect.signature(self.mod.segments).parameters["action"]
        ann = param.annotation
        literal_type = getattr(ann, "__args__", (None,))[0]
        choices = tuple(getattr(literal_type, "__args__", ()))
        for name in ("sreg_get", "sreg_set", "sreg_list"):
            self.assertIn(name, choices)

    def test_docstring_documents_sreg_actions(self):
        doc = self.mod.segments.__doc__ or ""
        for name in ("sreg_get", "sreg_set", "sreg_list"):
            self.assertIn(name, doc)


# ---------------------------------------------------------------------------
# RISC-V GP on an opaque raw firmware blob
# ---------------------------------------------------------------------------
class TestSregRiscvGpRawBlob(unittest.TestCase):
    def setUp(self):
        # A bare ROM image at a high address — no ELF metadata, GP must be
        # fixed manually, which is exactly the seam the paper asks for.
        self.segment = types.SimpleNamespace(
            start_ea=0x80000000, end_ea=0x80010000, name="ROM", sclass="CODE"
        )
        self.mod, self.segregs, _ = _build(self.segment)

    def test_gp_set_get_round_trip(self):
        set_result = self.mod.segments(action="sreg_set", start="0x80000000", reg="GP", value=0x80002000)
        self.assertTrue(set_result["ok"], set_result)
        self.assertEqual(set_result["reg"], "GP")
        self.assertEqual(set_result["value"], 0x80002000)

        get_result = self.mod.segments(action="sreg_get", start="0x80000000", reg="GP")
        self.assertTrue(get_result["ok"], get_result)
        self.assertEqual(get_result["reg"], "GP")
        self.assertEqual(get_result["value"], 0x80002000)
        self.assertEqual(get_result["range"]["start"], "0x80000000")
        self.assertGreaterEqual(int(get_result["range"]["end"], 16), 0x80010000)

    def test_gp_list_shows_the_value(self):
        self.mod.segments(action="sreg_set", start="0x80000000", reg="GP", value=0x80002000)
        result = self.mod.segments(action="sreg_list", start="0x80000000", reg="GP")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["reg"], "GP")
        self.assertEqual(len(result["ranges"]), 1)
        self.assertEqual(result["ranges"][0]["value"], 0x80002000)
        self.assertEqual(result["ranges"][0]["start"], "0x80000000")
        self.assertEqual(result["ranges"][0]["sr_type"], "signed")


# ---------------------------------------------------------------------------
# Error handling / governed-write pre-check (mirrors set_attr)
# ---------------------------------------------------------------------------
class TestSregErrorHandling(unittest.TestCase):
    def setUp(self):
        self.segment = types.SimpleNamespace(
            start_ea=0x1000, end_ea=0x1100, name=".text", sclass="CODE"
        )
        self.mod, self.segregs, _ = _build(self.segment)

    def test_sreg_set_missing_reg(self):
        result = self.mod.segments(action="sreg_set", start="0x1000", value=1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_ARGS")

    def test_sreg_set_missing_value(self):
        result = self.mod.segments(action="sreg_set", start="0x1000", reg="T")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_ARGS")

    def test_sreg_set_bad_sr_type(self):
        result = self.mod.segments(action="sreg_set", start="0x1000", reg="T", value=1, sr_type="tiny")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_ARGS")

    def test_sreg_set_unknown_register(self):
        result = self.mod.segments(action="sreg_set", start="0x1000", reg="ZZ", value=1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_ARGS")

    def test_sreg_set_non_numeric_value(self):
        result = self.mod.segments(action="sreg_set", start="0x1000", reg="T", value="not-a-number")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_ARG_TYPE")

    def test_sreg_set_unmapped_address_rejected(self):
        # validate_addr's is_mapped pre-check must reject before any write.
        result = self.mod.segments(action="sreg_set", start="0x9999", reg="T", value=1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "ADDRESS_NOT_MAPPED")
        self.assertEqual(self.segregs.get_sreg(0x9999, _REG_MAP["T"]), BADSEL)

    def test_sreg_get_missing_reg(self):
        result = self.mod.segments(action="sreg_get", start="0x1000")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_ARGS")

    def test_sreg_get_unknown_register(self):
        result = self.mod.segments(action="sreg_get", start="0x1000", reg="ZZ")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_ARGS")

    def test_sreg_list_unknown_register(self):
        result = self.mod.segments(action="sreg_list", start="0x1000", reg="ZZ")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_ARGS")


class TestSregNoSegmentDefensivePath(unittest.TestCase):
    def setUp(self):
        self.segment = types.SimpleNamespace(
            start_ea=0x1000, end_ea=0x1100, name=".text", sclass="CODE"
        )
        # A mapped region wider than the segment exercises the defensive
        # "mapped but no segment" SEGMENT_NOT_FOUND path.
        self.mod, self.segregs, _ = _build(self.segment, mapped=(0x1000, 0x1300))

    def test_sreg_get_mapped_but_no_segment(self):
        result = self.mod.segments(action="sreg_get", start="0x1200", reg="T")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "SEGMENT_NOT_FOUND")

    def test_sreg_set_mapped_but_no_segment(self):
        result = self.mod.segments(action="sreg_set", start="0x1200", reg="T", value=1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "SEGMENT_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
