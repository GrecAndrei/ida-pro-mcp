"""Regression tests for t08_idb_segments swarm fixes.

Covers (each maps to a confirmed finding in the t08 work order):
- segments find_data: string-literal values are decoded to str (never raw
  bytes), so the result stays JSON-RPC serializable.
- segments _seg_import_count: the enum_import_names callback returns True so
  IDA keeps enumerating — import counts are correct instead of 0/1.
- segments move: the destination address is parsed but NOT required to be
  mapped, so relocating to a free region works (the primary move_segm use case).
- idb_meta: compiler cc_id mapping matches IDA's stored INF_CC_ID nibble
  (COMP_GNU=6, COMP_VISAGE=7, COMP_BP=8) — verified against IDA 9.3's own
  idc.idc constants and a live headless idat run.
- idb_state open_seconds: returns a duration (max(idb_age, 60)) instead of an
  epoch timestamp, with no discontinuity at 60s.
"""
import json
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import load_tool_module


def _seg(start=0x1000, end=0x1100, name=".data"):
    return types.SimpleNamespace(start_ea=start, end_ea=end, name=name)


def _blank_modules(names):
    for name in names:
        sys.modules.setdefault(name, types.ModuleType(name))


# ---------------------------------------------------------------------------
# segments: find_data decodes string values to JSON-safe str
# ---------------------------------------------------------------------------
class TestFindDataStrlitValuesJsonSafe(unittest.TestCase):
    def setUp(self):
        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        idaapi.getseg = lambda ea: _seg() if ea == 0x1000 else None

        idc = types.ModuleType("idc")
        idc.get_strlit_contents = lambda ea, *a, **kw: {
            0x1000: b"hello\xffworld",
            0x1010: b"plain",
        }.get(ea)

        ida_bytes = types.ModuleType("ida_bytes")
        ida_bytes.get_flags = lambda ea: 1 if ea == 0x1000 else 2
        ida_bytes.is_data = lambda f: True
        ida_bytes.is_strlit = lambda f: f == 1
        ida_bytes.get_item_size = lambda ea: 8 if ea == 0x1000 else 4
        ida_bytes.get_long = lambda ea: 0x11223344
        ida_bytes.get_qword = lambda ea: 0x1122334455667788

        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.STRTYPE_C = 0

        ida_segment = types.ModuleType("ida_segment")
        ida_segment.get_segm_name = lambda seg: getattr(seg, "name", "")

        idautils = types.ModuleType("idautils")

        def next_head(ea, end):
            if ea == 0x1000:
                return 0x1010
            return idaapi.BADADDR

        idc.next_head = next_head

        _blank_modules(["ida_typeinf", "ida_name", "ida_lines", "ida_funcs",
                        "ida_hexrays", "ida_frame", "ida_struct", "ida_ua",
                        "ida_kernwin", "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_bytes"] = ida_bytes
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["ida_segment"] = ida_segment
        sys.modules["idautils"] = idautils
        self.mod = load_tool_module(
            "segments",
            common_overrides={"idaapi": idaapi, "idc": idc, "ida_bytes": ida_bytes,
                              "ida_nalt": ida_nalt, "ida_segment": ida_segment,
                              "idautils": idautils},
        )

    def test_data_item_string_value_is_decoded_str(self):
        result = self.mod.segments(action="find_data", start="0x1000")
        self.assertTrue(result["ok"], result)
        data_items = result["data_items"]
        self.assertEqual(data_items[0]["type"], "string")
        self.assertIsInstance(data_items[0]["value"], str)
        self.assertEqual(data_items[0]["value"], "hello�world")
        # A non-string data item keeps its numeric form.
        self.assertEqual(data_items[1]["type"], "data")
        self.assertEqual(data_items[1]["value"], "0x11223344")
        # Whole payload must be JSON-serializable (the old code embedded bytes).
        json.dumps(result)

    def test_strings_list_also_json_safe(self):
        result = self.mod.segments(action="find_data", start="0x1000")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["strings"][0]["value"], "hello�world")
        self.assertIsInstance(result["strings"][0]["value"], str)
        json.dumps(result)


# ---------------------------------------------------------------------------
# segments: _seg_import_count enumerates every import
# ---------------------------------------------------------------------------
class TestSegImportCountContinuesEnumeration(unittest.TestCase):
    def setUp(self):
        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.STRTYPE_C = 0
        ida_nalt.get_import_module_qty = lambda: 1
        # Faithful IDA semantics: a falsy callback return stops the walk.
        imports = [(0x3000, "first_outside"), (0x1500, "inside"), (0x4000, "last_outside")]

        def enum_import_names(idx, cb):
            for ea, name in imports:
                if not cb(ea, name, 0):
                    break

        ida_nalt.enum_import_names = enum_import_names
        idc = types.ModuleType("idc")
        idautils = types.ModuleType("idautils")
        _blank_modules(["ida_typeinf", "ida_segment", "ida_name", "ida_lines",
                        "ida_bytes", "ida_funcs", "ida_hexrays", "ida_frame",
                        "ida_struct", "ida_ua", "ida_kernwin", "ida_loader",
                        "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["idautils"] = idautils
        self.mod = load_tool_module(
            "segments",
            common_overrides={"idaapi": idaapi, "idc": idc, "ida_nalt": ida_nalt,
                              "idautils": idautils},
        )

    def test_all_imports_visited(self):
        seg = _seg(start=0x1000, end=0x2000)
        # Only 0x1500 falls inside the segment; the old callback returned None
        # (falsy), so IDA stopped after 0x3000 and counted 0.
        self.assertEqual(self.mod._seg_import_count(seg), 1)


# ---------------------------------------------------------------------------
# segments: move destination need not be mapped
# ---------------------------------------------------------------------------
class TestMoveToUnmappedRegion(unittest.TestCase):
    def setUp(self):
        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        src = _seg(start=0x1000, end=0x2000, name=".text")
        idaapi.getseg = lambda ea: src if ea == 0x1000 else None
        idaapi.is_mapped = lambda ea: False  # NOTHING is mapped, incl. dest
        idaapi.MOVE_SEGM_OK = 0
        calls = {}

        def move_segm(seg, to, flags):
            calls["to"] = to
            return idaapi.MOVE_SEGM_OK

        idaapi.move_segm = move_segm
        self.calls = calls

        idc = types.ModuleType("idc")
        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.STRTYPE_C = 0
        idautils = types.ModuleType("idautils")
        _blank_modules(["ida_typeinf", "ida_segment", "ida_name", "ida_lines",
                        "ida_bytes", "ida_funcs", "ida_hexrays", "ida_frame",
                        "ida_struct", "ida_ua", "ida_kernwin", "ida_loader",
                        "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["idautils"] = idautils
        self.mod = load_tool_module(
            "segments",
            common_overrides={"idaapi": idaapi, "idc": idc, "ida_nalt": ida_nalt,
                              "idautils": idautils},
        )

    def test_move_to_unmapped_destination_succeeds(self):
        result = self.mod.segments(action="move", start="0x1000", end="0x9000")
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.calls["to"], 0x9000)
        self.assertEqual(result["new"], "0x9000")


# ---------------------------------------------------------------------------
# segments: add action resolves parse_address_safe (import availability)
# ---------------------------------------------------------------------------
class TestAddActionResolvesParseAddressSafe(unittest.TestCase):
    def setUp(self):
        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        idaapi.getseg = lambda ea: None
        idaapi.segment_t = types.SimpleNamespace
        idaapi.add_segm_ex = lambda seg, name, sclass, flags: True
        idc = types.ModuleType("idc")
        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.STRTYPE_C = 0
        ida_segment = types.ModuleType("ida_segment")
        idautils = types.ModuleType("idautils")
        _blank_modules(["ida_typeinf", "ida_name", "ida_lines", "ida_bytes",
                        "ida_funcs", "ida_hexrays", "ida_frame", "ida_struct",
                        "ida_ua", "ida_kernwin", "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["ida_segment"] = ida_segment
        sys.modules["idautils"] = idautils
        self.mod = load_tool_module(
            "segments",
            common_overrides={"idaapi": idaapi, "idc": idc, "ida_nalt": ida_nalt,
                              "ida_segment": ida_segment, "idautils": idautils},
        )

    def test_add_uses_parse_address_safe_without_nameerror(self):
        result = self.mod.segments(action="add", start="0x2000", end="0x3000",
                                   name=".foo", sclass="DATA")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["start"], "0x2000")
        self.assertEqual(result["end"], "0x3000")


# ---------------------------------------------------------------------------
# idb: compiler cc_id map matches IDA's stored INF_CC_ID nibble
# ---------------------------------------------------------------------------
def _load_idb_module(cc_id, *, get_idb_path="/tmp/test.i64", mtime=None, now=None):
    idaapi = types.ModuleType("idaapi")
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi.get_idb_path = lambda: get_idb_path
    idaapi.get_input_file_path = lambda: ""
    idaapi.auto_state = lambda: 2
    idaapi.get_auto_display = lambda: ""
    idaapi.auto_is_ok = lambda: True
    idaapi.get_func_qty = lambda: 10
    idaapi.get_strlist_qty = lambda: 5
    idaapi.is_debugger_on = lambda: False
    idaapi.get_process_state = lambda: 0

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_cc_id = lambda: cc_id
    ida_ida.inf_get_min_ea = lambda: 0x1000
    ida_ida.inf_get_max_ea = lambda: 0x9000
    ida_ida.inf_get_baseaddr = lambda: 0x400000
    ida_ida.inf_is_dll = lambda: False
    ida_ida.inf_is_be = lambda: False

    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.get_input_file_path = lambda: "input.bin"
    ida_nalt.get_import_module_qty = lambda: 3

    ida_entry = types.ModuleType("ida_entry")
    ida_entry.get_entry_qty = lambda: 2

    ida_kernwin = types.ModuleType("ida_kernwin")
    ida_kernwin.get_cursor_ea = lambda: idaapi.BADADDR

    idc = types.ModuleType("idc")
    idautils = types.ModuleType("idautils")
    ida_segment = types.ModuleType("ida_segment")
    _blank_modules(["ida_typeinf", "ida_name", "ida_lines", "ida_bytes",
                    "ida_funcs", "ida_hexrays", "ida_frame", "ida_struct",
                    "ida_ua", "ida_loader", "ida_dbg"])
    sys.modules["idaapi"] = idaapi
    sys.modules["idc"] = idc
    sys.modules["ida_ida"] = ida_ida
    sys.modules["ida_nalt"] = ida_nalt
    sys.modules["ida_entry"] = ida_entry
    sys.modules["ida_kernwin"] = ida_kernwin
    sys.modules["idautils"] = idautils
    sys.modules["ida_segment"] = ida_segment
    mod = load_tool_module(
        "idb",
        common_overrides={"idaapi": idaapi, "idc": idc, "idautils": idautils},
    )
    # `import *` skips underscore-prefixed names, so inject the filetype helpers
    # directly (mirrors test_p13_ida_infra).
    mod._inf_filetype_id = lambda: 11
    mod._filetype_name = lambda ft: "elf"
    mod._inf_procname = lambda: "metapc"
    mod._inf_bitness = lambda: 64
    return mod


class TestCompilerMap(unittest.TestCase):
    def _compiler_for(self, cc_id):
        mod = _load_idb_module(cc_id)
        meta = mod.idb_meta()
        return meta["compiler"]

    def test_gnu_is_id_6(self):
        # Verified live: a GCC AND a clang-built ELF both report cc_id=6.
        self.assertEqual(self._compiler_for(6), "gnu")

    def test_visual_c_is_id_1(self):
        self.assertEqual(self._compiler_for(1), "visual_c")

    def test_visual_age_is_id_7(self):
        # Old map mislabeled 7 as "visual_cxx"; stored id 7 is COMP_VISAGE.
        self.assertEqual(self._compiler_for(7), "visual_age")

    def test_delphi_is_id_8(self):
        # Old map labeled 8 "bp"; stored id 8 is COMP_BP (Delphi).
        self.assertEqual(self._compiler_for(8), "delphi")

    def test_unknown_fallback(self):
        self.assertEqual(self._compiler_for(0), "unknown")


# ---------------------------------------------------------------------------
# idb: open_seconds is a duration, not an epoch timestamp
# ---------------------------------------------------------------------------
class TestOpenSecondsHeuristic(unittest.TestCase):
    def setUp(self):
        # Deterministic audit dir so _safe_audit_dir returns None.
        self._old_cache = os.environ.get("IDA_MCP_CACHE_DIR")
        os.environ["IDA_MCP_CACHE_DIR"] = "/tmp/ida_mcp_t08_no_such_dir"
        # idb_state uses the real os.path / time modules; save the globals we
        # stub so nothing leaks into later tests.
        self._saved = {
            "isfile": os.path.isfile,
            "getmtime": os.path.getmtime,
            "getsize": os.path.getsize,
            "time": __import__("time").time,
        }

    def tearDown(self):
        os.path.isfile = self._saved["isfile"]
        os.path.getmtime = self._saved["getmtime"]
        os.path.getsize = self._saved["getsize"]
        __import__("time").time = self._saved["time"]
        if self._old_cache is None:
            os.environ.pop("IDA_MCP_CACHE_DIR", None)
        else:
            os.environ["IDA_MCP_CACHE_DIR"] = self._old_cache

    def _state_with_age(self, age_seconds):
        import time as _time

        now = 2_000_000.0
        mtime = now - age_seconds
        mod = _load_idb_module(0, get_idb_path="/tmp/fake_t08.i64")
        _time.time = lambda: now
        os.path.isfile = lambda p: p == "/tmp/fake_t08.i64"
        os.path.getmtime = lambda p: mtime
        os.path.getsize = lambda p: 4096
        return mod.idb_state(audit_tail=0)

    def test_recent_idb_clamps_to_60(self):
        state = self._state_with_age(30)
        self.assertEqual(state["database"]["open_seconds"], 60.0)

    def test_old_idb_reports_age_not_epoch(self):
        # Old code returned ~now (an epoch timestamp) for idb_age > 60.
        state = self._state_with_age(5000)
        self.assertEqual(state["database"]["open_seconds"], 5000.0)
        self.assertLess(state["database"]["open_seconds"], 100_000.0)


if __name__ == "__main__":
    unittest.main()
