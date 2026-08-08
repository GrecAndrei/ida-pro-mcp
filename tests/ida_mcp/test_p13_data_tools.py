"""Regression tests for p13_data_tools audit fixes.

Covers (each maps to a confirmed finding in the p13 audit):
- data capability_matrix: risk_indicators now match mixed-case / A-W-suffix
  DANGEROUS_APIS keys case-insensitively.
- data functions: min_xrefs above the old 999 cap still matches hot functions.
- data globals: include_xrefs caps the count at 999 (no full-list materialisation).
- data strings: printable-ratio gate treats real newlines/tabs as printable, so
  short multi-line strings survive the adaptive gate.
- types search_structs: offset/count now paginate the returned matches and
  total reflects the whole TIL scan.
- types vtable: pointer entries respect database endianness (big-endian decode).
- types infer: response no longer carries a constant misleading `applied` field.
- idb architecture_profile: RISC-V GP recommendation is a single .format (the
  malformed double-apply is gone).
- idb_meta: min_ea/max_ea of 0 (raw firmware loaded at 0x0) are reported, not None.
- idb_summary: nullsub_/loc_/j_/empty names count as auto-named, matching the
  data annotations definition.
- segments analyze: code_data_ratio uses the JSON-safe "inf" sentinel, never
  float('inf').
"""
import os
import struct
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import load_tool_module


def _make_idc(**extra):
    mod = types.ModuleType("idc")
    mod.get_name = lambda ea: ""
    mod.get_func_name = lambda ea: ""
    mod.get_name_ea_simple = lambda name: 0xFFFFFFFFFFFFFFFF
    mod.get_func_cmt = lambda *a, **kw: ""
    mod.next_head = lambda ea, end: ea + 1
    mod.get_item_size = lambda ea: 1
    mod.get_strlit_contents = lambda *a, **kw: None
    mod.get_frame_id = lambda ea: 0xFFFFFFFFFFFFFFFF
    mod.print_insn_mnem = lambda ea: "MOV"
    for k, v in extra.items():
        setattr(mod, k, v)
    return mod


def _make_idaapi(**extra):
    mod = types.ModuleType("idaapi")
    mod.BADADDR = 0xFFFFFFFFFFFFFFFF
    mod.get_next_func = lambda ea: mod.BADADDR
    mod.get_idb = lambda: None
    mod.get_inf_structure = lambda: None
    mod.get_kernel_version = lambda: "9.2"
    mod.MFF_FAST = 0
    mod.MFF_READ = 1
    mod.MFF_WRITE = 2
    mod.execute_sync = lambda fn, flags=0: fn()
    for k, v in extra.items():
        setattr(mod, k, v)
    return mod


def _blank_modules(names):
    for name in names:
        sys.modules.setdefault(name, types.ModuleType(name))


class _Xrefs:
    """Iterable of n dummy xref objects (each __iter__ call is fresh)."""

    def __init__(self, n):
        self.n = n

    def __iter__(self):
        return iter(range(self.n))


class TestCapabilityMatrixRiskIndicators(unittest.TestCase):
    def setUp(self):
        idaapi = _make_idaapi(get_func=lambda ea: None)
        idc = _make_idc()
        imports = [
            ("VirtualAlloc", 0x1000),
            ("CreateRemoteThreadW", 0x2000),
            ("strcpy", 0x3000),
            ("virtualalloc", 0x4000),  # lowercase import still flagged
            ("SafeHelper", 0x5000),    # benign, must NOT be flagged
        ]
        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.get_import_module_qty = lambda: 1
        ida_nalt.enum_import_names = lambda i, cb: [cb(ea, name, 0) for name, ea in imports]
        idautils = types.ModuleType("idautils")
        idautils.Functions = lambda: iter([])
        _blank_modules(["ida_typeinf", "ida_segment", "ida_name", "ida_lines", "ida_bytes",
                        "ida_funcs", "ida_hexrays", "ida_frame", "ida_struct", "ida_ua",
                        "ida_kernwin", "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["idautils"] = idautils
        danger = {
            "VirtualAlloc": "rwx",
            "CreateRemoteThread": "inject",
            "strcpy": "overflow",
            "GetProcAddress": "evasion",
            "ShellExecute": "cmd",
        }
        overrides = {
            "idaapi": idaapi, "idc": idc, "idautils": idautils, "ida_nalt": ida_nalt,
            "DANGEROUS_APIS": danger,
            "API_CATEGORIES": {"network": ["recv"], "crypto": ["aes"], "process": ["OpenProcess"]},
        }
        self.mod = load_tool_module("data", common_overrides=overrides)

    def test_risk_indicators_match_mixed_case_and_suffixes(self):
        result = self.mod.data(action="capability_matrix")
        self.assertTrue(result["ok"], result)
        ri = result["risk_indicators"]
        self.assertIn("VirtualAlloc", ri)
        self.assertIn("CreateRemoteThreadW", ri)  # W-suffix base matched
        self.assertIn("strcpy", ri)
        self.assertIn("virtualalloc", ri)          # case-insensitive
        self.assertNotIn("SafeHelper", ri)


class TestFunctionsMinXrefsNoCap(unittest.TestCase):
    def setUp(self):
        idaapi = _make_idaapi(
            get_func=lambda ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x3000)
        )
        idc = _make_idc()
        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func_name = lambda ea: "hot_func" if ea == 0x1000 else ""
        idautils = types.ModuleType("idautils")
        idautils.Functions = lambda: iter([0x1000])
        idautils.XrefsTo = lambda ea: _Xrefs(2000)
        idautils.XrefsFrom = lambda ea, f=0: iter([])
        _blank_modules(["ida_nalt", "ida_typeinf", "ida_segment", "ida_name", "ida_lines",
                        "ida_bytes", "ida_hexrays", "ida_frame", "ida_struct", "ida_ua",
                        "ida_kernwin", "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils
        self.mod = load_tool_module(
            "data",
            common_overrides={"idaapi": idaapi, "idc": idc, "ida_funcs": ida_funcs,
                              "idautils": idautils},
        )

    def test_min_xrefs_above_999_still_matches(self):
        result = self.mod.data(action="functions", min_xrefs=1500, include_xrefs=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["total"], 1)
        self.assertIn("hot_func", result["functions"])
        # Display count stays capped at 999 like the other list actions.
        self.assertIn("xrefs=999", result["functions"])


class TestGlobalsXrefsCapped(unittest.TestCase):
    def setUp(self):
        idaapi = _make_idaapi(get_func=lambda ea: None)
        idc = _make_idc(get_item_size=lambda ea: 8)
        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.get_tinfo = lambda tif, ea: False
        ida_typeinf = types.ModuleType("ida_typeinf")
        ida_typeinf.tinfo_t = lambda: None
        idautils = types.ModuleType("idautils")
        idautils.Names = lambda: iter([(0x5000, "g_hot")])
        idautils.XrefsTo = lambda ea: _Xrefs(5000)
        _blank_modules(["ida_segment", "ida_name", "ida_lines", "ida_bytes", "ida_funcs",
                        "ida_hexrays", "ida_frame", "ida_struct", "ida_ua", "ida_kernwin",
                        "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["ida_typeinf"] = ida_typeinf
        sys.modules["idautils"] = idautils
        self.mod = load_tool_module(
            "data",
            common_overrides={"idaapi": idaapi, "idc": idc, "ida_nalt": ida_nalt,
                              "ida_typeinf": ida_typeinf, "idautils": idautils},
        )

    def test_globals_xref_count_capped_not_materialised(self):
        result = self.mod.data(action="globals", include_xrefs=True)
        self.assertTrue(result["ok"], result)
        self.assertIn("xrefs=999", result["globals"])


class TestStringsPrintableGateNewlines(unittest.TestCase):
    def setUp(self):
        idaapi = _make_idaapi(getseg=lambda ea: None)
        idc = _make_idc()

        class StrItem:
            def __init__(self, ea, text):
                self.ea = ea
                self.text = text

            def __str__(self):
                return self.text

        items = [
            StrItem(0x1000, "plain_text"),
            StrItem(0x1001, "hello_world"),
            StrItem(0x1002, "ok\nline"),  # real newline; must survive the gate
        ]
        idautils = types.ModuleType("idautils")
        idautils.Strings = lambda: iter(list(items))
        idautils.XrefsTo = lambda ea: iter([])
        _blank_modules(["ida_nalt", "ida_typeinf", "ida_segment", "ida_name", "ida_lines",
                        "ida_bytes", "ida_funcs", "ida_hexrays", "ida_frame", "ida_struct",
                        "ida_ua", "ida_kernwin", "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["idautils"] = idautils
        overrides = {"idaapi": idaapi, "idc": idc, "idautils": idautils,
                     "_inf_filetype_id": lambda: 11}
        self.mod = load_tool_module("data", common_overrides=overrides)
        self.mod._inf_filetype_id = lambda: 11

    def test_multiline_short_string_survives_printable_gate(self):
        result = self.mod.data(action="strings", min_len=3)
        self.assertTrue(result["ok"], result)
        # "ok\nline" must be kept (the old charset counted \n as non-printable
        # and the adaptive gate would filter it out).
        self.assertIn("0x1002", result["strings"])
        self.assertIn("ok", result["strings"])


class TestSearchStructsPagination(unittest.TestCase):
    def setUp(self):
        idaapi = _make_idaapi()
        idc = _make_idc()

        class FakeTinfo:
            def __init__(self):
                self._name = ""

            def get_numbered_type(self, til, ordinal):
                self._name = f"foo{ordinal}"
                return True

            def is_struct(self):
                return True

            def is_union(self):
                return False

            def get_type_name(self):
                return self._name

            def get_udt_details(self, udt):
                return False

        ida_typeinf = types.ModuleType("ida_typeinf")
        ida_typeinf.tinfo_t = FakeTinfo
        ida_typeinf.udt_type_data_t = types.SimpleNamespace
        ida_typeinf.get_ordinal_qty = lambda til: 5
        _blank_modules(["ida_nalt", "ida_segment", "ida_name", "ida_lines", "ida_bytes",
                        "ida_funcs", "ida_hexrays", "ida_frame", "ida_struct", "ida_ua",
                        "ida_kernwin", "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_typeinf"] = ida_typeinf
        self.mod = load_tool_module(
            "types",
            common_overrides={"idaapi": idaapi, "idc": idc, "ida_typeinf": ida_typeinf},
        )

    def test_offset_paginates_and_total_is_accurate(self):
        result = self.mod.types(action="search_structs", query="foo", offset=1, count=2)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["total"], 5)
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["offset"], 1)
        self.assertEqual([m["name"] for m in result["matches"]], ["foo2", "foo3"])


class TestVtableBigEndian(unittest.TestCase):
    def setUp(self):
        idaapi = _make_idaapi(get_func=lambda ea: None)
        names = {0x1000: "vtable_for_X", 0x2000: "X::a", 0x3000: "X::b"}
        idc = _make_idc(get_name=lambda ea: names.get(ea, ""))
        ida_bytes = types.ModuleType("ida_bytes")

        def _get_bytes(ea, size):
            if ea == 0x1000:
                return struct.pack(">Q", 0x2000)
            if ea == 0x1008:
                return struct.pack(">Q", 0x3000)
            if ea == 0x1010:
                return struct.pack(">Q", 0)
            return None

        ida_bytes.get_bytes = _get_bytes
        ida_bytes.is_loaded = lambda ea: ea in (0x2000, 0x3000)
        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.demangle_name = lambda name, *a, **kw: name
        ida_nalt.get_short_name_synonym = lambda: 0
        _blank_modules(["ida_typeinf", "ida_segment", "ida_name", "ida_lines", "ida_funcs",
                        "ida_hexrays", "ida_frame", "ida_struct", "ida_ua", "ida_kernwin",
                        "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_bytes"] = ida_bytes
        sys.modules["ida_nalt"] = ida_nalt
        overrides = {"idaapi": idaapi, "idc": idc, "ida_bytes": ida_bytes,
                     "ida_nalt": ida_nalt}
        self.mod = load_tool_module("types", common_overrides=overrides)
        self.mod._inf_is_be = lambda: True
        self.mod._inf_is_64bit = lambda: True

    def test_vtable_unpacks_big_endian_pointers(self):
        result = self.mod.types(action="vtable", addr="0x1000")
        self.assertTrue(result["ok"], result)
        self.assertEqual([e["addr"] for e in result["entries"]], ["0x2000", "0x3000"])


class TestInferNoMisleadingApplied(unittest.TestCase):
    def setUp(self):
        idaapi = _make_idaapi(get_func=lambda ea: None)
        idc = _make_idc()
        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.get_tinfo = lambda tif, ea: False
        ida_typeinf = types.ModuleType("ida_typeinf")
        ida_typeinf.tinfo_t = lambda: None
        _blank_modules(["ida_segment", "ida_name", "ida_lines", "ida_bytes", "ida_funcs",
                        "ida_hexrays", "ida_frame", "ida_struct", "ida_ua", "ida_kernwin",
                        "ida_loader", "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["ida_typeinf"] = ida_typeinf
        self.mod = load_tool_module(
            "types",
            common_overrides={"idaapi": idaapi, "idc": idc, "ida_nalt": ida_nalt,
                              "ida_typeinf": ida_typeinf},
        )

    def test_infer_has_no_constant_applied_field(self):
        result = self.mod.types(action="infer", addr="0x1000")
        self.assertTrue(result["ok"], result)
        self.assertNotIn("applied", result)
        self.assertIn("inferred_types", result)


class TestRiscvGpRecommendation(unittest.TestCase):
    def setUp(self):
        idaapi = _make_idaapi()
        idc = _make_idc()
        ida_ida = types.ModuleType("ida_ida")
        ida_entry = types.ModuleType("ida_entry")
        ida_nalt = types.ModuleType("ida_nalt")
        _blank_modules(["ida_typeinf", "ida_segment", "ida_name", "ida_lines", "ida_bytes",
                        "ida_funcs", "ida_hexrays", "ida_frame", "ida_struct", "ida_ua",
                        "ida_kernwin", "ida_loader", "ida_dbg", "idautils"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_ida"] = ida_ida
        sys.modules["ida_entry"] = ida_entry
        sys.modules["ida_nalt"] = ida_nalt
        self.mod = load_tool_module(
            "idb",
            common_overrides={"idaapi": idaapi, "idc": idc,
                              "is_riscv_family": lambda: True},
        )
        self.mod.detect_riscv_gp = lambda: {"found": True, "gp": 0x2A1000}

    def test_gp_recommendation_is_single_format(self):
        meta = {
            "binary_path": "",
            "file_type_id": 17,
            "file_type_info": {"effective": "raw", "loader": "raw"},
            "file_type_effective": "raw",
            "processor": "riscv",
            "bitness": 64,
            "is_be": False,
        }
        result = self.mod.idb_architecture_profile(meta=meta, summary={"imports": 0})
        gp_recs = [r for r in result["recommendations"] if "set_reg_value" in r]
        self.assertTrue(gp_recs, result["recommendations"])
        rec = gp_recs[0]
        self.assertIn('idc.set_reg_value("gp", 0x2a1000, idc.BADADDR)', rec)
        # The old double-format emitted a stray `.format(0x...)` at the end.
        self.assertNotIn(".format(", rec)


class TestIdbMetaZeroEa(unittest.TestCase):
    def setUp(self):
        idaapi = _make_idaapi(get_idb_path=lambda: "test.idb")
        idc = _make_idc()
        ida_ida = types.ModuleType("ida_ida")
        ida_ida.inf_get_min_ea = lambda: 0
        ida_ida.inf_get_max_ea = lambda: 0x2000
        ida_ida.inf_get_cc_id = lambda: 0
        ida_ida.inf_get_baseaddr = lambda: 0
        ida_ida.inf_is_dll = lambda: False
        ida_ida.inf_is_be = lambda: False
        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.get_input_file_path = lambda: "input.bin"
        ida_entry = types.ModuleType("ida_entry")
        _blank_modules(["ida_typeinf", "ida_segment", "ida_name", "ida_lines", "ida_bytes",
                        "ida_funcs", "ida_hexrays", "ida_frame", "ida_struct", "ida_ua",
                        "ida_kernwin", "ida_loader", "ida_dbg", "idautils"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_ida"] = ida_ida
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["ida_entry"] = ida_entry
        overrides = {"idaapi": idaapi, "idc": idc,
                     "_inf_filetype_id": lambda: 17,
                     "_filetype_name": lambda ft: "raw",
                     "_inf_procname": lambda: "metapc",
                     "_inf_bitness": lambda: 64}
        self.mod = load_tool_module("idb", common_overrides=overrides)
        self.mod._inf_filetype_id = lambda: 17
        self.mod._filetype_name = lambda ft: "raw"
        self.mod._inf_procname = lambda: "metapc"
        self.mod._inf_bitness = lambda: 64

    def test_zero_min_ea_reported_not_none(self):
        meta = self.mod.idb_meta()
        self.assertEqual(meta["min_ea"], "0x0")
        self.assertEqual(meta["max_ea"], "0x2000")
        self.assertEqual(meta["image_size"], "0x2000")


class TestIdbSummaryNamedFunctions(unittest.TestCase):
    def setUp(self):
        idaapi = _make_idaapi(get_strlist_qty=lambda: 0, auto_is_ok=lambda: True)
        names = {
            0x1000: "main",
            0x2000: "sub_123",
            0x3000: "nullsub_1",
            0x4000: "j_printf",
            0x5000: "",
        }
        idc = _make_idc(get_func_name=lambda ea: names.get(ea, ""))
        ida_funcs = types.ModuleType("ida_funcs")
        ida_ida = types.ModuleType("ida_ida")
        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.get_import_module_qty = lambda: 0
        ida_entry = types.ModuleType("ida_entry")
        ida_entry.get_entry_qty = lambda: 0
        ida_segment = types.ModuleType("ida_segment")
        ida_segment.getseg = lambda ea: None
        idautils = types.ModuleType("idautils")
        idautils.Functions = lambda: iter([0x1000, 0x2000, 0x3000, 0x4000, 0x5000])
        idautils.Segments = lambda: iter([])
        _blank_modules(["ida_typeinf", "ida_name", "ida_lines", "ida_bytes", "ida_hexrays",
                        "ida_frame", "ida_struct", "ida_ua", "ida_kernwin", "ida_loader",
                        "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["ida_ida"] = ida_ida
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["ida_entry"] = ida_entry
        sys.modules["ida_segment"] = ida_segment
        sys.modules["idautils"] = idautils
        self.mod = load_tool_module(
            "idb",
            common_overrides={"idaapi": idaapi, "idc": idc, "idautils": idautils},
        )

    def test_nullsub_loc_and_empty_names_count_as_auto(self):
        summary = self.mod.idb_summary(fast=True)
        self.assertEqual(summary["named_functions"], 1)
        self.assertEqual(summary["auto_named_functions"], 4)


class TestSegmentsCodeDataRatioSentinel(unittest.TestCase):
    def setUp(self):
        idaapi = _make_idaapi()
        idc = _make_idc()
        ida_segment = types.ModuleType("ida_segment")
        ida_segment.getseg = lambda ea: None
        ida_segment.get_segm_name = lambda seg: getattr(seg, "name", "")
        ida_bytes = types.ModuleType("ida_bytes")
        ida_bytes.get_flags = lambda ea: 0
        ida_bytes.is_code = lambda f: True
        ida_bytes.is_data = lambda f: False
        ida_bytes.is_strlit = lambda f: False
        ida_bytes.get_bytes = lambda ea, size: b"\x00" * size
        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.get_import_module_qty = lambda: 0
        idautils = types.ModuleType("idautils")
        idautils.Functions = lambda *a, **kw: iter([])
        _blank_modules(["ida_typeinf", "ida_name", "ida_lines", "ida_funcs", "ida_hexrays",
                        "ida_frame", "ida_struct", "ida_ua", "ida_kernwin", "ida_loader",
                        "ida_dbg"])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_segment"] = ida_segment
        sys.modules["ida_bytes"] = ida_bytes
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["idautils"] = idautils
        self.mod = load_tool_module(
            "segments",
            common_overrides={"idaapi": idaapi, "idc": idc, "ida_segment": ida_segment,
                              "ida_bytes": ida_bytes, "ida_nalt": ida_nalt,
                              "idautils": idautils},
        )

    def test_code_only_segment_reports_inf_sentinel(self):
        seg = types.SimpleNamespace(start_ea=0x1000, end_ea=0x2000, name=".text")
        result = self.mod._seg_density_analysis(seg)
        self.assertEqual(result["code_data_ratio"], "inf")


if __name__ == "__main__":
    unittest.main()
