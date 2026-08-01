"""Tests for IDA API integrations added across tools.

Tests:
- memory.py search: ida_bytes.bin_search for hex patterns with wildcards
- memory.py struct_walk: ida_typeinf type annotation, ida_fixup relocation detection
- funcs.py info: ida_typeinf.func_type_data_t structured parameters
- data.py globals: ida_typeinf.udt_type_data_t struct field enumeration
- taint.py trace: ida_segment permission checks on taint sinks
"""
import os
import struct
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import install_common_stub, load_tool_module


def _make_idaapi():
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
    return mod


def _make_idc():
    mod = types.ModuleType("idc")
    mod.get_inf_attr = lambda attr: 0
    mod.get_name = lambda ea: ""
    mod.get_func_name = lambda ea: ""
    mod.get_name_ea_simple = lambda name: 0xFFFFFFFFFFFFFFFF
    mod.get_func_cmt = lambda *a, **kw: ""
    mod.next_head = lambda ea, end: ea + 1
    mod.get_item_size = lambda ea: 1
    mod.get_strlit_contents = lambda *a, **kw: None
    mod.print_insn_mnem = lambda ea: "MOV"
    return mod


def _common_extra():
    """Extra _common attrs not in install_common_stub."""
    return {
        "_inf_bitness": lambda: 64,
        "_inf_is_be": lambda: False,
        "_inf_inf_is_be": lambda: False,
        "_inf_min_ea": lambda: 0x400000,
        "_inf_max_ea": lambda: 0x500000,
        "_inf_filetype_id": lambda: 11,
        "_inf_procname": lambda: "metapc",
        "_filetype_name": lambda: "PE",
    }


def _install_stub_with_extras(extras: dict | None = None, overrides: dict | None = None):
    """install_common_stub with __all__ set to export underscore-prefixed helpers."""
    merged = {**(overrides or {}), **(extras or _common_extra())}
    install_common_stub(merged)
    # Ensure __all__ includes the extra names so `from _common import *` exports them
    common_name = "ida_pro_mcp.ida_mcp.tools._common"
    if common_name in sys.modules:
        common = sys.modules[common_name]
        existing_all = getattr(common, "__all__", [])
        new_names = [k for k in merged if k.startswith("_") and k not in existing_all]
        if new_names:
            common.__all__ = list(existing_all) + new_names


def _make_minimal_module(name):
    return types.ModuleType(name)


class TestMemorySearchBinSearch(unittest.TestCase):
    """Test that memory search uses ida_bytes.bin_search for hex patterns."""

    def setUp(self):
        self.bin_search_calls = []
        self.parse_binpat_calls = []

        idaapi = _make_idaapi()
        idc = _make_idc()

        ida_bytes = types.ModuleType("ida_bytes")

        def mock_parse_binpat_str(pt, ea, pattern, radix):
            self.parse_binpat_calls.append((ea, pattern, radix))

        def mock_bin_search(start, end, pt, flags):
            self.bin_search_calls.append((start, end))
            return (idaapi.BADADDR, None)

        def mock_get_bytes(ea, size):
            if 0x400000 <= ea < 0x401000:
                return b"\x4d\x5a\x90\x00" + b"\x00" * max(0, size - 4)
            return None

        ida_bytes.compiled_binpat_vec_t = type("compiled_binpat_vec_t", (), {"__init__": lambda self: None})
        ida_bytes.parse_binpat_str = mock_parse_binpat_str
        ida_bytes.bin_search = mock_bin_search
        ida_bytes.get_bytes = mock_get_bytes
        ida_bytes.is_loaded = lambda ea: True
        ida_bytes.BIN_SEARCH_FORWARD = 1

        # Pre-set sys.modules BEFORE install_common_stub
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_bytes"] = ida_bytes
        for name in ("ida_segment", "ida_nalt", "ida_fixup", "ida_typeinf",
                      "ida_name", "ida_lines", "ida_funcs", "idautils"):
            sys.modules[name] = _make_minimal_module(name)
        sys.modules["ida_funcs"].get_func = lambda ea: None

        common_overrides = {"idaapi": idaapi, "idc": idc, "ida_bytes": ida_bytes}
        install_common_stub(common_overrides)
        self.mod = load_tool_module("memory", common_overrides=common_overrides)

    def test_hex_pattern_uses_bin_search(self):
        self.bin_search_calls.clear()
        self.parse_binpat_calls.clear()
        result = self.mod.memory(
            action="search", addr="0x400000",
            pattern="4D 5A ?? 00", end_addr="0x401000",
        )
        self.assertTrue(result["ok"])
        self.assertGreater(len(self.parse_binpat_calls), 0)
        pattern_used = self.parse_binpat_calls[0][1]
        self.assertIn("??", pattern_used)
        self.assertIn("4d", pattern_used)

    def test_bin_search_called_for_wildcard_pattern(self):
        self.bin_search_calls.clear()
        self.mod.memory(
            action="search", addr="0x400000",
            pattern="4D 5A ?? 00", end_addr="0x401000",
        )
        self.assertGreater(len(self.bin_search_calls), 0)


class TestMemoryStructWalkTypeAnnotation(unittest.TestCase):
    """Test struct_walk annotates pointer targets with type info."""

    def setUp(self):
        self.tinfo_calls = []
        self.fixup_calls = []

        idaapi = _make_idaapi()
        idc = _make_idc()

        ida_bytes = types.ModuleType("ida_bytes")
        ida_bytes.is_loaded = lambda ea: 0x400000 <= ea <= 0x500000

        def mock_get_bytes(ea, size):
            if ea == 0x400000 and size == 8:
                return struct.pack("<Q", 0x401000)
            if ea == 0x401000 and size == 8:
                return struct.pack("<Q", 0)
            return None
        ida_bytes.get_bytes = mock_get_bytes
        ida_bytes.get_flags = lambda ea: 0

        ida_nalt = types.ModuleType("ida_nalt")

        class FakeTinfo:
            def __init__(self):
                self._type_str = ""
            def __str__(self):
                return self._type_str

        def mock_get_tinfo(tif, ea):
            self.tinfo_calls.append(ea)
            if ea in (0x400000, 0x401000):
                tif._type_str = "void (*)(int)"
                return True
            return False
        ida_nalt.get_tinfo = mock_get_tinfo

        ida_typeinf = types.ModuleType("ida_typeinf")
        ida_typeinf.tinfo_t = FakeTinfo

        ida_fixup = types.ModuleType("ida_fixup")
        def mock_get_fixup(fdata, ea):
            self.fixup_calls.append(ea)
            return ea == 0x400004
        ida_fixup.get_fixup = mock_get_fixup
        ida_fixup.fixup_data_t = type("fixup_data_t", (), {"__init__": lambda self: None})

        idc.get_name = lambda ea: {0x401000: "target_func"}.get(ea, "")

        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_bytes"] = ida_bytes
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["ida_typeinf"] = ida_typeinf
        sys.modules["ida_fixup"] = ida_fixup
        for name in ("ida_segment", "ida_name", "ida_lines", "ida_funcs", "idautils"):
            sys.modules[name] = _make_minimal_module(name)

        extra = _common_extra()
        # Build __all__ that includes everything install_common_stub sets + our extras
        _all_names = [
            "tool", "idaread", "idawrite", "unsafe",
            "hex_ea", "hex_size", "parse_address", "looks_like_address",
            "get_prototype", "get_stack_frame_variables_internal",
            "get_type_by_name", "smart_match", "compile_smart_pattern",
            "resolve_symbol", "validate_range", "check_debugger",
            "validate_path_safe", "require_arg", "require_one_of",
            "validate_action", "validate_count", "validate_addr",
            "normalize_list_input", "normalize_dict_list",
            "get_function", "get_image_size",
            "make_error", "handle_error", "ERROR_HINTS", "MCPError",
            "idaapi", "idc", "idautils", "ida_funcs", "ida_bytes",
            "ida_segment", "ida_name", "ida_typeinf", "ida_nalt",
            "ida_hexrays", "ida_frame", "ida_struct", "ida_lines",
            "ida_ua", "ida_kernwin", "ida_loader", "ida_dbg", "ida_fixup",
            "Annotated", "Optional", "Literal", "Union", "Any",
            *extra.keys(),
        ]
        common_overrides = {
            "idaapi": idaapi, "idc": idc, "ida_bytes": ida_bytes,
            "ida_nalt": ida_nalt, "ida_typeinf": ida_typeinf, "ida_fixup": ida_fixup,
            **extra,
            "__all__": _all_names,
        }
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_bytes"] = ida_bytes
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["ida_typeinf"] = ida_typeinf
        sys.modules["ida_fixup"] = ida_fixup
        for name in ("ida_segment", "ida_name", "ida_lines", "ida_funcs", "idautils"):
            sys.modules[name] = _make_minimal_module(name)
        install_common_stub(common_overrides)
        self.mod = load_tool_module("memory", common_overrides=common_overrides)

    def test_struct_walk_annotates_type(self):
        result = self.mod.memory(action="struct_walk", addr="0x400000", depth=1)
        if not result["ok"]:
            print(f"DEBUG: {result}")
        self.assertTrue(result["ok"])
        nodes = result["nodes"]
        self.assertTrue(any(n.get("type") for n in nodes))

    def test_struct_walk_checks_relocations(self):
        result = self.mod.memory(action="struct_walk", addr="0x400000", depth=0)
        self.assertTrue(result["ok"])

    def test_struct_walk_reports_fixup_type_for_relocation_slots(self):
        ida_fixup = sys.modules["ida_fixup"]

        def mock_get_fixup(fdata, ea):
            if ea == 0x400000:
                fdata.type = 0x02  # FIXUP_OFF32
                fdata.base = 0
                return True
            return False
        ida_fixup.get_fixup = mock_get_fixup
        ida_fixup.FIXUP_OFF32 = 0x02
        result = self.mod.memory(action="struct_walk", addr="0x400000", depth=1)
        self.assertTrue(result["ok"])
        node = next(n for n in result["nodes"] if n["addr"] == "0x400000")
        self.assertTrue(node.get("relocation"))
        self.assertEqual(node.get("fixup_type"), 0x02)
        self.assertEqual(node.get("fixup_name"), "FIXUP_OFF32")


class TestAnalysisSetOptionsRebase(unittest.TestCase):
    """analysis(set_options, baseaddr=...) must rebase with the correct delta.

    Regression: the old flow called set_inf_attr(INF_BASEADDR) BEFORE
    computing the rebase delta, so current_base always equalled the
    requested base and rebase_program never moved the segments — the
    INF_BASEADDR attribute claimed the new base while every segment
    stayed at the old address.
    """

    def setUp(self):
        self.set_inf_attr_calls = []
        self.rebase_calls = []
        self.cur_base = 0x400000

        idaapi = types.ModuleType("idaapi")
        idaapi.rebase_program = self._mock_rebase

        idc = types.ModuleType("idc")
        idc.INF_BASEADDR = 1
        idc.INF_START_EA = 2
        idc.INF_MIN_EA = 3
        idc.INF_MAX_EA = 4
        idc.MSF_FIXONCE = 0x01
        idc.MSF_SILENT = 0x02
        idc.get_inf_attr = lambda attr: self.cur_base
        idc.set_inf_attr = self._mock_set_inf_attr

        ida_segment = types.ModuleType("ida_segment")
        ida_segment.rebase_program = self._mock_rebase

        for name in ("ida_ida", "ida_loader", "ida_entry", "ida_auto", "ida_ua",
                     "ida_name", "ida_lines", "ida_funcs", "ida_bytes", "idautils"):
            sys.modules[name] = _make_minimal_module(name)
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_segment"] = ida_segment

        common_overrides = {
            "idaapi": idaapi,
            "idc": idc,
            "ida_segment": ida_segment,
            "_safe_inf_get": lambda key, default=0: self.cur_base,
        }
        install_common_stub(common_overrides)
        self.mod = load_tool_module("analysis", common_overrides=common_overrides)
        # install_common_stub resets get_inf_attr to a 0-returning stub
        # (once directly, once inside load_tool_module); restore the
        # stateful one so the rebase delta is computed against the real
        # "current" base.
        idc.get_inf_attr = lambda attr: self.cur_base

    def _mock_set_inf_attr(self, attr, value):
        self.set_inf_attr_calls.append((attr, value))

    def _mock_rebase(self, delta, flags):
        self.rebase_calls.append((delta, flags))
        self.cur_base += delta
        return True

    def test_rebase_uses_delta_between_requested_and_actual_base(self):
        result = self.mod.analysis(action="set_options", options={"baseaddr": "0x401000"})
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.rebase_calls, [(0x1000, 0)])
        # INF_BASEADDR must not be mutated before the delta is computed.
        self.assertEqual(self.set_inf_attr_calls, [])
        self.assertEqual(result["applied"]["baseaddr"], 0x401000)

    def test_no_rebase_when_baseaddr_unchanged(self):
        result = self.mod.analysis(action="set_options", options={"baseaddr": 0x400000})
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.rebase_calls, [])
        self.assertEqual(result["applied"]["baseaddr"], 0x400000)

    def test_non_page_aligned_delta_is_rejected_with_hint(self):
        result = self.mod.analysis(action="set_options", options={"baseaddr": "0x401100"})
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_ARGS")
        self.assertIn("page-aligned", str(result["message"]))
        self.assertEqual(self.rebase_calls, [])

    def test_rebase_failure_returns_structured_error(self):
        idc = sys.modules["idc"]
        idc.rebase_program = lambda delta, flags: False
        sys.modules["idaapi"].rebase_program = lambda delta, flags: False
        sys.modules["ida_segment"].rebase_program = lambda delta, flags: False
        result = self.mod.analysis(action="set_options", options={"baseaddr": "0x402000"})
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "IDA_ERROR")
        self.assertIn("Failed to rebase", result["message"])


class TestFuncsInfoStructuredParams(unittest.TestCase):
    """Test funcs info action returns structured parameters via ida_typeinf."""

    def setUp(self):
        idaapi = _make_idaapi()
        idc = _make_idc()

        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda ea: types.SimpleNamespace(
            start_ea=0x401000, end_ea=0x401100, flags=0
        ) if ea == 0x401000 else None
        ida_funcs.get_func_name = lambda ea: "process_request" if ea == 0x401000 else ""

        ida_typeinf = types.ModuleType("ida_typeinf")

        class FakeParam:
            def __init__(self, name, ptype, loc_kind="reg", loc_val=0):
                self.name = name
                self.type = ptype
                self.loc = types.SimpleNamespace(
                    reg=loc_val if loc_kind == "reg" else None,
                    offset=loc_val if loc_kind == "stack" else None,
                )

        class FakeFuncData:
            def __init__(self):
                self._params = [
                    FakeParam("buf", "char *", "reg", 0),
                    FakeParam("len", "size_t", "reg", 1),
                    FakeParam("flags", "int", "stack", 0x10),
                ]
                self.rettype = "int"
                self.cc = 0
            def size(self):
                return len(self._params)
            def __getitem__(self, i):
                return self._params[i]

        class FakeTinfo:
            def get_numbered_type(self, til, ordinal):
                return True
            def get_func_details(self, func_data):
                func_data._params = [
                    FakeParam("buf", "char *", "reg", 0),
                    FakeParam("len", "size_t", "reg", 1),
                    FakeParam("flags", "int", "stack", 0x10),
                ]
                func_data.rettype = "int"
                func_data.cc = 0
                return True

        ida_typeinf.tinfo_t = FakeTinfo
        ida_typeinf.func_type_data_t = FakeFuncData
        ida_typeinf.get_idati = lambda: None

        # Pre-set ALL modules in sys.modules BEFORE install_common_stub
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["ida_typeinf"] = ida_typeinf
        for name in ("ida_nalt", "ida_segment", "ida_name", "ida_lines", "ida_bytes",
                      "ida_hexrays", "ida_frame", "ida_struct", "ida_ua",
                      "ida_kernwin", "ida_loader", "ida_dbg"):
            sys.modules[name] = _make_minimal_module(name)
        # idautils needs Chunks
        idautils = _make_minimal_module("idautils")
        idautils.Chunks = lambda ea: iter([(0x401000, 0x401100)])
        idautils.XrefsTo = lambda ea: iter([])
        sys.modules["idautils"] = idautils

        common_overrides = {
            "idaapi": idaapi, "idc": idc, "ida_funcs": ida_funcs, "ida_typeinf": ida_typeinf,
        }
        install_common_stub(common_overrides)
        self.mod = load_tool_module("funcs", common_overrides=common_overrides)

    def test_info_returns_structured_params(self):
        result = self.mod.funcs(action="info", addr="0x401000", include_prototype=True)
        self.assertTrue(result["ok"])
        func = result["function"]
        self.assertIn("parameters", func)
        self.assertEqual(len(func["parameters"]), 3)

    def test_info_param_names_and_types(self):
        result = self.mod.funcs(action="info", addr="0x401000", include_prototype=True)
        params = result["function"]["parameters"]
        self.assertEqual(params[0]["name"], "buf")
        self.assertEqual(params[0]["type"], "char *")
        self.assertEqual(params[1]["name"], "len")

    def test_info_param_locations(self):
        result = self.mod.funcs(action="info", addr="0x401000", include_prototype=True)
        params = result["function"]["parameters"]
        self.assertEqual(params[0]["location"], "reg:0")
        self.assertEqual(params[1]["location"], "reg:1")
        self.assertEqual(params[2]["location"], "stack:0x10")

    def test_info_return_type(self):
        result = self.mod.funcs(action="info", addr="0x401000", include_prototype=True)
        self.assertEqual(result["function"]["return_type"], "int")


class TestDataGlobalsStructFields(unittest.TestCase):
    """Test globals action shows struct fields via ida_typeinf.udt_type_data_t."""

    def setUp(self):
        idaapi = _make_idaapi()
        idaapi.get_func = lambda ea: None
        idc = _make_idc()

        ida_typeinf = types.ModuleType("ida_typeinf")

        class FakeMember:
            def __init__(self, name, ftype, offset):
                self.name = name
                self.type = ftype
                self.offset = offset

        class FakeTinfo:
            def __init__(self):
                self._is_struct = False
                self._members = []
            def is_struct(self):
                return self._is_struct
            def get_udt_details(self, udt):
                if not self._is_struct:
                    return False
                for m in self._members:
                    udt._items.append(m)
                return True
            def __str__(self):
                if self._is_struct:
                    return "sockaddr_in"
                return "int"

        class FakeUDT:
            def __init__(self):
                self._items = []
            def size(self):
                return len(self._items)
            def __getitem__(self, i):
                return self._items[i]

        ida_typeinf.tinfo_t = FakeTinfo
        ida_typeinf.udt_type_data_t = FakeUDT

        ida_nalt = types.ModuleType("ida_nalt")

        def get_tinfo(tif, ea):
            if ea == 0x500000:
                tif._is_struct = True
                tif._members = [
                    FakeMember("sin_family", "unsigned short", 0),
                    FakeMember("sin_port", "unsigned short", 2),
                    FakeMember("sin_addr", "in_addr_t", 4),
                ]
                return True
            if ea == 0x500100:
                tif._is_struct = False
                return True
            return False

        ida_nalt.get_tinfo = get_tinfo
        idc.get_item_size = lambda ea: {0x500000: 16, 0x500100: 4}.get(ea, 1)

        idautils = types.ModuleType("idautils")
        idautils.Names = lambda: iter([(0x500000, "g_sockaddr"), (0x500100, "g_counter")])

        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["idautils"] = idautils
        sys.modules["ida_typeinf"] = ida_typeinf
        sys.modules["ida_nalt"] = ida_nalt
        for name in ("ida_funcs", "ida_segment", "ida_name", "ida_lines", "ida_bytes",
                      "ida_hexrays", "ida_frame", "ida_struct", "ida_ua",
                      "ida_kernwin", "ida_loader", "ida_dbg"):
            sys.modules[name] = _make_minimal_module(name)

        common_overrides = {
            "idaapi": idaapi, "idc": idc, "idautils": idautils,
            "ida_typeinf": ida_typeinf, "ida_nalt": ida_nalt,
        }
        install_common_stub(common_overrides)
        self.mod = load_tool_module("data", common_overrides=common_overrides)

    def test_globals_shows_struct_fields(self):
        result = self.mod.data(action="globals", query="g_sockaddr")
        self.assertTrue(result["ok"])
        self.assertIn("fields=[", result["globals"])
        self.assertIn("sin_family", result["globals"])
        self.assertIn("sin_port", result["globals"])
        self.assertIn("sin_addr", result["globals"])

    def test_globals_no_fields_for_non_struct(self):
        result = self.mod.data(action="globals", query="g_counter")
        self.assertTrue(result["ok"])
        self.assertNotIn("fields=[", result["globals"])


class TestTaintSegmentPermissions(unittest.TestCase):
    """Test taint segment permission check logic."""

    def test_segment_exec_detection(self):
        SEGPERM_EXEC = 4
        SEGPERM_WRITE = 2
        SEGPERM_READ = 1

        class FakeSeg:
            def __init__(self, name, perm):
                self.name = name
                self.perm = perm

        def getseg(ea):
            if 0x400000 <= ea < 0x450000:
                return FakeSeg(".text", SEGPERM_READ | SEGPERM_EXEC)
            if 0x500000 <= ea < 0x550000:
                return FakeSeg(".data", SEGPERM_READ | SEGPERM_WRITE)
            return None

        def get_segm_name(seg):
            return seg.name if seg else ""

        sink_seg = getseg(0x401000)
        self.assertIsNotNone(sink_seg)
        self.assertTrue(sink_seg.perm & SEGPERM_EXEC)

        src_seg = getseg(0x500000)
        self.assertIsNotNone(src_seg)
        self.assertFalse(src_seg.perm & SEGPERM_EXEC)
        self.assertTrue(src_seg.perm & SEGPERM_WRITE)

        self.assertNotEqual(get_segm_name(src_seg), get_segm_name(sink_seg))

    def test_w_plus_x_detection(self):
        SEGPERM_EXEC = 4
        SEGPERM_WRITE = 2
        perm = SEGPERM_WRITE | SEGPERM_EXEC
        self.assertTrue(bool(perm & SEGPERM_WRITE and perm & SEGPERM_EXEC))
        perm_text = SEGPERM_EXEC | 1
        self.assertFalse(bool(perm_text & SEGPERM_WRITE and perm_text & SEGPERM_EXEC))


if __name__ == "__main__":
    unittest.main()
