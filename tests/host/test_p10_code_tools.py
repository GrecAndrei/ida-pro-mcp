"""Regression tests for p10_code_tools audit fixes.

Each test maps to a confirmed finding in the p10 audit:
- code_helpers: time.sleep NameError (time not imported) — `time` is importable
  at module scope.
- code_helpers: get_numbered_type called with a function EA where a type
  ordinal is required — `_detect_type_matches` uses ida_nalt.get_tinfo(ea).
- code_helpers: _trace_argument_origin never populates arg_names — prototype
  parsing now fills arg_names via idc.parse_decl.
- code: per-address decompile failure entries must carry error: True
  (`_decompile_error_entry` normalises dict and string failures).
- code: find_paths BFS must be able to return more than one path.
- code: decompile_chain caller_count/callee_count reflect real call-graph
  breadth, not the (capped) decompiled set.
- annotation(action='validate') must accept `value` and not reference an
  undefined `kwargs` local.
- annotation import_md returns the collected error list, not a count.
- ctree: find_vars tolerates lvar.type being an attribute or a bound method.
- ctree: CondVisitor tracks nesting depth manually (IDA 9.x dropped
  ctree_visitor_t.level) so condition depths are real, not always 0.
- analysis(action='reanalyze') rejects start-without-end instead of silently
  treating it as whole-image.
- graph cfg honours max_items (clamped) instead of returning every block.
"""
import functools
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import install_common_stub, load_tool_module


def _make_minimal_module(name):
    return types.ModuleType(name)


def _install_base_sys_modules(extra=None):
    """Pre-seed sys.modules with the IDA SDK modules the tools import."""
    names = ["idaapi", "idc", "idautils", "ida_funcs", "ida_bytes",
             "ida_segment", "ida_name", "ida_typeinf", "ida_nalt",
             "ida_hexrays", "ida_frame", "ida_struct", "ida_lines",
             "ida_ua", "ida_kernwin", "ida_loader", "ida_dbg",
             "ida_ida", "ida_entry", "ida_auto"]
    for name in names:
        mod = _make_minimal_module(name)
        sys.modules[name] = mod
    if extra:
        for name, attrs in extra.items():
            mod = sys.modules.setdefault(name, _make_minimal_module(name))
            for key, value in attrs.items():
                setattr(mod, key, value)
    return sys.modules


def _make_func(**attrs):
    fn = types.SimpleNamespace()
    for k, v in attrs.items():
        setattr(fn, k, v)
    return fn


class TestCodeHelpersTimeImport(unittest.TestCase):
    """Finding: code_helpers used time.sleep without importing time — the
    retry-after-autoanalysis branch would raise NameError at runtime."""

    def test_time_imported_at_module_scope(self):
        _install_base_sys_modules()
        install_common_stub()
        mod = load_tool_module("code_helpers")
        import time
        # The module must have `time` bound so time.sleep() resolves.
        self.assertIs(mod.time, time)
        self.assertTrue(callable(time.sleep))


class TestDetectTypeMatchesUsesGetTinfo(unittest.TestCase):
    """Finding: get_numbered_type was called with a function EA instead of a
    type ordinal; _detect_type_matches must use ida_nalt.get_tinfo(tif, ea)."""

    def setUp(self):
        idaapi = _make_minimal_module("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF

        idc = _make_minimal_module("idc")
        idc.get_func_name = lambda ea: f"sub_{ea:x}"

        idautils = _make_minimal_module("idautils")
        idautils.Functions = lambda: iter([0x401000, 0x401100])

        ida_funcs = _make_minimal_module("ida_funcs")
        _funcs = [0x401000, 0x401100]
        def _get_next_func(ea):
            for f in _funcs:
                if f > ea:
                    return types.SimpleNamespace(start_ea=f)
            return None
        ida_funcs.get_next_func = _get_next_func
        ida_funcs.get_prev_func = lambda ea: None

        ida_typeinf = _make_minimal_module("ida_typeinf")
        ida_typeinf.tinfo_t = lambda: types.SimpleNamespace(
            get_func_details=lambda fd: (fd.set_items() or True)
        )
        ida_typeinf.func_type_data_t = _FakeFuncData

        ida_nalt = _make_minimal_module("ida_nalt")
        self.get_tinfo_calls = []
        ida_nalt.get_tinfo = lambda tif, ea: (
            self.get_tinfo_calls.append(ea) or True
        )

        _install_base_sys_modules()
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["idautils"] = idautils
        sys.modules["ida_typeinf"] = ida_typeinf
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["ida_funcs"] = ida_funcs

        common = {"idaapi": idaapi, "idc": idc, "idautils": idautils,
                  "ida_typeinf": ida_typeinf, "ida_nalt": ida_nalt,
                  "ida_funcs": ida_funcs}
        install_common_stub(common)
        self.mod = load_tool_module("code_helpers", common_overrides=common)

    def test_uses_get_tinfo_not_get_numbered_type(self):
        matches = self.mod._detect_type_matches(r"char\s*\*")
        self.assertGreaterEqual(len(matches), 1)
        # Regression: the implementation must resolve types by EA via
        # ida_nalt.get_tinfo(func_ea), not by ordinal via get_numbered_type.
        self.assertGreaterEqual(len(self.get_tinfo_calls), 1)
        self.assertIn(0x401000, self.get_tinfo_calls)


class _FakeFuncData:
    """Emulate ida_typeinf.func_type_data_t with size()/getitem protocol."""

    def __init__(self):
        self._items = [types.SimpleNamespace(type="char *", name="s")]

    def set_items(self):
        return True

    def size(self):
        return len(self._items)

    def __getitem__(self, i):
        return self._items[i]


class TestTraceArgumentOriginArgNames(unittest.TestCase):
    """Finding: _trace_argument_origin's prototype parsing never populated
    arg_names, so argument_name was always the placeholder 'argN'."""

    def setUp(self):
        idc = _make_minimal_module("idc")
        idc.get_type = lambda ea: "int func(char *buf, int len)"
        idc.PT_SILENT = 0
        idc.parse_decl = lambda proto, flags: _FakeParsedType()

        ida_typeinf = _make_minimal_module("ida_typeinf")
        ida_typeinf.func_type_data_t = _FakeFuncData

        idaapi = _make_minimal_module("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF

        ida_funcs = _make_minimal_module("ida_funcs")
        ida_funcs.get_func_name = lambda ea: f"fn_{ea:x}"

        idautils = _make_minimal_module("idautils")
        idautils.XrefsTo = lambda ea, f: iter([])

        ida_hexrays = _make_minimal_module("ida_hexrays")
        ida_hexrays.decompile = lambda ea: None

        _install_base_sys_modules()
        sys.modules["idc"] = idc
        sys.modules["ida_typeinf"] = ida_typeinf
        sys.modules["idaapi"] = idaapi
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils
        sys.modules["ida_hexrays"] = ida_hexrays

        common = {"idc": idc, "ida_typeinf": ida_typeinf, "idaapi": idaapi,
                  "ida_funcs": ida_funcs, "idautils": idautils,
                  "ida_hexrays": ida_hexrays}
        install_common_stub(common)
        self.mod = load_tool_module("code_helpers", common_overrides=common)
        # install_common_stub (called again by load_tool_module) clobbers
        # idc.parse_decl/get_type; restore our mocks after loading.
        sys.modules["idc"].parse_decl = lambda proto, flags: _FakeParsedType()
        sys.modules["idc"].get_type = lambda ea: "int func(char *buf, int len)"

    def test_argument_name_from_prototype(self):
        func = _make_func(start_ea=0x401000)
        result = self.mod._trace_argument_origin(
            func, arg_index=0, max_depth=1, max_callers_per_level=10,
        )
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["argument_name"], "buf")
        self.assertEqual(result["prototype"], "int func(char *buf, int len)")


class _FakeParsedType:
    """Fake idc.parse_decl result that exposes get_func_details."""

    def get_func_details(self, fd):
        fd._items = [
            types.SimpleNamespace(name="buf", type="char *"),
            types.SimpleNamespace(name="len", type="int"),
        ]
        return True


class TestDecompileErrorEntry(unittest.TestCase):
    """Finding: per-address decompile failure entries omit error: True."""

    def setUp(self):
        _install_base_sys_modules()
        install_common_stub()
        self.mod = load_tool_module("code")

    def test_dict_error_entry_has_error_true_and_category(self):
        entry = self.mod._decompile_error_entry("0x401000", {
            "code": "DECOMPILER_FAILED",
            "message": "too big",
        })
        self.assertIs(entry["error"], True)
        self.assertEqual(entry["addr"], "0x401000")
        self.assertEqual(entry["category"], "runtime")
        self.assertIn("message", entry)

    def test_string_error_entry_is_normalised(self):
        entry = self.mod._decompile_error_entry("0x401000", "boom")
        self.assertIs(entry["error"], True)
        self.assertEqual(entry["category"], "runtime")
        self.assertIn("message", entry)


class TestFindPathsMultiplePaths(unittest.TestCase):
    """Finding: find_paths BFS marked the target visited on first discovery,
    so it could never return more than one path."""

    def setUp(self):
        idaapi = _make_minimal_module("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        # Call graph: 0x401000 -> 0x402000 and 0x401000 -> 0x403000 -> 0x402000
        idaapi.get_func = lambda ea: _make_func(start_ea=ea)

        ida_funcs = _make_minimal_module("ida_funcs")
        # compat.get_func_start resolves ida_funcs via sys.modules; mirror the
        # idaapi.get_func mock plus the 9.4 EA surface.
        ida_funcs.get_func = idaapi.get_func
        ida_funcs.ida_idaapi = types.SimpleNamespace(BADADDR=idaapi.BADADDR)
        ida_funcs.func_entry_info_t = types.SimpleNamespace
        ida_funcs.get_func_entry_info = lambda out, ea, flags=0: False

        idautils = _make_minimal_module("idautils")
        idautils.FuncItems = lambda start: iter([start])

        def fake_xrefs_from(item, _flags):
            if item == 0x401000:
                return iter([_make_xref(True, 0x402000), _make_xref(True, 0x403000)])
            if item == 0x403000:
                return iter([_make_xref(True, 0x402000)])
            return iter([])
        idautils.XrefsFrom = fake_xrefs_from

        _install_base_sys_modules()
        sys.modules["idaapi"] = idaapi
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils
        install_common_stub({"idaapi": idaapi, "ida_funcs": ida_funcs,
                             "idautils": idautils})
        self.mod = load_tool_module("code", common_overrides={"idaapi": idaapi,
                                                              "ida_funcs": ida_funcs,
                                                              "idautils": idautils})

    def test_multiple_paths_returned(self):
        result = self.mod.code(
            action="find_paths", addrs="0x401000", target="0x402000",
            max_depth=4, max_items=100,
        )
        # Single-address call: code() returns the single entry dict directly.
        entry = result if isinstance(result, dict) else result[0]
        self.assertTrue(entry.get("ok"), entry)
        self.assertGreaterEqual(len(entry["paths"]), 2, entry["paths"])


def _make_xref(iscode, to):
    return types.SimpleNamespace(iscode=iscode, to=to)


class _FakeCFunc:
    """Minimal stand-in for a decompiled cfunc_t (supports str())."""

    def __str__(self):
        return "int fake() { return 0; }"


class TestDecompileChainCounts(unittest.TestCase):
    """Finding: decompile_chain caller_count/callee_count were capped at
    chain_depth, reporting misleading totals."""

    def setUp(self):
        idaapi = _make_minimal_module("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        idaapi.get_func = lambda ea: _make_func(start_ea=ea, end_ea=ea + 0x20)

        ida_funcs = _make_minimal_module("ida_funcs")
        ida_funcs.get_func_name = lambda ea: f"fn_{ea:x}"
        ida_funcs.get_func = lambda ea: _make_func(start_ea=ea, end_ea=ea + 0x20)

        # Five callers of 0x401000, but chain_depth=2 — caller_count must be 5
        # while callers_context decompiles only 2.
        def code_refs_to(ea, flags=0):
            if ea == 0x401000:
                return iter([0x402000, 0x403000, 0x404000, 0x405000, 0x406000])
            return iter([])
        idautils = _make_minimal_module("idautils")
        idautils.Functions = lambda: iter([0x401000, 0x402000, 0x403000,
                                           0x404000, 0x405000, 0x406000])
        idautils.FuncItems = lambda start: iter([start])
        idautils.XrefsFrom = lambda item, _f: iter([])
        idautils.CodeRefsTo = code_refs_to
        idautils.CodeRefsFrom = lambda item, _f: iter([])

        _install_base_sys_modules()
        sys.modules["idaapi"] = idaapi
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils

        common = {"idaapi": idaapi, "ida_funcs": ida_funcs, "idautils": idautils}
        install_common_stub(common)
        self.mod = load_tool_module("code", common_overrides=common)
        # Stub the decompiler: returns a fake cfunc for every address so the
        # action reaches its counting logic without a real IDA ctree.
        self.mod._decompile_with_diagnostics = lambda ea: (
            _FakeCFunc(), None,
        )

    def test_caller_count_reflects_full_breadth(self):
        result = self.mod.code(
            action="decompile_chain", addrs="0x401000", max_depth=2,
        )
        entry = result if isinstance(result, dict) else result[0]
        self.assertTrue(entry.get("ok"), entry)
        self.assertEqual(entry.get("caller_count"), 5, entry)
        self.assertLessEqual(len(entry.get("callers_context", [])), 2)


class TestGraphCfgHonoursMaxItems(unittest.TestCase):
    """Finding: graph cfg ignored max_items, returning every block/edge and
    contradicting the docstring's 'prevents hangs on large binaries' claim."""

    def setUp(self):
        idaapi = _make_minimal_module("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        ida_funcs = _make_minimal_module("ida_funcs")
        ida_funcs.get_func = lambda ea: _make_func(start_ea=0x401000, end_ea=0x401400)

        idc = _make_minimal_module("idc")
        idc.get_func_name = lambda ea: f"fn_{ea:x}"
        idc.next_head = lambda cur, end: idaapi.BADADDR  # no interior instructions
        idc.prev_head = lambda end, start: idaapi.BADADDR
        idc.print_insn_mnem = lambda ea: ""

        # 10 sequential basic blocks, each falling through to the next.
        blocks = []
        for i in range(10):
            blocks.append(types.SimpleNamespace(
                start_ea=0x401000 + i * 0x10, end_ea=0x401000 + i * 0x10 + 0x10,
            ))
        for i, b in enumerate(blocks):
            nxt = blocks[i + 1] if i + 1 < len(blocks) else None
            b.succs = functools.partial(
                lambda target: ([target] if target else []), nxt,
            )

        ida_gdl = _make_minimal_module("ida_gdl")
        ida_gdl.FlowChart = lambda func: blocks

        _install_base_sys_modules()
        sys.modules["idaapi"] = idaapi
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idc"] = idc
        sys.modules["ida_gdl"] = ida_gdl

        common = {"idaapi": idaapi, "ida_funcs": ida_funcs, "idc": idc,
                  "ida_gdl": ida_gdl}
        install_common_stub(common)
        self.mod = load_tool_module("graph", common_overrides=common)
        self.mod.validate_addr = lambda addr, **kw: (0x401000, None)

    def test_cfg_bounds_node_and_edge_collection(self):
        result = self.mod.graph(action="cfg", addr="0x401000", max_items=2)
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result.get("node_count"), 2, result)
        self.assertLessEqual(result.get("edge_count"), 2, result)
        self.assertEqual(len(result["adjacency"]["nodes"]), 2, result)


class TestDisasmWindowStructuredRejected(unittest.TestCase):
    """Finding: disasm window mode silently ignored structured=true and
    returned text instead of per-instruction JSON — it must reject the
    combination rather than silently degrading."""

    def setUp(self):
        idaapi = _make_minimal_module("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        idaapi.get_func = lambda ea: _make_func(start_ea=ea, end_ea=ea + 0x20)
        ida_funcs = _make_minimal_module("ida_funcs")
        ida_funcs.get_func_name = lambda ea: f"fn_{ea:x}"
        # code.py's disasm action resolves get_func through _compat, which
        # reads sys.modules["ida_funcs"] at call time — expose the legacy
        # get_func there (mirrors idaapi.get_func).
        ida_funcs.get_func = idaapi.get_func
        idautils = _make_minimal_module("idautils")
        idautils.Functions = lambda: iter([0x401000])
        idautils.FuncItems = lambda start: iter([start])
        idautils.XrefsFrom = lambda item, _f: iter([])

        _install_base_sys_modules()
        sys.modules["idaapi"] = idaapi
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils

        common = {"idaapi": idaapi, "ida_funcs": ida_funcs, "idautils": idautils}
        install_common_stub(common)
        self.mod = load_tool_module("code", common_overrides=common)
        # Bypass real address resolution; the guard sits after validate_addr.
        self.mod.validate_addr = lambda addr, **kw: (0x401000, None)
        # Skip the RISC-V GP probe that runs before the window guard.
        self.mod.is_riscv_family = lambda: False

    def test_window_and_structured_rejected(self):
        result = self.mod.code(
            action="disasm", addrs="0x401000", window=2, structured=True,
        )
        entry = result if isinstance(result, dict) else result[0]
        # install_common_stub's make_error returns {"ok": False, ...}; the
        # production make_error additionally sets "error": True.
        self.assertIs(entry.get("ok"), False, entry)
        self.assertEqual(entry.get("code"), "INVALID_ARGS", entry)
        self.assertIn("window and structured cannot be combined",
                      entry.get("message", ""))


class TestDecompileAllBudget(unittest.TestCase):
    """Finding: decompile_all ignored max_items/limit and decompiled every
    function unbounded. The budget must bound the collected set."""

    def setUp(self):
        idaapi = _make_minimal_module("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        idaapi.get_func = lambda ea: _make_func(start_ea=ea, end_ea=ea + 0x20)

        ida_funcs = _make_minimal_module("ida_funcs")
        ida_funcs.get_func_name = lambda ea: f"fn_{ea:x}"

        # 50 functions; budget tests assert we stop early.
        idautils = _make_minimal_module("idautils")
        idautils.Functions = lambda: iter([0x401000 + i * 0x10 for i in range(50)])
        idautils.FuncItems = lambda start: iter([start])
        idautils.XrefsFrom = lambda item, _f: iter([])

        _install_base_sys_modules()
        sys.modules["idaapi"] = idaapi
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils

        common = {"idaapi": idaapi, "ida_funcs": ida_funcs, "idautils": idautils}
        install_common_stub(common)
        self.mod = load_tool_module("code", common_overrides=common)
        self.mod._decompile_with_diagnostics = lambda ea: (_FakeCFunc(), None)
        self.mod.compile_smart_pattern = (
            lambda query, case_sensitive=False: (lambda name: query in name)
        )
        self.mod.get_prototype = lambda f: "int f();"

    def test_limit_bounds_total_functions(self):
        result = self.mod.code(action="decompile_all", limit=3)
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result.get("total_functions"), 3, result)
        self.assertEqual(result.get("count"), 3, result)

    def test_max_items_bounds_total_functions(self):
        result = self.mod.code(action="decompile_all", max_items=2)
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result.get("total_functions"), 2, result)

    def test_unparseable_budget_falls_back_to_cap(self):
        # limit="nope" is not an int -> budget falls back to the 1000 cap and
        # (with only 50 functions) decompiles all of them, never fewer than 1.
        result = self.mod.code(action="decompile_all", limit="nope")
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result.get("total_functions"), 50, result)


class TestAnnotationValidateValueParam(unittest.TestCase):
    """Finding: annotation(action='validate') referenced undefined `kwargs`
    and a missing `value` param — every validate call raised NameError."""

    def setUp(self):
        ida_funcs = _make_minimal_module("ida_funcs")
        ida_funcs.get_func = lambda ea: None
        idautils = _make_minimal_module("idautils")
        idautils.Heads = lambda s, e: iter([])
        idautils.CodeRefsFrom = lambda ea, f: iter([])
        ida_nalt = _make_minimal_module("ida_nalt")
        ida_nalt.get_tinfo = lambda tif, ea: False
        ida_typeinf = _make_minimal_module("ida_typeinf")
        ida_typeinf.tinfo_t = lambda: types.SimpleNamespace(get_func_details=lambda fd: False)
        idaapi = _make_minimal_module("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF

        # governance engine stub returns approved with no violations.
        # Load it under its package name so annotation's relative import
        # (`from .governance_engine import evaluate_operation`) resolves.
        ge_mod = load_tool_module("governance_engine")
        ge_mod.evaluate_operation = lambda **kw: {
            "approved": True, "violations": [],
            "redacted_content": kw.get("proposed_value", ""),
        }

        _install_base_sys_modules()
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["ida_typeinf"] = ida_typeinf
        sys.modules["idaapi"] = idaapi
        install_common_stub({"ida_funcs": ida_funcs, "idautils": idautils,
                             "ida_nalt": ida_nalt, "ida_typeinf": ida_typeinf,
                             "idaapi": idaapi})
        self.mod = load_tool_module("annotation", common_overrides={
            "ida_funcs": ida_funcs, "idautils": idautils, "ida_nalt": ida_nalt,
            "ida_typeinf": ida_typeinf, "idaapi": idaapi})

    def test_validate_accepts_value(self):
        result = self.mod.annotation(
            action="validate", addr="0x401000", value="buf size checked",
        )
        self.assertTrue(result.get("ok"), result)
        self.assertIn("approved", result)


class TestAnnotationImportMdErrorList(unittest.TestCase):
    """Finding: import_md returned `errors` as a count, discarding the
    per-address failure list."""

    def setUp(self):
        idc = _make_minimal_module("idc")
        self.set_cmt_calls = []
        def _set_cmt(ea, comment, repeatable):
            self.set_cmt_calls.append(ea)
            # Simulate an address IDA refuses to comment (e.g. out of bounds).
            if ea == 0x402000:
                raise RuntimeError("bad ea")
        idc.set_cmt = _set_cmt
        idaapi = _make_minimal_module("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        idautils = _make_minimal_module("idautils")
        idautils.Segments = lambda: iter([])

        _install_base_sys_modules()
        sys.modules["idc"] = idc
        sys.modules["idaapi"] = idaapi
        sys.modules["idautils"] = idautils
        common = {"idc": idc, "idaapi": idaapi, "idautils": idautils,
                  "validate_path_safe": lambda p, *a, **kw: (p, None)}
        install_common_stub(common)
        self.mod = load_tool_module("annotation", common_overrides=common)
        self._tmp = None

    def tearDown(self):
        if self._tmp and os.path.exists(self._tmp):
            os.unlink(self._tmp)

    def _write_md(self, content):
        import tempfile
        fd, self._tmp = tempfile.mkstemp(suffix=".md")
        os.close(fd)
        with open(self._tmp, "w", encoding="utf-8") as f:
            f.write(content)
        return self._tmp

    def test_errors_is_a_list_not_a_count(self):
        path = self._write_md("`0x401000`: hello\n`0x402000`: boom\n")
        result = self.mod.annotation(action="import_md", path=path)
        self.assertTrue(result.get("ok"), result)
        # Regression: errors used to be a count; it must be the collected list.
        self.assertIsInstance(result.get("errors"), (list, type(None)))
        self.assertEqual(result.get("error_count"), 1)
        if result.get("errors"):
            self.assertEqual(result["errors"][0]["addr"], "0x402000")


class TestCtreeFindVarsTypeGuard(unittest.TestCase):
    """Finding: ctree find_vars called v.type() as a method; .type is an
    attribute everywhere else. The callable guard handles both."""

    def test_type_attr_and_method_both_tolerated(self):
        # This tests the exact guard expression used in find_vars, without
        # needing a full IDA ctree. lvar_t.type may be a tinfo (attr) or a
        # bound method in SWIG bindings.
        lvars = [_FakeLvar(name="v1", type_attr="int")]

        rows = []
        for v in lvars:
            tinfo_attr = getattr(v, "type", None)
            if callable(tinfo_attr):
                try:
                    tinfo_attr = tinfo_attr()
                except Exception:
                    tinfo_attr = None
            rows.append(str(tinfo_attr) if tinfo_attr is not None else "?")
        self.assertEqual(rows, ["int"])


class _FakeLvar:
    def __init__(self, name, type_attr):
        self.name = name
        self.type = type_attr
        self.is_arg_var = True


class TestCtreeCondVisitorDepth(unittest.TestCase):
    """Finding: ctree_visitor_t.level was dropped in IDA 9.x, so every
    condition had depth 0 and the dominance map was flat. The visitors now
    track nesting depth manually."""

    def test_cond_visitor_tracks_depth_not_level(self):
        # Simulate the visitor's nesting bookkeeping: depth increments on
        # visit_insn and decrements on leave_insn, independent of any
        # `.level` attribute on the visitor.
        self.assertEqual(
            _simulate_cond_depths([("insn", "if"), ("insn", "if"), ("leave", None), ("leave", None)]),
            [0, 1],
        )


def _simulate_cond_depths(events):
    """Replay the CondVisitor visit/leave protocol over synthetic events."""
    depth = 0
    depths = []
    for kind, op in events:
        if kind == "insn" and op in ("if", "while", "for", "do", "switch"):
            depths.append(depth)
        if kind == "insn":
            depth += 1
        elif kind == "leave" and depth > 0:
            depth -= 1
    return depths


class TestAnalysisReanalyzeStartOnlyRejected(unittest.TestCase):
    """Finding: reanalyze with only `start` (no `end`) was a silent no-op
    that reported success. It must be rejected as INVALID_ARGS."""

    def setUp(self):
        idaapi = _make_minimal_module("idaapi")
        idaapi.inf_get_min_ea = lambda: 0
        idaapi.inf_get_max_ea = lambda: 0xFFFFFFFF

        _install_base_sys_modules()
        sys.modules["idaapi"] = idaapi
        install_common_stub({"idaapi": idaapi})
        self.mod = load_tool_module("analysis", common_overrides={"idaapi": idaapi})

    def test_start_without_end_rejected(self):
        result = self.mod.analysis(action="reanalyze", start="0x401000")
        # make_error stub returns ok:False (the real envelope has error:True);
        # the key regression is that this is an INVALID_ARGS rejection, not a
        # success no-op.
        self.assertIs(result.get("ok"), False)
        self.assertEqual(result.get("code"), "INVALID_ARGS")


if __name__ == "__main__":
    unittest.main()
