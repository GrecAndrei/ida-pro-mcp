"""Regression tests for swarm t03_code audit fixes.

Covers (each maps to a confirmed finding in the t03 work order):
- funcs: IDB-mutating actions (create/change/delete/set_flags) ran under raw
  sync_wrapper(MFF_WRITE) and never invalidated the @idaread TOOL_CACHE, so
  cached functions listings / decompiled pseudocode stayed stale for the whole
  300s TTL after a mutation. Writes now drop cached reads like @idawrite does.
- code decompile_chain: when Hex-Rays refused the main function, dec_err was
  discarded and the action returned ok:true with an empty pseudocode body. It
  must surface an error entry (error: True) like every sibling decompile action.
"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import install_common_stub, load_tool_module


def _make_minimal_module(name):
    return types.ModuleType(name)


def _install_base_sys_modules(extra=None):
    names = ["idaapi", "idc", "idautils", "ida_funcs", "ida_bytes",
             "ida_segment", "ida_name", "ida_typeinf", "ida_nalt",
             "ida_hexrays", "ida_frame", "ida_struct", "ida_lines",
             "ida_ua", "ida_kernwin", "ida_loader", "ida_dbg",
             "ida_ida", "ida_entry", "ida_auto"]
    for name in names:
        sys.modules.setdefault(name, _make_minimal_module(name))
    if extra:
        for name, attrs in extra.items():
            mod = sys.modules.setdefault(name, _make_minimal_module(name))
            for key, value in attrs.items():
                setattr(mod, key, value)


def _make_func(**attrs):
    fn = types.SimpleNamespace()
    for k, v in attrs.items():
        setattr(fn, k, v)
    return fn


class TestFuncsWriteInvalidatesToolCache(unittest.TestCase):
    """Finding: funcs write actions bypassed @idawrite, so the @idaread
    TOOL_CACHE was never invalidated and read results stayed stale after a
    function mutation (e.g. a deleted function still listed)."""

    def setUp(self):
        idaapi = _make_minimal_module("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF

        idc = _make_minimal_module("idc")
        idc.get_name_ea_simple = lambda name: 0xFFFFFFFFFFFFFFFF
        idc.get_func_name = lambda ea: "target" if ea == 0x1000 else ""

        ida_funcs = _make_minimal_module("ida_funcs")
        ida_funcs.get_func = lambda ea: _make_func(start_ea=0x1000, end_ea=0x2000)
        ida_funcs.get_func_name = lambda ea: "target"
        ida_funcs.del_func = lambda ea: True

        idautils = _make_minimal_module("idautils")
        idautils.Functions = lambda: iter([])

        _install_base_sys_modules()
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils

        common = {"idaapi": idaapi, "idc": idc, "ida_funcs": ida_funcs,
                  "idautils": idautils}
        install_common_stub(common)
        self.mod = load_tool_module("funcs", common_overrides=common)

    def test_delete_drops_cached_read_results(self):
        from ida_pro_mcp.ida_mcp.sync import _tool_cache
        cache = _tool_cache()
        cache.clear()
        key_kwargs = {"action": "functions", "query": "", "count": 50}
        cache.put("data", key_kwargs, {"ok": True, "functions": "0x1000  target"})
        self.assertIsNotNone(cache.get("data", key_kwargs))
        result = self.mod.funcs(action="delete", addr="0x1000")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["addr"], "0x1000")
        # Regression: the write used to leave the seeded read entry live for
        # the whole TTL; it must be dropped like any @idawrite op.
        self.assertIsNone(cache.get("data", key_kwargs))


class TestDecompileChainErrorEnvelope(unittest.TestCase):
    """Finding: decompile_chain discarded dec_err when Hex-Rays refused the
    main function and returned ok:true with an empty pseudocode body — the
    host error contract is violated on that path."""

    def setUp(self):
        idaapi = _make_minimal_module("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        idaapi.get_func = lambda ea: _make_func(start_ea=ea, end_ea=ea + 0x20)

        ida_funcs = _make_minimal_module("ida_funcs")
        ida_funcs.get_func_name = lambda ea: f"fn_{ea:x}"
        ida_funcs.get_func = lambda ea: _make_func(start_ea=ea, end_ea=ea + 0x20)

        idautils = _make_minimal_module("idautils")
        idautils.Functions = lambda: iter([0x401000])
        idautils.FuncItems = lambda start: iter([start])
        idautils.XrefsFrom = lambda item, _f: iter([])
        idautils.CodeRefsTo = lambda ea, flags=0: iter([])
        idautils.CodeRefsFrom = lambda item, _f: iter([])

        _install_base_sys_modules()
        sys.modules["idaapi"] = idaapi
        sys.modules["ida_funcs"] = ida_funcs
        sys.modules["idautils"] = idautils

        common = {"idaapi": idaapi, "ida_funcs": ida_funcs, "idautils": idautils}
        install_common_stub(common)
        self.mod = load_tool_module("code", common_overrides=common)
        # Simulate a Hex-Rays refusal on the main function.
        self.mod._decompile_with_diagnostics = lambda ea: (None, {
            "code": "DECOMPILER_FAILED",
            "category": "runtime",
            "message": "function is too big",
        })

    def test_refused_decompile_is_an_error_not_empty_success(self):
        result = self.mod.code(action="decompile_chain", addrs="0x401000", max_depth=2)
        entry = result if isinstance(result, dict) else result[0]
        self.assertIs(entry.get("error"), True)
        self.assertEqual(entry.get("addr"), "0x401000")
        self.assertEqual(entry.get("category"), "runtime")
        self.assertIn("message", entry)
        # Regression: the old code reported success with an empty pseudocode.
        self.assertNotIn("pseudocode", entry)
        self.assertNotIn("callers_context", entry)


if __name__ == "__main__":
    unittest.main()
