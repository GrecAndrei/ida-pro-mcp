"""Regression tests for work order s04-q05-memory-misc (settle wave).

Pins the settle fixes for the memory / misc / symbols tools. The underlying
behavior was introduced by the opaque-binary (RISC-V) analysis wave; this file
verifies it is intact and regression-proofs it:

- memory.py dispatch split: read-only actions (read/hexdump/search/compare/
  pointers/entropy/strings/struct_walk/histogram) ride the ``@idaread``
  ``_memory_read_impl`` (result cache) and only the write action routes through
  the ``@idawrite`` ``_memory_write_impl`` that invalidates the cache.
- memory(read, type="string") falls back to a bounded printable-run scan with a
  ``defined: false`` marker when no string literal is defined at the address —
  the opaque raw-blob / RISC-V firmware case where IDA has no strlit marks.
- memory(pointers, aligned=True) scans at every byte offset (step 1) so
  pointers in packed / hand-built / unaligned tables are found.
- misc read_file / write_file / python stay gated on an explicit call: the path
  and script parameters are required and path traversal is rejected, so file
  access and script execution stay safe.
- symbols load_dwarf preserves its IDA_ERROR error envelope when the dwarf
  plugin fails to load/run.

Host-side tests: ida_* modules are stubbed via tests._isolated_repo_loader;
no live IDA session is required.
"""
import io
import os
import struct
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import load_tool_module


def _blank_modules(names):
    for name in names:
        sys.modules.setdefault(name, types.ModuleType(name))


# ---------------------------------------------------------------------------
# memory module loader (mirrors test_swarm_t07's fake)
# ---------------------------------------------------------------------------

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
    mem = load_tool_module("memory", common_overrides={
        "ida_bytes": ida_bytes,
        "idc": idc,
        "ida_segment": ida_segment,
    })
    # Stub MCPError lacks the codes memory.py uses; add them in place like the
    # t07 suite does for GOVERNANCE_BLOCKED.
    for code in ("ADDRESS_INVALID", "SIZE_LIMIT_EXCEEDED", "GOVERNANCE_BLOCKED",
                 "IDA_ERROR", "INVALID_ARGS"):
        setattr(mem.MCPError, code, code)
    mem._inf_bitness = lambda: bitness
    mem._inf_is_be = lambda: False
    mem._inf_min_ea = lambda: 0x1000
    return mem


# ---------------------------------------------------------------------------
# memory dispatch split — read actions vs the single write action
# ---------------------------------------------------------------------------

READ_ACTIONS = ["read", "hexdump", "search", "compare", "pointers",
                "entropy", "strings", "struct_walk", "histogram"]


class TestMemoryReadWriteCacheSplit(unittest.TestCase):
    def setUp(self):
        self.mem = _load_memory()
        self.calls = []
        self.mem._memory_read_impl = lambda *a, **kw: (self.calls.append("read") or {})
        self.mem._memory_write_impl = lambda *a, **kw: (self.calls.append("write") or {})

    def test_every_read_action_routes_to_read_impl(self):
        # Each read-only action must be dispatched to the @idaread-decorated
        # implementation (the cacheable path), never the @idawrite one.
        for action in READ_ACTIONS:
            self.mem._memory_impl(action, "0x1000", "bytes", 16, None, None, 2)
            self.assertEqual(self.calls[-1], "read", f"{action} must route to @idaread")
        self.assertEqual(self.calls.count("write"), 0)

    def test_write_is_the_only_action_routing_to_write_impl(self):
        # The single mutating action rides @idawrite so only it invalidates
        # the read cache.
        self.mem._memory_impl("write", "0x1000", "bytes", 16, "90 90", None, 2)
        self.assertEqual(self.calls[-1], "write")
        self.assertEqual(self.calls.count("read"), 0)

    def test_unknown_action_still_reaches_read_impl_and_errors(self):
        # An unknown action is not a write: it stays on the read side and the
        # read implementation rejects it (never touches the @idawrite path).
        # The write impl is faked only to prove the unknown action never lands
        # there; the real read impl produces the INVALID_ARGS envelope.
        mem = _load_memory()
        mem._memory_write_impl = lambda *a, **kw: (self.calls.append("write") or {})
        res = mem._memory_impl("bogus", "0x1000", "bytes", 16, None, None, 2)
        self.assertEqual(self.calls.count("write"), 0)
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "INVALID_ARGS")


# ---------------------------------------------------------------------------
# memory(read, type="string") printable-run fallback
# ---------------------------------------------------------------------------

class TestMemoryStringFallback(unittest.TestCase):
    def setUp(self):
        self.mem = _load_memory()
        self.ida_bytes = self.mem.ida_bytes
        self.idc = self.mem.idc

    def test_fallback_when_no_literal_defined(self):
        # No string literal at the address (opaque blob): the read falls back
        # to a printable-run scan and flags the value as a heuristic.
        self.idc.get_strlit_contents = lambda *a: None
        self.ida_bytes.get_bytes = lambda ea, n: b"HELLO RAW" + b"\x00" * 8
        res = self.mem._memory_impl("read", "0x1000", "string", 16, None, None, 2)
        self.assertIs(res["ok"], True)
        self.assertEqual(res["value"], "HELLO RAW")
        self.assertEqual(res["length"], 9)
        self.assertIs(res["defined"], False)

    def test_defined_literal_keeps_defined_true(self):
        self.idc.get_strlit_contents = lambda *a: b"real string"
        res = self.mem._memory_impl("read", "0x1000", "string", 16, None, None, 2)
        self.assertIs(res["ok"], True)
        self.assertEqual(res["value"], "real string")
        self.assertIs(res["defined"], True)

    def test_fallback_stops_at_non_printable_byte(self):
        self.idc.get_strlit_contents = lambda *a: None
        self.ida_bytes.get_bytes = lambda ea, n: b"AB" + b"\xff" + b"CD"
        res = self.mem._memory_impl("read", "0x1000", "string", 16, None, None, 2)
        self.assertEqual(res["value"], "AB")
        self.assertEqual(res["length"], 2)
        self.assertIs(res["defined"], False)

    def test_fallback_stops_at_nul(self):
        self.idc.get_strlit_contents = lambda *a: None
        self.ida_bytes.get_bytes = lambda ea, n: b"AB" + b"\x00" + b"CD"
        res = self.mem._memory_impl("read", "0x1000", "string", 16, None, None, 2)
        self.assertEqual(res["value"], "AB")
        self.assertIs(res["defined"], False)

    def test_fallback_no_printable_run_returns_invalid_addr(self):
        self.idc.get_strlit_contents = lambda *a: None
        self.ida_bytes.get_bytes = lambda ea, n: b"\xff\xfe\x01\x02"
        res = self.mem._memory_impl("read", "0x1000", "string", 16, None, None, 2)
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "ADDRESS_INVALID")

    def test_fallback_caps_scan_length(self):
        # The fallback must cap the scanned run (request size bounded), not
        # slurp the whole region.
        self.idc.get_strlit_contents = lambda *a: None
        self.mem._STRING_FALLBACK_MAX = 8
        self.ida_bytes.get_bytes = lambda ea, n: b"A" * n
        res = self.mem._memory_impl("read", "0x1000", "string", 16, None, None, 2)
        self.assertEqual(res["value"], "A" * 8)
        self.assertEqual(res["length"], 8)

    def test_fallback_via_public_tool_entry(self):
        # The behavior advertised in the tool docstring must be reachable
        # through the public @tool entry point.
        self.mem.idc.get_strlit_contents = lambda *a: None
        self.mem.ida_bytes.get_bytes = lambda ea, n: b"pub entry" + b"\x00" * 8
        res = self.mem.memory(action="read", addr="0x1000", type="string")
        self.assertIs(res["ok"], True)
        self.assertEqual(res["value"], "pub entry")
        self.assertIs(res["defined"], False)

    def test_fallback_on_opaque_riscv_raw_blob(self):
        # Headerless RISC-V firmware dump: 32-bit raw blob with no strlit
        # marks anywhere — the string read must still surface the text with a
        # defined:false marker rather than erroring or inventing a literal.
        mem = _load_memory(bitness=32)
        mem.idc.get_strlit_contents = lambda *a: None
        mem.ida_bytes.get_bytes = lambda ea, n: b"Firmware banner\x00\x00" + b"\x00" * 64
        res = mem._memory_impl("read", "0x1000", "string", 16, None, None, 2)
        self.assertIs(res["ok"], True)
        self.assertEqual(res["value"], "Firmware banner")
        self.assertIs(res["defined"], False)


# ---------------------------------------------------------------------------
# memory _find_pointers byte-aligned scan mode
# ---------------------------------------------------------------------------

class TestMemoryByteAlignedPointers(unittest.TestCase):
    def _set_pointers(self, mem, raw):
        mem.ida_bytes.get_bytes = lambda ea, n: raw[:n]
        mem.ida_bytes.is_loaded = lambda v: v in (0x2000, 0x8000)
        mem.idc.get_name = lambda ea: "target" if ea in (0x2000, 0x8000) else ""

    def test_default_stride_misses_unaligned_pointer(self):
        # 64-bit pointer stored at offset 3 (not 8-aligned): the default
        # pointer-size stride must miss it.
        mem = _load_memory(bitness=64)
        raw = b"\x00\x00\x00" + struct.pack("<Q", 0x2000) + b"\x00" * 16
        self._set_pointers(mem, raw)
        self.assertEqual(mem._find_pointers(raw, 0x1000, aligned=False), [])

    def test_byte_aligned_scan_finds_unaligned_pointer(self):
        mem = _load_memory(bitness=64)
        raw = b"\x00\x00\x00" + struct.pack("<Q", 0x2000) + b"\x00" * 16
        self._set_pointers(mem, raw)
        ptrs = mem._find_pointers(raw, 0x1000, aligned=True)
        self.assertEqual([p["offset"] for p in ptrs], [3])
        self.assertEqual(ptrs[0]["target_addr"], "0x2000")
        self.assertEqual(ptrs[0]["target_name"], "target")

    def test_pointers_action_aligned_reports_byte_aligned_mode(self):
        # The pointers action exposes the aligned kwarg and labels the scan.
        mem = _load_memory(bitness=64)
        raw = b"\x00\x00\x00" + struct.pack("<Q", 0x2000) + b"\x00" * 8
        self._set_pointers(mem, raw)
        res = mem._memory_impl("pointers", "0x1000", "bytes", 16, None, "0x1020", 2,
                               aligned=True)
        self.assertIs(res["ok"], True)
        self.assertEqual(res["mode"], "byte_aligned")
        self.assertEqual([p["offset"] for p in res["pointers"]], [3])

    def test_packed_riscv_blob_32bit_unaligned_pointer(self):
        # Opaque RISC-V blob, 32-bit pointers in a packed table at a
        # non-4-aligned offset: only the byte-aligned scan finds them.
        mem = _load_memory(bitness=32)
        raw = b"\xaa\xbb" + struct.pack("<I", 0x8000) + b"\x00" * 8
        self._set_pointers(mem, raw)
        self.assertEqual(mem._find_pointers(raw, 0x1000, aligned=False), [])
        ptrs = mem._find_pointers(raw, 0x1000, aligned=True)
        self.assertEqual([p["offset"] for p in ptrs], [2])
        self.assertEqual(ptrs[0]["target_addr"], "0x8000")


# ---------------------------------------------------------------------------
# misc read_file / write_file / python guards
# ---------------------------------------------------------------------------

def _real_require_arg(value, name, hint=None):
    if value is None or (isinstance(value, str) and not value.strip()):
        return {"ok": False, "code": "MISSING_REQUIRED_ARG",
                "message": f"'{name}' parameter is required"}
    return None


def _real_require_one_of(**kwargs):
    provided = {k: v for k, v in kwargs.items()
                if v is not None and (not isinstance(v, str) or v.strip())}
    if not provided:
        return {"ok": False, "code": "MISSING_REQUIRED_ARG",
                "message": "At least one of {} is required".format(", ".join(kwargs))}
    return None


def _real_validate_path_safe(path, allow_absolute=True):
    import os as _os
    if not path:
        return None, {"ok": False, "code": "MISSING_REQUIRED_ARG", "message": "Path required"}
    if "\x00" in path:
        return None, {"ok": False, "code": "INVALID_ARG_VALUE", "message": "Path contains null bytes"}
    if ".." in path.replace("\\", "/").split("/"):
        return None, {"ok": False, "code": "PATH_TRAVERSAL", "message": "Path traversal detected"}
    return _os.path.normpath(path), None


def _load_misc():
    # The isolated _common stub does not bind io/sys/os (the real _common
    # re-exports them); misc's execute_python needs io.StringIO + sys, and the
    # file actions need os. Provide them so the module behaves like the real
    # runtime under IDA.
    misc = load_tool_module("misc", common_overrides={
        "io": io,
        "sys": sys,
        "os": os,
        "require_arg": _real_require_arg,
        "require_one_of": _real_require_one_of,
        "validate_path_safe": _real_validate_path_safe,
    })
    for code in ("MISSING_REQUIRED_ARG", "PATH_TRAVERSAL", "INVALID_ARG_VALUE",
                 "FILE_NOT_FOUND", "INVALID_FILE_FORMAT", "FILE_READ_ERROR",
                 "FILE_WRITE_ERROR", "FILE_ENCODING_ERROR"):
        setattr(misc.MCPError, code, code)
    return misc


class TestMiscFileAndExecGuards(unittest.TestCase):
    def setUp(self):
        self.misc = _load_misc()

    def test_read_file_requires_explicit_path(self):
        # File access is gated on an explicit call naming a path; a read with
        # no path is refused before any filesystem access.
        res = self.misc.misc(action="read_file")
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "MISSING_REQUIRED_ARG")

    def test_read_file_rejects_path_traversal(self):
        res = self.misc.read_file_impl("../etc/passwd")
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "PATH_TRAVERSAL")

    def test_read_file_rejects_traversal_via_tool(self):
        res = self.misc.misc(action="read_file", path="../../etc/passwd")
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "PATH_TRAVERSAL")

    def test_write_file_requires_explicit_path(self):
        res = self.misc.misc(action="write_file", content="data")
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "MISSING_REQUIRED_ARG")

    def test_write_file_requires_content(self):
        res = self.misc.misc(action="write_file", path="/tmp/x")
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "MISSING_REQUIRED_ARG")

    def test_write_file_rejects_path_traversal(self):
        res = self.misc.write_file_impl("../etc/x", "data")
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "PATH_TRAVERSAL")

    def test_python_requires_explicit_script(self):
        # Script execution is gated on an explicit expr/code argument; with
        # neither supplied the call is refused before any exec.
        res = self.misc.misc(action="python")
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "MISSING_REQUIRED_ARG")

    def test_python_blank_script_is_refused(self):
        res = self.misc.misc(action="python", expr="   ")
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "MISSING_REQUIRED_ARG")

    def test_python_script_given_proceeds(self):
        # With an explicit script the gated call runs and returns its result.
        res = self.misc.misc(action="python", expr="1 + 1")
        self.assertIs(res["ok"], True)
        self.assertEqual(res["result"], 2)

    def test_python_namespace_includes_idautils(self):
        import idautils
        res = self.misc.misc(action="python", expr="idautils")
        self.assertIs(res["ok"], True, res)
        self.assertIs(res["result"], idautils)


# ---------------------------------------------------------------------------
# symbols load_dwarf error envelope
# ---------------------------------------------------------------------------

class TestSymbolsLoadDwarfEnvelope(unittest.TestCase):
    def test_load_dwarf_error_envelope_on_plugin_failure(self):
        mod = load_tool_module("symbols")
        sys.modules["ida_loader"].load_and_run_plugin = lambda name, arg: False
        res = mod.symbols(action="load_dwarf")
        # Pre-fix this returned {"ok": True, ...} on a load failure.
        self.assertIs(res["ok"], False)
        self.assertEqual(res["code"], "IDA_ERROR")

    def test_load_dwarf_ok_on_plugin_success(self):
        mod = load_tool_module("symbols")
        sys.modules["ida_loader"].load_and_run_plugin = lambda name, arg: True
        res = mod.symbols(action="load_dwarf")
        self.assertIs(res["ok"], True)
        self.assertIs(res["loaded"], True)


if __name__ == "__main__":
    unittest.main()
