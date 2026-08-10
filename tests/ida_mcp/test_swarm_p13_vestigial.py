"""p13 vestigial error-code/comment surface regression tests (paper 10.2 item 12).

The DEBUGGER_*/EMULATION_*/BOOKMARK_* error codes were designed for a
debugger/emulation/bookmark-mutation surface.  Since then the emulation surface
became public (the ``emulate`` tool, ida_dbg-backed), so the EMULATION_* hints
point at it; the debugger and bookmark surfaces are still NOT exposed as public
operations.  This file pins the honest rebuild:

- Every DEBUGGER_*/BOOKMARK_* hint states the real path: no public op exists;
  drive the underlying capability through ``misc(action='python')`` (``ida_dbg``
  helpers) if code execution is authorized, or the host ``ida_r2_*`` triage
  namespace once enabled.
- The EMULATION_* hints point at the now-public ``emulate`` tool
  (``emulate(action='info')`` for the backend/state overview) and are not
  marked vestigial.
- None of the edited hints reference a claimed-but-absent tool/op (the
  ``ida_python`` op alias, a fake ``max_steps`` emulation parameter,
  ``search(action="emulate")``, ...) or the old misleading phrasing that
  implied a public breakpoint/step/process/thread/emulation op existed.
- The vestigial surface is otherwise intact: every code still exists (no
  removals) and the ``make_error`` envelope/categories are unchanged.

Verification pins (no source change): ``tools/__init__.py`` carries no
commented-out ``api_enums``/``api_bookmarks``/``api_signatures``/``api_resources``
blocks, and ``idb.py``'s ``firmware_detected`` stays live (derives from
``arch_profile.raw_binary_mode``) — exercised with an opaque RISC-V raw-blob
profile.

The IDA-side modules are loaded via ``tests._isolated_repo_loader``; no live
IDA session is required.
"""

import sys
import types
import unittest

from tests._isolated_repo_loader import (
    IDA_MCP_ROOT,
    install_common_stub,
    load_ida_module,
)

# The three vestigial families.  All must stay defined (do-not-remove) while
# their hints state the honest path.
DEBUGGER_CODES = [
    "DEBUGGER_NOT_RUNNING",
    "DEBUGGER_ACTIVE",
    "DEBUGGER_BREAKPOINT_ERROR",
    "DEBUGGER_MEMORY_ERROR",
    "DEBUGGER_REGISTER_ERROR",
    "DEBUGGER_STEP_ERROR",
    "DEBUGGER_PROCESS_ERROR",
    "DEBUGGER_THREAD_ERROR",
]
EMULATION_CODES = ["EMULATION_ERROR", "EMULATION_TIMEOUT"]
BOOKMARK_CODES = ["BOOKMARK_NOT_FOUND", "BOOKMARK_DUPLICATE"]
VESTIGIAL_CODES = DEBUGGER_CODES + EMULATION_CODES + BOOKMARK_CODES

# Codes whose hints must not use the pre-rebuild "operation failed" phrasing
# (it implied a public op that did not exist). EMULATION is excluded: the
# ``emulate`` tool IS a public op now, so "Emulation/emulator operation failed"
# is honest, not misleading.
_NON_EMULATION_VESTIGIAL_CODES = DEBUGGER_CODES + BOOKMARK_CODES

# Misleading phrasing from the pre-rebuild surface that must be gone.
_MISLEADING_SUBSTRINGS = [
    "operation failed",        # implied a public breakpoint/step/process/thread op
    "this operation requires",  # implied a public op existed
    "reduce max_steps",        # implied a public emulation op with max_steps
]

# Claimed-but-absent tools/ops that the edited hints must not reference.
_ABSENT_OP_REFERENCES = [
    "ida_python",              # op alias superseded by the honest misc(python) path
    'search(action="emulate"', # no public search action emulates
    "max_steps",               # no public emulation op exposes max_steps
    "ida_debug",               # no such op exists
]


class TestVestigialHintsHonest(unittest.TestCase):
    """The rebuilt DEBUGGER_*/EMULATION_*/BOOKMARK_* hints state the honest
    path and never claim a public op that does not exist."""

    @classmethod
    def setUpClass(cls):
        install_common_stub()
        cls.mod = load_ida_module("error_handling")
        cls.hints = cls.mod.ERROR_HINTS
        cls.codes = cls.mod.MCPError

    def test_all_vestigial_codes_still_exist(self):
        # Directive: do NOT remove any codes.
        for code in VESTIGIAL_CODES:
            self.assertIs(getattr(self.codes, code), code)
            self.assertIn(code, self.hints, f"{code} missing from ERROR_HINTS")

    def test_debugger_hints_state_honest_misc_python_path(self):
        for code in DEBUGGER_CODES:
            hint = self.hints[code]
            self.assertIn("public", hint, code)
            self.assertIn("misc(action=", hint, code)
            self.assertIn("ida_dbg", hint, code)

    def test_emulation_hints_point_to_public_emulate_tool(self):
        # Emulation became a public op (the ``emulate`` tool); the EMULATION_*
        # hints must not point at the vestigial misc(action='python') path or a
        # claimed-but-absent ida_r2_* engine, and the error hint must name the
        # public tool for recovery.
        for code in EMULATION_CODES:
            hint = self.hints[code]
            self.assertNotIn("misc(action=", hint, code)
            self.assertNotIn("ida_r2_", hint, code)
        self.assertIn("emulate(action=", self.hints["EMULATION_ERROR"])

    def test_bookmark_hints_state_honest_path(self):
        for code in BOOKMARK_CODES:
            hint = self.hints[code]
            self.assertIn("public", hint, code)
            self.assertIn("misc(action=", hint, code)
        # Read-only native bookmark listing IS public via idb(action="bookmarks").
        self.assertIn("idb(action=", self.hints["BOOKMARK_NOT_FOUND"])

    def test_misleading_wording_gone_from_edited_hints(self):
        # EMULATION is exempt (public op now); the truly-vestigial codes must
        # keep the honest phrasing.
        for code in _NON_EMULATION_VESTIGIAL_CODES:
            hint = self.hints[code].lower()
            for bad in _MISLEADING_SUBSTRINGS:
                self.assertNotIn(bad, hint, (code, self.hints[code]))

    def test_no_claimed_but_absent_tool_referenced(self):
        for code in VESTIGIAL_CODES:
            hint = self.hints[code]
            for ref in _ABSENT_OP_REFERENCES:
                self.assertNotIn(ref, hint, (code, hint))


class TestFirmwareDetectedStaysLive(unittest.TestCase):
    """idb(action='overview') must still set firmware_detected from
    arch_profile.raw_binary_mode on an opaque raw-blob (RISC-V) profile."""

    @classmethod
    def setUpClass(cls):
        from tests._isolated_repo_loader import load_tool_module

        # Snapshot sys.modules before mutating it at class scope. The autouse
        # _isolate_sys_modules fixture snapshots per-test (after setUpClass
        # runs), so without an explicit restore here these blank ida_* modules
        # leak into subsequent test files (e.g. firmware's bounds probe reads
        # ida_ida.inf_get_min_ea from the stale module).
        cls._pre_class_sys_modules = dict(sys.modules)

        def _blank(names):
            for name in names:
                sys.modules.setdefault(name, types.ModuleType(name))

        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        idaapi.get_idb = lambda: None
        idaapi.get_inf_structure = lambda: None
        idc = types.ModuleType("idc")
        ida_ida = types.ModuleType("ida_ida")
        ida_ida.inf_get_min_ea = lambda: 0
        ida_ida.inf_get_max_ea = lambda: 0x2000
        ida_ida.inf_get_cc_id = lambda: 0
        ida_ida.inf_get_baseaddr = lambda: 0
        ida_ida.inf_is_dll = lambda: False
        ida_ida.inf_is_be = lambda: False
        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.get_input_file_path = lambda: "blob.bin"
        ida_entry = types.ModuleType("ida_entry")
        _blank([
            "ida_typeinf", "ida_segment", "ida_name", "ida_lines",
            "ida_bytes", "ida_funcs", "ida_hexrays", "ida_frame",
            "ida_struct", "ida_ua", "ida_kernwin", "ida_loader",
            "ida_dbg", "idautils",
        ])
        sys.modules["idaapi"] = idaapi
        sys.modules["idc"] = idc
        sys.modules["ida_ida"] = ida_ida
        sys.modules["ida_nalt"] = ida_nalt
        sys.modules["ida_entry"] = ida_entry
        cls.mod = load_tool_module(
            "idb", common_overrides={"idaapi": idaapi, "idc": idc}
        )

    @classmethod
    def tearDownClass(cls):
        """Restore sys.modules to the pre-class snapshot so the blank ida_*
        modules do not leak into later tests."""
        snapshot = getattr(cls, "_pre_class_sys_modules", None)
        if snapshot is None:
            return
        for name in list(sys.modules.keys()):
            if name not in snapshot:
                del sys.modules[name]
        for name, mod in snapshot.items():
            if sys.modules.get(name) is not mod:
                sys.modules[name] = mod

    def _overview_with_profile(self, raw_binary_mode):
        mod = self.mod
        # Patch the internals the overview action delegates to so only the
        # firmware_detected derivation is under test.
        mod.idb_meta = dict
        mod.idb_summary = lambda **kw: {}
        mod.idb_segments_detailed = lambda **kw: []
        mod.idb_entrypoints_detailed = lambda: {"entrypoints": []}
        profile = {
            "raw_binary_mode": raw_binary_mode,
            "inferred_from_binary": {"candidates": []},
        }
        mod.idb_architecture_profile = lambda **kw: profile
        return mod.idb(action="overview")

    def test_opaque_riscv_raw_blob_sets_firmware_detected(self):
        # Opaque RISC-V raw blob -> arch_profile.raw_binary_mode True -> the
        # firmware_detected flag + firmware next-actions surface.
        result = self._overview_with_profile(raw_binary_mode=True)
        self.assertIs(result["ok"], True)
        self.assertIs(result["firmware_detected"], True)
        self.assertTrue(result["next_actions"])

    def test_known_container_does_not_set_firmware_detected(self):
        result = self._overview_with_profile(raw_binary_mode=False)
        self.assertIs(result["ok"], True)
        self.assertNotIn("firmware_detected", result)


class TestToolsPackageCleanNoApiBlocks(unittest.TestCase):
    """Verification pins: tools/__init__.py stays free of commented-out
    api_enums/api_bookmarks/api_signatures/api_resources blocks."""

    def test_tools_init_has_no_commented_api_blocks(self):
        text = (IDA_MCP_ROOT / "tools" / "__init__.py").read_text()
        for api in ("api_enums", "api_bookmarks", "api_signatures", "api_resources"):
            self.assertNotIn(api, text, f"tools/__init__.py must stay free of {api}")

    def test_package_init_has_no_commented_api_blocks(self):
        # The package __init__ no longer carries commented-out api_* imports
        # (the api_enums/api_bookmarks/api_signatures/api_resources modules were
        # deleted; the stale commented lines were a dangling-reference hangover).
        text = (IDA_MCP_ROOT / "__init__.py").read_text()
        for api in ("api_enums", "api_bookmarks", "api_signatures", "api_resources"):
            self.assertNotIn(api, text, f"ida_mcp/__init__.py must stay free of {api}")

    def test_idb_firmware_detected_derives_from_raw_binary_mode(self):
        text = (IDA_MCP_ROOT / "tools" / "idb.py").read_text()
        self.assertIn(
            'is_firmware = bool(arch_profile.get("raw_binary_mode"))', text
        )
        self.assertIn('result["firmware_detected"] = True', text)
