"""Regression tests for the opaque raw-blob / RISC-V fixture seam (WO-T1).

Loads the committed ``tests/fixtures/riscv_blob.bin`` — a hand-assembled
RV64IMAC firmware slice (reset-vector jal, auipc+jalr init, a trap/vector
pointer table, ISRs, data) — into the shared single-segment raw-flat-blob fake
(``tests/ida_mcp/raw_blob_fake.py``) and pins the p-wave opaque-binary
surface:

- WO-F1 firmware seam: the real fixture bytes must keep producing sane
  vector-table / load-base candidates.  The IDA-side ``idb``
  architecture_profile action runs the real host inference on the fixture and
  must report ``file_kind=raw``, a riscv-first candidate with an RV64 lean,
  ``load_base=0x80000000`` (dominant lui/auipc), ``raw_binary_mode`` and the
  ``firmware_detected`` derivation idb.py:155 keys off.
- analysis tool on the raw blob: ``set_architecture`` (metapc/32 -> riscv/64
  with RISC-V hints), ``set_gp`` (the RISC-V GP seam), ``add_entry`` for a
  bootstrapped reset-vector, and ``_bootstrap_raw_entry_points`` seeding the
  reset vector + vector-table ISR targets.
- segments tool: the segment-register (sreg) GP round-trip on the flat blob.
- modify tool: ``create_data`` (pointer/array over the vector table) and
  ``create_strlit`` (over the rodata message) authoring on the raw blob.

Everything runs on the shared fake — no live IDA is required.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests.ida_mcp.raw_blob_fake import (
    RISCV_ISR_DEFAULT,
    RISCV_ISR_TIMER,
    RISCV_ISR_UART,
    RISCV_MAIN,
    RISCV_MSG,
    RISCV_RESET_HANDLER,
    RISCV_RESET_VEC,
    RISCV_TEXT_LEN,
    RISCV_UART_BASE,
    RISCV_VECTOR_TABLE,
    fixture_bytes,
    fixture_path,
    install_raw_blob,
)

# Load base the fixture is linked at (see the wiki provenance appendix).
LOAD_BASE = 0x80000000


def _vector_ptr(off: int) -> int:
    """Absolute VA of a fixture offset when loaded at 0x80000000."""
    return LOAD_BASE + off


# ---------------------------------------------------------------------------
# WO-F1 firmware seam: vector-table / load-base candidates on the fixture
# ---------------------------------------------------------------------------

class TestFixtureArchSeam(unittest.TestCase):
    """The committed fixture must keep producing the firmware signals WO-F1's
    vector-table / load-base ops build on (verified through the IDA-side idb
    architecture_profile action so the host inference runs on the real bytes)."""

    def setUp(self):
        self.blob = install_raw_blob(
            fixture_bytes(), processor="metapc", bitness=32, base=LOAD_BASE
        )
        self.mod = self.blob.load_tool("idb")

    def _raw_meta(self):
        # meta shaped like idb_meta() would produce for a raw .bin loaded at
        # 0x80000000 with the bin loader.
        return {
            "binary_path": fixture_path(),
            "file_type_id": 17,
            "file_type_info": {"effective": "raw", "loader": "bin"},
            "file_type_effective": "raw",
            "file_type": "raw",
            "processor": "metapc",
            "bitness": 32,
            "is_be": False,
        }

    def test_architecture_profile_reports_raw_riscv_with_load_base(self):
        result = self.mod.idb_architecture_profile(
            meta=self._raw_meta(), summary={"imports": 0, "exports": 0}
        )
        # Raw-blob surface on the fixture.
        self.assertTrue(result["raw_binary_mode"], result)
        inferred = result["inferred_from_binary"]
        self.assertEqual(inferred.get("file_kind"), "raw")
        self.assertTrue(inferred.get("looks_like_code"))
        # The vector-table / load-base ops see a riscv candidate first...
        cands = list(inferred.get("candidates") or [])
        self.assertTrue(cands, inferred)
        self.assertEqual(cands[0]["processor"], "riscv", cands)
        self.assertEqual(cands[0]["bitness"], 64, cands)  # RV64 lean from ld/sd
        rv32 = next((c for c in cands if c["bitness"] == 32), None)
        self.assertIsNotNone(rv32)
        self.assertGreater(cands[0]["confidence"], rv32["confidence"])
        # ...and the dominant lui/auipc hi20 resolves to the linked base.
        self.assertEqual(inferred.get("load_base"), LOAD_BASE, inferred)
        self.assertEqual(result["inferred_load_base"], LOAD_BASE)
        self.assertIn("0x80000000", inferred.get("reason", ""))
        # firmware_detected derivation used by idb.py overview (line 155).
        is_firmware = bool(result["raw_binary_mode"])
        self.assertTrue(is_firmware)

    def test_architecture_profile_carries_honest_raw_warning(self):
        result = self.mod.idb_architecture_profile(
            meta=self._raw_meta(), summary={"imports": 0, "exports": 0}
        )
        self.assertIn("raw_binary_warning", result)
        self.assertIn("entrypoints_note", result)  # opaque blob: no headers

    def test_fixture_reset_vector_and_vector_table_bytes(self):
        """Data-integrity guard: the fixture bytes at the documented offsets
        match the assembly in the wiki provenance appendix."""
        data = fixture_bytes()
        self.assertEqual(len(data), 300)
        # Reset vector: j reset_handler (jal x0, +0x20) = 0x0200006f.
        self.assertEqual(data[RISCV_RESET_VEC:RISCV_RESET_VEC + 4], b"\x6f\x00\x00\x02")
        # Vector table: LE u32 absolute VAs into the 0x80000000-linked image.
        vt = data[RISCV_VECTOR_TABLE:RISCV_VECTOR_TABLE + 16]
        self.assertEqual(
            vt,
            _vector_ptr(RISCV_RESET_HANDLER).to_bytes(4, "little")
            + _vector_ptr(RISCV_ISR_TIMER).to_bytes(4, "little")
            + _vector_ptr(RISCV_ISR_UART).to_bytes(4, "little")
            + _vector_ptr(RISCV_ISR_DEFAULT).to_bytes(4, "little"),
        )
        # rodata starts right after .text; uart_base holds 0x10003000.
        self.assertEqual(
            data[RISCV_UART_BASE:RISCV_UART_BASE + 4], b"\x00\x30\x00\x10"
        )


# ---------------------------------------------------------------------------
# analysis tool on the raw blob: set_architecture / set_gp / add_entry /
# raw entry bootstrap
# ---------------------------------------------------------------------------

def _load_arch_utils(blob):
    """Load the real arch_utils through the loader (bypassing the
    ida_mcp/__init__ runtime chain) and point it at the fake idaapi so
    get_arch() / is_riscv_family() resolve the blob's mutable arch state."""
    from tests._isolated_repo_loader import load_support_module
    arch_utils = load_support_module("arch_utils")
    arch_utils.idaapi = blob.module("idaapi")
    return arch_utils


def _analysis_helpers(arch_utils):
    """Real arch_utils family helpers the analysis tool star-imports from the
    real _common.__all__ (public names; the loader stub has no __all__ so the
    underscore helpers are bound on the module separately)."""
    return {
        "get_arch": arch_utils.get_arch,
        "is_riscv_family": arch_utils.is_riscv_family,
        "is_arm_family": arch_utils.is_arm_family,
    }


def _analysis_module_attrs(arch_utils):
    """Underscore info helpers the real _common.__all__ star-exports to
    analysis but the loader stub skips; bind them on the loaded module."""
    get_arch = arch_utils.get_arch

    def _is_64() -> bool:
        return get_arch() in ("x64", "arm64", "riscv64", "mips64", "ppc64", "sparc64")

    return {
        "_inf_procname": get_arch,
        "_inf_is_64bit": _is_64,
        "_inf_bitness": lambda: 64 if _is_64() else 32,
        "_inf_is_be": lambda: False,
        "_inf_filetype_id": lambda: 17,
        "_filetype_name": lambda ft: "raw" if ft == 17 else f"type_{ft}",
    }


class TestAnalysisRawBlobFlow(unittest.TestCase):
    def setUp(self):
        # A bare-metal RISC-V ISR map for the disasm helpers.  The reset
        # vector decodes as `j 0x80000020`; the GP init at reset_handler is
        # the auipc+addi pair detect_riscv_gp / the wiki recipe read.
        self.blob = install_raw_blob(
            fixture_bytes(), processor="metapc", bitness=32, base=LOAD_BASE,
            insn_map={
                LOAD_BASE: ("j", [_vector_ptr(RISCV_RESET_HANDLER)]),
                LOAD_BASE + RISCV_RESET_HANDLER: ("auipc", ["gp", 0x80000]),
                LOAD_BASE + RISCV_RESET_HANDLER + 4: ("addi", ["gp", "gp", 0]),
                LOAD_BASE + RISCV_MAIN: ("addi", ["sp", "sp", -16]),
                LOAD_BASE + RISCV_ISR_DEFAULT: ("auipc", ["gp", 0x80000]),
                LOAD_BASE + RISCV_ISR_TIMER: ("auipc", ["gp", 0x80000]),
                LOAD_BASE + RISCV_ISR_UART: ("auipc", ["gp", 0x80000]),
            },
        )
        self.arch_utils = _load_arch_utils(self.blob)
        self.mod = self.blob.load_tool(
            "analysis", overrides=_analysis_helpers(self.arch_utils)
        )
        # The isolated _common stub has no __all__, so star-import skips the
        # underscore helpers (_inf_procname, ...) — bind them on the loaded
        # module explicitly (same pattern t07/p13 use) so actions like the
        # set_gp non-RISCV guard can build their error details.
        for _helper, _fn in _analysis_module_attrs(self.arch_utils).items():
            setattr(self.mod, _helper, _fn)
        # Reset the module-global GP-apply cache so each test re-applies.
        self.arch_utils._APPLIED_RISCV_GP = None

    def test_set_architecture_switches_metapc32_to_riscv64(self):
        res = self.mod.analysis(
            action="set_architecture", processor="riscv", bitness=64, endian="le"
        )
        self.assertTrue(res["ok"], res)
        applied = res["applied"]
        proc = applied["processor"]
        self.assertEqual(proc["value"], "riscv")
        self.assertEqual(proc["previous"], "metapc")
        self.assertEqual(applied["bitness"], 64)
        # RISC-V arch hints for the raw-blob recipe (GP / alignment note).
        hints = applied.get("arch_hints", {})
        self.assertEqual(hints.get("ptr_size"), 8)
        self.assertIn("riscv_note", hints)
        self.assertIn("set_gp", hints["riscv_note"])
        # The fake recorded the switch so later actions see riscv.
        self.assertEqual(self.blob.state["processor_applied"], "riscv")
        self.assertEqual(self.blob.state["bitness_applied"], 64)

    def test_set_architecture_requires_an_argument(self):
        res = self.mod.analysis(action="set_architecture")
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], "INVALID_ARGS")

    def test_set_gp_applies_and_queues_reanalysis(self):
        # Move to RISC-V first (set_gp is RISC-V-only).
        self.mod.analysis(action="set_architecture", processor="riscv", bitness=64)
        res = self.mod.analysis(action="set_gp", gp="0x80002000")
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["gp"], 0x80002000)
        self.assertTrue(res["applied"], res)
        self.assertTrue(res["reanalysis_queued"], res)
        self.assertIn("gp=0x80002000", self.blob.state["processor_options"])
        self.assertTrue(self.blob.state["planned_ranges"])  # plan_range queued

    def test_set_gp_rejects_non_riscv_target(self):
        res = self.mod.analysis(action="set_gp", gp="0x80002000")
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], "INVALID_ARGS")
        self.assertIn("only valid for RISC-V", res["message"])

    def test_add_entry_registers_bootstrapped_reset_vector(self):
        res = self.mod.analysis(
            action="add_entry", addr="0x80000000", ordinal=1, name="reset"
        )
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["ordinal"], 1)
        self.assertEqual(res["addr"], hex(LOAD_BASE))
        self.assertEqual(res["name"], "reset")
        self.assertEqual(self.blob.state["entries"], [(1, LOAD_BASE, "reset")])

    def test_entry_bootstrap_seeds_reset_and_isr_targets(self):
        """_bootstrap_raw_entry_points must seed the reset-vector jal target
        and the LE u32 vector-table ISR pointers as code/entry candidates."""
        # Switch to RISC-V first so the bootstrap takes the RISC-V branch
        # (reset `j` + LE u32 ISR table scan).
        self.mod.analysis(action="set_architecture", processor="riscv", bitness=64)
        end = LOAD_BASE + len(fixture_bytes())
        boot = self.mod._bootstrap_raw_entry_points(LOAD_BASE, end)
        self.assertGreaterEqual(boot["seeded_entries"], 1, boot)
        functions = self.blob.state["functions"]
        self.assertIn(_vector_ptr(RISCV_RESET_HANDLER), functions)
        self.assertIn(_vector_ptr(RISCV_ISR_TIMER), functions)
        self.assertIn(_vector_ptr(RISCV_ISR_UART), functions)
        # Candidates are promoted to real entries via ida_entry.add_entry.
        entry_eas = [ea for (_o, ea, _n) in self.blob.state["entries"]]
        self.assertTrue(entry_eas)
        self.assertIn(_vector_ptr(RISCV_RESET_HANDLER), entry_eas)


# ---------------------------------------------------------------------------
# segments tool: segment-register (GP) round-trip on the flat blob
# ---------------------------------------------------------------------------

class TestSregGpOnRawBlob(unittest.TestCase):
    def setUp(self):
        self.blob = install_raw_blob(
            fixture_bytes(), processor="riscv", bitness=64, base=LOAD_BASE
        )
        idaapi = self.blob.module("idaapi")

        def _validate_addr(addr, *a, **kw):
            ea = int(str(addr), 0)
            if not idaapi.is_mapped(ea):
                return None, {
                    "ok": False,
                    "code": "ADDRESS_NOT_MAPPED",
                    "message": f"Address {hex(ea)} is not mapped in the database",
                }
            return ea, None

        self.mod = self.blob.load_tool("segments", overrides={"validate_addr": _validate_addr})

    def test_gp_sreg_round_trip(self):
        set_res = self.mod.segments(
            action="sreg_set", start="0x80000000", reg="GP", value=0x80002000
        )
        self.assertTrue(set_res["ok"], set_res)
        self.assertEqual(set_res["reg"], "GP")
        self.assertEqual(set_res["value"], 0x80002000)

        get_res = self.mod.segments(action="sreg_get", start="0x80000000", reg="GP")
        self.assertTrue(get_res["ok"], get_res)
        self.assertEqual(get_res["value"], 0x80002000)
        self.assertEqual(get_res["reg"], "GP")
        self.assertEqual(get_res["range"]["start"], "0x80000000")
        # split_sreg_range carries the value to the end of the flat segment.
        self.assertGreaterEqual(int(get_res["range"]["end"], 16), LOAD_BASE + len(fixture_bytes()))

    def test_sreg_list_shows_gp(self):
        self.mod.segments(action="sreg_set", start="0x80000000", reg="GP", value=0x80002000)
        result = self.mod.segments(action="sreg_list", start="0x80000000", reg="GP")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["reg"], "GP")
        self.assertEqual(len(result["ranges"]), 1)
        self.assertEqual(result["ranges"][0]["value"], 0x80002000)
        self.assertEqual(result["ranges"][0]["start"], "0x80000000")

    def test_sreg_set_unmapped_address_rejected(self):
        res = self.mod.segments(action="sreg_set", start="0x99990000", reg="GP", value=1)
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], "ADDRESS_NOT_MAPPED")


# ---------------------------------------------------------------------------
# modify tool: create_data / create_strlit authoring on the raw blob
# ---------------------------------------------------------------------------

class TestModifyRawBlobAuthoring(unittest.TestCase):
    def setUp(self):
        self.blob = install_raw_blob(
            fixture_bytes(), processor="riscv", bitness=64, base=LOAD_BASE
        )
        # The modify tool does `from .governance_engine import
        # evaluate_operation`; load it under the tools package first so the
        # relative import resolves (mirrors test_swarm_p03_authoring).
        from tests._isolated_repo_loader import load_tool_module
        load_tool_module("governance_engine")
        self.mod = self.blob.load_tool("modify")

    def test_create_data_pointer_array_over_vector_table(self):
        res = self.mod.modify(
            action="create_data", addr="0x80000008", item_type="array", count=4
        )
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["count"], 4)
        self.assertEqual(res["size"], 16)
        self.assertEqual(res["item_type"], "array")
        self.assertEqual(int(res["end"], 16), LOAD_BASE + RISCV_VECTOR_TABLE + 16)
        self.assertEqual(len(self.blob.state["data_items"]), 4)

    def test_create_data_unknown_item_type_rejected(self):
        res = self.mod.modify(action="create_data", addr="0x80000008", item_type="mumbo")
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], "INVALID_ARGS")

    def test_create_strlit_over_rodata_message(self):
        msg_addr = LOAD_BASE + RISCV_MSG
        # "RV64FW" is 6 bytes including the NUL terminator.
        res = self.mod.modify(action="create_strlit", addr=hex(msg_addr), size=6, strtype="c")
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["size"], 6)
        self.assertEqual(res["length"], 6)
        self.assertEqual(self.blob.state["strlits"], [(msg_addr, 6, 0)])

    def test_create_strlit_requires_size(self):
        res = self.mod.modify(action="create_strlit", addr="0x800000c7")
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], "INVALID_ARGS")


if __name__ == "__main__":
    unittest.main()
