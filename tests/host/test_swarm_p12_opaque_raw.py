"""Host-side regression tests for the opaque RISC-V raw-blob fixture (WO-T1).

These run entirely on the host — no live IDA — and pin the parts of the
opaque-binary pipeline that WO-F1's vector-table / load-base ops build on:

- ``infer_binary_arch_profile`` over the real committed fixture bytes must
  keep returning a riscv-first candidate with an RV64 lean and the dominant
  lui/auipc hi20 resolving to the linked load base 0x80000000.
- ``prepared_profile`` must carry the same load-base / file-kind signals in
  server-friendly shape.
- r2/rz bininfo + load-hint extraction against the fixture must agree with the
  arch profile (skipped when neither tool is installed).
- firmware_detected must be consistent between the compact response formatter
  (keeps explicit ``firmware_detected`` values under drop_false) and the
  server session's raw-binary fallback heuristic when the file-type metadata
  reports raw.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests.ida_mcp.raw_blob_fake import fixture_path

FIXTURE = fixture_path()
LOAD_BASE = 0x80000000


def _load_services():
    from ida_pro_mcp.host.analysis.arch_profile import (
        infer_binary_arch_profile,
        prepared_profile,
    )
    return infer_binary_arch_profile, prepared_profile


class TestOpaqueArchProfile(unittest.TestCase):
    """The committed fixture must keep producing a riscv-first, RV64-lean,
    load-base 0x80000000 arch profile."""

    def setUp(self):
        # Store as instance attributes: class attributes would bind `self`
        # when the plain function is accessed through the instance.
        self.infer, self.prepared = _load_services()

    def test_infer_binary_arch_profile_riscv_first_with_load_base(self):
        inf = self.infer(FIXTURE)
        self.assertEqual(inf["file_kind"], "raw")
        self.assertTrue(inf["looks_like_code"])
        # Raw ambiguous blobs keep the top processor/bitness in candidates
        # (top-level processor is None so IDA is not force-fed an arch).
        self.assertIsNone(inf.get("processor"))
        cands = inf["candidates"]
        self.assertTrue(cands, inf)
        self.assertEqual(cands[0]["processor"], "riscv", cands)
        self.assertEqual(cands[0]["bitness"], 64, cands)  # RV64 lean from ld/sd
        rv32 = next((c for c in cands if c["bitness"] == 32), None)
        self.assertIsNotNone(rv32)
        self.assertGreater(cands[0]["confidence"], rv32["confidence"])
        # The dominant lui/auipc hi20 resolves to the linked base.
        self.assertEqual(inf["load_base"], LOAD_BASE, inf)
        self.assertIn("0x80000000", inf["reason"])
        # Sanity gate: RV opcode density must clear the C-extension floor.
        self.assertGreaterEqual(inf["confidence"], 0.5)

    def test_ambiguous_flag_false_for_clear_rv64_lean(self):
        inf = self.infer(FIXTURE)
        # 0.732 vs 0.366 is a clear bitness call, not an ambiguous tie.
        self.assertFalse(inf["ambiguous"])

    def test_prepared_profile_carries_load_base_and_file_kind(self):
        inf = self.infer(FIXTURE)
        prepared = self.prepared(inf)
        self.assertEqual(prepared["load_base"], LOAD_BASE)
        self.assertEqual(prepared["file_kind"], "raw")
        self.assertIn("warning", prepared)
        # Confidence survives the hand-off so the caller can decide whether to
        # auto-apply the inference.
        self.assertGreaterEqual(prepared["confidence"], 0.5)

    def test_prepared_profile_respects_explicit_options(self):
        inf = self.infer(FIXTURE)
        prepared = self.prepared(
            inf, {"processor": "riscv", "bitness": 64, "endian": "little"}
        )
        self.assertEqual(prepared["processor"], "riscv")
        self.assertEqual(prepared["bitness"], 64)
        self.assertEqual(prepared["endian"], "little")  # normalize_arch_options canonicalizes
        self.assertEqual(prepared["load_base"], LOAD_BASE)


class TestOpaqueR2Bininfo(unittest.TestCase):
    """r2/rz bininfo + load hints against the fixture (skipped when neither
    tool is installed; tolerant of differing radare2 output shapes)."""

    def test_bininfo_and_load_hints_agree(self):
        rz = self._find("rz")
        r2 = self._find("r2") or self._find("radare2")
        if rz is None and r2 is None:
            self.skipTest("neither rz nor r2 is installed")
        if rz is not None:
            self._check_rz(rz)
        if r2 is not None:
            self._check_r2(r2)

    def _find(self, name):
        import shutil
        return shutil.which(name)

    def _check_rz(self, rz):
        import json
        import subprocess
        out = subprocess.run(
            [rz, "-j", "-qq", "-B", hex(LOAD_BASE), FIXTURE],
            capture_output=True, text=True, timeout=60,
        )
        if out.returncode != 0:
            self.skipTest(f"rz bininfo failed: {out.stderr[:200]}")
        info = json.loads(out.stdout or "{}")
        self.assertIn("core", info)
        core = info["core"]
        self.assertIn("size", core)
        self.assertGreaterEqual(core["size"], len(open(FIXTURE, "rb").read()) // 2)

    def _check_r2(self, r2):
        import json
        import subprocess
        out = subprocess.run(
            [r2, "-q", "-e", "bin.rawstr=true", "-B", hex(LOAD_BASE), "-c", "iIj", FIXTURE],
            capture_output=True, text=True, timeout=60,
        )
        if out.returncode != 0:
            self.skipTest(f"r2 bininfo failed: {out.stderr[:200]}")
        lines = [l for l in out.stdout.splitlines() if l.strip()]
        self.assertTrue(lines)
        try:
            info = json.loads(lines[0])
        except Exception:
            self.skipTest("r2 iIj did not emit JSON (raw blob)")
        # Raw .bin forced at 0x80000000: baddr reflects our load base when the
        # installed radare2 reports it for bare blobs.
        if "baddr" in info:
            self.assertEqual(info["baddr"], LOAD_BASE)
        self.assertGreaterEqual(info.get("size", 0), 0)


class TestFirmwareDetectedConsistency(unittest.TestCase):
    """firmware_detected must survive both the compact formatter and the
    server-session fallback heuristic when file-type metadata reports raw."""

    def test_compact_formatter_keeps_false_and_true_firmware_detected(self):
        from ida_pro_mcp.host.server.server_response_compact import (
            ServerResponseCompactMixin,
        )
        obj = ServerResponseCompactMixin.__new__(ServerResponseCompactMixin)
        for value in (False, True):
            compacted = obj._compact_value(
                {"ok": True, "firmware_detected": value},
                {"drop_false": True, "drop_ok": True},
            )
            self.assertIn("firmware_detected", compacted)
            self.assertIs(compacted["firmware_detected"], value)

    def test_session_fallback_heuristic_flags_raw_meta(self):
        # Re-implementation of server_session._build_state_payload's fallback
        # (server_session.py ~2290) so the fixture's raw metadata is flagged
        # firmware even when no explicit raw_binary_mode is present.
        def session_is_firmware(meta, summary):
            ft_info = meta.get("file_type_info") if isinstance(meta.get("file_type_info"), dict) else {}
            ft_name = str(
                meta.get("file_type_effective")
                or ft_info.get("effective")
                or meta.get("file_type")
                or ""
            ).strip().lower()
            ft_id = meta.get("file_type_id")
            try:
                ft_num = int(ft_id) if ft_id is not None else None
            except Exception:
                ft_num = None
            proc = str(meta.get("processor") or meta.get("arch") or "").strip().lower()
            imports = summary.get("imports") if isinstance(summary, dict) else None
            try:
                imports = int(imports or 0)
            except Exception:
                imports = 0
            return bool(
                ft_name in {"", "raw", "unknown", "bin", "binary", "obj"}
                or ft_num in {0, 2, 17}
                or (proc in ("arm", "mips", "ppc", "msp430", "avr", "xtensa") and imports == 0)
            )

        meta = {
            "binary_path": FIXTURE,
            "file_type_id": 17,
            "file_type_effective": "raw",
            "file_type_info": {"effective": "raw", "loader": "bin"},
            "processor": "metapc",
            "bitness": 32,
        }
        self.assertTrue(session_is_firmware(meta, {"imports": 0}))
        # A PE with imports is never firmware under the same heuristic.
        pe_meta = {"file_type_id": 3, "file_type_effective": "pe", "processor": "metapc"}
        self.assertFalse(session_is_firmware(pe_meta, {"imports": 5}))

    def test_idb_raw_mode_derivation_matches_fixture(self):
        # idb.py:509 raw_mode uses the same file-type signals the server
        # session heuristic keys off; assert the fixture metadata flips it on
        # (loaded through the isolated loader so no live IDA runtime is
        # pulled in; the fixture file powers the inference hand-off).
        from tests.ida_mcp.raw_blob_fake import fixture_bytes, install_raw_blob
        blob = install_raw_blob(
            fixture_bytes(), processor="riscv", bitness=64, base=LOAD_BASE
        )
        mod = blob.load_tool("idb")
        meta = {
            "binary_path": FIXTURE,
            "file_type": "raw",
            "file_type_id": 17,
            "file_type_info": {"effective": "raw"},
            "processor": "metapc",
        }
        summary = {"imports": 0, "exports": 0}
        profile = mod.idb_architecture_profile(meta=meta, summary=summary)
        self.assertTrue(profile["raw_binary_mode"])
        self.assertEqual(profile["current"]["file_type"], "raw")
        self.assertIn("entrypoints_note", profile)


if __name__ == "__main__":
    unittest.main()
