"""Tests for ida_mcp/compat.py — runtime feature-detection shim."""
from __future__ import annotations

import sys
import unittest
from unittest import mock

from tests._isolated_repo_loader import load_ida_module


def _load_compat():
    """Load compat.py directly through the shared isolated loader."""
    return load_ida_module("compat")


class CompatOutsideIdaTests(unittest.TestCase):
    """When the SDK isn't importable, version-gated probes return safe defaults."""

    def setUp(self) -> None:
        self.mod = _load_compat()
        # Force the version cache to re-resolve against the *current* sys.modules
        # (in case a previous test injected a fake idaapi)
        self.mod._MAJOR = 0
        self.mod._MINOR = 0
        self.mod._PATCH = 0
        self.mod._version_loaded = False
        # Also make sure no fake idaapi is in sys.modules
        self._saved_idaapi = sys.modules.get("idaapi")
        sys.modules.pop("idaapi", None)
        self._saved_lumina = sys.modules.get("ida_lumina")
        sys.modules.pop("ida_lumina", None)
        self.mod.reset_probe_cache()

    def tearDown(self) -> None:
        if self._saved_idaapi is not None:
            sys.modules["idaapi"] = self._saved_idaapi
        if self._saved_lumina is not None:
            sys.modules["ida_lumina"] = self._saved_lumina
        self.mod.reset_probe_cache()

    def test_version_is_zero_zero_zero_outside_ida(self) -> None:
        self.assertEqual(self.mod.ida_version(), (0, 0, 0))

    def test_version_str_unknown_outside_ida(self) -> None:
        self.assertEqual(self.mod.ida_version_str(), "unknown")

    def test_at_least_conservative_outside_ida(self) -> None:
        # Outside IDA, at_least returns True so feature-gated tools can still
        # load.  Hard guards belong in has_feature() (which checks the probe).
        self.assertTrue(self.mod.at_least(9, 3))
        self.assertTrue(self.mod.at_least(9, 2))
        self.assertTrue(self.mod.at_least(0, 0))

    def test_attribute_probes_are_false_outside_ida(self) -> None:
        # Without idaapi, probes that depend on SDK attributes return False
        self.assertFalse(self.mod.has_cfunc_serialize())
        self.assertFalse(self.mod.has_ida_lumina())
        self.assertFalse(self.mod.has_forbid_noprop())
        self.assertFalse(self.mod.has_xref_tree_widget())

    def test_probe_cache_is_written(self) -> None:
        self.mod.has_cfunc_serialize()
        self.assertIn("cfunc_serialize", self.mod._PROBE_CACHE)

    def test_reset_probe_cache_clears(self) -> None:
        self.mod.has_cfunc_serialize()
        self.mod.reset_probe_cache()
        self.assertEqual(self.mod._PROBE_CACHE, {})


class CompatFakeIda93Tests(unittest.TestCase):
    """Simulate running inside IDA 9.3 — all 9.3 features should be available."""

    def setUp(self) -> None:
        self.mod = _load_compat()
        self.mod.reset_probe_cache()

        # Build a fake idaapi module that reports kernel 9.3 and has all
        # the new 9.3 attributes present.
        class _FakeCfunc:
            def serialize(self, *a, **k): ...
            def deserialize(self, *a, **k): ...

        class _FakeVdui:
            def ui_noprop_lvar(self, *a, **k): ...

        fake_idaapi = mock.MagicMock()
        fake_idaapi.get_kernel_version.return_value = "9.3.260421"
        fake_idaapi.cfunc_t = _FakeCfunc
        fake_idaapi.vdui_t = _FakeVdui
        fake_idaapi.PLFM_NDS32 = 76
        fake_idaapi.SRCLANG_OBJCPP = 0x20
        fake_idaapi.BWN_XREF_TREE = "BWN_XREF_TREE"

        # Insert a fake `idaapi` into sys.modules so the probe can import it
        self._saved_idaapi = sys.modules.get("idaapi")
        sys.modules["idaapi"] = fake_idaapi

        # Build a fake `ida_lumina` module
        self._saved_lumina = sys.modules.get("ida_lumina")
        sys.modules["ida_lumina"] = mock.MagicMock()

    def tearDown(self) -> None:
        if self._saved_idaapi is not None:
            sys.modules["idaapi"] = self._saved_idaapi
        else:
            sys.modules.pop("idaapi", None)
        if self._saved_lumina is not None:
            sys.modules["ida_lumina"] = self._saved_lumina
        else:
            sys.modules.pop("ida_lumina", None)
        self.mod.reset_probe_cache()

    def test_version_is_9_3(self) -> None:
        self.assertEqual(self.mod.ida_version(), (9, 3, 260421))

    def test_version_str(self) -> None:
        self.assertEqual(self.mod.ida_version_str(), "9.3.260421")

    def test_at_least_9_3(self) -> None:
        self.assertTrue(self.mod.at_least(9, 3))
        self.assertTrue(self.mod.at_least(9, 2))
        self.assertTrue(self.mod.at_least(8, 0))

    def test_all_9_3_features_available(self) -> None:
        self.assertTrue(self.mod.has_cfunc_serialize())
        self.assertTrue(self.mod.has_ida_lumina())
        self.assertTrue(self.mod.has_forbid_noprop())
        self.assertTrue(self.mod.has_microcode_assertions())
        self.assertTrue(self.mod.has_mte_intrinsics())
        self.assertTrue(self.mod.has_neon_crypto_intrinsics())
        self.assertTrue(self.mod.has_cssc_intrinsics())
        self.assertTrue(self.mod.has_v850_decompiler())
        self.assertTrue(self.mod.has_nds32_processor())
        self.assertTrue(self.mod.has_objc_parser())
        self.assertTrue(self.mod.has_xref_tree_widget())
        self.assertTrue(self.mod.has_qset_qmap_headers())
        self.assertTrue(self.mod.has_golang_type_folders())


class CompatFakeIda92Tests(unittest.TestCase):
    """Simulate IDA 9.2 — 9.3-specific features should be unavailable."""

    def setUp(self) -> None:
        self.mod = _load_compat()
        self.mod.reset_probe_cache()

        fake_idaapi = mock.MagicMock()
        fake_idaapi.get_kernel_version.return_value = "9.2.250908"
        # No 9.3 attributes
        del fake_idaapi.cfunc_t  # remove auto-generated attr
        del fake_idaapi.vdui_t
        # Explicitly set to None
        fake_idaapi.cfunc_t = None
        fake_idaapi.vdui_t = None
        fake_idaapi.PLFM_NDS32 = None
        fake_idaapi.SRCLANG_OBJCPP = None
        fake_idaapi.BWN_XREF_TREE = None

        self._saved_idaapi = sys.modules.get("idaapi")
        sys.modules["idaapi"] = fake_idaapi

    def tearDown(self) -> None:
        if self._saved_idaapi is not None:
            sys.modules["idaapi"] = self._saved_idaapi
        else:
            sys.modules.pop("idaapi", None)
        self.mod.reset_probe_cache()

    def test_version_is_9_2(self) -> None:
        self.assertEqual(self.mod.ida_version()[:2], (9, 2))

    def test_9_3_features_unavailable(self) -> None:
        # All 9.3 features return False on 9.2
        self.assertFalse(self.mod.has_cfunc_serialize())
        self.assertFalse(self.mod.has_ida_lumina())
        self.assertFalse(self.mod.has_forbid_noprop())
        self.assertFalse(self.mod.has_microcode_assertions())
        self.assertFalse(self.mod.has_mte_intrinsics())
        self.assertFalse(self.mod.has_v850_decompiler())
        self.assertFalse(self.mod.has_nds32_processor())
        self.assertFalse(self.mod.has_xref_tree_widget())
        self.assertFalse(self.mod.has_qset_qmap_headers())

    def test_at_least_9_3_false_on_9_2(self) -> None:
        self.assertFalse(self.mod.at_least(9, 3))
        self.assertTrue(self.mod.at_least(9, 2))
        self.assertTrue(self.mod.at_least(8, 0))


if __name__ == "__main__":
    unittest.main()
