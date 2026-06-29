"""Tests for installer/discovery.py — multi-install detection + selection."""
from __future__ import annotations

import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_pro_mcp.installer.discovery import (  # noqa: E402
    STATE_FILE,
    IdaInstall,
    detect_ida_installs,
    read_install_state,
    select_ida_install,
    write_install_state,
)


def _make_fake_install(tmp: Path, name: str, build: str, *, version: tuple[int, int] = (9, 3)) -> Path:
    """Create a directory that looks like an IDA Pro install.

    `tmp / name` will contain a small script named 'idat' (the wrapper) and
    a fake 'ida' binary.  We can't ship a real IDA, but we can produce a
    file that contains the version string `strings` will find.
    """
    d = tmp / name
    d.mkdir(parents=True, exist_ok=True)
    # On Windows, the discovery code looks for the .exe suffix; on POSIX
    # it looks for the bare name.  Create both so the test is portable.
    idat_bare = d / "idat"
    ida_bare = d / "ida"
    idat_win = d / "idat.exe"
    ida_win = d / "ida.exe"
    # Tiny `idat` wrapper script
    idat_bare.write_text("#!/bin/sh\nexec ./ida \"$@\"\n")
    idat_bare.chmod(0o755)
    idat_win.write_text("@echo off\r\nida.exe %*\r\n")
    idat_win.chmod(0o755)
    # Fake `ida` binary containing the version string.  Real IDA has
    # '9.3.260421.be7de18d' embedded in the binary; we simulate that.
    payload = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 12
    payload += f"{version[0]}.{version[1]}.{build}.deadbeef".encode("ascii") + b"\x00" * 256
    ida_bare.write_bytes(payload)
    ida_bare.chmod(0o755)
    # On Windows, the file is a PE not ELF, but the version string still
    # appears in the raw bytes that `strings` reads.
    ida_win.write_bytes(payload)
    ida_win.chmod(0o755)
    # Fake pro license
    (d / "idapro_99-9999-AAAA-99.hexlic").write_text("FAKE")
    return d


def _strings_calls_real(binary: Path):
    """Use a real `strings` invocation against the fake binary."""
    import subprocess

    result = subprocess.run(
        ["strings", "-n", "5", str(binary)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.splitlines() if result.returncode == 0 else []


class _DiscoveryFixture(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.tmp = Path(tempfile.mkdtemp(prefix="ida-discovery-"))
        # Patch all discovery scan functions to use the fixture dir
        from ida_pro_mcp.installer import discovery

        def _fake_scan_home():
            for p in sorted(self.tmp.iterdir()):
                if p.is_dir() and p.name.startswith("ida-pro-"):
                    yield p.resolve()

        self._home_patcher = mock.patch.object(discovery, "_scan_home", _fake_scan_home)
        self._sys_patcher = mock.patch.object(discovery, "_scan_system_dirs", lambda: iter([]))
        self._path_patcher = mock.patch.object(discovery, "_from_path", lambda: iter([]))
        self._env_patcher = mock.patch.object(discovery, "_from_env", lambda: iter([]))
        self._home_patcher.start()
        self._sys_patcher.start()
        self._path_patcher.start()
        self._env_patcher.start()
        self.addCleanup(self._home_patcher.stop)
        self.addCleanup(self._sys_patcher.stop)
        self.addCleanup(self._path_patcher.stop)
        self.addCleanup(self._env_patcher.stop)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


class IdaInstallDataclassTests(unittest.TestCase):
    def test_to_from_dict_roundtrip(self) -> None:
        # On Windows, Path("/opt/...") gets rendered with backslashes by
        # str(); compare via os.path.normpath so the test is portable.
        inst = IdaInstall(
            path=Path("/opt/ida-pro-9.3"),
            version=(9, 3),
            build="260421.be7de18d",
            idat_binary=Path("/opt/ida-pro-9.3/idat"),
            arch="x64",
            flavor="pro",
            source="home_scan",
        )
        d = inst.to_dict()
        self.assertEqual(os.path.normpath(d["path"]), os.path.normpath("/opt/ida-pro-9.3"))
        self.assertEqual(tuple(d["version"]), (9, 3))
        self.assertEqual(d["build"], "260421.be7de18d")
        back = IdaInstall.from_dict(d)
        self.assertEqual(back, inst)

    def test_display_format(self) -> None:
        # Use a path under $HOME so display() relativizes to ~/
        home = Path.home()
        inst = IdaInstall(
            path=home / "ida-pro-9.3",
            version=(9, 3),
            build="260421.be7de18d",
            idat_binary=home / "ida-pro-9.3" / "idat",
            arch="x64",
            flavor="pro",
            source="home_scan",
        )
        d = inst.display
        self.assertIn("9.3.260421.be7de18d", d)
        self.assertIn("pro", d)
        # Uses ~/... for home paths
        self.assertIn("~", d)


class DetectionTests(_DiscoveryFixture):
    def test_detects_two_fake_installs(self) -> None:
        _make_fake_install(self.tmp, "ida-pro-9.2", "250908", version=(9, 2))
        _make_fake_install(self.tmp, "ida-pro-9.3", "260421", version=(9, 3))

        installs = detect_ida_installs()
        self.assertEqual(len(installs), 2)
        # Sorted newest first
        self.assertEqual(installs[0].version, (9, 3))
        self.assertEqual(installs[1].version, (9, 2))

    def test_detection_skips_dirs_without_idat(self) -> None:
        (self.tmp / "ida-pro-9.2").mkdir()
        (self.tmp / "ida-pro-9.3").mkdir()
        installs = detect_ida_installs()
        # Both are empty dirs — should be empty
        self.assertEqual(installs, [])

    def test_version_string_format(self) -> None:
        _make_fake_install(self.tmp, "ida-pro-9.3", "260421", version=(9, 3))
        installs = detect_ida_installs()
        self.assertEqual(len(installs), 1)
        self.assertEqual(installs[0].version_str, "9.3")
        self.assertEqual(installs[0].full_version_str, "9.3.260421.deadbeef")
        self.assertIn("deadbeef", installs[0].build)


class SelectionTests(_DiscoveryFixture):
    def setUp(self) -> None:
        super().setUp()
        _make_fake_install(self.tmp, "ida-pro-9.2", "250908", version=(9, 2))
        _make_fake_install(self.tmp, "ida-pro-9.3", "260421", version=(9, 3))
        self.installs = detect_ida_installs()

    def test_explicit_version_major_minor(self) -> None:
        chosen = select_ida_install(self.installs, explicit_version="9.2")
        self.assertEqual(chosen.version, (9, 2))

    def test_explicit_version_three_components_matches_build_prefix(self) -> None:
        chosen = select_ida_install(self.installs, explicit_version="9.3.260421")
        self.assertEqual(chosen.version, (9, 3))
        self.assertTrue(chosen.build.startswith("260421"))

    def test_explicit_version_major_only(self) -> None:
        chosen = select_ida_install(self.installs, explicit_version="9")
        # Multiple 9.x installs; picks highest
        self.assertEqual(chosen.version, (9, 3))

    def test_explicit_dir(self) -> None:
        chosen = select_ida_install([], explicit_dir=self.tmp / "ida-pro-9.2")
        self.assertEqual(chosen.version, (9, 2))
        self.assertEqual(chosen.flavor, "pro")

    def test_no_installs_raises(self) -> None:
        with self.assertRaises(RuntimeError):
            select_ida_install([])

    def test_no_match_raises_with_helpful_message(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            select_ida_install(self.installs, explicit_version="8.5")
        msg = str(cm.exception)
        self.assertIn("8.5", msg)
        self.assertIn("9.3", msg)
        self.assertIn("9.2", msg)

    def test_invalid_version_string_raises(self) -> None:
        with self.assertRaises(RuntimeError):
            select_ida_install(self.installs, explicit_version="abc")
        # "9.3.260421.abcdef" now parses as (9, 3, 260421) via defensive parser,
        # matching build prefix "260421" on the 9.3 install. The old strict int()
        # parser raised by accident; the new behavior preserves the match.
        chosen = select_ida_install(self.installs, explicit_version="9.3.260421.abcdef")
        self.assertEqual(chosen.version, (9, 3))
        self.assertTrue(chosen.build.startswith("260421"))

    def test_single_install_auto_picked(self) -> None:
        only_92 = [self.installs[1]]  # 9.2
        chosen = select_ida_install(only_92)
        self.assertEqual(chosen.version, (9, 2))

    def test_default_picks_highest(self) -> None:
        chosen = select_ida_install(self.installs)
        self.assertEqual(chosen.version, (9, 3))

    def test_prompt_fn_called_for_multiple(self) -> None:
        captured = {}

        def _prompt(installs):
            captured["called"] = True
            return installs[1]

        chosen = select_ida_install(self.installs, prompt_fn=_prompt)
        self.assertTrue(captured.get("called"))
        self.assertEqual(chosen.version, (9, 2))


class StateFileTests(_DiscoveryFixture):
    def setUp(self) -> None:
        super().setUp()
        _make_fake_install(self.tmp, "ida-pro-9.3", "260421", version=(9, 3))

    def test_write_and_read_roundtrip(self) -> None:
        inst = detect_ida_installs()[0]
        path = write_install_state(self.tmp, inst)
        self.assertEqual(path, self.tmp / STATE_FILE)
        back = read_install_state(self.tmp)
        self.assertIsNotNone(back)
        self.assertEqual(back.path, inst.path)
        self.assertEqual(back.version, inst.version)

    def test_read_missing_returns_none(self) -> None:
        self.assertIsNone(read_install_state(self.tmp / "nonexistent"))

    def test_read_corrupt_returns_none(self) -> None:
        (self.tmp / STATE_FILE).write_text("not json at all")
        self.assertIsNone(read_install_state(self.tmp))

    def test_read_partial_returns_none(self) -> None:
        (self.tmp / STATE_FILE).write_text(json.dumps({"foo": "bar"}))
        self.assertIsNone(read_install_state(self.tmp))


class DetectOnRealSystemTests(unittest.TestCase):
    """When run on the user's actual machine, we should find 9.2 and 9.3."""

    @unittest.skipUnless(
        (Path.home() / "ida-pro-9.3").is_dir() and (Path.home() / "ida-pro-9.2").is_dir(),
        "requires ~/ida-pro-9.2 and ~/ida-pro-9.3 to exist",
    )
    def test_finds_both_9_2_and_9_3(self) -> None:
        installs = detect_ida_installs()
        versions = {i.version for i in installs}
        self.assertIn((9, 2), versions)
        self.assertIn((9, 3), versions)
        # 9.3 should sort first
        self.assertEqual(installs[0].version, (9, 3))


if __name__ == "__main__":
    unittest.main()
