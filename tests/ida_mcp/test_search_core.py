"""Regression tests for t15_search_core audit fix.

Covers the dead md5 fingerprint fast path in search.core._get_db_fingerprint:
IDAPython's ida_nalt.retrieve_input_file_md5() returns a lowercase hex string
(not bytes), so the old ``md5.hex()`` raised AttributeError that was silently
swallowed — making every _db_changed() call fall through to a full-DB scan of
all functions, segments, and names. The fix normalizes both return types so the
fast path runs.
"""

from __future__ import annotations

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_submodule  # noqa: E402

MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def _core():
    return load_tool_submodule("search.core")


def _boom(calls, what):
    def _inner(*a, **k):
        calls.append(what)
        raise AssertionError(f"full-DB scan ({what}) should not run when md5 fast path works")
    return _inner


def test_md5_str_fastpath_skips_full_db_scan():
    core = _core()
    core.ida_nalt.retrieve_input_file_md5 = lambda: MD5

    scanned = []
    core.idautils.Functions = _boom(scanned, "Functions")
    core.idautils.Segments = _boom(scanned, "Segments")
    core.idautils.Names = _boom(scanned, "Names")

    assert core._get_db_fingerprint() == MD5
    assert scanned == []


def test_md5_bytes_return_type_is_decoded():
    # Older bindings return bytes; the fingerprint must still be a string.
    core = _core()
    core.ida_nalt.retrieve_input_file_md5 = lambda: MD5.encode("ascii")
    assert core._get_db_fingerprint() == MD5


def test_md5_absent_uses_count_fallback():
    core = _core()
    core.ida_nalt.retrieve_input_file_md5 = lambda: None
    core.idautils.Functions = lambda: [0x1000, 0x2000]
    core.idautils.Segments = lambda: [0x1000]
    core.idautils.Names = lambda: [("0x1000", "foo"), ("0x2000", "bar"), ("0x3000", "baz")]
    assert core._get_db_fingerprint() == "fallback:2:1:3"


def test_get_cached_strings_reaccess_skips_full_db_scan_when_md5_present():
    # Regression for the per-access cost. The cache guards short-circuit the
    # fingerprint on the first build, so the second (cached) access is where
    # _db_changed() runs — it must not trigger a Functions/Segments/Names scan
    # when the md5 fast path is live.
    core = _core()
    core.ida_nalt.retrieve_input_file_md5 = lambda: MD5
    core.safe_get_strlist_items = lambda: iter(())
    core.safe_get_strlit_contents = lambda ea: None
    assert core.get_cached_strings() == []  # first build, fingerprint not consulted

    scanned = []
    core.idautils.Functions = _boom(scanned, "Functions")
    core.idautils.Segments = _boom(scanned, "Segments")
    core.idautils.Names = _boom(scanned, "Names")

    assert core.get_cached_strings() == []  # cached path -> _db_changed() runs
    assert scanned == []


def test_db_changed_stable_under_same_md5():
    core = _core()
    core.ida_nalt.retrieve_input_file_md5 = lambda: MD5
    core._DB_FINGERPRINT = None
    assert core._db_changed() is True
    assert core._db_changed() is False
