"""Unit tests for the offline pytest filesystem guard in tests/conftest.py."""

from __future__ import annotations

import pytest

from tests.conftest import _TEST_REPO_ROOT, _assert_test_path_safe


def test_offline_fs_guard_allows_pytest_cache_and_machinery():
    # Cache and temporary pytest directories under repo root must be permitted
    _assert_test_path_safe(_TEST_REPO_ROOT / ".pytest_cache" / "v" / "cache" / "nodeids")
    _assert_test_path_safe(_TEST_REPO_ROOT / "pytest-cache-files-123456" / "CACHEDIR.TAG")
    _assert_test_path_safe(_TEST_REPO_ROOT / ".pytest_tmp" / "run_1" / "temp.txt")
    _assert_test_path_safe(_TEST_REPO_ROOT / ".coverage.offline.123")
    _assert_test_path_safe(_TEST_REPO_ROOT / "__pycache__" / "mod.pyc")


def test_offline_fs_guard_blocks_repository_source_and_tests():
    # Production sources, config, and tests must be blocked from direct writes
    with pytest.raises(RuntimeError, match="blocked a write outside temporary roots"):
        _assert_test_path_safe(_TEST_REPO_ROOT / "src" / "ida_pro_mcp" / "tampered.py")

    with pytest.raises(RuntimeError, match="blocked a write outside temporary roots"):
        _assert_test_path_safe(_TEST_REPO_ROOT / "tests" / "tampered.py")

    with pytest.raises(RuntimeError, match="blocked a write outside temporary roots"):
        _assert_test_path_safe(_TEST_REPO_ROOT / "pyproject.toml")
