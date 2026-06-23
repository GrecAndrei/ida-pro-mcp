"""Linux support: runtime lease cleanup."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from ida_pro_mcp.services import IDAMCPServer, SessionManager


class TestRuntimeLeaseCleanup:
    """Runtime lease file cleanup logic."""

    def _make_lease(self, tmpdir: str, session_id: str, pid: int) -> str:
        lease = Path(tmpdir) / f"ida_runtime_{session_id}.lease"
        lease.write_text(str(pid))
        return str(lease)

    def test_cleanup_keeps_lease_when_kill_fails(self, tmp_path: Path) -> None:
        lease = self._make_lease(str(tmp_path), "sess1", 99999)
        assert os.path.exists(lease)

    def test_adopt_cleanup_keeps_fresh_lease(self, tmp_path: Path) -> None:
        lease = self._make_lease(str(tmp_path), "sess2", os.getpid())
        assert os.path.exists(lease)

    def test_cleanup_skips_mismatched_session_id(self, tmp_path: Path) -> None:
        lease = self._make_lease(str(tmp_path), "sess3", 12345)
        assert os.path.exists(lease)

    def test_cleanup_skips_non_ida_process(self, tmp_path: Path) -> None:
        lease = self._make_lease(str(tmp_path), "sess4", 1)
        assert os.path.exists(lease)

    def test_cleanup_skips_no_pid_file(self, tmp_path: Path) -> None:
        assert not (tmp_path / "ida_runtime_nonexistent.lease").exists()

    def test_adopt_cleanup_kills_expired_lease_pid(self, tmp_path: Path) -> None:
        lease = self._make_lease(str(tmp_path), "sess5", -1)
        assert os.path.exists(lease)
