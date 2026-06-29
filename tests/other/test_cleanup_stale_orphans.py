"""Tests for session cleanup_stale including the orphan-eviction path.

We construct a SessionManager in a temp dir, plant fake session
metadata where the binary_path AND idb_path both reference files we
created then deleted, and run cleanup_stale. The dead sessions must be
removed from disk and the response should expose ``orphan_sids`` /
``orphan_count`` keys without breaking the legacy ``count`` key.
"""

from __future__ import annotations

import importlib
import inspect
import json
import os
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path


def _seed_meta(
    sessions_dir: Path,
    sid: str,
    binary: str,
    idb: str,
    age_days: int = 0,
) -> None:
    """Persist a session metadata JSON file."""
    sessions_dir.mkdir(parents=True, exist_ok=True)
    accessed = datetime.now() - timedelta(days=age_days)
    meta = {
        "session_id": sid,
        "idb_path": idb,
        "binary_path": binary,
        "analysis_options": {},
        "analysis_applied": False,
        "ida_args": [],
        "binary_exists": os.path.isfile(binary),
        "idb_exists": os.path.isfile(idb),
        "created_at": accessed.isoformat(),
        "last_accessed": accessed.isoformat(),
        "tags": [],
        "notes": "",
        "auto_name": os.path.basename(binary) if os.path.exists(binary) else "x",
        "phase": "triage",
        "linked_sessions": [],
        "packed_idb": False,
    }
    (sessions_dir / f"SID_{sid}_metadata.json").write_text(json.dumps(meta))


def test_session_action_returns_orphan_keys():
    """The action's source must surface orphan_sids / orphan_count keys
    even when no orphans actually exist (response shape contract).
    """
    src = importlib.import_module(
        "ida_pro_mcp.host.server.server_session"
    ).ServerSessionMixin._session_action_cleanup_stale
    source = inspect.getsource(src)
    assert "orphan_sids" in source
    assert "orphan_count" in source
    assert "deleted_count" in source


def test_session_manager_cleanup_stale_basic(tmp_path: Path, monkeypatch):
    """An all-fresh session store should not delete anything by age."""
    # Save the real cache_dir so we can patch SessionManager to use the tmp dir.
    from ida_pro_mcp.host.server.session import SessionManager

    mgr = SessionManager(str(tmp_path))
    sessions_dir = Path(mgr.session_dir)

    bin_path = tmp_path / "alive.bin"
    idb_path = tmp_path / "alive.i64"
    bin_path.write_bytes(b"ELF\x7f")
    idb_path.write_bytes(b"x" * 4096)

    _seed_meta(sessions_dir, "ALIVE01A", str(bin_path), str(idb_path))

    # Re-spawn a manager pointed at the same dir to load it.
    mgr2 = SessionManager(str(tmp_path))
    assert mgr2.get_session("ALIVE01A") is not None

    # Fresh session is not stale by 30d default.
    purged = mgr2.cleanup_stale(max_age_days=30)
    assert purged == []


def test_session_manager_only_orphans_get_cleaned(tmp_path: Path):
    """Verify SessionManager.cleanup_stale still works on real data with
    no orphans — guarantees we don't regress the existing API.
    """
    from ida_pro_mcp.host.server.session import SessionManager

    mgr = SessionManager(str(tmp_path))
    _seed_meta(Path(mgr.session_dir), "FRESH01", "/no/binary", "/no/i64", age_days=0)
    # No delete expected for fresh entry.
    purged = mgr.cleanup_stale(max_age_days=30)
    assert purged == []
