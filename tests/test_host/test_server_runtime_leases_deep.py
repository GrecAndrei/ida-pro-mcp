from __future__ import annotations

import json
import math
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.host.server.server_runtime_leases import (
    ServerRuntimeLeasesMixin,
    _lease_pid,
    _lease_timestamp,
    _process_start_token,
    _resolve_stale_cleanup_budget,
    _runtime_lease_io_lock,
)


def test_lease_pid_parsing() -> None:
    assert _lease_pid(1234) == 1234
    assert _lease_pid("5678") == 5678
    assert _lease_pid(True) == 0
    assert _lease_pid(False) == 0
    assert _lease_pid("not_a_number") == 0
    assert _lease_pid(None) == 0


def test_lease_timestamp_parsing() -> None:
    now = time.time()
    assert _lease_timestamp(now) == now
    assert _lease_timestamp("12345.67") == 12345.67
    assert _lease_timestamp(float("nan")) == 0.0
    assert _lease_timestamp(float("inf")) == 0.0
    assert _lease_timestamp("invalid") == 0.0


def test_resolve_stale_cleanup_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_MCP_STALE_LEASE_CLEANUP_BUDGET", "15.5")
    assert _resolve_stale_cleanup_budget() == 15.5

    # Values below 1.0 are clamped to min_value=1.0
    monkeypatch.setenv("IDA_MCP_STALE_LEASE_CLEANUP_BUDGET", "0.2")
    assert _resolve_stale_cleanup_budget() == 1.0


def test_runtime_lease_io_lock(tmp_path: Path) -> None:
    lease_file = str(tmp_path / "test.lease")
    with _runtime_lease_io_lock(lease_file):
        assert Path(lease_file + ".lock").exists()


def test_runtime_leases_mixin_write_record(tmp_path: Path) -> None:
    mixin = ServerRuntimeLeasesMixin()
    lease_path = str(tmp_path / "runtime.lease")
    now = time.time()
    payload = {
        "pid": 12345,
        "session_id": "sess-alpha",
        "created_at": now,
        "updated_at": now,
    }

    mixin._write_runtime_lease_record(lease_path, payload)
    assert Path(lease_path).is_file()
    data = json.loads(Path(lease_path).read_text(encoding="utf-8"))
    assert data["pid"] == 12345
    assert data["session_id"] == "sess-alpha"
