"""Function-management coverage across public and legacy argument modes."""

from __future__ import annotations

import idautils
import pytest

from ida_pro_mcp.ida_mcp.tools.funcs import funcs
from tests.fakes.ida_fake import create_sample_firmware_idb, install_fake_idb


def _ok(result):
    assert result.get("ok") is True, result
    return result


def test_function_reads_use_public_and_legacy_modes(fresh_fake_idb, monkeypatch):
    # The public spelling (address/limit) and the compatibility spelling
    # (addr/count) must drive the same underlying action.
    info = _ok(
        funcs(
            action="info",
            address="0x140001000",
            include_xrefs=True,
            include_prototype=True,
            include_stack=True,
        )
    )
    assert info["function"]["name"] == "main"
    assert info["function"]["caller_count"] >= 0
    assert "stack_frame" in info["function"]

    metrics = _ok(funcs(action="metrics", addr="0x140001000"))
    assert metrics["metrics"]["instruction_count"] >= 1
    assert metrics["metrics"]["density"] >= 0

    listing = _ok(funcs(action="list", address="0x140001000", limit=1, named_only=True))
    assert listing["count"] <= 1
    assert "sub_helper" not in listing.get("functions", "")

    similar = _ok(funcs(action="find_similar", addr="0x140001000", limit=5, min_score=0))
    assert similar["target"] == "0x140001000"
    assert similar["scanned"] >= 1

    # The wrapper accepts an alternate public address spelling even when the
    # operation reaches the legacy implementation.
    monkeypatch.setattr(idautils, "Functions", lambda *args, **kwargs: iter([0x140001000]), raising=False)
    one = _ok(funcs(action="list", address="0x140001000", limit=5))
    assert one["total"] == 1


def test_function_mutations_cover_create_change_flags_and_delete(fresh_fake_idb):
    created = _ok(
        funcs(
            action="create",
            address="0x140001100",
            end="0x140001120",
            name="new_entry",
            flags=1,
        )
    )
    assert created["name"] == "new_entry"
    changed = _ok(funcs(action="change", addr="0x140001100", end="0x140001130"))
    assert changed["changed"] is True
    flagged = _ok(funcs(action="set_flags", address="0x140001100", flags=4))
    assert flagged["flags"] == "0x4"

    # Resolve from the middle of the function, just as an IDA cursor action
    # would, and verify the containing function is the one removed.
    deleted = _ok(funcs(action="delete", address="0x140001110"))
    assert deleted["addr"] == "0x140001100"
    assert funcs(action="info", address="0x140001100")["error"] is True
    assert funcs(action="create", address="bad")["error"] is True
    assert funcs(action="change", address="0x140001000")["error"] is True


def test_function_metrics_follow_riscv_classification_mode(monkeypatch):
    db = create_sample_firmware_idb()
    install_fake_idb(db, processor="riscv", bitness=32, base=0x80000000)
    result = _ok(funcs(action="metrics", address="0x80000030"))
    assert result["function"] == "main"
    assert result["metrics"]["return_count"] >= 1
    assert funcs(action="info", address="0x80000030")["ok"] is True
