"""Behavior tests for relocation handling and session lifecycle fixes.

Relocation handling
- ``_build_ida_command`` must accept hex-string ``baseaddr``/``rebase_to``
  (the public schema documents them as strings like "0x400000") instead of
  silently dropping the flags on ``int("0x400000")``.
- ``_get_session_imagebase`` must never invent a default image base
  (the old hardcoded 0x140000000 rebased every 32-bit address into garbage).
- ``_add_address_calculations`` must skip enrichment when the image base is
  unknown and must not RVA-rebase addresses at/above a known image base.

Session lifecycle
- Session metadata (watchdog verdicts, apply transcripts) must survive a
  to_dict/from_dict round trip.
- Stale-session pruning must not delete sessions that still own a live
  IDA runtime (that would orphan the process and the IDB lock).
- ``_update_session_indexing_metadata`` must not rewrite the metadata file
  when nothing changed (it runs every watchdog tick).
"""

from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.server.server import IDAMCPServer
from ida_pro_mcp.host.server.session import Session, SessionManager


def _make_server(tmp_path, monkeypatch) -> IDAMCPServer:
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_STRUCTURED_CONTENT", "1")
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    return IDAMCPServer()


def _fake_session(**overrides) -> SimpleNamespace:
    base = {
        "session_id": "ABC12345",
        "idb_path": "/tmp/SID_ABC12345_x.i64",
        "binary_path": "/tmp/x.bin",
        "ida_args": [],
        "analysis_options": {},
        "packed_idb": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


# ---------------------------------------------------------------------------
# Relocation: IDA command-line load flags
# ---------------------------------------------------------------------------


class TestBuildIdaCommandRelocationFlags:
    def test_baseaddr_hex_string_becomes_paragraph_flag(self, tmp_path, monkeypatch):
        server = _make_server(tmp_path, monkeypatch)
        server.idat_exe = "/usr/bin/idat"
        session = _fake_session(analysis_options={"baseaddr": "0x400000"})
        cmd = server._build_ida_command(
            session, "/tmp/ida.log", "/tmp/server_script.py", False, session.idb_path
        )
        assert "-b0x40000" in cmd, cmd

    def test_baseaddr_int_becomes_paragraph_flag(self, tmp_path, monkeypatch):
        server = _make_server(tmp_path, monkeypatch)
        server.idat_exe = "/usr/bin/idat"
        session = _fake_session(analysis_options={"baseaddr": 0x400000})
        cmd = server._build_ida_command(
            session, "/tmp/ida.log", "/tmp/server_script.py", False, session.idb_path
        )
        assert "-b0x40000" in cmd, cmd

    def test_rebase_to_hex_string_becomes_paragraph_flag(self, tmp_path, monkeypatch):
        server = _make_server(tmp_path, monkeypatch)
        server.idat_exe = "/usr/bin/idat"
        session = _fake_session(analysis_options={"rebase_to": "0x400000"})
        cmd = server._build_ida_command(
            session, "/tmp/ida.log", "/tmp/server_script.py", False, session.idb_path
        )
        assert "-R0x40000" in cmd, cmd

    def test_entry_point_int_is_hex_formatted(self, tmp_path, monkeypatch):
        server = _make_server(tmp_path, monkeypatch)
        server.idat_exe = "/usr/bin/idat"
        session = _fake_session(analysis_options={"entry_point": 0x401000})
        cmd = server._build_ida_command(
            session, "/tmp/ida.log", "/tmp/server_script.py", False, session.idb_path
        )
        assert "-e401000" in cmd, cmd

    def test_stack_size_hex_string_parsed(self, tmp_path, monkeypatch):
        server = _make_server(tmp_path, monkeypatch)
        server.idat_exe = "/usr/bin/idat"
        session = _fake_session(analysis_options={"stack_size": "0x100000"})
        cmd = server._build_ida_command(
            session, "/tmp/ida.log", "/tmp/server_script.py", False, session.idb_path
        )
        assert "-s1048576" in cmd, cmd


# ---------------------------------------------------------------------------
# Relocation: image-base resolution and address enrichment
# ---------------------------------------------------------------------------


class TestGetSessionImagebase:
    def test_no_fabricated_default_when_unknown(self, tmp_path, monkeypatch):
        server = _make_server(tmp_path, monkeypatch)
        try:
            assert server._get_session_imagebase(None) is None
            assert server._get_session_imagebase("NOPE1234") is None
        finally:
            server.shutdown()

    def test_uses_target_session_options_not_current(self, tmp_path, monkeypatch):
        server = _make_server(tmp_path, monkeypatch)
        try:
            target = server.session_mgr.create_session(
                "/tmp/target.bin", analysis_options={"baseaddr": "0x400000"}
            )
            other = server.session_mgr.create_session(
                "/tmp/other.bin", analysis_options={"baseaddr": "0x800000"}
            )
            server.current_session = other
            assert server._get_session_imagebase(target.session_id) == 0x400000
        finally:
            server.shutdown()

    def test_caches_rpc_answer_on_runtime(self, tmp_path, monkeypatch):
        server = _make_server(tmp_path, monkeypatch)
        seen = {}

        def fake_rpc(payload, port, **kwargs):
            seen["port"] = port
            return {"ok": True, "image_base": "0x140000000"}

        try:
            sid = "ABC12345"
            server.session_runtimes[sid] = {"port": 9999, "auth_token": "t"}
            server._send_rpc_raw = fake_rpc
            assert server._get_session_imagebase(sid) == 0x140000000
            assert "imagebase" in server.session_runtimes[sid]
            # Second call must hit the cache, not another RPC.
            assert server._get_session_imagebase(sid) == 0x140000000
            assert seen == {"port": 9999}
        finally:
            server.shutdown()


class TestAddAddressCalculations:
    def test_skipped_when_imagebase_unknown(self, tmp_path, monkeypatch):
        server = _make_server(tmp_path, monkeypatch)
        try:
            compacted = {"text": "the pointer lives at 0x401000"}
            server._add_address_calculations(compacted, None)
            assert "llm_address_calculation" not in compacted
        finally:
            server.shutdown()

    def test_32bit_address_not_rebased_to_garbage(self, tmp_path, monkeypatch):
        server = _make_server(tmp_path, monkeypatch)
        try:
            sid = server.session_mgr.create_session(
                "/tmp/t.bin", analysis_options={"baseaddr": "0x400000"}
            ).session_id
            compacted = {"text": "address 0x401000 and rva-ish 0x1000"}
            server._add_address_calculations(compacted, sid)
            calc = compacted.get("llm_address_calculation") or {}
            # 0x401000 is at/above the image base: must stay absolute.
            assert "is_rva" not in calc.get("0x401000", {})
            assert calc["0x401000"]["decimal"] == 0x401000
            # 0x1000 is below the image base: legitimately an RVA.
            assert calc["0x1000"]["is_rva"] is True
            assert calc["0x1000"]["decimal"] == 0x401000
            assert compacted["llm_address_calculation_imagebase"] == "0x400000"
        finally:
            server.shutdown()


# ---------------------------------------------------------------------------
# Session lifecycle: metadata persistence and prune guards
# ---------------------------------------------------------------------------


class TestSessionMetadataPersistence:
    def test_metadata_round_trips_through_to_dict_from_dict(self):
        session = Session("ABC12345", "/tmp/SID_ABC12345_x.i64", "/tmp/x.bin")
        session.metadata = {
            "analysis_state": "stalled",
            "analysis_stall_seconds": 42.0,
            "apply_steps": [{"step": "reanalyze", "ok": True}],
        }
        restored = Session.from_dict(session.to_dict())
        assert restored.metadata == session.metadata

    def test_metadata_survives_manager_save_and_reload(self, tmp_path):
        mgr = SessionManager(str(tmp_path / "cache"))
        session = mgr.create_session("/tmp/x.bin")
        session.metadata = {"analysis_state": "ready", "indexing_state": "idle"}
        mgr._save_metadata(session)
        reloaded = SessionManager(str(tmp_path / "cache"))
        assert reloaded.get_session(session.session_id).metadata == {
            "analysis_state": "ready",
            "indexing_state": "idle",
        }


class TestStalePruneRespectsLiveRuntimes:
    def test_cleanup_stale_skips_sessions_with_live_runtime(self, tmp_path):
        mgr = SessionManager(str(tmp_path / "cache"))
        live = mgr.create_session("/tmp/live.bin")
        stale = mgr.create_session("/tmp/stale.bin")
        live.last_accessed = __import__("datetime").datetime(2000, 1, 1)
        stale.last_accessed = __import__("datetime").datetime(2000, 1, 1)
        pruned = mgr.cleanup_stale(max_age_days=1, runtime_alive=lambda sid: sid == live.session_id)
        assert pruned == [stale.session_id]
        assert mgr.get_session(live.session_id) is not None
        assert mgr.get_session(stale.session_id) is None

    def test_auto_prune_skips_sessions_with_live_runtime(self, tmp_path):
        mgr = SessionManager(str(tmp_path / "cache"))
        live = mgr.create_session("/tmp/live.bin")
        stale = mgr.create_session("/tmp/stale.bin")
        live.last_accessed = __import__("datetime").datetime(2000, 1, 1)
        stale.last_accessed = __import__("datetime").datetime(2000, 1, 1)
        pruned = mgr.auto_prune_if_over_budget(
            budget=1, max_age_days=1, runtime_alive=lambda sid: sid == live.session_id
        )
        assert pruned == 1
        assert mgr.get_session(live.session_id) is not None


class TestIndexingMetadataChangeGating:
    def test_unchanged_updates_do_not_rewrite_metadata_file(self, tmp_path, monkeypatch):
        server = _make_server(tmp_path, monkeypatch)
        writes = []

        def counting_save(session):
            writes.append(session.session_id)
            SessionManager._save_metadata(server.session_mgr, session)

        try:
            session = server.session_mgr.create_session("/tmp/x.bin")
            server.session_mgr._save_metadata = counting_save
            server._update_session_indexing_metadata(session.session_id, analysis_state="ready")
            assert len(writes) == 1
            # Same value again: no rewrite.
            server._update_session_indexing_metadata(session.session_id, analysis_state="ready")
            assert len(writes) == 1
            # A changed value rewrites once.
            server._update_session_indexing_metadata(session.session_id, analysis_state="stalled")
            assert len(writes) == 2
        finally:
            server.shutdown()

    def test_watchdog_verdict_survives_restart_via_metadata(self, tmp_path, monkeypatch):
        server = _make_server(tmp_path, monkeypatch)
        try:
            session = server.session_mgr.create_session("/tmp/x.bin")
            server._update_session_indexing_metadata(
                session.session_id, analysis_state="ready", analysis_is_ok=True
            )
            reloaded = SessionManager(server.cache_dir)
            restored = reloaded.get_session(session.session_id)
            assert restored is not None
            assert restored.metadata.get("analysis_state") == "ready"
            assert restored.metadata.get("analysis_is_ok") is True
        finally:
            server.shutdown()
