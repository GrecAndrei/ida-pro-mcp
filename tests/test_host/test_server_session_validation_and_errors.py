from __future__ import annotations

import contextlib
import os
import sys
import threading
import time
import types
from datetime import UTC, datetime, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.host.server.server_session import (
    ServerSessionMixin,
    _sess_coerce_none,
    _sess_coerce_note,
    _sess_coerce_query,
    _sess_coerce_rename,
    _sess_coerce_tag,
    _sess_coerce_untag,
    _substitute_params,
)
from tests._thread_doubles import CaptureThread as _CaptureThread, SyncThread as _SyncThread


class DummySessionServer(ServerSessionMixin):
    def __init__(self, tmp_path=None):
        self.session_mgr = MagicMock()
        self.current_session = None
        self.session_runtimes = {}
        self._pending_analysis = set()
        self._analysis_complete_sessions = set()
        self._analysis_complete_in_flight = set()
        self._reloading_sessions = set()
        self._background_load_errors = {}
        self._pending_session_notices = {}
        self._analysis_watchers = set()
        self._session_groups = {}

    def _ensure_client_owns_session(self, session: Any) -> dict[str, Any] | None:
        return None

    def _require_owned_session_id(self, sid: str) -> dict | None:
        return None

    def _drop_sid_from_groups(self, sid: str) -> None:
        pass

    def _cleanup_runtime(self, sid: str) -> None:
        pass

    @contextlib.contextmanager
    def _teardown_session(self, sid: str):
        yield

    def _session_blackboard_path(self, session_obj=None):
        return "/tmp/bb.db"

    def _arm_analysis_watcher_if_needed(self, sid: str) -> None:
        pass

    def _kill_ida_process(self, runtime: dict, grace_sec: float = 3.0) -> dict:
        return {"ok": True, "terminated": True}

    def _collect_ida_state_snapshot(self, **kwargs) -> dict:
        return {}


def test_session_coercion_guards() -> None:
    # None coercion
    kw, err = _sess_coerce_none({})
    assert kw == {}
    assert err is None

    # Rename: missing name returns error
    kw, err = _sess_coerce_rename({})
    assert err is not None
    assert "name required" in err["message"]

    # Rename: valid name
    kw, err = _sess_coerce_rename({"name": "new_session_name"})
    assert err is None
    assert kw == {"new_name": "new_session_name"}

    # Tag: missing tag returns error
    kw, err = _sess_coerce_tag({})
    assert err is not None
    assert "tag required" in err["message"]

    # Tag: valid tag
    kw, err = _sess_coerce_tag({"tag": "important"})
    assert err is None
    assert kw == {"tag": "important"}

    # Untag: missing tag returns error
    kw, err = _sess_coerce_untag({})
    assert err is not None
    assert "tag required" in err["message"]

    # Untag: valid tag (line 113)
    kw, err = _sess_coerce_untag({"tag": "important"})
    assert err is None
    assert kw == {"tag": "important"}

    # Untag: empty after strip returns error
    kw, err = _sess_coerce_untag({"tag": "   "})
    assert err is not None
    assert "tag required" in err["message"]

    # Note: missing note returns error
    kw, err = _sess_coerce_note({})
    assert err is not None
    assert "note required" in err["message"]

    # Note: valid note
    kw, err = _sess_coerce_note({"note": "Session analysis notes"})
    assert err is None
    assert kw == {"note": "Session analysis notes"}

    # Query: missing query returns error
    kw, err = _sess_coerce_query({})
    assert err is not None
    assert "query required" in err["message"]

    # Query: valid query
    kw, err = _sess_coerce_query({"query": "SELECT 1"})
    assert err is None
    assert kw == {"query": "SELECT 1"}


def test_substitute_params() -> None:
    params = {"$addr": "0x401000", "name": "main_func"}
    data = {
        "target": "$addr",
        "title": "Analysis of $name at $addr",
        "nested_list": ["$name", "static_val", {"k": "$addr"}],
        "number": 12345,
    }

    substituted = _substitute_params(data, params)
    assert substituted["target"] == "0x401000"
    assert substituted["title"] == "Analysis of main_func at 0x401000"
    assert substituted["nested_list"] == ["main_func", "static_val", {"k": "0x401000"}]
    assert substituted["number"] == 12345
    assert _substitute_params(999, params) == 999


def test_trigger_session_diff_branches() -> None:
    # 1. Exception branch in _diff (lines 168-169)
    with patch("threading.Thread", _SyncThread), patch("ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder", side_effect=RuntimeError("diff boom")):
        ServerSessionMixin._trigger_session_diff("old_err", "new_err")

    # 2. Empty index branch (line 160)
    mock_idx = MagicMock()
    mock_idx.size = 0
    with (
        patch("threading.Thread", _SyncThread),
        patch("ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder"),
        patch("ida_pro_mcp.host.intelligence.core.FunctionEmbeddingIndex", return_value=mock_idx),
    ):
        ServerSessionMixin._trigger_session_diff("old_empty", "new_empty")


def test_handle_session_bootstrap_and_spec_error() -> None:
    server = DummySessionServer()

    # Bootstrap action returns result (line 232)
    server._handle_session_bootstrap = MagicMock(return_value={"ok": True, "bootstrapped": True})
    res = server._handle_session({"action": "bootstrap_workflow"})
    assert res == {"ok": True, "bootstrapped": True}

    # _run_session_spec with invalid sid returns err (line 266)
    res = server._run_session_spec(
        ("dict", "rename_session", _sess_coerce_rename),
        {"session_id": "invalid/session/id"},
    )
    assert res.get("error") is True


def test_session_action_health_and_sso_actions() -> None:
    server = DummySessionServer()

    # health action (line 328)
    server._handle_session_health = MagicMock(return_value={"healthy": True})
    assert server._session_action_health({}) == {"healthy": True}

    # sso_activate error and ok (lines 336-339)
    server._sso_activate_realm = MagicMock(return_value=(None, {"error": True, "msg": "failed"}))
    assert server._session_action_sso_activate({}) == {"error": True, "msg": "failed"}
    server._sso_activate_realm = MagicMock(return_value=({"ok": True}, None))
    assert server._session_action_sso_activate({}) == {"ok": True}

    # agent_login error and ok (lines 343-346)
    server._sso_agent_login = MagicMock(return_value=(None, {"error": True, "msg": "failed"}))
    assert server._session_action_agent_login({}) == {"error": True, "msg": "failed"}
    server._sso_agent_login = MagicMock(return_value=({"ok": True}, None))
    assert server._session_action_agent_login({}) == {"ok": True}

    # agent_logout error and ok (lines 350-353)
    server._sso_agent_logout = MagicMock(return_value=(None, {"error": True, "msg": "failed"}))
    assert server._session_action_agent_logout({}) == {"error": True, "msg": "failed"}
    server._sso_agent_logout = MagicMock(return_value=({"ok": True}, None))
    assert server._session_action_agent_logout({}) == {"ok": True}


def test_session_action_create_branches(tmp_path) -> None:
    server = DummySessionServer()

    # 1. Auto background for large binary (lines 394-396)
    server._prepare_open_args = MagicMock(return_value=("/path/to/bin", {}, {}, False, None, None))
    server._select_reuse_candidate = MagicMock(return_value=None)
    server._is_large_binary = MagicMock(return_value=True)
    server._session_action_create_background = MagicMock(return_value={"background": True})

    with patch("ida_pro_mcp.host.server.server_session.background_open_enabled", return_value=True):
        res = server._session_action_create({"binary_path": "/path/to/bin"})
        assert res == {"background": True}

    # 2. Preload mismatch note (lines 455, 490)
    existing = SimpleNamespace(analysis_options={"processor": "metapc"})
    server._prepare_open_args = MagicMock(
        return_value=("/path/to/bin", {"processor": "arm"}, {}, False, None, None)
    )
    server._select_reuse_candidate = MagicMock(return_value=existing)
    server._is_large_binary = MagicMock(return_value=False)

    fake_sess = SimpleNamespace(session_id="11223344", idb_path=None)
    server.session_mgr.create_session = MagicMock(return_value=fake_sess)
    server._mark_analysis_pending = MagicMock()
    server._open_result = MagicMock(return_value={"ok": True})
    server._ensure_runtime_and_idb = MagicMock(return_value=None)
    server._wait_for_analysis_complete = MagicMock(return_value=None)
    server._analysis_is_complete = MagicMock(return_value=True)
    server._safe_mode_active = MagicMock(return_value=False)

    with patch("ida_pro_mcp.host.server.server_session.background_open_enabled", return_value=False):
        res = server._session_action_create({"binary_path": "/path/to/bin", "processor": "arm"})
        assert "Created a fresh session because architecture/loader options were provided" in res.get("note", "")

    # 3. _preloads_match empty analysis_options (line 568)
    assert ServerSessionMixin._preloads_match(None, {}) is True
    assert ServerSessionMixin._preloads_match(None, None) is True


def test_prepare_open_args_and_is_large_binary(tmp_path) -> None:
    server = DummySessionServer()

    # Relative binary path resolved to absolute + top level option merged (lines 812, 825)
    test_bin = tmp_path / "relative_sample.bin"
    test_bin.write_bytes(b"\x7fELF" + b"\x00" * 30)

    cwd = os.getcwd()
    try:
        os.chdir(str(tmp_path))
        args = {"binary_path": "relative_sample.bin", "processor": "arm"}
        with patch.object(server, "_auto_apply_inferred_profile", return_value="custom warning applied"):
            bp, aopts, ameta, force, iargs, err = server._prepare_open_args(args)
            assert err is None
            assert os.path.isabs(bp)
            assert aopts.get("processor") == "arm"
            assert ameta.get("inference_warning") == "custom warning applied"  # line 848
    finally:
        os.chdir(cwd)

    # _is_large_binary empty path (line 901)
    assert ServerSessionMixin._is_large_binary("") is False


def test_forget_analysis_state_dict_collection() -> None:
    server = DummySessionServer()
    server._reloading_sessions = {"A1B2C3D4": True}  # Dict instead of set (line 1055)
    server._forget_analysis_state("A1B2C3D4")
    assert "A1B2C3D4" not in server._reloading_sessions


def test_analysis_watcher_error_and_dead_consecutive() -> None:
    server = DummySessionServer()
    server.session_mgr.get_session = MagicMock(return_value=SimpleNamespace(session_id="A1B2C3D4"))
    server._safe_mode_active = MagicMock(return_value=True)

    runtime_alive_results = [True, False, False]
    server._runtime_record = MagicMock(return_value={"port": 1234})
    server._runtime_alive = MagicMock(side_effect=lambda r: runtime_alive_results.pop(0))
    server._send_rpc_raw = MagicMock(side_effect=RuntimeError("rpc failed"))
    server._record_background_error = MagicMock()

    with patch("threading.Thread", _CaptureThread), patch("time.sleep", return_value=None):
        server._spawn_analysis_watcher("A1B2C3D4")
        thread = server._analysis_watcher_threads["A1B2C3D4"]
        assert isinstance(thread, _CaptureThread)
        thread.run_captured()

    assert server._record_background_error.called

    # Line 1196: safe mode lifted / inactive -> returns early
    server._safe_mode_active = MagicMock(return_value=False)
    thread.run_captured()


def test_record_background_error_missing_dict() -> None:
    server = DummySessionServer()
    server._background_load_errors = None
    server._record_background_error("A1B2C3D4")
    assert isinstance(server._background_load_errors, dict)
    assert "A1B2C3D4" in server._background_load_errors


def test_on_analysis_complete_guards() -> None:
    server = DummySessionServer()
    fake_sess = SimpleNamespace(session_id="A1B2C3D4")

    # Safe mode not active (line 1307)
    server._safe_mode_active = MagicMock(return_value=False)
    server._on_analysis_complete(fake_sess, reload=False)

    # Already complete (line 1309)
    server._safe_mode_active = MagicMock(return_value=True)
    server._analysis_is_complete = MagicMock(return_value=True)
    server._on_analysis_complete(fake_sess, reload=False)

    # In-flight (line 1317)
    server._analysis_is_complete = MagicMock(return_value=False)
    server._analysis_complete_in_flight = {"A1B2C3D4"}
    server._on_analysis_complete(fake_sess, reload=False)

    # Session disappeared (line 1326)
    server._analysis_complete_in_flight = set()
    server.session_mgr.get_session = MagicMock(return_value=None)
    server._on_analysis_complete(fake_sess, reload=False)


def test_spawn_background_load_error_recording() -> None:
    server = DummySessionServer()
    session = SimpleNamespace(session_id="A1B2C3D4")

    server._ensure_runtime_and_idb = MagicMock(return_value={"error": True, "message": "Failed spawn"})
    server._record_background_load_error = MagicMock()

    with patch("threading.Thread", _SyncThread):
        server._spawn_runtime_background(session)

    server._record_background_load_error.assert_called_once_with(
        "A1B2C3D4", {"error": True, "message": "Failed spawn"}
    )


def test_checkpoint_staleness_warning_branches() -> None:
    # Not a dict (line 1744)
    assert ServerSessionMixin._checkpoint_staleness_warning(SimpleNamespace(metadata="string_meta")) is None

    # Recent timestamp returns None (line 1764)
    recent = datetime.now(UTC).isoformat()
    assert ServerSessionMixin._checkpoint_staleness_warning(
        SimpleNamespace(metadata={"analysis_checkpointed_at": recent})
    ) is None


def test_session_action_switch_idb_wait(tmp_path) -> None:
    server = DummySessionServer()
    bin_file = tmp_path / "bin_switch.bin"
    bin_file.write_bytes(b"\x00" * 32)

    fake_session = SimpleNamespace(
        session_id="A1B2C3D4",
        binary_path=str(bin_file),
        idb_path=str(tmp_path / "nonexistent.i64"),
        to_dict=lambda: {"session_id": "A1B2C3D4"},
    )
    server.session_mgr.get_session = MagicMock(return_value=fake_session)
    server._runtime_record = MagicMock(return_value={"port": 1234})
    server._runtime_alive = MagicMock(return_value=True)
    server._wait_for_idb = MagicMock(return_value=True)
    server._safe_mode_active = MagicMock(return_value=False)
    server._analysis_is_complete = MagicMock(return_value=True)
    server._start_server = MagicMock(return_value={"ok": True})
    server._mark_analysis_pending = MagicMock()

    res = server._session_action_switch({"session_id": "A1B2C3D4", "reopen": True})
    assert res.get("ok") is True
    assert server._wait_for_idb.called

    # Line 1952: ownership_error in switch
    server_unowned = DummySessionServer()
    server_unowned.session_mgr.get_session = MagicMock(return_value=SimpleNamespace(session_id="A1B2C3D4"))
    server_unowned._ensure_client_owns_session = MagicMock(return_value={"error": True, "message": "unowned"})
    assert server_unowned._session_action_switch({"session_id": "A1B2C3D4"}).get("error") is True


def test_ensure_runtime_and_idb_and_wait_for_idb(tmp_path) -> None:
    server = DummySessionServer()
    idb_file = tmp_path / "sample.i64"
    idb_file.write_bytes(b"IDA2")

    fake_session = SimpleNamespace(session_id="A1B2C3D4", idb_path=str(idb_file))
    server._start_server = MagicMock()

    # 1. Runtime alive and IDB on disk returns None (line 2052)
    server._runtime_record = MagicMock(return_value={"port": 1234})
    server._runtime_alive = MagicMock(return_value=True)
    assert server._ensure_runtime_and_idb(fake_session) is None

    # 2. Runtime started but wait_for_idb times out (lines 2068-2069)
    server2 = DummySessionServer()
    server2._runtime_record = MagicMock(return_value={"port": 1234})
    server2._runtime_alive = MagicMock(return_value=True)
    server2._start_server = MagicMock(return_value={"ok": True})
    server2._wait_for_idb = MagicMock(return_value=False)
    fake_session_dead = SimpleNamespace(session_id="A1B2C3D4", idb_path=str(tmp_path / "missing.i64"))
    # first check dead, then after start alive
    server2._runtime_alive = MagicMock(side_effect=[False, True])
    err = server2._ensure_runtime_and_idb(fake_session_dead)
    assert err is not None
    assert "IDB was not written within the timeout" in err["message"]

    # 3. _wait_for_idb update_session exception (lines 2137-2138)
    server3 = DummySessionServer()
    bin_file = tmp_path / "sample.bin"
    bin_file.write_bytes(b"BIN")
    expected_idb = f"{bin_file}.i64"
    fake_sess_update_fail = SimpleNamespace(
        session_id="A1B2C3D4",
        idb_path=None,
        binary_path=str(bin_file),
    )
    server3.session_mgr.update_session = MagicMock(side_effect=RuntimeError("db update failed"))
    with patch("os.path.isfile", side_effect=lambda p: p == expected_idb):
        res = server3._wait_for_idb(fake_sess_update_fail, timeout=1.0)
        assert res is True


def test_wait_for_idb_loop_finds_different_path() -> None:
    server = DummySessionServer()
    sess = SimpleNamespace(
        session_id="A1B2C3D4",
        idb_path="/tmp/orig.i64",
        binary_path="/tmp/test.bin",
    )
    server.session_mgr.update_session = MagicMock(side_effect=RuntimeError("update error in loop"))
    call_count = 0

    def mock_isfile(p):
        nonlocal call_count
        call_count += 1
        return call_count >= 5 and p == "/tmp/test.bin.i64"

    with patch("os.path.isfile", side_effect=mock_isfile), patch("time.sleep", return_value=None):
        res = server._wait_for_idb(sess, timeout=5.0)
        assert res is True
        assert sess.idb_path == "/tmp/test.bin.i64"


def test_session_action_close_branches() -> None:
    server = DummySessionServer()

    # sid_err (line 2162)
    res = server._session_action_close({"session_id": "invalid/path/sid"})
    assert res.get("error") is True

    # Line 2171: owned_err in close
    server_unowned = DummySessionServer()
    server_unowned._require_owned_session_id = MagicMock(return_value={"error": True, "message": "unowned"})
    assert server_unowned._session_action_close({"session_id": "A1B2C3D4"}).get("error") is True

    # Valid close (lines 2172-2194)
    server._export_session_hypotheses_to_symbol_db = MagicMock()
    server.session_mgr.delete_session = MagicMock(return_value=True)
    server.current_session = SimpleNamespace(session_id="A1B2C3D4")

    res = server._session_action_close({"session_id": "A1B2C3D4"})
    assert res.get("ok") is True
    assert server.current_session is None


def test_cached_coverage_blank_lines() -> None:
    server = DummySessionServer()
    server._execute_tool = MagicMock(
        return_value={"functions": "0x401000 100 xrefs=1 func1\n\n   \n0x402000 200 xrefs=2 sub_402000"}
    )
    cov = server._get_cached_coverage("A1B2C3D4")
    assert cov["total_functions"] == 2
    assert cov["named_functions"] == 1


def test_build_state_payload_edges() -> None:
    class BrokenMgrServer(DummySessionServer):
        def __init__(self):
            super().__init__()
            self._broken = False

        @property
        def session_mgr(self):
            if self._broken:
                raise RuntimeError("mgr error")
            return self._sm

        @session_mgr.setter
        def session_mgr(self, val):
            self._sm = val

    server = BrokenMgrServer()
    server.current_session = SimpleNamespace(session_id="A1B2C3D4")
    server._execute_tool = MagicMock(return_value={})
    server._get_cached_coverage = MagicMock(return_value={})

    # 1. _bb_store raises (lines 2429-2430)
    server._bb_store = MagicMock(side_effect=RuntimeError("bb boom"))

    # 2. session_mgr raises (lines 2437-2438)
    server._broken = True

    payload = server._build_state_payload()
    assert payload["blackboard"] == {}
    assert payload["session"] == {}


def test_build_state_payload_kg_and_narrative(tmp_path) -> None:
    from ida_pro_mcp.host.stores.knowledge_graph import KnowledgeGraph

    server = DummySessionServer()
    server.current_session = SimpleNamespace(session_id="A1B2C3D4")
    server._execute_tool = MagicMock(return_value={})
    server._get_cached_coverage = MagicMock(return_value={})

    # Knowledge graph gaps and systems (lines 2456, 2465-2472)
    db_path = str(tmp_path / "kg_test.db")
    kg = KnowledgeGraph(db_path)
    kg.add_system("crypto", ["0x401000"])
    kg.add_gap("expected_crypto")

    mock_bb = MagicMock()
    mock_bb.stats = MagicMock(return_value={})
    mock_bb.next_target = MagicMock(return_value=[])
    mock_bb.list = MagicMock(side_effect=RuntimeError("narrative error"))  # line 2491-2492

    server._bb_store = MagicMock(return_value=mock_bb)
    server._session_blackboard_path = MagicMock(return_value=db_path)

    payload = server._build_state_payload()
    assert "top_gaps" in payload.get("knowledge_graph", {})
    assert "systems" in payload.get("knowledge_graph", {})

    # Lines 2471-2472: exception in KG processing
    corrupt_kg = tmp_path / "corrupt.db"
    corrupt_kg.write_text("not a db")
    server._session_blackboard_path = MagicMock(return_value=str(corrupt_kg))
    payload2 = server._build_state_payload()
    assert isinstance(payload2, dict)


def test_bb_store_module_restore_and_error() -> None:
    server = DummySessionServer()

    # Prepopulate sys.modules with dummy idaapi without BADADDR (lines 2543, 2551)
    dummy_idaapi = types.ModuleType("idaapi")
    with patch.dict(sys.modules, {"idaapi": dummy_idaapi}):
        store = server._bb_store()
        assert sys.modules.get("idaapi") is dummy_idaapi
        assert store is not None

    # Error path returns None (lines 2555-2556)
    with patch("importlib.util.spec_from_file_location", side_effect=RuntimeError("spec error")):
        assert server._bb_store() is None


def test_session_action_status_and_kill_branches(tmp_path) -> None:
    from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore

    server = DummySessionServer()

    # Line 2608: target error
    server_tgt = DummySessionServer()
    server_tgt._session_target = MagicMock(return_value=(None, {"error": True, "message": "tgt error"}))
    assert server_tgt._session_action_status({}).get("error") is True

    session = SimpleNamespace(
        session_id="A1B2C3D4",
        metadata="not_a_dict",
        to_dict=lambda: {"session_id": "A1B2C3D4"},
    )  # line 2637

    server.session_mgr.get_session = MagicMock(return_value=session)
    server.current_session = session
    server._safe_mode_active = MagicMock(return_value=False)
    server._analysis_is_complete = MagicMock(return_value=True)

    # Status with string metadata
    res = server._session_action_status({"session_id": "A1B2C3D4"})
    assert res.get("ok") is True

    # Status with working memory entries (lines 2719-2720) and hot_indexed_count exception (lines 2684-2685)
    session.metadata = {"hot_indexed_count": "invalid_int"}
    bb_path = str(tmp_path / "bb_status.db")
    bb = BlackboardStore(bb_path)
    bb.write("Test Memory Entry", addr="0x401000", category="hypothesis")
    server._session_blackboard_path = MagicMock(return_value=bb_path)

    res = server._session_action_status({"session_id": "A1B2C3D4"})
    assert res.get("session", {}).get("working_memory_count") == 1

    # Kill: sid_err (line 2741)
    res = server._session_action_kill({"session_id": "invalid/path"})
    assert res.get("error") is True

    # Kill: use current_session when _resolve_session_id returns (None, None) (line 2743)
    server_kill = DummySessionServer()
    server_kill._resolve_session_id = MagicMock(return_value=(None, None))
    server_kill.current_session = SimpleNamespace(session_id="A1B2C3D4")
    server_kill._runtime_record = MagicMock(return_value=None)
    res = server_kill._session_action_kill({})
    assert res.get("error") is True
    assert "No runtime for session A1B2C3D4" in res["message"]  # line 2754

    # Kill: no sid and no current_session (line 2745)
    server.current_session = None
    res = server._session_action_kill({})
    assert res.get("error") is True
    assert "session_id required" in res["message"]

    # Kill: grace_sec exception (lines 2760-2761)
    mock_runtime = {"process": MagicMock(poll=MagicMock(return_value=0)), "port": 1234}
    server._runtime_record = MagicMock(return_value=mock_runtime)
    server.session_mgr.get_session = MagicMock(return_value=SimpleNamespace(session_id="A1B2C3D4"))
    res = server._session_action_kill({"session_id": "A1B2C3D4", "grace_sec": "not_a_float"})
    assert res.get("ok") is True


def test_session_action_rebuild_and_update() -> None:
    server = DummySessionServer()

    # Rebuild: sid_err (line 2801)
    assert server._session_action_rebuild({"session_id": "invalid/path"}).get("error") is True

    # Rebuild: session not found (line 2813)
    server._resolve_session_id = MagicMock(return_value=("A1B2C3D4", None))
    server.session_mgr.get_session = MagicMock(return_value=None)
    assert "not found" in server._session_action_rebuild({"session_id": "A1B2C3D4"}).get("message", "")

    # Rebuild: session disappeared during rebuild (line 2860)
    sess_obj = SimpleNamespace(session_id="A1B2C3D4", idb_path="/nonexistent/idb")
    server.session_mgr.get_session = MagicMock(side_effect=[sess_obj, None])
    assert "disappeared" in server._session_action_rebuild({"session_id": "A1B2C3D4"}).get("message", "")

    # Update: sid_err (line 2898)
    server_upd = DummySessionServer()
    assert server_upd._session_action_update({"session_id": "invalid/path"}).get("error") is True

    # Update: missing sid (line 2900)
    server_upd.current_session = None
    server_upd._resolve_session_id = MagicMock(return_value=(None, None))
    assert "session_id required" in server_upd._session_action_update({}).get("message", "")


def test_cleanup_stale_and_idle_purge_branches() -> None:
    server = DummySessionServer()

    # 1. cleanup_stale with alive runtime skips session (line 3033)
    server._runtime_record = MagicMock(return_value={"port": 1234})
    server._runtime_alive = MagicMock(return_value=True)
    server._require_owned_session_id = MagicMock(return_value=None)
    server.session_mgr.list_sessions = MagicMock(
        return_value={
            "sessions": [
                {
                    "session_id": "A1B2C3D4",
                    "last_accessed": "2020-01-01T00:00:00Z",
                    "binary_path": "/nonexistent",
                    "idb_path": "/nonexistent",
                }
            ]
        }
    )
    res = server._session_action_cleanup_stale({"max_age_days": 1, "prune_orphans": False})
    assert res.get("deleted_count") == 0

    # 2. cleanup_stale orphan prune: unformatted hex session id uppercase (line 3056)
    server.session_mgr.list_sessions = MagicMock(
        return_value={
            "sessions": [
                {
                    "session_id": "short5",
                    "binary_path": "/missing/bin",
                    "idb_path": "/missing/idb",
                }
            ]
        }
    )
    server.session_mgr.delete_session = MagicMock(return_value=True)
    res = server._session_action_cleanup_stale({"max_age_days": 10000, "prune_orphans": True})
    assert "SHORT5" in res.get("orphan_sids", [])

    # 3. idle_purge: invalid sid skipped (line 3149)
    # and recent session skipped (line 3167)
    server.session_mgr.list_sessions = MagicMock(
        return_value={
            "sessions": [
                {"session_id": "invalid/sid"},  # line 3149
                {"session_id": "A1B2C3D4", "last_accessed": "2099-01-01T00:00:00Z"},  # line 3167
            ]
        }
    )
    server._require_owned_session_id = MagicMock(return_value=None)
    res = server._session_action_idle_purge({"idle_seconds": 100, "prune_orphans": False})
    assert res.get("closed_count") == 0

    # 4. idle_purge orphan prune: invalid sid, foreign owned, and delete exception (lines 3201, 3204, 3217-3218)
    server.session_mgr.list_sessions = MagicMock(
        return_value={
            "sessions": [
                {"session_id": "invalid/sid"},  # line 3201
                {
                    "session_id": "11223344",
                    "binary_path": "/missing",
                    "idb_path": "/missing",
                },  # line 3204 (foreign)
                {
                    "session_id": "55667788",
                    "binary_path": "/missing",
                    "idb_path": "/missing",
                },  # lines 3217-3218 (delete exception)
            ]
        }
    )
    ownership_map = {
        "11223344": {"error": True},  # foreign
        "55667788": None,  # owned
    }
    server._require_owned_session_id = MagicMock(side_effect=ownership_map.get)
    server.session_mgr.delete_session = MagicMock(side_effect=RuntimeError("delete error"))
    res = server._session_action_idle_purge({"idle_seconds": 100000, "prune_orphans": True})
    assert res.get("ok") is True


def test_session_action_bulk_and_hypotheses_guards() -> None:
    # 1. Bulk delete: owned_err (line 3311)
    s1 = DummySessionServer()
    s1._require_owned_session_id = MagicMock(return_value={"error": True, "message": "unowned"})
    assert s1._session_action_bulk_delete({"session_ids": ["A1B2C3D4"]}).get("error") is True

    # 2. Snapshot: sid_err (line 3362)
    s2 = DummySessionServer()
    assert s2._session_action_snapshot({"session_id": "invalid/sid"}).get("error") is True

    # 3. Restore snapshot: sid_err (line 3376)
    s3 = DummySessionServer()
    assert s3._session_action_restore_snapshot({"session_id": "invalid/sid"}).get("error") is True

    # 4. Skill and strategy owned errors (lines 3429, 3446, 3465, 3485, 3497, 3506)
    s4 = DummySessionServer()
    s4._require_session_sid = MagicMock(return_value=("A1B2C3D4", None))
    s4._require_owned_session_id = MagicMock(return_value={"error": True, "message": "unowned"})
    assert s4._session_action_rate_skill({}).get("error") is True  # line 3429
    assert s4._session_action_list_skills({}).get("error") is True  # line 3446
    assert s4._session_action_suggest_triage({}).get("error") is True  # line 3465
    assert s4._session_action_suggest_strategy({}).get("error") is True  # line 3485
    assert s4._session_action_get_phase({}).get("error") is True  # line 3497
    assert s4._session_action_dashboard({}).get("error") is True  # line 3506

    # 5. sid_err on analogy, activity, and hypothesis actions (lines 3512, 3551, 3605, 3625, 3651, 3663)
    s5 = DummySessionServer()
    assert s5._session_action_suggest_analogy({"session_id": "invalid/sid"}).get("error") is True
    assert s5._session_action_apply_analogy({"session_id": "invalid/sid"}).get("error") is True
    assert s5._session_action_log_activity({"session_id": "invalid/sid"}).get("error") is True
    assert s5._session_action_track_hypothesis({"session_id": "invalid/sid"}).get("error") is True
    assert s5._session_action_confirm_hypothesis({"session_id": "invalid/sid"}).get("error") is True
    assert s5._session_action_refute_hypothesis({"session_id": "invalid/sid"}).get("error") is True
