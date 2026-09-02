"""Cross-mode coverage for session opening, inference, and analysis gating."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_session as session_mod
from ida_pro_mcp.host.server.server_session import ServerSessionMixin


class _Session:
    def __init__(self, sid="SID12345", binary_path=""):
        self.session_id = sid
        self.binary_path = binary_path
        self.idb_path = binary_path + ".i64" if binary_path else ""
        self.analysis_options = {}
        self.ida_args = None
        self.metadata = {}
        self.created_at = "2026-09-01T00:00:00+00:00"

    def idb_on_disk(self):
        return bool(self.idb_path and os.path.isfile(self.idb_path))

    def to_dict(self):
        return {
            "session_id": self.session_id,
            "binary_path": self.binary_path,
            "idb_path": self.idb_path,
            "analysis_options": self.analysis_options,
            "metadata": self.metadata,
        }


class _Manager:
    def __init__(self, sessions=()):
        self.sessions = list(sessions)
        self.updated = []
        self.created = []

    def find_sessions_by_path(self, path):
        return [s for s in self.sessions if s.binary_path == path]

    def get_session(self, sid):
        return next((s for s in self.sessions if s.session_id == sid), None)

    def update_session(self, sid, **updates):
        session = self.get_session(sid)
        if session is None:
            return None
        self.updated.append((sid, updates))
        for key, value in updates.items():
            setattr(session, key, value)
        return session

    def create_session(self, binary_path, **kwargs):
        session = _Session(f"NEW{len(self.created):05d}", binary_path)
        for key, value in kwargs.items():
            setattr(session, key, value)
        self.created.append(session)
        self.sessions.append(session)
        return session

    def list_sessions(self, **_kwargs):
        return {"sessions": [s.to_dict() for s in self.sessions]}


def _host(tmp_path, sessions=()):
    manager = _Manager(sessions)
    host = ServerSessionMixin.__new__(ServerSessionMixin)
    host.session_mgr = manager
    host.current_session = None
    host._runtime_lock = threading.RLock()
    host.session_runtimes = {}
    host._session_last_activity = {}
    host._pending_analysis = set()
    host._analysis_complete_sessions = set()
    host._analysis_watchers = set()
    host._analysis_watcher_stop_events = {}
    host._analysis_watcher_threads = {}
    host._background_load_errors = {}
    host._resume_counters = {}
    host._session_teardown = set()
    host.safe_mode_poll_seconds = 0.05
    host.analysis_confirm_polls = 2
    host._client_owns_session = lambda _sid: True
    host._session_is_busy = lambda _sid: False
    host._session_ownership_report = lambda _sid: {"locked": False}
    host._update_session_indexing_metadata = lambda sid, **kw: manager.updated.append((sid, kw))
    host._save_metadata = lambda: None
    host._spawn_analysis_watcher = lambda _sid: None
    host._stop_analysis_watcher = lambda _sid, join_timeout=1.0: None
    host._run_analysis_checkpoint = lambda _sid: None
    host._normalize_ida_args = lambda value: list(value) if isinstance(value, list) else (_ for _ in ()).throw(ValueError("bad ida args"))
    host._is_large_binary = lambda _path: False
    host._ensure_runtime_and_idb = lambda _session: None
    host._session_is_running = lambda _sid: False
    return host, manager


def _code(result):
    assert result["error"] is True
    return result["code"]


def test_prepare_open_args_validates_aliases_conflicts_and_files(tmp_path, monkeypatch):
    host, _ = _host(tmp_path)
    assert _code(host._prepare_open_args({"idb_path": "x"})[-1]) == MCPError.INVALID_ARGS
    assert _code(host._prepare_open_args({"binary_path": 4})[-1]) == MCPError.INVALID_ARGS
    assert _code(host._prepare_open_args({"analysis_options": []})[-1]) == MCPError.INVALID_ARGS
    assert _code(host._prepare_open_args({"architecture": []})[-1]) == MCPError.INVALID_ARGS
    assert _code(host._prepare_open_args({"binary_path": str(tmp_path / "missing")})[-1]) == MCPError.FILE_NOT_FOUND
    assert _code(host._prepare_open_args({})[-1]) == MCPError.INVALID_ARGS

    path = tmp_path / "blob.bin"
    path.write_bytes(b"blob")
    conflict = host._prepare_open_args({
        "binary_path": str(path),
        "analysis_options": {"processor": "x86"},
        "architecture": {"arch": "arm"},
    })
    assert _code(conflict[-1]) == MCPError.INVALID_ARGS
    conflict = host._prepare_open_args({
        "binary_path": str(path),
        "analysis_options": {"bitness": 32},
        "bitness": 64,
    })
    assert _code(conflict[-1]) == MCPError.INVALID_ARGS
    bad_args = host._prepare_open_args({"binary_path": str(path), "ida_args": {"bad": True}})
    assert _code(bad_args[-1]) == MCPError.INVALID_ARGS

    monkeypatch.setattr(session_mod, "infer_binary_arch_profile", lambda _path: {
        "processor": "arm",
        "bitness": 32,
        "endian": "little",
        "confidence": 0.95,
        "candidates": [],
    })
    result = host._prepare_open_args({
        "binary_path": str(path),
        "architecture": {"arch": "arm", "bits": 32, "endianness": "little"},
        "ida_args": ["-z"],
    })
    assert result[-1] is None
    assert result[0] == str(path)
    assert result[1]["processor"] == "arm"
    assert result[4] == ["-z"]


def test_architecture_recommendations_inference_warning_and_stale_checkpoint(monkeypatch):
    host = ServerSessionMixin.__new__(ServerSessionMixin)
    assert host._arch_recommendations(None) is None
    assert host._arch_recommendations({"inferred_profile": {"candidates": []}})[0]["confidence"] == 0.2
    recs = host._arch_recommendations({"inferred_profile": {"candidates": [
        {"processor": "x86", "bitness": 64, "confidence": 0.8, "reason": "a"},
        {"processor": "arm", "bitness": 32, "confidence": 0.7, "reason": "b"},
        {"processor": "mips", "bitness": 32, "confidence": 0.6, "reason": "c"},
        {"processor": "ignored", "bitness": 32},
    ]}})
    assert len(recs) == 3
    assert host._arch_inference_warning({"inference_warning": "use arm"}) == "use arm"
    assert host._arch_inference_warning([]) is None

    opts = {}
    warning = host._auto_apply_inferred_profile(opts, {
        "confidence": "bad", "processor": "arm", "bitness": 32,
    })
    assert warning is None and opts == {}
    opts = {}
    warning = host._auto_apply_inferred_profile(opts, {
        "confidence": 0.95, "candidates": [{"processor": "riscv", "bitness": 64, "confidence": 0.99}],
        "endian": "little", "load_base": 0x8000,
    })
    assert warning and opts == {"processor": "riscv", "bitness": 64, "endian": "little", "baseaddr": 0x8000}
    assert host._auto_apply_inferred_profile({"processor": "arm", "bitness": 32, "endian": "little", "baseaddr": 1}, {
        "confidence": 1.0, "processor": "arm", "bitness": 32, "endian": "little", "load_base": 2,
    }) is None
    assert host._auto_apply_inferred_profile({}, {"ambiguous": True, "confidence": 1.0, "processor": "arm", "bitness": 32}) is None
    assert host._auto_apply_inferred_profile({}, {"confidence": 0.8, "processor": "arm", "bitness": 32}) is None
    assert host._auto_apply_inferred_profile({}, {"confidence": 1.0}) is None

    session = SimpleNamespace(metadata={})
    assert host._checkpoint_staleness_warning(session) is None
    session.metadata["analysis_checkpointed_at"] = "not-a-date"
    assert host._checkpoint_staleness_warning(session) is None
    session.metadata["analysis_checkpointed_at"] = "2000-01-01T00:00:00Z"
    assert "stale" in host._checkpoint_staleness_warning(session)
    session.metadata["analysis_checkpointed_at"] = "2999-01-01T00:00:00+00:00"
    assert "stale" in host._checkpoint_staleness_warning(session)
    monkeypatch.setattr(session_mod, "_CHECKPOINT_STALENESS_SECONDS", 3600)


def test_analysis_gate_lifecycle_persists_and_refuses_closing(tmp_path):
    session = _Session(binary_path=str(tmp_path / "a.bin"))
    host, manager = _host(tmp_path, [session])
    host._mark_analysis_pending(session)
    assert host._safe_mode_active(session.session_id)
    assert not host._analysis_is_complete(session.session_id)
    assert session.metadata["analysis_gate"] == "pending"
    host._mark_analysis_complete(session)
    assert not host._safe_mode_active(session.session_id)
    assert host._analysis_is_complete(session.session_id)
    assert session.metadata["analysis_gate"] == "complete"
    host._mark_analysis_pending(session)
    host._session_teardown.add(session.session_id)
    host._on_analysis_complete(session, reload=True)
    assert host._safe_mode_active(session.session_id)
    host._session_teardown.clear()
    host._on_analysis_complete(session, reload=False)
    assert host._analysis_is_complete(session.session_id)
    assert host._pending_session_notices[session.session_id]["code"] == "analysis_complete"
    host._forget_analysis_state(session.session_id)
    assert not host._analysis_is_complete(session.session_id)
    assert not host._safe_mode_active(session.session_id)
    assert session.session_id not in host._pending_session_notices
    assert any("analysis_gate" in updates for _sid, updates in manager.updated)


def test_open_analysis_state_and_wait_cover_live_error_and_completion(tmp_path, monkeypatch):
    session = _Session(binary_path=str(tmp_path / "a.bin"))
    host, _ = _host(tmp_path, [session])
    assert host._open_analysis_state(session) == {}
    host.session_runtimes[session.session_id] = {"port": 7000, "process": SimpleNamespace(poll=lambda: None)}
    host._runtime_alive = lambda _runtime: True
    host._send_rpc_raw = lambda *_args, **_kwargs: {"analysis_complete": False}
    assert host._open_analysis_state(session) == {}
    host._send_rpc_raw = lambda *_args, **_kwargs: {"analysis_complete": True, "functions": "12"}
    assert host._open_analysis_state(session) == {"analysis_complete": True, "analysis_functions": 12}
    host.session_runtimes[session.session_id]["port"] = 0
    assert host._open_analysis_state(session) == {}

    host.session_runtimes[session.session_id]["port"] = 7000
    host._send_rpc_raw = lambda *_args, **_kwargs: {"analysis_complete": True, "functions": 2}
    host._mark_analysis_pending(session)
    host._wait_for_analysis_complete(session, timeout=0.1)
    assert host._analysis_is_complete(session.session_id)
    host._mark_analysis_pending(session)
    host._runtime_alive = lambda _runtime: False
    assert host._wait_for_analysis_complete(session, timeout=0.1) == {}
    monkeypatch.setattr(session_mod.time, "sleep", lambda _seconds: None)


def test_wait_for_idb_finds_metadata_sibling_and_legacy_paths(tmp_path, monkeypatch):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"x")
    session = _Session(binary_path=str(binary))
    host, manager = _host(tmp_path, [session])
    sibling = Path(str(binary) + ".i64")
    sibling.write_bytes(b"idb")
    assert host._wait_for_idb(session, timeout=0.01) is True
    assert session.idb_path == str(sibling)
    sibling.unlink()
    session.idb_path = str(tmp_path / "stored.i64")
    legacy = tmp_path / f"SID_{session.session_id}.id0"
    legacy.write_bytes(b"part")
    assert host._wait_for_idb(session, timeout=0.01) is True
    assert session.idb_path == str(tmp_path / "stored.i64")
    legacy.unlink()
    host._runtime_record = lambda _sid: {"process": object()}
    host._runtime_alive = lambda _runtime: False
    monkeypatch.setattr(session_mod.time, "sleep", lambda _seconds: None)
    assert host._wait_for_idb(session, timeout=0.01) is False


def test_reuse_selection_size_detection_and_open_envelope_modes(tmp_path, monkeypatch):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"x" * 8)
    first = _Session("FIRST001", str(binary))
    first.analysis_options = {"processor": "arm", "bitness": 32}
    second = _Session("SECOND01", str(binary))
    second.analysis_options = {"processor": "x86", "bitness": 64}
    host, manager = _host(tmp_path, [first, second])
    assert host._select_reuse_candidate(str(binary), {"processor": "arm"}, False) is first
    assert host._select_reuse_candidate(str(binary), {"processor": "mips"}, False) is first
    assert host._select_reuse_candidate(str(binary), {}, True) is None
    host._session_is_busy = lambda sid: sid == "FIRST001"
    host._client_owns_session = lambda _sid: False
    assert host._select_reuse_candidate(str(binary), {}, False) is second
    assert host._select_reuse_candidate("", {}, False) is None

    assert not host._is_large_binary("")
    assert not host._is_large_binary(str(tmp_path / "nope"))
    packed = tmp_path / "packed.idb"
    packed.write_bytes(b"IDA2" + b"x" * 32)
    assert not host._is_large_binary(str(packed))
    regular = tmp_path / "regular.bin"
    regular.write_bytes(b"x" * 32)
    monkeypatch.setattr(session_mod, "LARGE_BINARY_THRESHOLD_BYTES", 16)
    host._is_large_binary = ServerSessionMixin._is_large_binary
    assert host._is_large_binary(str(regular))

    first.metadata["analysis_checkpointed_at"] = "2000-01-01T00:00:00Z"
    host._safe_mode_active = lambda _sid: True
    host._analysis_is_complete = lambda _sid: False
    host._session_is_running = lambda _sid: True
    out = host._open_result(first, background=True, reused=True, note="n", extra={"x": 1})
    assert out["background"] is True
    assert out["reused_existing_session"] is True
    assert out["warning"].startswith("Resumed session")
    assert out["x"] == 1
    assert manager.updated == []


def test_background_open_disabled_and_enabled_reuse_and_fresh_paths(tmp_path, monkeypatch):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"data")
    host, manager = _host(tmp_path)
    disabled = host._session_action_create_background({"binary_path": str(binary)})
    assert _code(disabled) == MCPError.FEATURE_DISABLED

    monkeypatch.setattr(session_mod, "background_open_enabled", lambda: True)
    host._spawn_runtime_background = lambda _session: None
    host._open_analysis_state = lambda _session: {}
    host._attach_open_envelope = ServerSessionMixin._attach_open_envelope.__get__(host)
    fresh = host._session_action_create_background({
        "binary_path": str(binary), "tags": "one,two", "notes": "note", "_auto_backgrounded": True,
    })
    assert fresh["ok"] is True
    assert fresh["background"] is True
    assert fresh["auto_backgrounded"] is True
    assert manager.created[0].tags == ["one", "two"]

    existing = manager.created[0]
    existing.analysis_options = {"processor": "arm"}
    host._select_reuse_candidate = lambda *_args: existing
    host._preloads_match = lambda *_args: True
    reused = host._session_action_create_background({
        "binary_path": str(binary), "architecture": {"processor": "arm"},
    })
    assert reused["reused_existing_session"] is True
    assert reused["background"] is True
    assert any(sid == existing.session_id for sid, _updates in manager.updated)


def test_attach_open_envelope_includes_recommendations_errors_and_completion(tmp_path):
    session = _Session(binary_path=str(tmp_path / "sample.bin"))
    host, _ = _host(tmp_path, [session])
    host._background_load_errors = {session.session_id: {"error": True, "message": "spawn"}}
    host._open_analysis_state = lambda _session: {"analysis_complete": True, "analysis_functions": 7}
    host._session_is_running = lambda _sid: True
    host._attach_open_envelope(session, {}, {
        "inferred_profile": {"candidates": [{"processor": "arm", "bitness": 32}]},
        "inference_warning": "check architecture",
    })
    out = {}
    host._attach_open_envelope(session, out, {"inferred_profile": {"candidates": []}})
    assert out["architecture_recommendations"][0]["arguments"]["processor"] == "arm"
    assert out["analysis_complete"] is True
    assert out["safe_mode"] is False


def test_get_list_search_and_discover_visibility_paths(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"x")
    session = _Session(binary_path=str(binary))
    host, manager = _host(tmp_path, [session])
    host._session_ownership_report = lambda _sid: {
        "locked": True, "holder": "peer", "owner_id": "o", "owner_pid": 1,
        "owner_alive": True, "idat_pid": 2, "lease_age_seconds": 3,
    }
    host._runtime_record = lambda _sid: {"port": 7000, "process": SimpleNamespace(poll=lambda: None)}
    got = host._session_action_get({"session_id": "simple"})
    assert _code(got) == MCPError.SESSION_NOT_FOUND
    got = host._session_action_get({"session_id": "bad/id"})
    assert _code(got) == MCPError.INVALID_ARGS
    host._client_owns_session = lambda _sid: True
    got = host._session_action_get({"session_id": session.session_id})
    assert got["ok"] is True and got["session"]["port"] == 7000
    manager.list_sessions = lambda **_kwargs: {"sessions": [session.to_dict()], "total": 1}
    listed = host._session_action_list({"limit": "2", "offset": "1", "query": "x"})
    assert listed["ok"] is True and listed["count"] == 1
    manager.search_notes = lambda _query: [session]
    host._session_is_busy = lambda _sid: False
    searched = host._session_action_search_notes({"query": "x"})
    assert searched["count"] == 1
    manager._load_orphaned_idbs = lambda: None
    manager.discover_sessions = lambda **_kwargs: [session]
    discovered = host._session_action_discover({"query": "x", "binary_name": "sample"})
    assert discovered["count"] == 1
