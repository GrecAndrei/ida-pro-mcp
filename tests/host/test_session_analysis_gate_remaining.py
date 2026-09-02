"""Exercise the remaining session analysis-gate and lifecycle boundaries."""

from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError, make_error
from ida_pro_mcp.host.server import server_session as session_mod
from tests.host.test_session_action_modes_full import _host


def test_analysis_watcher_handles_deleted_session_and_confirmation_polling(tmp_path, monkeypatch):
    host, manager, session = _host(tmp_path)
    sid = session.session_id

    # A watcher that wakes after its session was deleted must exit without
    # re-arming itself or changing the safe-mode collections.
    host._pending_analysis = {sid}
    host._analysis_watchers = {sid}
    manager.get_session = lambda _sid: None
    host._watch_analysis_completion(sid)
    assert sid not in host._analysis_watchers

    # Exercise the real poll loop: an incomplete sample is followed by two
    # confirmations, which is the production handoff threshold.
    host, manager, session = _host(tmp_path / "confirmed")
    sid = session.session_id
    host._pending_analysis = {sid}
    host._analysis_watchers = {sid}
    host._analysis_watcher_stop_events = {}
    host._runtime_record = lambda _sid: {
        "port": 31337,
        "process": SimpleNamespace(poll=lambda: None),
    }
    host._runtime_alive = lambda _runtime: True
    responses = iter([
        {"analysis_complete": False},
        {"analysis_complete": True},
        {"analysis_complete": True},
    ])
    host._send_rpc_raw = lambda *_args, **_kwargs: next(responses)
    monkeypatch.setattr(session_mod.time, "sleep", lambda _seconds: None)
    host._watch_analysis_completion(sid)
    assert host._analysis_is_complete(sid) is True
    assert host._safe_mode_active(sid) is False
    assert session.metadata["analysis_gate"] == "complete"


def test_analysis_gate_guards_persistence_completion_and_cleanup(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id

    host._shutdown_requested = True
    host._spawn_analysis_watcher(sid)
    assert not hasattr(host, "_analysis_watchers")

    # Both optional resume-counter dependencies are absent/invalid on a bare
    # mixin host and must remain harmless.
    host._reset_resume_counter(sid)
    host._session_resume_calls = {sid: 3}
    host._session_resume_calls_lock = object()
    host._reset_resume_counter(sid)
    assert host._session_resume_calls[sid] == 3

    host._update_session_indexing_metadata = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("index unavailable"))
    session.metadata = {}
    host._persist_analysis_gate(session, "pending")
    assert session.metadata == {}
    session.metadata = []
    host._persist_analysis_gate(session, "complete")

    host._pending_analysis = {sid}
    host._session_teardown = {sid}
    host._finish_analysis_complete(session)
    assert host._safe_mode_active(sid) is True
    host._session_teardown.clear()
    manager.get_session = lambda _sid: None
    host._finish_analysis_complete(session)
    assert host._safe_mode_active(sid) is True

    # A normal completion creates a notice, clears a prior background error,
    # and tolerates a checkpoint callback that fails.
    manager.get_session = lambda _sid: session
    host._background_load_errors = {sid: {"error": True}}
    host._pending_session_notices = []
    host._run_analysis_checkpoint = lambda _sid: (_ for _ in ()).throw(OSError("checkpoint"))
    host._finish_analysis_complete(session)
    assert host._analysis_is_complete(sid) is True
    assert sid not in host._background_load_errors
    assert host._pending_session_notices[sid]["code"] == "analysis_complete"


def test_analysis_confirmation_and_background_error_guards(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    host._pending_analysis = {sid}

    host._reloading_sessions = {sid}
    host._maybe_resolve_analysis_state(session)
    host._reloading_sessions.clear()
    host._runtime_record = lambda _sid: {"process": object(), "port": 0}
    host._runtime_alive = lambda _runtime: True
    host._maybe_resolve_analysis_state(session)

    host._runtime_record = lambda _sid: {"process": object(), "port": 1234}
    host._send_rpc_raw = lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("closed"))
    host._maybe_resolve_analysis_state(session)

    host._send_rpc_raw = lambda *_args, **_kwargs: {"analysis_complete": True}
    host._on_analysis_complete = lambda current, reload: host._mark_analysis_complete(current)
    host._maybe_resolve_analysis_state(session)
    assert host._analysis_is_complete(sid) is True

    host._session_teardown = {sid}
    host._record_background_load_error(sid, make_error(MCPError.IDA_CRASHED, "spawn"))
    assert not hasattr(host, "_background_load_errors")
    host._session_teardown.clear()
    manager.get_session = lambda _sid: None
    host._record_background_load_error(sid, {"error": True})
    manager.get_session = lambda _sid: session
    host._record_background_load_error(sid, {"error": True})
    assert host._background_load_errors[sid]["error"] is True


def test_architecture_recommendation_and_inference_boundaries():
    assert session_mod.ServerSessionMixin._arch_recommendations({"inferred_profile": "unknown"}) is None
    fallback = session_mod.ServerSessionMixin._arch_recommendations(
        {"inferred_profile": {"candidates": []}}
    )
    assert fallback[0]["arguments"]["processor"] == "arm"
    assert session_mod.ServerSessionMixin._arch_inference_warning(None) is None

    host = session_mod.ServerSessionMixin.__new__(session_mod.ServerSessionMixin)
    options = {}
    assert host._auto_apply_inferred_profile(options, None) is None
    assert host._auto_apply_inferred_profile(options, {"ambiguous": True, "confidence": 1}) is None
    assert host._auto_apply_inferred_profile(options, {"confidence": "not-a-number"}) is None
    assert host._auto_apply_inferred_profile(
        options,
        {
            "confidence": 0.99,
            "candidates": [{"processor": "riscv", "bitness": 64, "confidence": 1.0}],
            "endian": "little",
            "load_base": 0x1000,
        },
    )
    assert options == {"processor": "riscv", "bitness": 64, "endian": "little", "baseaddr": 0x1000}


def test_background_create_and_switch_select_paths(tmp_path, monkeypatch):
    host, manager, session = _host(tmp_path)
    session.analysis_options = {"processor": "arm"}
    session.binary_path = str(tmp_path / "sample.bin")
    (tmp_path / "sample.bin").write_bytes(b"payload")

    monkeypatch.setattr(session_mod, "background_open_enabled", lambda: True)
    host._prepare_open_args = lambda _args: (session.binary_path, {"processor": "arm"}, {}, False, ["-A"], make_error(MCPError.INVALID_ARGS, "bad"))
    assert host._session_action_create_background({})["code"] == MCPError.INVALID_ARGS

    host._prepare_open_args = lambda _args: (session.binary_path, {"processor": "arm"}, {}, False, ["-A"], None)
    host._select_reuse_candidate = lambda *_args: session
    host._preloads_match = lambda *_args: True
    host._mark_analysis_pending = lambda _session: None
    host._open_result = lambda _session, **_kwargs: {"ok": True}
    host._spawn_runtime_background = lambda _session: None
    host._attach_open_envelope = lambda *_args: None
    reused = host._session_action_create_background({"_auto_backgrounded": True})
    assert reused["auto_backgrounded"] is True
    assert manager.updated[-1][1]["ida_args"] == ["-A"]

    manager.update_session = lambda *_args, **_kwargs: None
    assert host._session_action_create_background({})["code"] == MCPError.SESSION_NOT_FOUND

    # Switching by binary path exercises candidate selection and the normal
    # no-spawn response when the target already has a live runtime.
    manager.update_session = lambda sid, **kwargs: session
    manager.find_sessions_by_path = lambda _path: [session]
    host._client_owns_session = lambda _sid: True
    host._session_is_busy = lambda _sid: False
    host._runtime_record = lambda _sid: {"process": SimpleNamespace(poll=lambda: None)}
    host._runtime_alive = lambda _runtime: True
    host._session_ownership_report = lambda _sid: {}
    switched = host._session_action_switch({"binary_path": session.binary_path})
    assert switched["ok"] is True
    assert switched["runtime_attached"] is True
