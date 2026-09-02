"""Deep offline coverage for the composed session lifecycle surface."""

from __future__ import annotations

import threading
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server import server_session as session_mod
from tests.host.test_session_action_modes_full import _error, _host


def test_session_diff_deduplicates_and_cleans_up_background_work(monkeypatch):
    class _Embedder:
        pass

    class _Index:
        size = 1

        def __init__(self, path, _embedder):
            self.path = path
            self._cache = {0x401000: [1.0]} if path.startswith("new") else {}

        def similar_vec(self, _vector, **_kwargs):
            return []

    monkeypatch.setattr(session_mod, "threading", threading)
    import ida_pro_mcp.host.intelligence.core as core_mod

    monkeypatch.setattr(core_mod, "BgeCodeEmbedder", _Embedder)
    monkeypatch.setattr(core_mod, "FunctionEmbeddingIndex", _Index)
    messages = []
    monkeypatch.setattr(session_mod, "log_rpc", messages.append)

    threads = []

    class _HeldThread:
        def __init__(self, target, **_kwargs):
            self.target = target

        def start(self):
            threads.append(self)

    monkeypatch.setattr(threading, "Thread", _HeldThread)
    with session_mod._SESSION_DIFF_LOCK:
        session_mod._SESSION_DIFF_INFLIGHT.clear()
    session_mod.ServerSessionMixin._trigger_session_diff("old", "new")
    session_mod.ServerSessionMixin._trigger_session_diff("old", "new")
    assert len(threads) == 1
    threads[0].target()
    assert any("new functions" in message for message in messages)
    with session_mod._SESSION_DIFF_LOCK:
        assert ("old", "new") not in session_mod._SESSION_DIFF_INFLIGHT


def test_prepare_open_args_validates_aliases_conflicts_and_paths(tmp_path):
    host, _manager, session = _host(tmp_path)

    def normalize_args(value):
        values = [str(value)] if isinstance(value, str) else list(value)
        if any(item.startswith(("-S", "-L", "-o")) for item in values):
            raise ValueError("reserved argument")
        return values

    host._normalize_ida_args = normalize_args
    binary = Path(session.binary_path)
    binary.write_bytes(b"raw binary")

    _, _, _, force_new, ida_args, error = host._prepare_open_args(
        {
            "binary_path": str(binary),
            "force_new": True,
            "architecture": {
                "arch": "arm",
                "bits": 32,
                "endianness": "little",
                "loader_options": "x=1",
            },
            "ida_args": ["-z"],
        }
    )
    assert error is None and force_new is True and ida_args == ["-z"]

    cases = [
        ({"idb_path": "old.i64"}, MCPError.INVALID_ARGS),
        ({"binary_path": 4}, MCPError.INVALID_ARGS),
        ({"binary_path": str(binary), "analysis_options": []}, MCPError.INVALID_ARGS),
        ({"binary_path": str(binary), "architecture": []}, MCPError.INVALID_ARGS),
        (
            {"binary_path": str(binary), "analysis_options": {"processor": "arm"}, "architecture": {"arch": "x86"}},
            MCPError.INVALID_ARGS,
        ),
        (
            {"binary_path": str(binary), "analysis_options": {"bitness": 32}, "bitness": 64},
            MCPError.INVALID_ARGS,
        ),
        ({"binary_path": str(binary), "ida_args": "-Sbad"}, MCPError.INVALID_ARGS),
        ({"binary_path": str(tmp_path / "missing")}, MCPError.FILE_NOT_FOUND),
        ({}, MCPError.INVALID_ARGS),
    ]
    for args, code in cases:
        result = host._prepare_open_args(args)
        assert result[-1]["code"] == code


def test_session_reuse_selection_large_binary_and_open_state_modes(tmp_path, monkeypatch):
    host, manager, session = _host(tmp_path)
    host._client_owns_session = lambda sid: sid == "OWN12345"
    host._session_is_busy = lambda sid: sid == "BUSY1234"
    candidate_owned = SimpleNamespace(
        session_id="OWN12345", analysis_options={"processor": "arm"}
    )
    candidate_free = SimpleNamespace(
        session_id="FREE1234", analysis_options={"processor": "x86"}
    )
    manager.find_sessions_by_path = lambda _path: [candidate_owned, candidate_free]
    assert host._select_reuse_candidate("/bin", {"processor": "arm"}, False) is candidate_owned
    assert host._select_reuse_candidate("/bin", {}, True) is None

    blob = Path(session.binary_path)
    blob.write_bytes(b"IDA2 packed")
    assert host._is_large_binary(str(blob)) is False
    blob.write_bytes(b"raw")
    monkeypatch.setattr(session_mod, "LARGE_BINARY_THRESHOLD_BYTES", 2)
    assert host._is_large_binary(str(blob)) is True
    assert host._is_large_binary(str(tmp_path / "missing")) is False

    host._runtime_record = lambda _sid: {"process": SimpleNamespace(poll=lambda: None), "port": 7777}
    host._runtime_alive = lambda _runtime: True
    host._send_rpc_raw = lambda *_args, **_kwargs: {"analysis_complete": True, "functions": "9"}
    state = host._open_analysis_state(session)
    assert state == {"analysis_complete": True, "analysis_functions": 9}
    host._send_rpc_raw = lambda *_args, **_kwargs: {"analysis_complete": False}
    assert host._open_analysis_state(session) == {}
    host._mark_analysis_complete = lambda _session: None
    host.safe_mode_poll_seconds = 0
    assert host._wait_for_analysis_complete(session, timeout=0.01) == {}

    host._session_is_running = lambda _sid: False
    host._safe_mode_active = lambda _sid: True
    host._analysis_is_complete = lambda _sid: False
    warning = host._open_result(session, reused=True, background=True, note="note")
    assert warning["reused_existing_session"] and warning["background"]
    assert warning["safe_mode"] is True


def test_session_discover_get_list_and_runtime_start_error_modes(tmp_path):
    host, manager, session = _host(tmp_path)
    manager._load_orphaned_idbs = lambda: None
    manager.discover_sessions = lambda **_kwargs: [session]
    assert host._session_action_discover({"query": "demo", "binary_name": "sample"})["count"] == 1

    host._ensure_client_owns_session = lambda _session: None
    host._runtime_record = lambda _sid: {"process": SimpleNamespace(poll=lambda: None), "port": 123}
    host._session_ownership_report = lambda _sid: {
        "locked": False,
        "holder": None,
        "owner_id": "owner",
        "owner_pid": 1,
        "owner_alive": True,
        "idat_pid": 2,
        "lease_age_seconds": 0,
    }
    result = host._session_action_get({"session_id": session.session_id})
    assert result["session"]["is_running"] is True and result["session"]["port"] == 123

    manager.list_sessions = lambda **_kwargs: {"sessions": [session.to_dict()], "total": 1}
    host._client_owns_session = lambda _sid: True
    listed = host._session_action_list({"limit": "2", "offset": "1", "query": "demo"})
    assert listed["count"] == 1 and listed["sessions"][0]["is_running"] is True

    host.session_runtimes = {}
    host._start_server = lambda _session: {"error": True, "code": MCPError.IDA_CRASHED}
    failure = host._ensure_runtime_and_idb(session)
    assert failure["code"] == MCPError.IDA_CRASHED and failure["session_id"] == session.session_id

    host._start_server = lambda _session: (_ for _ in ()).throw(RuntimeError("spawn"))
    failure = host._ensure_runtime_and_idb(session)
    assert failure["code"] == MCPError.IDA_CRASHED

    host._runtime_record = lambda _sid: {"process": SimpleNamespace(poll=lambda: None)}
    host._runtime_alive = lambda _runtime: True
    host._wait_for_idb = lambda *_args, **_kwargs: False
    failure = host._ensure_runtime_and_idb(session)
    assert failure["code"] == MCPError.IDA_CRASHED


def test_session_target_visibility_and_state_error_boundaries(tmp_path):
    host, manager, session = _host(tmp_path)
    host._ensure_client_owns_session = lambda _session: {"error": True, "code": MCPError.FILE_LOCKED}
    assert host._session_target({"session_id": session.session_id})[1]["code"] == MCPError.FILE_LOCKED

    host._ensure_client_owns_session = lambda _session: None
    manager.get_session = lambda _sid: (_ for _ in ()).throw(RuntimeError("lookup"))
    assert host._session_target({"session_id": session.session_id})[1]["code"] == MCPError.SESSION_NOT_FOUND
    assert host._session_target({"session_id": "bad/id"})[1]["code"] == MCPError.INVALID_ARGS

    host.current_session = session
    host._build_state_payload = lambda: {"binary": {}, "coverage": {}}
    host._arm_analysis_watcher_if_needed = lambda _sid: None
    host._session_ownership_report = lambda _sid: {}
    state = host._session_action_state({})
    assert state["ok"] is True and state["state"]["safe_mode"] is False

    host._build_state_payload = lambda: (_ for _ in ()).throw(RuntimeError("state"))
    failure = host._session_action_state({})
    assert failure["code"] == MCPError.IDA_ERROR


def test_session_create_reuse_and_background_modes(tmp_path, monkeypatch):
    host, manager, original = _host(tmp_path)
    binary = Path(original.binary_path)
    binary.write_bytes(b"ELF-like test input")
    created = []

    def create_session(path, **kwargs):
        created_session = SimpleNamespace(
            session_id=f"NEW{len(created):05d}",
            binary_path=path,
            idb_path=str(tmp_path / f"new-{len(created)}.i64"),
            analysis_options=kwargs.get("analysis_options") or {},
            metadata={},
            to_dict=lambda: {
                "session_id": created_session.session_id,
                "binary_path": created_session.binary_path,
                "idb_path": created_session.idb_path,
            },
        )
        created.append(created_session)
        return created_session

    manager.create_session = create_session
    manager.find_sessions_by_path = lambda _path: []
    host._spawn_analysis_watcher = lambda _sid: None
    host._prepare_open_args = lambda _args: (
        str(binary),
        {"processor": "arm"},
        {"inferred_profile": {"candidates": [{"processor": "arm", "bitness": 32, "endian": "little"}]}},
        False,
        ["-z"],
        None,
    )
    host._runtime_record = lambda _sid: None
    host._safe_mode_active = lambda _sid: True
    host._analysis_is_complete = lambda _sid: False
    host._mark_analysis_pending = lambda session: setattr(session, "pending", True)
    opened = host._session_action_create({"binary_path": str(binary)})
    assert opened["ok"] is True
    assert opened["session_id"] == "NEW00000"
    assert opened["safe_mode"] is True
    assert opened["architecture_recommendations"][0]["arguments"]["processor"] == "arm"

    reused = SimpleNamespace(
        session_id="REUSE123",
        binary_path=str(binary),
        idb_path=str(tmp_path / "reuse.i64"),
        analysis_options={},
        metadata={},
        idb_on_disk=lambda: False,
        to_dict=lambda: {"session_id": "REUSE123", "binary_path": str(binary)},
    )
    manager.find_sessions_by_path = lambda _path: [reused]
    manager.update_session = lambda _sid, **_kwargs: reused
    host._prepare_open_args = lambda _args: (
        str(binary),
        {},
        {},
        False,
        None,
        None,
    )
    host._mark_analysis_pending = lambda _session: None
    reused_result = host._session_action_create({"binary_path": str(binary)})
    assert reused_result["reused_existing_session"] is True
    assert reused_result["session_id"] == "REUSE123"

    monkeypatch.setattr(session_mod, "background_open_enabled", lambda: False)
    disabled = host._session_action_create_background({"binary_path": str(binary)})
    assert disabled["code"] == MCPError.FEATURE_DISABLED

    monkeypatch.setattr(session_mod, "background_open_enabled", lambda: True)
    manager.find_sessions_by_path = lambda _path: []
    host._prepare_open_args = lambda _args: (
        str(binary),
        {},
        {},
        False,
        None,
        None,
    )
    host._spawn_runtime_background = lambda _session: None
    background = host._session_action_create_background({"binary_path": str(binary)})
    assert background["ok"] is True
    assert background["background"] is True
    assert background["session_id"] == "NEW00001"


def test_session_coverage_cache_state_narrative_and_manager_actions(tmp_path):
    host, manager, session = _host(tmp_path)
    sid = session.session_id
    manager.get_session = lambda _sid: session
    manager.session_exists = lambda _sid: True
    manager.get_stats = lambda: {"sessions": 1, "running": 0}
    manager.validate_session = lambda _sid: {"valid": True, "warnings": []}
    manager.snapshot_session = lambda _sid: {"snapshot_id": "snap-1", "message": "saved"}
    manager.restore_snapshot = lambda _sid, _snapshot: session
    manager.merge_sessions = lambda _target, _source: session
    manager.rate_skill = lambda target, **kwargs: {"sid": target, **kwargs}
    manager.list_skills = lambda target, **kwargs: {"sid": target, **kwargs}
    manager.suggest_triage = lambda target, **kwargs: {"sid": target, "triage": kwargs}
    manager.suggest_strategy = lambda target, **kwargs: {"sid": target, "strategy": kwargs}
    manager.suggest_analogy = lambda target, **kwargs: {"sid": target, "analogy": kwargs}
    manager.get_phase = lambda target: {"sid": target, "phase": "triage"}
    manager.dashboard = lambda target: {"sid": target, "dashboard": {"open": 1}}
    manager.export_session = lambda target: {"session_id": target, "version": 1}
    manager.import_session = lambda _data: session
    manager.bulk_tag = lambda targets, tag: [{"session_id": target, "tag": tag} for target in targets]
    manager.bulk_delete = lambda targets: [{"session_id": target, "deleted": True} for target in targets]
    host._export_session_hypotheses_to_symbol_db = lambda _sid: 2
    assert host._session_action_stats({})["stats"]["sessions"] == 1
    assert host._session_action_validate({"session_id": sid})["validation"]["valid"] is True
    assert host._session_action_snapshot({"session_id": sid})["snapshot_id"] == "snap-1"
    assert host._session_action_restore_snapshot({"session_id": sid, "snapshot_id": "snap-1"})["session"]["session_id"] == sid
    assert host._session_action_merge({"session_id": sid, "source_id": "OTHER123"})["session"]["session_id"] == sid
    assert host._session_action_rate_skill({"session_id": sid, "skill_id": "cfg", "reward": "0.8"})["reward"] == 0.8
    assert host._session_action_list_skills({"session_id": sid, "min_q": "0.2", "global_skills": "false"})["global_skills"] is False
    assert host._session_action_suggest_triage({"session_id": sid, "context": 7, "limit": "3"})["triage"]["limit"] == 3
    assert host._session_action_suggest_strategy({"session_id": sid})["strategy"]["context"] is None
    assert host._session_action_get_phase({"session_id": sid})["phase"] == "triage"
    assert host._session_action_dashboard({"session_id": sid})["dashboard"]["open"] == 1
    assert host._session_action_suggest_analogy({"session_id": sid, "library_idbs": ["a.i64"], "limit": "2"})["sid"] == sid
    applied = []
    host.call_tool = lambda *args, **kwargs: applied.append((args, kwargs)) or {"ok": True}
    analogy = host._session_action_apply_analogy({
        "session_id": sid,
        "mappings": [{"addr": "0x1000", "name": "entry", "comment": "review"}, "bad", {"name": "missing addr"}],
    })
    assert analogy["applied"] == 3 and len(applied) == 2
    assert host._session_action_export_session({"session_id": sid})["exported_hypotheses"] == 2
    imported = host._session_action_import_session({"data": {"binary_path": session.binary_path}})
    assert imported["session"]["session_id"] == sid
    host._activity_log = [
        {"tool": "idb", "action": "overview", "addresses": ["0x1000"], "topic": "identity", "target": "main", "ts": "now"},
        {"tool": "code", "action": "decompile", "addresses": [], "ts": "later"},
    ]
    narrative = host._session_action_narrative({"limit": "1"})
    assert narrative["turn_count"] == 1 and "addresses" not in narrative["turns"][0]
    assert host._session_action_bulk_tag({"session_ids": [sid], "tag": "review"})["results"]
    assert host._session_action_bulk_delete({"session_ids": [sid]})["results"][0]["deleted"] is True

    calls = []
    host._execute_tool = lambda *_args: calls.append(1) or {
        "items": [
            {"addr": "0x1", "name": "sub_1"},
            {"addr": "0x2", "name": "useful"},
            {"addr": "0x3", "name": "j_dispatch"},
        ]
    }
    first = host._get_cached_coverage(sid)
    second = host._get_cached_coverage(sid)
    assert first == {"total_functions": 3, "named_functions": 1, "unnamed_functions": 2, "pct_named": 33.3}
    assert second == first and len(calls) == 1
    host._session_state_cache.clear()
    host._execute_tool = lambda *_args: {"functions": "0x10 4 sub_10\n0x20 4 named"}
    assert host._get_cached_coverage("LEGACY1")["named_functions"] == 1
    host._execute_tool = lambda *_args: (_ for _ in ()).throw(RuntimeError("rpc"))
    assert host._get_cached_coverage("FAILED1") == {}
    host._session_state_cache = {
        f"OLD{i}": {"coverage": {}, "_ts": 0} for i in range(128)
    }
    host._execute_tool = lambda *_args: {"items": []}
    host._get_cached_coverage("NEW1")
    assert len(host._session_state_cache) == 128 and "NEW1" in host._session_state_cache


def test_session_state_payload_exposes_blackboard_and_actionable_narrative(tmp_path):
    host, manager, session = _host(tmp_path)
    manager.active_session_id = session.session_id
    host._get_cached_coverage = lambda _sid: {"total_functions": 40, "named_functions": 5, "pct_named": 12.5}

    class Blackboard:
        def stats(self):
            return {"total": 3}

        def next_target(self, limit):
            assert limit == 5
            return [{"addr": "0x401000", "title": "Decode packet"}]

        def list(self, *, category, limit, **_kwargs):
            if category == "hypothesis":
                return [{"title": "entry point", "addr": "0x1000", "confidence": 0.8}]
            if category == "ioc":
                return [{"ioc_type": "domain", "ioc_value": "example.test", "addr": "0x2000"}]
            if category == "vuln":
                return [{"title": "unsafe copy", "addr": "0x3000", "confidence": 0.9}]
            if category == "narrative":
                return []
            return []

    blackboard = Blackboard()

    def get_blackboard():
        return blackboard

    host._bb_store = get_blackboard
    host._execute_tool = lambda action, _args: {
        "meta": {"binary_path": "sample.bin", "processor": "x86", "bitness": 64, "image_size": 10},
        "summary": {"imports": 4},
    } if action == "idb" else {}
    state = host._build_state_payload()
    assert state["blackboard"]["stats"] == {"total": 3}
    assert state["blackboard"]["next_targets"][0]["addr"] == "0x401000"
    assert state["blackboard"]["vulns"][0]["title"] == "unsafe copy"
    assert len(state["_next_actions"]) == 3

    class NarrativeBlackboard(Blackboard):
        def list(self, *, category, limit, **kwargs):
            if category == "narrative":
                return [{"content": "A durable narrative with enough content to be returned as a text handoff."}]
            return super().list(category=category, limit=limit, **kwargs)

    narrative_blackboard = NarrativeBlackboard()

    def get_narrative_blackboard():
        return narrative_blackboard

    host._bb_store = get_narrative_blackboard
    narrative = host._build_state_payload()
    assert isinstance(narrative, str) and narrative.startswith("<!-- state:")
