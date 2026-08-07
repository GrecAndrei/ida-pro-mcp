"""Reranker lifecycle tests: discovery, lease plumbing, idle shutdown,
request/response handling, and the subprocess start path.

Mocks stay at the process/network boundary (``subprocess.Popen``,
``urllib.request.urlopen``, process introspection), per project test rules.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import threading
import time

import pytest

from ida_pro_mcp.host.intelligence import rerank as rerank_mod, rerank_profiles


def _reset_singleton():
    old = rerank_mod.Reranker._instance
    rerank_mod.Reranker._instance = None
    return old


def _restore_singleton(old):
    inst = rerank_mod.Reranker._instance
    if inst is not None:
        with contextlib.suppress(Exception):
            inst.stop()
    rerank_mod.Reranker._instance = old


def _stub_reranker(**attrs) -> rerank_mod.Reranker:
    """Minimal Reranker without _init() (no discovery, no singleton)."""
    obj = object.__new__(rerank_mod.Reranker)
    obj._server_bin = ""
    obj._model_path = ""
    obj._profile = rerank_profiles.QWEN3_RERANKER_0_6B
    obj._port = None
    obj._proc = None
    obj._ready = False
    obj._start_lock = threading.Lock()
    obj._use_llama = False
    obj._owns_proc = False
    obj._stop_registered = True
    obj._consecutive_rpc_failures = 0
    obj._max_rpc_failures = 2
    obj._last_batch_timeout = False
    obj._last_recycle_reason = ""
    obj._identity_cache = None
    obj._server_started_at = 0.0
    obj._idle_lock = threading.Lock()
    obj._idle_timer = None
    obj._idle_generation = 0
    obj._ctx = 1024
    for key, value in attrs.items():
        setattr(obj, key if key.startswith("_") else f"_{key}", value)
    return obj


class _FakeProc:
    def __init__(self, pid=12345, poll_result=None):
        self.pid = pid
        self._poll = poll_result
        self.terminated = False
        self.killed = False
        self.waited: list[float | None] = []

    def poll(self):
        return self._poll

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.waited.append(timeout)
        return 0


class _FakeResp:
    def __init__(self, data: bytes):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._data


# ---------------------------------------------------------------------------
# module-level discovery helpers
# ---------------------------------------------------------------------------

class TestModuleHelpers:
    def test_rerank_enabled_toggles(self, monkeypatch):
        monkeypatch.delenv("IDA_MCP_RERANK_DISABLED", raising=False)
        monkeypatch.delenv("IDA_MCP_RERANK_ENABLED", raising=False)
        assert rerank_mod._rerank_enabled() is True

        monkeypatch.setenv("IDA_MCP_RERANK_DISABLED", "1")
        assert rerank_mod._rerank_enabled() is False

        # Explicit disable is authoritative even when enable is forced.
        monkeypatch.setenv("IDA_MCP_RERANK_ENABLED", "true")
        assert rerank_mod._rerank_enabled() is False
        monkeypatch.setenv("IDA_MCP_RERANK_DISABLED", "0")
        assert rerank_mod._rerank_enabled() is True

        monkeypatch.setenv("IDA_MCP_RERANK_DISABLED", "no")
        assert rerank_mod._rerank_enabled() is True

    def test_read_rerank_state_returns_subsection(self, monkeypatch):
        monkeypatch.setattr(
            rerank_mod, "_read_embedder_state",
            lambda: {"rerank": {"model_path": "/x/model.gguf", "profile": "qwen3"}},
        )
        assert rerank_mod._read_rerank_state() == {
            "model_path": "/x/model.gguf", "profile": "qwen3",
        }

    def test_read_rerank_state_ignores_non_dict(self, monkeypatch):
        monkeypatch.setattr(rerank_mod, "_read_embedder_state", lambda: {"rerank": "nope"})
        assert rerank_mod._read_rerank_state() == {}
        monkeypatch.setattr(rerank_mod, "_read_embedder_state", dict)
        assert rerank_mod._read_rerank_state() == {}

    def test_scan_bases_prefers_q4_and_dedups(self, tmp_path, monkeypatch):
        base = tmp_path / "models"
        base.mkdir()
        q8 = base / "qwen3-reranker-0.6b-q8_0.gguf"
        q4 = base / "qwen3-reranker-0.6b-q4_k_m.gguf"
        q8.write_bytes(b"x")
        q4.write_bytes(b"x")
        # Same file appears twice via a duplicated base -> dedup, first wins.
        found = rerank_mod._scan_bases(
            [str(base), str(base)],
            ("qwen3-reranker-0.6b*.gguf",),
        )
        assert os.path.basename(found) == "qwen3-reranker-0.6b-q4_k_m.gguf"

    def test_scan_bases_empty(self):
        assert rerank_mod._scan_bases(["/nonexistent"], ("*.gguf",)) == ""

    def test_find_rerank_model_env_var(self, tmp_path, monkeypatch):
        model = tmp_path / "qwen3-reranker-0.6b-q8_0.gguf"
        model.write_bytes(b"m")
        monkeypatch.setenv("IDA_MCP_RERANK_MODEL", str(model))
        assert rerank_mod._find_rerank_model() == str(model)

    def test_find_rerank_model_env_list(self, tmp_path, monkeypatch):
        model = tmp_path / "qwen3-reranker-0.6b-q8_0.gguf"
        model.write_bytes(b"m")
        monkeypatch.setenv(
            "IDA_MCP_RERANK_MODEL", f"{tmp_path / 'missing.gguf'};{model}"
        )
        assert rerank_mod._find_rerank_model() == str(model)

    def test_find_rerank_model_state_override(self, tmp_path, monkeypatch):
        model = tmp_path / "qwen3-reranker-0.6b-q8_0.gguf"
        model.write_bytes(b"m")
        monkeypatch.delenv("IDA_MCP_RERANK_MODEL", raising=False)
        monkeypatch.setattr(
            rerank_mod, "_read_rerank_state",
            lambda: {"model_path": str(model)},
        )
        assert rerank_mod._find_rerank_model() == str(model)

    def test_find_rerank_model_hf_cache(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        hf_file = home / ".cache" / "huggingface" / "hub" / "models--ggml-org--Qwen3-Reranker-0.6B-Q8_0-GGUF" / "snapshots" / "abc" / "Qwen3-Reranker-0.6B-q8_0.gguf"
        hf_file.parent.mkdir(parents=True)
        hf_file.write_bytes(b"m")
        monkeypatch.delenv("IDA_MCP_RERANK_MODEL", raising=False)
        monkeypatch.setattr(rerank_mod, "_read_rerank_state", dict)

        class _StubPath:
            @classmethod
            def home(cls):
                return str(home)

        monkeypatch.setattr(rerank_mod, "Path", _StubPath)
        monkeypatch.setattr(rerank_mod, "_install_root", lambda: str(tmp_path / "install"))
        assert rerank_mod._find_rerank_model() == str(hf_file)

    def test_find_rerank_model_empty_when_nothing_installed(self, tmp_path, monkeypatch):
        monkeypatch.delenv("IDA_MCP_RERANK_MODEL", raising=False)
        monkeypatch.setattr(rerank_mod, "_read_rerank_state", dict)
        monkeypatch.setattr(
            rerank_mod, "Path",
            type("_P", (), {"home": classmethod(lambda cls: str(tmp_path / "home"))}),
        )
        monkeypatch.setattr(rerank_mod, "_install_root", lambda: str(tmp_path / "install"))
        assert rerank_mod._find_rerank_model() == ""

    def test_lock_paths(self, monkeypatch):
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", "/tmp/lease.json")
        assert rerank_mod._rerank_request_lock_path() == "/tmp/lease.json.request.lock"
        assert rerank_mod._rerank_start_lock_path() == "/tmp/lease.json.startup.lock"


# ---------------------------------------------------------------------------
# singleton / init / status
# ---------------------------------------------------------------------------

class TestSingletonAndStatus:
    def test_new_returns_singleton(self, monkeypatch):
        old = _reset_singleton()
        monkeypatch.setattr(rerank_mod, "_find_llama_server", lambda: "")
        monkeypatch.setattr(rerank_mod, "_find_rerank_model", lambda: "")
        try:
            a = rerank_mod.Reranker()
            b = rerank_mod.Reranker()
            assert a is b
            assert a._use_llama is False
        finally:
            _restore_singleton(old)

    def test_reset_stops_previous_and_pins_model(self, tmp_path, monkeypatch):
        old = _reset_singleton()
        model = tmp_path / "qwen3-reranker-0.6b-q8_0.gguf"
        model.write_bytes(b"m")
        monkeypatch.setattr(rerank_mod, "_find_llama_server", lambda: "/bin/echo")
        monkeypatch.setattr(rerank_mod, "_find_rerank_model", lambda: "")
        monkeypatch.setattr(rerank_mod, "_rerank_enabled", lambda: True)
        monkeypatch.setattr(rerank_mod, "_read_rerank_state", dict)
        stopped: list = []

        class _Old:
            def stop(self):
                stopped.append(1)

        try:
            rerank_mod.Reranker._instance = _Old()
            r = rerank_mod.Reranker.reset(str(model))
            assert stopped == [1]
            assert r._model_path == str(model)
            assert r._profile.key == "qwen3-reranker-0.6b"
            assert r._use_llama is True
            assert rerank_mod.Reranker() is r
        finally:
            _restore_singleton(old)

    def test_status_reports_config(self):
        obj = _stub_reranker(
            use_llama=True,
            server_bin="/bin/echo",
            model_path="/tmp/model.gguf",
            port=1234,
            owns_proc=True,
            ready=True,
        )
        st = obj.status()
        assert st["backend"] == "local"
        assert st["enabled"] is True
        assert st["server_bin"] == "/bin/echo"
        assert st["model_path"] == "/tmp/model.gguf"
        assert st["ready"] is True
        assert st["port"] == 1234
        assert st["owns_process"] is True
        assert st["profile"] == "qwen3-reranker-0.6b"

    def test_status_probe_calls_ensure_ready(self, monkeypatch):
        obj = _stub_reranker()
        monkeypatch.setattr(obj, "ensure_ready", lambda: True)
        assert obj.status(probe=True)["ready"] is True


# ---------------------------------------------------------------------------
# lease plumbing
# ---------------------------------------------------------------------------

class TestLease:
    def test_write_and_read_lease_roundtrip(self, tmp_path, monkeypatch):
        lease_file = tmp_path / "lease.json"
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(lease_file))
        rerank_mod.Reranker._write_lease({"schema": 1, "pid": 7})
        assert rerank_mod.Reranker._read_lease() == {"schema": 1, "pid": 7}

    def test_read_lease_missing_or_corrupt(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(tmp_path / "nope.json"))
        assert rerank_mod.Reranker._read_lease() == {}
        bad = tmp_path / "bad.json"
        bad.write_text("{not json")
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(bad))
        assert rerank_mod.Reranker._read_lease() == {}

    def test_lease_identity_cached(self, tmp_path):
        model = tmp_path / "model.gguf"
        server = tmp_path / "llama-server"
        model.write_bytes(b"m" * 64)
        server.write_bytes(b"s" * 64)
        obj = _stub_reranker(model_path=str(model), server_bin=str(server))
        first = obj._lease_identity()
        assert first["model_path"] == str(model)
        assert first["server_path"] == str(server)
        assert obj._identity_cache is not None
        assert obj._lease_identity() == first

    def test_lease_matches_healthy_lease(self, tmp_path, monkeypatch):
        model = tmp_path / "model.gguf"
        model.write_bytes(b"m" * 64)
        obj = _stub_reranker(model_path=str(model), port=1234)
        identity = obj._lease_identity()
        lease = {
            "schema": 1, "pid": 42, "owner_pid": 43,
            "process_start_token": "tok", "owner_start_token": "otok",
            "port": 1234,
        }
        lease.update(identity)
        monkeypatch.setattr(rerank_mod, "_pid_alive", lambda pid: True)
        monkeypatch.setattr(rerank_mod, "_process_start_token", lambda pid: "tok" if pid == 42 else "otok")

        responses = [{"status": "ok"}, {"model_path": str(model)}]
        monkeypatch.setattr(obj, "_server_json", lambda port, ep: responses.pop(0))
        assert obj._lease_matches(lease) is True

    def test_lease_matches_rejects_bad_lease(self, tmp_path, monkeypatch):
        model = tmp_path / "model.gguf"
        model.write_bytes(b"m" * 64)
        obj = _stub_reranker(model_path=str(model), port=1234)
        identity = obj._lease_identity()
        base = {
            "schema": 1, "pid": 42, "owner_pid": 43,
            "process_start_token": "tok", "owner_start_token": "otok",
            "port": 1234,
        }
        base.update(identity)

        monkeypatch.setattr(rerank_mod, "_pid_alive", lambda pid: True)
        monkeypatch.setattr(rerank_mod, "_process_start_token", lambda pid: "tok" if pid == 42 else "otok")

        bad_schema = dict(base, schema=9)
        assert obj._lease_matches(bad_schema) is False

        monkeypatch.setattr(rerank_mod, "_pid_alive", lambda pid: False)
        assert obj._lease_matches(base) is False
        monkeypatch.setattr(rerank_mod, "_pid_alive", lambda pid: True)

        monkeypatch.setattr(rerank_mod, "_process_start_token", lambda pid: "other")
        assert obj._lease_matches(base) is False
        monkeypatch.setattr(rerank_mod, "_process_start_token", lambda pid: "tok" if pid == 42 else "otok")

        wrong_identity = dict(base, model_size=99999)
        assert obj._lease_matches(wrong_identity) is False

        recycled = dict(base, recycle_requested=True)
        assert obj._lease_matches(recycled) is False

        responses = [{"status": "down"}]
        monkeypatch.setattr(obj, "_server_json", lambda port, ep: responses.pop(0))
        assert obj._lease_matches(base) is False

    def test_pid_is_expected_server(self, monkeypatch):
        obj = _stub_reranker(server_bin="/bin/llama-server", model_path="/m.gguf")
        monkeypatch.setattr(
            rerank_mod, "_process_command",
            lambda pid: "/bin/llama-server --rerank --model /m.gguf --port 1",
        )
        assert obj._pid_is_expected_server(1) is True
        monkeypatch.setattr(
            rerank_mod, "_process_command",
            lambda pid: "/bin/llama-server --embedding --model /m.gguf",
        )
        assert obj._pid_is_expected_server(1) is False
        monkeypatch.setattr(rerank_mod, "_process_command", lambda pid: "")
        assert obj._pid_is_expected_server(1, {"schema": 1}) is True
        assert obj._pid_is_expected_server(1, {"schema": 9}) is False

    def test_retire_lease_kills_and_clears(self, tmp_path, monkeypatch):
        lease_file = tmp_path / "lease.json"
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(lease_file))
        lease = {"schema": 1, "pid": 42}
        obj = _stub_reranker(proc=_FakeProc(pid=42), ready=True)
        obj._retire_lease_process = rerank_mod.Reranker._retire_lease_process  # keep real impl? no
        # Use real implementation via unbound call; replace module helpers.
        alive = {"n": 0}

        def _alive(pid):
            alive["n"] += 1
            return alive["n"] <= 2  # alive at first check, then dies after SIGTERM

        kills: list = []
        monkeypatch.setattr(rerank_mod, "_pid_alive", _alive)
        monkeypatch.setattr(rerank_mod.os, "kill", lambda pid, sig: kills.append((pid, sig)))
        monkeypatch.setattr(rerank_mod.time, "sleep", lambda _s: None)
        monkeypatch.setattr(obj, "_pid_is_expected_server", lambda pid, lease=None: True)
        obj._proc = _FakeProc(pid=42)

        rerank_mod.Reranker._retire_lease_process(obj, lease, "stale")
        assert kills == [(42, 15)]
        assert obj._last_recycle_reason == "stale"
        assert obj._ready is False
        assert obj._owns_proc is False
        assert obj._proc is None

    def test_retire_lease_escalates_to_kill9(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(tmp_path / "lease.json"))
        kills: list = []
        monkeypatch.setattr(rerank_mod, "_pid_alive", lambda pid: True)
        monkeypatch.setattr(rerank_mod.os, "kill", lambda pid, sig: kills.append((pid, sig)))
        monkeypatch.setattr(rerank_mod.time, "sleep", lambda _s: None)
        obj = _stub_reranker()
        monkeypatch.setattr(obj, "_pid_is_expected_server", lambda pid, lease=None: True)
        rerank_mod.Reranker._retire_lease_process(obj, {"schema": 1, "pid": 42}, "stale")
        assert kills == [(42, 15), (42, 9)]


# ---------------------------------------------------------------------------
# idle shutdown machinery
# ---------------------------------------------------------------------------

class TestIdleShutdown:
    def test_cancel_idle_shutdown(self):
        obj = _stub_reranker()
        timer = threading.Timer(30.0, lambda: None)
        obj._idle_timer = timer
        obj._idle_generation = 5
        obj._cancel_idle_shutdown()
        assert obj._idle_timer is None
        assert obj._idle_generation == 6
        assert timer.finished.is_set()

    def test_schedule_zero_timeout_is_noop(self):
        obj = _stub_reranker()
        obj._schedule_idle_shutdown(0.0)
        assert obj._idle_timer is None

    def test_schedule_and_fire_stops_when_idle(self, monkeypatch):
        obj = _stub_reranker()
        stopped: list = []
        monkeypatch.setattr(obj, "_server_has_active_slots", lambda: False)
        monkeypatch.setattr(obj, "stop", lambda: stopped.append(1))
        obj._schedule_idle_shutdown(0.05)
        assert obj._idle_timer is not None
        deadline = time.monotonic() + 1.0
        while not stopped and time.monotonic() < deadline:
            time.sleep(0.01)
        obj._cancel_idle_shutdown()
        assert stopped == [1]

    def test_shutdown_if_idle_generation_mismatch(self, monkeypatch):
        obj = _stub_reranker()
        stopped: list = []
        monkeypatch.setattr(obj, "stop", lambda: stopped.append(1))
        obj._idle_generation = 2
        obj._shutdown_if_idle(1)
        assert stopped == []

    def test_shutdown_if_idle_reschedules_when_busy(self, monkeypatch):
        obj = _stub_reranker()
        scheduled: list = []
        monkeypatch.setattr(obj, "_server_has_active_slots", lambda: True)
        monkeypatch.setattr(obj, "_schedule_idle_shutdown", lambda *a, **k: scheduled.append(1))
        monkeypatch.setattr(obj, "stop", lambda: None)
        obj._idle_generation = 2
        obj._shutdown_if_idle(2)
        assert scheduled == [1]

    def test_server_has_active_slots(self, monkeypatch):
        obj = _stub_reranker(port=1234)
        assert obj._server_has_active_slots() is False  # no lease
        monkeypatch.setattr(obj, "_read_lease", lambda: {"pid": 1})
        monkeypatch.setattr(obj, "_server_json", lambda port, ep: [{"is_processing": True}])
        assert obj._server_has_active_slots() is True
        monkeypatch.setattr(obj, "_server_json", lambda port, ep: [{"is_processing": False}])
        assert obj._server_has_active_slots() is False
        monkeypatch.setattr(obj, "_server_json", lambda port, ep: (_ for _ in ()).throw(RuntimeError()))
        assert obj._server_has_active_slots() is False


# ---------------------------------------------------------------------------
# recycling / limits / ports
# ---------------------------------------------------------------------------

class TestRecycleAndLimits:
    def test_rss_limit_bytes_env(self, monkeypatch):
        monkeypatch.setattr(rerank_mod, "RERANK_MAX_RSS_MB", 512)
        obj = _stub_reranker()
        assert obj._rss_limit_bytes() == 512 * 1024 * 1024

    def test_rss_limit_bytes_model_based(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rerank_mod, "RERANK_MAX_RSS_MB", 0)
        model = tmp_path / "model.gguf"
        model.write_bytes(b"x" * 1000)
        obj = _stub_reranker(model_path=str(model))
        assert obj._rss_limit_bytes() == 5 * 1024**3

    def test_record_success_without_lease(self, monkeypatch):
        obj = _stub_reranker()
        monkeypatch.setattr(obj, "_read_lease", dict)
        written: list = []
        monkeypatch.setattr(obj, "_write_lease", written.append)
        monkeypatch.setattr(obj, "_lease_matches", lambda lease: True)
        obj._record_success_and_maybe_recycle()
        assert written == []

    def test_record_success_updates_lease(self, monkeypatch):
        obj = _stub_reranker()
        lease = {"schema": 1, "pid": 42, "rss": 10, "request_count": 1}
        monkeypatch.setattr(obj, "_read_lease", lambda: dict(lease))
        monkeypatch.setattr(obj, "_lease_matches", lambda lease: True)
        monkeypatch.setattr(rerank_mod, "_process_rss_bytes", lambda pid: 25)
        monkeypatch.setattr(rerank_mod, "RERANK_MAX_REQUESTS", 1000)
        written: list = []
        monkeypatch.setattr(obj, "_write_lease", written.append)
        obj._record_success_and_maybe_recycle()
        assert written == [dict(lease, request_count=2, rss=25, updated_at=written[0]["updated_at"])]

    def test_record_success_recycles_on_request_limit(self, monkeypatch):
        obj = _stub_reranker()
        monkeypatch.setattr(obj, "_read_lease", lambda: {"schema": 1, "pid": 42, "request_count": 511})
        monkeypatch.setattr(obj, "_lease_matches", lambda lease: True)
        monkeypatch.setattr(rerank_mod, "_process_rss_bytes", lambda pid: 0)
        monkeypatch.setattr(rerank_mod, "RERANK_MAX_REQUESTS", 512)
        retired: list = []
        monkeypatch.setattr(obj, "_retire_lease_process", lambda lease, reason: retired.append(reason))
        obj._record_success_and_maybe_recycle()
        assert retired == ["request limit reached (512)"]

    def test_record_success_recycles_on_rss_limit(self, monkeypatch):
        obj = _stub_reranker()
        monkeypatch.setattr(obj, "_read_lease", lambda: {"schema": 1, "pid": 42, "rss": 0, "request_count": 0})
        monkeypatch.setattr(obj, "_lease_matches", lambda lease: True)
        monkeypatch.setattr(rerank_mod, "_process_rss_bytes", lambda pid: 9999)
        monkeypatch.setattr(obj, "_rss_limit_bytes", lambda: 100)
        monkeypatch.setattr(rerank_mod, "RERANK_MAX_REQUESTS", 0)
        retired: list = []
        monkeypatch.setattr(obj, "_retire_lease_process", lambda lease, reason: retired.append(reason))
        obj._record_success_and_maybe_recycle()
        assert retired and "RSS limit exceeded" in retired[0]

    def test_record_success_recycles_on_growth(self, monkeypatch):
        obj = _stub_reranker()
        monkeypatch.setattr(obj, "_read_lease", lambda: {"schema": 1, "pid": 42, "rss": 100, "request_count": 0})
        monkeypatch.setattr(obj, "_lease_matches", lambda lease: True)
        monkeypatch.setattr(rerank_mod, "_process_rss_bytes", lambda pid: 100 + 4096 * 1024 * 1024)
        monkeypatch.setattr(obj, "_rss_limit_bytes", lambda: 10**15)
        monkeypatch.setattr(rerank_mod, "RERANK_MAX_REQUESTS", 0)
        monkeypatch.setattr(rerank_mod, "RERANK_MAX_RSS_GROWTH_MB", 2048)
        retired: list = []
        monkeypatch.setattr(obj, "_retire_lease_process", lambda lease, reason: retired.append(reason))
        obj._record_success_and_maybe_recycle()
        assert retired and "RSS grew" in retired[0]

    def test_pick_port_env_and_ephemeral(self, monkeypatch):
        monkeypatch.setenv("IDA_MCP_RERANK_PORT", "12345")
        assert _stub_reranker()._pick_port() == 12345
        monkeypatch.delenv("IDA_MCP_RERANK_PORT")
        port = _stub_reranker()._pick_port()
        assert 1024 < port < 65536


# ---------------------------------------------------------------------------
# server start
# ---------------------------------------------------------------------------

class TestStartServer:
    def test_lock_translates_busy_to_rerank_timeout(self, monkeypatch):
        from ida_pro_mcp.host.intelligence import core as core_mod

        def _busy_enter(self):
            raise core_mod.EmbeddingQueueTimeout("embedding queue is busy")

        monkeypatch.setattr(core_mod._InterProcessLock, "__enter__", _busy_enter)
        with pytest.raises(rerank_mod.RerankQueueTimeout):
            rerank_mod._RerankInterProcessLock("/tmp/lease.lock", 1.0).__enter__()

    def test_start_server_returns_false_when_disabled(self, monkeypatch):
        obj = _stub_reranker()
        monkeypatch.setattr(rerank_mod, "_find_llama_server", lambda: "")
        monkeypatch.setattr(rerank_mod, "_find_rerank_model", lambda: "")
        monkeypatch.setattr(rerank_mod, "_read_rerank_state", dict)
        monkeypatch.setattr(rerank_mod, "_rerank_enabled", lambda: True)
        assert obj._start_server() is False
        assert obj._ready is False

    def test_start_server_lock_timeout_returns_false(self, monkeypatch):
        obj = _stub_reranker()

        class _BusyLock:
            def __init__(self, path, timeout):
                pass

            def __enter__(self):
                raise rerank_mod.RerankQueueTimeout("busy")

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(rerank_mod, "_RerankInterProcessLock", _BusyLock)
        assert obj._start_server() is False

    def test_start_server_locked_attaches_to_valid_lease(self, tmp_path, monkeypatch):
        lease_file = tmp_path / "lease.json"
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(lease_file))
        obj = _stub_reranker()
        monkeypatch.setattr(obj, "_read_lease", lambda: {"port": 4321})
        monkeypatch.setattr(obj, "_lease_matches", lambda lease: True)
        assert obj._start_server_locked() is True
        assert obj._port == 4321
        assert obj._ready is True
        assert obj._owns_proc is False

    def test_start_server_locked_spawns_process(self, tmp_path, monkeypatch):
        lease_file = tmp_path / "lease.json"
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(lease_file))
        model = tmp_path / "qwen3-reranker-0.6b-q8_0.gguf"
        model.write_bytes(b"m" * 64)
        obj = _stub_reranker(server_bin="/bin/echo", model_path=str(model), use_llama=True)
        monkeypatch.setattr(obj, "_read_lease", dict)
        monkeypatch.setattr(obj, "_pick_port", lambda: 9999)
        monkeypatch.setattr(rerank_mod.time, "sleep", lambda _s: None)

        proc = _FakeProc(pid=777)

        def _fake_popen(cmd, **kwargs):
            proc.cmd = cmd
            return proc

        monkeypatch.setattr(rerank_mod.subprocess, "Popen", _fake_popen)
        responses = [_FakeResp(b'{"status":"ok"}')]
        monkeypatch.setattr(
            rerank_mod.urllib.request, "urlopen",
            lambda req, timeout=2: responses.pop(0),
        )
        assert obj._start_server_locked() is True
        assert obj._ready is True
        assert obj._owns_proc is True
        assert "--rerank" in proc.cmd
        assert "--model" in proc.cmd and str(model) in proc.cmd
        assert "--parallel" in proc.cmd
        assert "--device" in proc.cmd
        lease = json.loads(lease_file.read_text())
        assert lease["pid"] == 777
        assert lease["port"] == 9999
        assert lease["schema"] == rerank_mod._RERANK_LEASE_SCHEMA

    def test_start_server_locked_retires_stale_lease(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(tmp_path / "lease.json"))
        obj = _stub_reranker()
        monkeypatch.setattr(obj, "_read_lease", lambda: {"schema": 1, "pid": 1})
        monkeypatch.setattr(obj, "_lease_matches", lambda lease: False)
        retired: list = []
        monkeypatch.setattr(obj, "_retire_lease_process", lambda lease, reason: retired.append(reason))
        monkeypatch.setattr(rerank_mod, "_find_llama_server", lambda: "")
        monkeypatch.setattr(rerank_mod, "_find_rerank_model", lambda: "")
        monkeypatch.setattr(rerank_mod, "_read_rerank_state", dict)
        assert obj._start_server_locked() is False
        assert retired == ["stale or incompatible rerank lease"]


# ---------------------------------------------------------------------------
# stop / ensure_ready
# ---------------------------------------------------------------------------

class TestStopAndReady:
    def test_stop_terminates_owned_proc_and_unlinks_lease(self, tmp_path, monkeypatch):
        lease_file = tmp_path / "lease.json"
        lease_file.write_text(json.dumps({"schema": 1, "pid": 777, "owner_pid": os.getpid()}))
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(lease_file))
        proc = _FakeProc(pid=777)
        obj = _stub_reranker(proc=proc, owns_proc=True, ready=True)
        obj.stop()
        assert proc.terminated is True
        assert obj._ready is False
        assert obj._proc is None
        assert obj._owns_proc is False
        assert not lease_file.exists()

    def test_stop_kills_leased_process_when_proc_unknown(self, tmp_path, monkeypatch):
        lease_file = tmp_path / "lease.json"
        lease_file.write_text(json.dumps({"schema": 1, "pid": 777, "owner_pid": os.getpid()}))
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(lease_file))
        killed: list = []
        monkeypatch.setattr(rerank_mod.os, "kill", lambda pid, sig: killed.append((pid, sig)))
        obj = _stub_reranker()
        obj.stop()
        assert (777, 15) in killed

    def test_stop_leaves_foreign_lease(self, tmp_path, monkeypatch):
        lease_file = tmp_path / "lease.json"
        lease_file.write_text(json.dumps({"schema": 1, "pid": 777, "owner_pid": 999999}))
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(lease_file))
        obj = _stub_reranker()
        obj.stop()
        assert lease_file.exists()

    def test_ensure_ready_schedules_activation_grace(self, monkeypatch):
        obj = _stub_reranker()
        monkeypatch.setattr(obj, "_start_server", lambda: True)
        scheduled: list = []
        monkeypatch.setattr(obj, "_schedule_idle_shutdown", lambda *a, **k: scheduled.append(a))
        assert obj.ensure_ready() is True
        assert scheduled == [(rerank_mod.EMBED_ACTIVATION_GRACE_TIMEOUT,)]


# ---------------------------------------------------------------------------
# request / response handling
# ---------------------------------------------------------------------------

class TestRequestRerank:
    def _ready(self, monkeypatch, lease_file: str) -> rerank_mod.Reranker:
        monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", lease_file)
        monkeypatch.setattr(rerank_mod, "_rerank_request_lock_path", lambda: lease_file + ".request.lock")
        obj = _stub_reranker(ready=True, port=1234, server_started_at=time.monotonic())
        monkeypatch.setattr(obj, "_record_success_and_maybe_recycle", lambda: None)
        monkeypatch.setattr(obj, "_schedule_idle_shutdown", lambda *a, **k: None)
        monkeypatch.setattr(obj, "_cancel_idle_shutdown", lambda: None)
        return obj

    def test_returns_none_when_not_ready_or_no_docs(self, monkeypatch):
        obj = _stub_reranker()
        assert obj._request_rerank("q", ["d"], timeout=1.0) is None
        obj2 = _stub_reranker(ready=True, port=1)
        assert obj2._request_rerank("q", [], timeout=1.0) is None

    def test_success_parses_and_sorts(self, tmp_path, monkeypatch):
        obj = self._ready(monkeypatch, str(tmp_path / "lease.json"))
        body: dict = {}

        def _fake_urlopen(req, timeout=2.0):
            body["data"] = json.loads(req.data.decode())
            assert req.get_header("Content-type") == "application/json"
            return _FakeResp(json.dumps({
                "results": [
                    {"index": 1, "relevance_score": 0.5},
                    {"index": 0, "relevance_score": 0.9},
                ]
            }).encode())

        monkeypatch.setattr(rerank_mod.urllib.request, "urlopen", _fake_urlopen)
        out = obj._request_rerank("query", ["a", "b"], timeout=2.0)
        assert out == [{"index": 0, "score": 0.9}, {"index": 1, "score": 0.5}]
        assert body["data"]["query"] == "query"
        assert body["data"]["documents"] == ["a", "b"]
        assert obj._consecutive_rpc_failures == 0

    def test_missing_results_returns_none_and_counts_failure(self, tmp_path, monkeypatch):
        obj = self._ready(monkeypatch, str(tmp_path / "lease.json"))
        monkeypatch.setattr(
            rerank_mod.urllib.request, "urlopen",
            lambda req, timeout=2.0: _FakeResp(b"{}"),
        )
        assert obj._request_rerank("q", ["a"], timeout=2.0) is None
        assert obj._consecutive_rpc_failures == 1

    def test_count_mismatch_returns_none(self, tmp_path, monkeypatch):
        obj = self._ready(monkeypatch, str(tmp_path / "lease.json"))
        monkeypatch.setattr(
            rerank_mod.urllib.request, "urlopen",
            lambda req, timeout=2.0: _FakeResp(json.dumps({
                "results": [{"index": 0, "relevance_score": 0.9}]
            }).encode()),
        )
        assert obj._request_rerank("q", ["a", "b"], timeout=2.0) is None

    def test_timeout_retires_lease_outside_grace(self, tmp_path, monkeypatch):
        obj = self._ready(monkeypatch, str(tmp_path / "lease.json"))
        obj._server_started_at = (
            time.monotonic() - rerank_mod.EMBED_ACTIVATION_GRACE_TIMEOUT - 1.0
        )
        retired: list = []
        monkeypatch.setattr(obj, "_retire_lease_process", lambda lease, reason: retired.append(reason))
        monkeypatch.setattr(obj, "_read_lease", lambda: {"pid": 1})

        def _timeout(req, timeout=2.0):
            raise TimeoutError("slow")

        monkeypatch.setattr(rerank_mod.urllib.request, "urlopen", _timeout)
        assert obj._request_rerank("q", ["a"], timeout=2.0) is None
        assert obj._last_batch_timeout is True
        assert retired == ["rerank request timeout"]

    def test_timeout_inside_grace_does_not_retire(self, tmp_path, monkeypatch):
        obj = self._ready(monkeypatch, str(tmp_path / "lease.json"))
        retired: list = []
        monkeypatch.setattr(obj, "_retire_lease_process", lambda lease, reason: retired.append(reason))
        monkeypatch.setattr(obj, "_read_lease", lambda: {"pid": 1})

        def _timeout(req, timeout=2.0):
            raise TimeoutError("slow")

        monkeypatch.setattr(rerank_mod.urllib.request, "urlopen", _timeout)
        assert obj._request_rerank("q", ["a"], timeout=2.0) is None
        assert retired == []

    def test_failures_flip_ready_false_at_threshold(self, tmp_path, monkeypatch):
        obj = self._ready(monkeypatch, str(tmp_path / "lease.json"))
        obj._max_rpc_failures = 2
        monkeypatch.setattr(
            rerank_mod.urllib.request, "urlopen",
            lambda req, timeout=2.0: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        assert obj._request_rerank("q", ["a"], timeout=2.0) is None
        assert obj._ready is True
        assert obj._request_rerank("q", ["a"], timeout=2.0) is None
        assert obj._ready is False
        assert obj._consecutive_rpc_failures == 0

    def test_busy_queue_returns_none_without_retiring(self, tmp_path, monkeypatch):
        """Regression: lock contention must not retire a healthy server."""
        obj = self._ready(monkeypatch, str(tmp_path / "lease.json"))

        class _BusyLock:
            def __init__(self, path, timeout):
                pass

            def __enter__(self):
                raise rerank_mod.RerankQueueTimeout("busy")

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(rerank_mod, "_RerankInterProcessLock", _BusyLock)
        retired: list = []
        monkeypatch.setattr(obj, "_retire_lease_process", lambda lease, reason: retired.append(reason))
        assert obj._request_rerank("q", ["a"], timeout=2.0) is None
        assert retired == []
        assert obj._consecutive_rpc_failures == 0
        assert obj._ready is True


class TestRerankPublic:
    def test_returns_none_when_disabled_and_not_ready(self):
        obj = _stub_reranker(use_llama=False)
        assert obj.rerank("q", ["a"]) is None

    def test_auto_recovers_when_not_ready(self, monkeypatch):
        obj = _stub_reranker(use_llama=True)
        monkeypatch.setattr(obj, "ensure_ready", lambda: True)
        monkeypatch.setattr(obj, "_request_rerank", lambda q, part, timeout=None: [{"index": 0, "score": 0.9}])
        assert obj.rerank("q", ["a"]) == [{"index": 0, "score": 0.9}]

    def test_chunks_and_offsets_indices(self, monkeypatch):
        obj = _stub_reranker(ready=True)
        monkeypatch.setattr(rerank_mod, "RERANK_CHUNK_SIZE", 2)
        responses = iter([
            [{"index": 0, "score": 0.1}, {"index": 1, "score": 0.9}],
            [{"index": 0, "score": 0.7}, {"index": 1, "score": 0.3}],
        ])
        parts: list = []
        monkeypatch.setattr(
            obj, "_request_rerank",
            lambda q, part, timeout=None: parts.append(part) or next(responses),
        )
        out = obj.rerank("q", ["d0", "d1", "d2", "d3"])
        assert parts == [["d0", "d1"], ["d2", "d3"]]
        assert [x["index"] for x in out] == [1, 2, 3, 0]

    def test_top_k_applied(self, monkeypatch):
        obj = _stub_reranker(ready=True)
        monkeypatch.setattr(rerank_mod, "RERANK_CHUNK_SIZE", 8)
        monkeypatch.setattr(
            obj, "_request_rerank",
            lambda q, part, timeout=None: [{"index": 0, "score": 0.5}, {"index": 1, "score": 0.9}],
        )
        out = obj.rerank("q", ["a", "b"], top_k=1)
        assert out == [{"index": 1, "score": 0.9}]

    def test_chunk_failure_returns_none(self, monkeypatch):
        obj = _stub_reranker(ready=True)
        monkeypatch.setattr(rerank_mod, "RERANK_CHUNK_SIZE", 1)
        responses = iter([[{"index": 0, "score": 0.9}], None])
        monkeypatch.setattr(
            obj, "_request_rerank",
            lambda q, part, timeout=None: next(responses),
        )
        assert obj.rerank("q", ["a", "b"]) is None
