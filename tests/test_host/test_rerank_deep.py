from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.host.intelligence import core as core_mod, rerank as rerank_mod, rerank_profiles
from ida_pro_mcp.host.intelligence.core import write_embedder_state
from ida_pro_mcp.host.intelligence.rerank import (
    Reranker,
    _find_rerank_model,
    _read_rerank_state,
    _rerank_enabled,
    _scan_bases,
)


class _FakeProc:
    def __init__(self, pid: int = 12345, poll_result: int | None = None) -> None:
        self.pid = pid
        self._poll = poll_result
        self.terminated = False
        self.killed = False
        self.waited: list[float | None] = []

    def poll(self) -> int | None:
        return self._poll

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float | None = None) -> int:
        self.waited.append(timeout)
        if self.waited.count(timeout) == 1 and timeout == 5:
            import subprocess

            raise subprocess.TimeoutExpired(cmd="llama-server", timeout=timeout)
        return 0


class _FakeResp:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._data


def _stub_reranker(**attrs: object) -> rerank_mod.Reranker:
    obj = object.__new__(rerank_mod.Reranker)
    obj._server_bin = "/mock/bin/llama-server"
    obj._model_path = "/mock/models/rerank.gguf"
    obj._profile = rerank_profiles.QWEN3_RERANKER_0_6B
    obj._port = 8089
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
    obj._server_started_at = time.monotonic() - 3600.0
    obj._idle_lock = threading.Lock()
    obj._idle_timer = None
    obj._idle_generation = 0
    obj._score_cache = {}
    obj._score_cache_lock = threading.Lock()
    obj._score_inflight = {}
    obj._ctx = 1024
    for key, value in attrs.items():
        setattr(obj, key if key.startswith("_") else f"_{key}", value)
    return obj


@pytest.fixture(autouse=True)
def _fresh_reranker_singleton():
    """Keep this module's environment-sensitive singleton per-test."""
    Reranker._instance = None
    yield
    instance = Reranker._instance
    if instance is not None:
        with contextlib.suppress(Exception):
            instance.stop()
    Reranker._instance = None


def test_rerank_state_read_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_PRO_MCP_HOME", str(tmp_path))
    write_embedder_state(
        tmp_path,
        rerank={
            "model_path": "/path/to/rerank.gguf",
            "profile": "qwen3-reranker-0.6b",
        },
    )

    read_back = _read_rerank_state()
    assert read_back.get("model_path") == "/path/to/rerank.gguf"
    assert read_back.get("profile") == "qwen3-reranker-0.6b"


def test_find_rerank_model(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_model = tmp_path / "rerank_qwen.gguf"
    fake_model.write_bytes(b"GGUF")

    monkeypatch.setenv("IDA_MCP_RERANK_MODEL", str(fake_model))
    found = _find_rerank_model()
    assert found == str(fake_model)


def test_reranker_disabled_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_MCP_RERANK_DISABLED", "1")
    reranker = Reranker()
    status = reranker.status()
    assert status.get("ready") is False

    # Calling rerank on disabled backend returns un-reranked items or None
    res = reranker.rerank("find main", ["doc A", "doc B"])
    assert res is None or res == []


def test_rerank_enabled_configured_strings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IDA_MCP_RERANK_DISABLED", raising=False)
    monkeypatch.delenv("IDA_MCP_RERANK_ENABLED", raising=False)

    monkeypatch.setattr(rerank_mod, "_read_rerank_state", lambda: {"enabled": "yes"})
    assert _rerank_enabled() is True

    monkeypatch.setattr(rerank_mod, "_read_rerank_state", lambda: {"enabled": "off"})
    assert _rerank_enabled() is False

    monkeypatch.setattr(rerank_mod, "_read_rerank_state", lambda: {"enabled": "unknown_val"})
    assert _rerank_enabled() is True


def test_find_rerank_model_variations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IDA_MCP_RERANK_MODEL", raising=False)
    monkeypatch.setattr(rerank_mod, "_read_rerank_state", dict)

    def _exploding_expandvars(val: str) -> str:
        if "bad" in val:
            raise RuntimeError("expansion failed")
        return os.path.expandvars(val)

    monkeypatch.setenv("IDA_MCP_RERANK_MODEL", "   ; ; bad_var ; /does/not/exist.gguf ")
    monkeypatch.setattr(os.path, "expandvars", _exploding_expandvars)
    assert _find_rerank_model() == ""

    monkeypatch.delenv("IDA_MCP_RERANK_MODEL", raising=False)
    mock_found = tmp_path / "model.gguf"
    mock_found.write_bytes(b"GGUF")
    monkeypatch.setattr(rerank_mod, "_scan_bases", lambda bases, pats: str(mock_found))
    assert _find_rerank_model() == str(mock_found)

    monkeypatch.setattr(rerank_mod, "_scan_bases", lambda bases, pats: "")
    mock_fallback = tmp_path / "bge_reranker.gguf"
    mock_fallback.write_bytes(b"GGUF")

    orig_glob = rerank_mod.glob.glob

    def _custom_glob(pattern: str) -> list[str]:
        if "models--" in pattern:
            return []
        if pattern.endswith((".gguf", "*")):
            return [str(mock_fallback)]
        return orig_glob(pattern)

    monkeypatch.setattr(rerank_mod.glob, "glob", _custom_glob)
    assert _find_rerank_model() == str(mock_fallback)

    hf_dir = tmp_path / ".cache" / "huggingface" / "hub"
    hf_dir.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    def _hf_glob(pattern: str) -> list[str]:
        if "snapshots" in pattern:
            return [str(mock_fallback)]
        return []

    monkeypatch.setattr(rerank_mod.glob, "glob", _hf_glob)
    assert _find_rerank_model() == str(mock_fallback)


def test_scan_bases_details(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f1 = tmp_path / "qwen_q4.gguf"
    f1.write_bytes(b"1")
    f2 = tmp_path / "qwen_q8.gguf"
    f2.write_bytes(b"2")

    bases = ["", str(tmp_path), str(tmp_path)]
    patterns = ("*.gguf",)

    found = _scan_bases(bases, patterns)
    assert found in (str(f1), str(f2))

    monkeypatch.setattr(
        core_mod,
        "_model_quant_rank",
        MagicMock(side_effect=RuntimeError("rank failure")),
    )
    found2 = _scan_bases([str(tmp_path)], patterns)
    assert found2 != ""

    orig_abspath = os.path.abspath

    def _failing_abspath(p: str) -> str:
        if str(f1) in p:
            raise RuntimeError("cannot resolve")
        return orig_abspath(p)

    monkeypatch.setattr(os.path, "abspath", _failing_abspath)
    found3 = _scan_bases([str(tmp_path)], patterns)
    assert found3 == str(f2)


def test_reranker_native_routing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_native_reranker = MagicMock()
    fake_native_cls = MagicMock(return_value=fake_native_reranker)
    fake_native_cls.reset = MagicMock(return_value=fake_native_reranker)

    fake_module = MagicMock()
    fake_module.NativeReranker = fake_native_cls
    fake_module.prefer_native_rerank = MagicMock(return_value=True)

    monkeypatch.setitem(sys.modules, "ida_pro_mcp.host.intelligence.native", fake_module)

    res = Reranker()
    assert res is fake_native_reranker

    res_reset = Reranker.reset("/custom/model.gguf")
    assert res_reset is fake_native_reranker
    fake_native_cls.reset.assert_called_with("/custom/model.gguf")


def test_reranker_server_json_and_lease_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    reranker = _stub_reranker()

    monkeypatch.setattr(
        rerank_mod.urllib.request,
        "urlopen",
        lambda url, timeout=2.0: _FakeResp(b'{"status": "ok"}'),
    )
    data = reranker._server_json(8089, "/health")
    assert data == {"status": "ok"}

    assert reranker._lease_matches(None) is False
    assert reranker._lease_matches("not a dict") is False

    lease = {
        "schema": rerank_mod._RERANK_LEASE_SCHEMA,
        "pid": os.getpid(),
        "owner_pid": os.getpid(),
        "port": 8089,
        "owner_start_token": "token_A",
    }
    monkeypatch.setattr(rerank_mod, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(rerank_mod, "_process_start_token", lambda pid: "token_B")
    assert reranker._lease_matches(lease) is False

    monkeypatch.setattr(rerank_mod, "_process_start_token", lambda pid: "token_A")
    lease["process_start_token"] = "token_A"
    identity = reranker._lease_identity()
    lease.update(identity)

    def _mock_server_json(port: int, endpoint: str) -> dict[str, str]:
        if endpoint == "health":
            return {"status": "ok"}
        return {"model_path": "/different/served.gguf"}

    monkeypatch.setattr(reranker, "_server_json", _mock_server_json)
    assert reranker._lease_matches(lease) is False

    def _exploding_server_json(port: int, endpoint: str) -> dict[str, str]:
        raise RuntimeError("network down")

    monkeypatch.setattr(reranker, "_server_json", _exploding_server_json)
    assert reranker._lease_matches(lease) is False


def test_pid_is_expected_server_start_token(monkeypatch: pytest.MonkeyPatch) -> None:
    reranker = _stub_reranker()
    monkeypatch.setattr(rerank_mod, "_process_command", lambda pid: "llama-server --rerank")
    monkeypatch.setattr(rerank_mod, "_process_start_token", lambda pid: "proc_tok_1")

    lease = {"process_start_token": "proc_tok_2"}
    assert reranker._pid_is_expected_server(1234, lease) is False


def test_retire_lease_process_invalid_pid() -> None:
    reranker = _stub_reranker()
    reranker._retire_lease_process({"pid": "not_an_int"}, "testing invalid pid")


def test_idle_shutdown_timer_and_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    reranker = _stub_reranker()
    reranker._ready = True

    reranker._schedule_idle_shutdown(timeout=10.0)
    timer1 = reranker._idle_timer
    assert timer1 is not None

    reranker._schedule_idle_shutdown(timeout=10.0)
    timer2 = reranker._idle_timer
    assert timer2 is not None
    assert timer2 is not timer1

    timer2.cancel()

    reranker._idle_lock = None
    reranker._shutdown_if_idle(1)


def test_start_server_locked_edge_cases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reranker = _stub_reranker()

    reranker._ready = True
    assert reranker._start_server_locked() is True
    reranker._ready = False

    monkeypatch.setattr(time, "sleep", lambda s: None)
    reranker._use_llama = True
    monkeypatch.setattr(reranker, "_read_lease", lambda: None)

    monkeypatch.setenv("IDA_MCP_RERANK_GPU", "1")
    monkeypatch.setattr(rerank_mod, "_detect_gpu_device", lambda s: "cuda:0")

    fake_proc = _FakeProc(pid=55555, poll_result=None)
    monkeypatch.setattr(rerank_mod.subprocess, "Popen", lambda *args, **kwargs: fake_proc)
    reranker._stop_registered = False

    monkeypatch.setattr(
        rerank_mod.urllib.request,
        "urlopen",
        lambda url, timeout=2: _FakeResp(b'{"status":"ok"}'),
    )

    monkeypatch.setattr(
        reranker,
        "_write_lease",
        MagicMock(side_effect=RuntimeError("disk full")),
    )

    started = reranker._start_server_locked()
    assert started is True
    assert reranker._stop_registered is True
    assert reranker._ready is True

    # 3. Process poll exits prematurely -> aborts
    reranker._ready = False
    fake_proc_dead = _FakeProc(pid=55556, poll_result=1)
    monkeypatch.setattr(rerank_mod.subprocess, "Popen", lambda *args, **kwargs: fake_proc_dead)
    monkeypatch.setattr(
        rerank_mod.urllib.request,
        "urlopen",
        MagicMock(side_effect=OSError("connection refused")),
    )
    failed = reranker._start_server_locked()
    assert failed is False

    # 4. Loop times out while proc is still running -> abandons server
    fake_proc_hanging = _FakeProc(pid=55557, poll_result=None)
    monkeypatch.setattr(rerank_mod.subprocess, "Popen", lambda *args, **kwargs: fake_proc_hanging)
    # Advance time quickly
    curr_time = 100.0

    def _fast_time():
        nonlocal curr_time
        curr_time += 1000.0
        return curr_time

    monkeypatch.setattr(time, "time", _fast_time)

    abandoned = False

    def _mock_abandon(reason: str) -> None:
        nonlocal abandoned
        abandoned = True

    monkeypatch.setattr(reranker, "_abandon_owned_server", _mock_abandon)
    failed2 = reranker._start_server_locked()
    assert failed2 is False
    assert abandoned is True


def test_stop_edge_cases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reranker = _stub_reranker()
    reranker._owns_proc = True

    fake_proc = _FakeProc(pid=99999, poll_result=None)
    reranker._proc = fake_proc

    lease_file = tmp_path / "rerank_lease.json"
    lease_file.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(lease_file))

    reranker.stop()
    assert fake_proc.terminated is True
    assert fake_proc.killed is True

    fake_proc_dead = _FakeProc(pid=99998, poll_result=0)
    reranker._owns_proc = True
    reranker._proc = fake_proc_dead
    reranker.stop()
    assert reranker._proc is None

    valid_lease = {
        "schema": rerank_mod._RERANK_LEASE_SCHEMA,
        "pid": 88888,
        "owner_pid": os.getpid(),
        "owner_start_token": "token1",
    }
    lease_file.write_text(json.dumps(valid_lease), encoding="utf-8")
    monkeypatch.setattr(rerank_mod, "_process_start_token", lambda pid: "token1")
    monkeypatch.setattr(reranker, "_pid_is_expected_server", lambda pid, lease: True)

    killed_signals: list[int] = []

    def _mock_kill(pid: int, sig: int) -> None:
        killed_signals.append(sig)

    monkeypatch.setattr(os, "kill", _mock_kill)
    monkeypatch.setattr(rerank_mod, "_pid_alive", lambda pid: False)
    monkeypatch.setattr(reranker, "_read_lease", lambda: valid_lease)

    monkeypatch.setattr(os, "unlink", MagicMock(side_effect=OSError("permission denied")))

    reranker._proc = None
    reranker.stop()
    assert 15 in killed_signals


def test_reranker_dim() -> None:
    reranker = _stub_reranker()
    assert reranker.dim == 0


def test_scan_bases_seen_duplicate(tmp_path: Path) -> None:
    non_file = str(tmp_path / "non_file.gguf")
    with patch.object(rerank_mod.glob, "glob", return_value=[non_file, non_file]):
        found = _scan_bases([str(tmp_path)], ("*.gguf",))
        assert found == ""


def test_reranker_native_exception_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_module = MagicMock()
    fake_module.prefer_native_rerank = MagicMock(side_effect=RuntimeError("native err"))
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.host.intelligence.native", fake_module)

    r = Reranker()
    assert isinstance(r, Reranker)
    r_reset = Reranker.reset()
    assert isinstance(r_reset, Reranker)


def test_find_rerank_model_fallback_loops(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IDA_MCP_RERANK_MODEL", raising=False)
    monkeypatch.setattr(rerank_mod, "_read_rerank_state", dict)
    monkeypatch.setattr(rerank_mod, "_scan_bases", lambda bases, pats: "")
    monkeypatch.setattr(rerank_mod, "_install_root", lambda: "")

    valid_file = tmp_path / "valid.gguf"
    valid_file.write_bytes(b"GGUF")

    orig_abspath = os.path.abspath

    def _failing_abspath(p: str) -> str:
        if "bad_abspath" in p:
            raise RuntimeError("abspath failed")
        return orig_abspath(p)

    monkeypatch.setattr(os.path, "abspath", _failing_abspath)

    mock_candidates = ["/bad_abspath", "/not_file_xyz", str(valid_file)]
    call_count = 0

    def _selective_glob(pattern: str) -> list[str]:
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            return []
        return mock_candidates

    with patch.object(rerank_mod.glob, "glob", _selective_glob):
        found = _find_rerank_model()
        assert found == str(valid_file)

    # 2. Test fallback loop in HF cache when bases find nothing
    hf_dir = tmp_path / ".cache" / "huggingface" / "hub"
    hf_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    fake_empty_prof = MagicMock()
    fake_empty_prof.filename_patterns = ()
    real_bge = rerank_profiles.BGE_RERANKER_V2_M3

    def _hf_glob_fallback(pattern: str) -> list[str]:
        if "snapshots" in pattern and "bge" in pattern:
            return [str(valid_file)]
        return []

    with patch.object(
        rerank_mod,
        "RERANK_MODEL_PROFILES",
        {"empty_prof": fake_empty_prof, "bge": real_bge},
    ), patch.object(rerank_mod.glob, "glob", _hf_glob_fallback):
        found2 = _find_rerank_model()
        assert found2 == str(valid_file)


def test_retire_lease_process_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    reranker = _stub_reranker()
    monkeypatch.setattr(rerank_mod, "_lease_pid", MagicMock(side_effect=ValueError("bad pid")))
    reranker._retire_lease_process({"pid": "anything"}, "test")


def test_start_server_locked_gpu_device_none(monkeypatch: pytest.MonkeyPatch) -> None:
    reranker = _stub_reranker(_use_llama=True)
    monkeypatch.setattr(reranker, "_read_lease", lambda: None)
    monkeypatch.setenv("IDA_MCP_RERANK_GPU", "1")
    monkeypatch.setattr(rerank_mod, "_detect_gpu_device", lambda s: "")

    fake_proc = _FakeProc(pid=55555, poll_result=None)
    captured_cmd: list[str] = []

    def _mock_popen(cmd, *args, **kwargs):
        captured_cmd.extend(cmd)
        return fake_proc

    monkeypatch.setattr(rerank_mod.subprocess, "Popen", _mock_popen)
    monkeypatch.setattr(
        rerank_mod.urllib.request,
        "urlopen",
        lambda url, timeout=2: _FakeResp(b'{"status":"ok"}'),
    )
    monkeypatch.setattr(time, "sleep", lambda s: None)

    assert reranker._start_server_locked() is True
    assert "--device" in captured_cmd
    idx = captured_cmd.index("--device")
    assert captured_cmd[idx + 1] == "none"


def test_stop_proc_kill_wait_exception(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reranker = _stub_reranker(_owns_proc=True)

    class _StubbornProc(_FakeProc):
        def wait(self, timeout: float | None = None) -> int:
            self.waited.append(timeout)
            raise RuntimeError("wait failed")

    stubborn_proc = _StubbornProc(pid=99991, poll_result=None)
    reranker._proc = stubborn_proc
    reranker.stop()
    assert stubborn_proc.killed is True


def test_stop_os_kill_branches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reranker = _stub_reranker()

    valid_lease = {
        "schema": rerank_mod._RERANK_LEASE_SCHEMA,
        "pid": 88889,
        "owner_pid": os.getpid(),
        "owner_start_token": "token1",
    }
    monkeypatch.setattr(rerank_mod, "_process_start_token", lambda pid: "token1")
    monkeypatch.setattr(reranker, "_pid_is_expected_server", lambda pid, lease: True)
    monkeypatch.setattr(reranker, "_read_lease", lambda: valid_lease)

    lease_file = tmp_path / "rerank_lease.json"
    lease_file.write_text(json.dumps(valid_lease), encoding="utf-8")
    monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(lease_file))

    # 1. os.kill(pid, 0) raises OSError -> breaks out of wait loop
    def _kill_os_err_on_zero(pid: int, sig: int) -> None:
        if sig == 0:
            raise OSError("no such process")

    monkeypatch.setattr(os, "kill", _kill_os_err_on_zero)
    reranker._proc = None
    reranker.stop()


def test_stop_os_kill_timeout_and_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reranker = _stub_reranker()

    valid_lease = {
        "schema": rerank_mod._RERANK_LEASE_SCHEMA,
        "pid": 88889,
        "owner_pid": os.getpid(),
        "owner_start_token": "token1",
    }
    monkeypatch.setattr(rerank_mod, "_process_start_token", lambda pid: "token1")
    monkeypatch.setattr(reranker, "_pid_is_expected_server", lambda pid, lease: True)
    monkeypatch.setattr(reranker, "_read_lease", lambda: valid_lease)

    lease_file = tmp_path / "rerank_lease2.json"
    lease_file.write_text(json.dumps(valid_lease), encoding="utf-8")
    monkeypatch.setattr(rerank_mod, "RERANK_LEASE_FILE", str(lease_file))

    def _kill_os_err_on_nine(pid: int, sig: int) -> None:
        if sig == 9:
            raise OSError("permission denied on kill 9")

    curr_mono = 100.0

    def _advancing_mono() -> float:
        nonlocal curr_mono
        curr_mono += 5.0
        return curr_mono

    monkeypatch.setattr(time, "monotonic", _advancing_mono)
    monkeypatch.setattr(os, "kill", _kill_os_err_on_nine)
    reranker._proc = None
    reranker.stop()


def test_request_rerank_cached_branches() -> None:
    reranker = _stub_reranker()

    assert reranker._request_rerank_cached("test", [], timeout=2.0) == []

    class _ExplodingCache(dict):
        def pop(self, *args, **kwargs):
            raise RuntimeError("pop failed")

    monkeypatch_cache_max = 1
    with patch.object(rerank_mod, "RERANK_CACHE_MAX", monkeypatch_cache_max):
        reranker._score_cache = _ExplodingCache({"k1": [{"index": 0, "score": 0.5}]})
        with patch.object(
            reranker,
            "_request_rerank",
            return_value=[{"index": 0, "score": 0.9}],
        ):
            res = reranker._request_rerank_cached("q_new", ["doc_new"], timeout=1.0)
            assert res == [{"index": 0, "score": 0.9}]


def test_rerank_ensure_ready_failure() -> None:
    reranker = _stub_reranker(_ready=False, _use_llama=True)
    with patch.object(reranker, "ensure_ready", return_value=False):
        res = reranker.rerank("query", ["doc1", "doc2"])
        assert res is None
