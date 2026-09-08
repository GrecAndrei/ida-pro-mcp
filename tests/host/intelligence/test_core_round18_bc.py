"""Round 18 group B/C gap closure for intelligence core (offline, deterministic).

Every test maps to one or more coverage gaps in
``src/ida_pro_mcp/host/intelligence/core.py``.  Idioms follow
``test_core_remaining_modes.py`` / ``test_core_runtime_modes.py``: stub
embedders via ``object.__new__``, ``tmp_path``, ``monkeypatch``; no real
servers, models, network, IDA, or timing-dependent threads.  Imports are
faked by intercepting ``builtins.__import__`` (never ``sys.modules``).
"""

from __future__ import annotations

import json
import os
from types import SimpleNamespace

from ida_pro_mcp.host.intelligence import core
from tests.host.intelligence.test_core_runtime_modes import (
    _embedder,
    _Process,
    _Response,
)

# ── _find_model discovery gaps ──────────────────────────────────────────────
# Lines 653 (empty base, main loop), 662-663 (abspath failure, main loop),
# 674->685 (no HF cache dir), 688 (empty base, legacy fallback),
# 695-696 (abspath failure, legacy fallback), 697->692 (isfile miss, fallback).


def _reset_find_model(monkeypatch, tmp_path, *, project_root, profile=None):
    """Pin _find_model inputs to empty state/cache for deterministic tests."""
    monkeypatch.setattr(core, "_MODEL_PATH_CACHE", None)
    monkeypatch.setattr(core, "_read_embedder_state", dict)
    monkeypatch.delenv("IDA_MCP_EMBED_MODEL", raising=False)
    if profile is None:
        monkeypatch.delenv("IDA_MCP_EMBED_PROFILE", raising=False)
    else:
        monkeypatch.setenv("IDA_MCP_EMBED_PROFILE", profile)
    monkeypatch.setattr(core, "_install_root", lambda: str(tmp_path))
    monkeypatch.setattr(core, "_PROJECT_ROOT", project_root)
    monkeypatch.setattr(
        core.Path, "home", classmethod(lambda cls: tmp_path)
    )


def test_find_model_skips_empty_bases_abspath_failures_and_legacy_fallback(
    monkeypatch, tmp_path
):
    # _PROJECT_ROOT="" exercises `if not base: continue` in both the main
    # loop (653) and the legacy-fallback loop (688).
    _reset_find_model(
        monkeypatch, tmp_path, project_root="", profile="qwen3-embedding-0.6b"
    )
    legacy = tmp_path / "legacy-fallback-model.gguf"
    legacy.write_bytes(b"model")

    def fake_glob(pattern):
        if "models--" in pattern:
            return []
        if "bge-code-v1" in pattern:
            return [
                "bad-fallback-entry",
                str(tmp_path / "no-such-file.gguf"),
                str(legacy),
            ]
        return ["bad-main-entry"]

    monkeypatch.setattr(core, "glob", SimpleNamespace(glob=fake_glob))
    orig_abspath = os.path.abspath

    def fake_abspath(path):
        if "bad-" in str(path):
            raise OSError("unresolvable candidate")
        return orig_abspath(path)

    monkeypatch.setattr(core.os.path, "abspath", fake_abspath)
    # Home has no huggingface hub cache, so the HF directory check fails and
    # discovery falls through to the legacy fallback.
    found = core._find_model()
    assert found == orig_abspath(str(legacy))


def test_find_model_hf_snapshot_skips_missing_file(monkeypatch, tmp_path):
    # HF glob yields a missing entry first: `os.path.isfile` is False so the
    # loop iterates again (677->674) before hitting the real snapshot file.
    _reset_find_model(monkeypatch, tmp_path, project_root=str(tmp_path))
    snap_dir = tmp_path / ".cache" / "huggingface" / "hub" / "models--qwen" / "snapshots" / "rev1"
    snap_dir.mkdir(parents=True)
    real = snap_dir / "Qwen3-Embedding-0.6B-Q8_0.gguf"
    real.write_bytes(b"model")
    missing = snap_dir / "Qwen3-Embedding-0.6B-Q4_K_M.gguf"

    def fake_glob(pattern):
        if "models--" in pattern:
            return [str(missing), str(real)]
        return []

    monkeypatch.setattr(core, "glob", SimpleNamespace(glob=fake_glob))
    assert core._find_model() == os.path.abspath(str(real))


def test_find_model_skips_empty_hf_snapshot_dir(monkeypatch, tmp_path):
    # hf_root exists but the snapshot glob matches nothing, so the loop body
    # never runs (674->685) and discovery falls through to "" here.
    _reset_find_model(monkeypatch, tmp_path, project_root=str(tmp_path))
    (tmp_path / ".cache" / "huggingface" / "hub").mkdir(parents=True)
    monkeypatch.setattr(core, "glob", SimpleNamespace(glob=lambda _pattern: []))
    assert core._find_model() == ""


# ── small helper gaps ───────────────────────────────────────────────────────
# 752->759 (_available_cpu_count without sched_getaffinity),
# 835 (_pid_alive True), 878->883 (no VmRSS line), 944 (empty chunk),
# 976 (max_idents early return).


def test_available_cpu_count_without_affinity(monkeypatch):
    monkeypatch.delattr(core.os, "sched_getaffinity", raising=False)
    assert core._available_cpu_count() == max(1, os.cpu_count() or 1)


def test_pid_alive_reports_listening_process(monkeypatch):
    monkeypatch.setattr(core.os, "kill", lambda _pid, _sig: None)
    assert core._pid_alive(1234) is True  # line 835

    def gone(_pid, _sig):
        raise OSError("no such process")

    monkeypatch.setattr(core.os, "kill", gone)
    assert core._pid_alive(1234) is False
    assert core._pid_alive(0) is False


def test_process_rss_bytes_without_vmrss_line(monkeypatch):
    class _Status:
        def __init__(self, *_args, **_kwargs):
            pass

        def read_text(self, *_args, **_kwargs):
            return "Name:\tbash\nState:\tR (running)\n"

    monkeypatch.setattr(core, "Path", _Status)
    # The status loop exhausts without finding VmRSS (878->883).
    assert core._process_rss_bytes(4321) == 0


def test_identifier_terms_skips_empty_chunks():
    assert core._identifier_terms("") == []  # line 944
    assert core._identifier_terms("__") == []


def test_extract_signature_returns_at_budget():
    # max_idents=1 forces the early `return " ".join(out)` at line 976.
    assert core._extract_signature("alpha_second third_fourth", max_idents=1) == "alpha"


# ── _InterProcessLock gaps: 917 (contended retry) and 921 (exit w/o handle) ──


def test_interprocess_lock_retries_then_acquires(monkeypatch, tmp_path):
    import builtins

    real_import = builtins.__import__
    real_fcntl = real_import("fcntl")
    attempts = {"count": 0}

    class _FakeFcntl:
        LOCK_EX = real_fcntl.LOCK_EX
        LOCK_NB = real_fcntl.LOCK_NB
        LOCK_UN = real_fcntl.LOCK_UN

        def flock(self, _fd, _flags):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise BlockingIOError("busy")

    fake_fcntl = _FakeFcntl()

    def fake_import(name, *args, **kwargs):
        if name == "fcntl":
            return fake_fcntl
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(core.time, "sleep", lambda _seconds: None)
    lock = core._InterProcessLock(str(tmp_path / "queue.lock"), timeout=5.0)
    with lock:
        assert lock.handle is not None  # line 917 ran on the first attempt
    assert lock.handle is None
    assert attempts["count"] >= 2


def test_interprocess_lock_exit_without_handle(tmp_path):
    lock = core._InterProcessLock(str(tmp_path / "never.lock"), timeout=0.0)
    assert lock.__exit__(None, None, None) is False  # line 921


# ── BgeCodeEmbedder.__new__ gaps ────────────────────────────────────────────
# 1035->1043 (subclass skips native routing), 1040-1042 (native hit + failure).


def test_new_skips_native_routing_for_subclass(monkeypatch):
    inited = []

    def record_init(self):
        inited.append(self)

    monkeypatch.setattr(core.BgeCodeEmbedder, "_init", record_init)

    class Sub(core.BgeCodeEmbedder):
        _instance = None

    obj = Sub.__new__(Sub)  # 1035->1043: cls is not BgeCodeEmbedder
    assert isinstance(obj, core.BgeCodeEmbedder)
    assert inited == [obj]
    assert Sub._instance is obj


def test_new_native_backend_routing(monkeypatch):
    import builtins

    real_import = builtins.__import__
    sentinel = object()
    state = {"prefer": True}

    def fake_import(name, *args, **kwargs):
        if isinstance(name, str) and name.endswith("native"):
            if not state["prefer"]:
                raise ImportError("no native backend")
            return SimpleNamespace(
                NativeEmbedder=lambda: sentinel,
                prefer_native_embed=lambda: True,
            )
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    # Native preferred: __new__ returns the native embedder (line 1040).
    assert core.BgeCodeEmbedder.__new__(core.BgeCodeEmbedder) is sentinel

    # Native import failure is swallowed (1041-1042); with a preset instance
    # the lock path returns it without running _init.
    state["prefer"] = False
    marker = object()
    monkeypatch.setattr(core.BgeCodeEmbedder, "_instance", marker)
    assert core.BgeCodeEmbedder.__new__(core.BgeCodeEmbedder) is marker


# ── status() lease-probe gaps ───────────────────────────────────────────────
# 1155->1168 (lease without usable port), 1159->1168 (unhealthy lease
# server), 1165-1166 (lease probe raises).


def _lease_status_embedder(tmp_path, lease):
    obj = _embedder(tmp_path, ready=True, use_llama=False)
    obj._port = None
    lease_file = tmp_path / "embed-lease.json"
    lease_file.write_text(json.dumps(lease), encoding="utf-8")
    return obj, lease_file


def test_status_probe_lease_without_port(monkeypatch, tmp_path):
    obj, lease_file = _lease_status_embedder(tmp_path, {"port": 0})
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(lease_file))
    result = obj.status(probe=True)  # 1155->1168
    assert result["ready"] is True
    assert result["probe_error"] == ""


def test_status_probe_lease_server_not_healthy(monkeypatch, tmp_path):
    obj, lease_file = _lease_status_embedder(tmp_path, {"port": 19111})
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(lease_file))
    monkeypatch.setattr(
        core.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b'{"status":"loading"}'),
    )
    result = obj.status(probe=True)  # 1159->1168
    assert result["ready"] is True
    assert result["probe_error"] == ""


def test_status_probe_lease_error_is_recorded(monkeypatch, tmp_path):
    obj, lease_file = _lease_status_embedder(tmp_path, {"port": 19112})
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(lease_file))

    def gone(*_args, **_kwargs):
        raise OSError("lease server down")

    monkeypatch.setattr(core.urllib.request, "urlopen", gone)
    result = obj.status(probe=True)  # lines 1165-1166
    assert result["probe_error"] == "lease server down"


# ── _lease_matches tail gaps: 1293-1295 ─────────────────────────────────────


def _matching_lease(tmp_path):
    identity = {
        "profile": core.BGE_CODE_V1.key,
        "dimension": 2,
        "model_path": str(tmp_path / "model.gguf"),
        "server_path": str(tmp_path / "llama-server"),
    }
    lease = {
        "schema": 2,
        "pid": 11,
        "owner_pid": 12,
        "port": 18000,
        "process_start_token": "proc",
        "owner_start_token": "owner",
        **identity,
    }
    return identity, lease


def test_lease_matches_rejects_model_mismatch_and_probe_error(
    monkeypatch, tmp_path
):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    identity, lease = _matching_lease(tmp_path)
    obj._lease_identity = lambda: dict(identity)
    monkeypatch.setattr(core, "_pid_alive", lambda _pid: True)
    monkeypatch.setattr(
        core, "_process_start_token", lambda pid: "proc" if pid == 11 else "owner"
    )

    def mismatch(port, endpoint):
        if endpoint == "health":
            return {"status": "ok"}
        return {"model_path": "/elsewhere/other.gguf"}

    obj._server_json = mismatch
    assert obj._lease_matches(lease) is False  # lines 1292-1293

    def failing(_port, _endpoint):
        raise OSError("probe gone")

    obj._server_json = failing
    assert obj._lease_matches(lease) is False  # lines 1294-1295


# ── _retire_lease_process gaps ──────────────────────────────────────────────
# 1318-1319 (pid parse raises), 1328-1329 (SIGKILL escalation),
# 1334->1336 (foreign lease left in place).


class _BadPidLease(dict):
    def get(self, key, default=None):  # noqa: ANN001, ANN202
        raise TypeError("unparseable lease")


def test_retire_lease_process_with_unparseable_pid(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(tmp_path / "missing-lease.json"))
    obj._retire_lease_process(_BadPidLease(), "bad pid")  # lines 1318-1319
    assert obj._last_recycle_reason == "bad pid"
    assert obj._ready is False


def test_retire_lease_process_escalates_to_sigkill(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    lease = {
        "pid": 77,
        "server_path": obj._server_bin,
        "model_path": obj._model_path,
    }
    monkeypatch.setattr(core, "_pid_alive", lambda _pid: True)
    monkeypatch.setattr(obj, "_pid_is_expected_server", lambda *_args: True)
    kills = []
    monkeypatch.setattr(core.os, "kill", lambda pid, sig: kills.append((pid, sig)))
    monkeypatch.setattr(
        core.time, "monotonic", iter([0.0, 1.0, 2.0, 9.0]).__next__
    )
    monkeypatch.setattr(core.time, "sleep", lambda _seconds: None)
    obj._retire_lease_process(lease, "wedged server")
    assert kills == [(77, 15), (77, 9)]  # lines 1328-1329
    assert obj._last_recycle_reason == "wedged server"


def test_retire_lease_process_keeps_foreign_lease(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    lease_file = tmp_path / "lease.json"
    lease_file.write_text(
        json.dumps({"pid": 9999, "marker": "current"}), encoding="utf-8"
    )
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(lease_file))
    obj._retire_lease_process({"pid": 0, "marker": "arg"}, "stale")
    # Current lease differs, so the unlink is skipped (1334->1336).
    assert lease_file.exists()
    assert obj._last_recycle_reason == "stale"


# ── idle shutdown without a lock: line 1381 ─────────────────────────────────


def test_shutdown_if_idle_without_lock(tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    obj._idle_lock = None
    assert obj._shutdown_if_idle(0) is None  # line 1381


# ── recycle on RSS limit: line 1432 ─────────────────────────────────────────


def test_record_success_recycles_on_rss_limit(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    obj._read_lease = lambda: {"schema": 2, "pid": 7, "request_count": 5, "rss": 1}
    obj._lease_matches = lambda _value: True
    monkeypatch.setattr(core, "_process_rss_bytes", lambda _pid: 10 * 1024**3)
    monkeypatch.setattr(core, "EMBED_MAX_REQUESTS", 0)
    obj._retire_lease_process = lambda _lease, reason: setattr(obj, "reason", reason)
    obj._record_success_and_maybe_recycle()
    assert "RSS limit" in obj.reason  # line 1432


# ── GPU fallback to CPU device: lines 1539-1540 ─────────────────────────────


def test_start_server_gpu_request_without_device_falls_back_to_cpu(
    monkeypatch, tmp_path
):
    obj = _embedder(tmp_path, ready=False, use_llama=True)
    obj._read_lease = dict
    obj._pick_port = lambda: 19002
    obj._write_lease = lambda _lease: None
    obj._lease_identity = lambda: {"profile": core.BGE_CODE_V1.key, "dimension": 2}
    obj._stop_registered = True
    proc = _Process()
    # GPU requested but no device detected: `--device none` (1539-1540).
    monkeypatch.setattr(core, "_detect_gpu_device", lambda _path: "")
    monkeypatch.setenv("IDA_MCP_EMBED_GPU", "true")
    monkeypatch.setattr(
        core.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b'{"status":"ok"}'),
    )
    monkeypatch.setattr(core.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(core.time, "time", lambda: 0.0)
    command = []

    def capture_popen(args, **kwargs):
        command.extend(args)
        return proc

    monkeypatch.setattr(core.subprocess, "Popen", capture_popen)
    assert obj._start_server_locked() is True
    assert command[-2:] == ["--device", "none"]
