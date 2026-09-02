"""Exercise intelligence discovery, lease, cache, and classifier boundaries."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

from ida_pro_mcp.host.intelligence import core
from ida_pro_mcp.host.intelligence.core import BehaviorClassifier, BgeCodeEmbedder
from tests.host.intelligence.test_core_runtime_modes import _embedder, _Process, _Response


def test_state_reader_falls_through_bad_install_and_cache_files(tmp_path, monkeypatch):
    install = tmp_path / "install"
    cache = tmp_path / "cache"
    config = tmp_path / "config"
    install.mkdir()
    cache.mkdir()
    (config / "ida-pro-mcp").mkdir(parents=True)
    (install / "embedder.json").write_text("not-json", encoding="utf-8")
    (cache / "embedder.json").write_text("[]", encoding="utf-8")
    (config / "ida-pro-mcp" / "embedder.json").write_text(
        json.dumps({"backend": "local", "model_path": "portable.gguf"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(core, "_install_root", lambda: str(install))
    monkeypatch.setattr(core, "CACHE_DIR", str(cache))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    state = core._read_embedder_state()
    assert state["model_path"] == "portable.gguf"
    assert state["_source"] == str(config / "ida-pro-mcp" / "embedder.json")

    (config / "ida-pro-mcp" / "embedder.json").write_text(
        json.dumps(["not a mapping"]), encoding="utf-8"
    )
    assert core._read_embedder_state() == {}


def test_model_discovery_cache_empty_parts_and_legacy_fallback(tmp_path, monkeypatch):
    model = tmp_path / "bge-code-v1-fallback.gguf"
    model.write_bytes(b"model")
    monkeypatch.setattr(core, "_install_root", lambda: str(tmp_path))
    monkeypatch.setattr(core, "_PROJECT_ROOT", str(tmp_path))
    monkeypatch.setattr(core, "_read_embedder_state", dict)
    monkeypatch.setattr(core, "_MODEL_PATH_CACHE", None)
    monkeypatch.setenv("IDA_MCP_EMBED_PROFILE", "zembed-1")
    monkeypatch.setenv("IDA_MCP_EMBED_MODEL", ";$UNSET_MODEL;")
    monkeypatch.setattr(core, "glob", types.SimpleNamespace(
        glob=lambda pattern: [str(model)] if "bge-code-v1" in pattern else []
    ))
    assert core._find_model() == str(model)

    # A cache hit is valid only while the cached file still exists.
    monkeypatch.delenv("IDA_MCP_EMBED_MODEL")
    monkeypatch.setenv("IDA_MCP_EMBED_PROFILE", "bge-code-v1")
    monkeypatch.setattr(core, "_MODEL_PATH_CACHE", None)
    assert core._find_model() == str(model)
    assert core._find_model() == str(model)
    model.unlink()
    assert core._find_model() == ""


def test_model_discovery_handles_custom_profile_without_patterns(monkeypatch, tmp_path):
    custom = types.SimpleNamespace(key="custom", filename_patterns=())
    monkeypatch.setenv("IDA_MCP_EMBED_PROFILE", "custom")
    monkeypatch.setattr(core, "get_model_profile", lambda _name: custom)
    monkeypatch.setattr(core, "_read_embedder_state", dict)
    monkeypatch.setattr(core, "_MODEL_PATH_CACHE", None)
    monkeypatch.setattr(core, "_install_root", lambda: str(tmp_path))
    monkeypatch.setattr(core, "glob", types.SimpleNamespace(glob=lambda _pattern: []))
    assert core._find_model() == ""


def test_lease_pid_and_windows_interprocess_lock_modes(monkeypatch, tmp_path):
    assert core._lease_pid(True) == 0
    assert core._lease_pid(" 42 ") == 42
    assert core._lease_pid("１２") == 0
    assert core._lease_pid("-3") == 0
    assert core._lease_pid(0) == 0
    assert core._lease_pid(object()) == 0

    calls = []
    fake_msvcrt = types.SimpleNamespace(
        LK_NBLCK=1,
        LK_UNLCK=2,
        locking=lambda fd, mode, count: calls.append((fd, mode, count)),
    )
    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)
    monkeypatch.setattr(core.sys, "platform", "win32")
    lock = core._InterProcessLock(str(tmp_path / "windows.lock"), timeout=0)
    with lock:
        assert lock.handle is not None
    assert [item[1] for item in calls] == [1, 2]
    assert lock.handle is None


def test_lease_matching_rejects_bad_types_tokens_identity_and_props(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    identity = {
        "profile": core.BGE_CODE_V1.key,
        "dimension": 2,
        "model_path": str(tmp_path / "model.gguf"),
        "server_path": str(tmp_path / "llama-server"),
    }
    obj._lease_identity = lambda: dict(identity)
    valid = {
        "schema": 2,
        "pid": 11,
        "owner_pid": 12,
        "port": 18000,
        "process_start_token": "proc",
        "owner_start_token": "owner",
        **identity,
    }
    monkeypatch.setattr(core, "_pid_alive", lambda _pid: True)
    monkeypatch.setattr(
        core,
        "_process_start_token",
        lambda pid: "proc" if pid == 11 else "owner",
    )
    obj._server_json = lambda _port, endpoint: (
        {"status": "ok"} if endpoint == "health" else {"model_path": identity["model_path"]}
    )
    assert obj._lease_matches(valid) is True
    assert obj._lease_matches(None) is False
    assert obj._lease_matches({**valid, "port": "bad"}) is False
    assert obj._lease_matches({**valid, "process_start_token": "wrong"}) is False
    assert obj._lease_matches({**valid, "owner_start_token": "wrong"}) is False
    assert obj._lease_matches({**valid, "dimension": 99}) is False
    obj._server_json = lambda _port, _endpoint: []
    assert obj._lease_matches(valid) is False


def test_retire_lease_process_is_conservative_and_reaps_owned_child(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    lease_file = tmp_path / "lease.json"
    lease = {"pid": "bad", "server_path": obj._server_bin, "model_path": obj._model_path}
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(lease_file))
    monkeypatch.setattr(obj, "_invalidate_embedding_cache", lambda: None)
    obj._retire_lease_process(lease, "bad pid")
    assert obj._last_recycle_reason == "bad pid"

    lease = {"pid": 77, "server_path": obj._server_bin, "model_path": obj._model_path}
    lease_file.write_text(json.dumps(lease), encoding="utf-8")
    monkeypatch.setattr(core, "_pid_alive", lambda _pid: True)
    monkeypatch.setattr(obj, "_pid_is_expected_server", lambda *_args: False)
    killed = []
    monkeypatch.setattr(core.os, "kill", lambda *args: killed.append(args))
    obj._retire_lease_process(lease, "foreign process")
    assert killed == []
    assert lease_file.exists()

    child = _Process()
    child.pid = 77
    obj._proc = child
    obj._owns_proc = True
    monkeypatch.setattr(obj, "_pid_is_expected_server", lambda *_args: True)
    alive = iter([True, True, False])
    monkeypatch.setattr(core, "_pid_alive", lambda _pid: next(alive, False))
    monkeypatch.setattr(core.time, "monotonic", iter([0.0, 0.1]).__next__)
    monkeypatch.setattr(core.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(core.os, "kill", lambda *_args: None)
    obj._retire_lease_process(lease, "child recycle")
    assert obj._proc is None
    assert obj._owns_proc is False
    assert child.wait_calls == [0.1]


def test_active_slots_and_startup_cover_empty_error_and_gpu_paths(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    obj._port = 19001
    obj._read_lease = lambda: {"pid": 1}
    obj._server_json = lambda _port, _endpoint: []
    assert obj._server_has_active_slots() is False
    obj._server_json = lambda _port, _endpoint: [{"is_processing": True}]
    assert obj._server_has_active_slots() is True
    obj._server_json = lambda _port, _endpoint: (_ for _ in ()).throw(OSError("gone"))
    assert obj._server_has_active_slots() is False

    stale = _embedder(tmp_path, ready=False, use_llama=True)
    stale._read_lease = lambda: {"pid": 9}
    stale._lease_matches = lambda _lease: False
    retired = []
    stale._retire_lease_process = lambda lease, reason: retired.append((lease, reason))
    monkeypatch.setattr(core.subprocess, "Popen", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("spawn")))
    assert stale._start_server_locked() is False
    assert retired and retired[0][1] == "stale or incompatible lease"

    started = _embedder(tmp_path, ready=False, use_llama=True)
    started._read_lease = dict
    started._pick_port = lambda: 19002
    started._write_lease = lambda _lease: None
    started._lease_identity = lambda: {"profile": core.BGE_CODE_V1.key, "dimension": 2}
    started._stop_registered = True
    proc = _Process()
    monkeypatch.setattr(core, "_detect_gpu_device", lambda _path: "Vulkan0")
    monkeypatch.setenv("IDA_MCP_EMBED_GPU", "true")
    monkeypatch.setattr(core.urllib.request, "urlopen", lambda *_args, **_kwargs: _Response(b'{"status":"ok"}'))
    monkeypatch.setattr(core.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(core.time, "time", lambda: 0.0)
    command = []
    def capture_popen(args, **kwargs):
        command.extend(args)
        return proc

    monkeypatch.setattr(core.subprocess, "Popen", capture_popen)
    assert started._start_server_locked() is True
    assert command[-2:] == ["--device", "Vulkan0"]


def test_embedding_cache_waiter_and_batch_chunk_boundaries(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    formatted = obj._profile.format_text("waiting", "document")[: obj.max_input_chars]
    key = (
        0,
        (str(Path(obj._model_path).resolve()), obj._profile.key, obj._dimension),
        "document",
        formatted,
    )
    event = __import__("threading").Event()
    event.set()
    obj._embedding_inflight[key] = event
    monkeypatch.setattr(obj, "_request_embeddings", lambda *_args, **_kwargs: pytest.fail("waiter became owner"))
    assert obj._llama_embed("waiting") is None

    obj._batch_size = 2
    obj._max_batch_size = 2
    obj._llama_embed_batch = lambda chunk, **_kwargs: [[float(len(chunk)), 0.0] for _ in chunk]
    rows = obj.embed_batch(["a", "b", "c"])
    assert len(rows) == 3 and all(row.ok for row in rows)
    assert obj._batch_size == 2
    assert obj._llama_embed_batch([], purpose="document") == []


def test_classifier_rebind_cache_validation_and_report_failures(monkeypatch, tmp_path):
    import ida_pro_mcp.host.config as host_config

    monkeypatch.setattr(core, "CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(host_config, "CACHE_DIR", str(tmp_path))

    class Embedder:
        backend = "offline"
        dim = 2
        _model_path = str(tmp_path / "model.gguf")

        def embed(self, _text):
            return core._EmbedResult([1.0, 0.0], "offline", True)

    first = BehaviorClassifier(Embedder())
    first._save_anchor = lambda *_args: None
    first._anchor_embs["network_raw"] = [1.0, 0.0]
    monkeypatch.setattr(BehaviorClassifier, "_shared", None)
    monkeypatch.setattr(BehaviorClassifier, "_shared", first)
    second_embedder = Embedder()
    shared = BehaviorClassifier.instance(second_embedder)
    assert shared is first and shared._embedder is second_embedder
    assert shared._anchor_embs == {}

    cached_path = Path(shared._cache_path())
    cached_path.parent.mkdir(parents=True, exist_ok=True)
    cached_path.write_text(json.dumps({"version": 99, "anchors": {}}), encoding="utf-8")
    cold = BehaviorClassifier(second_embedder)
    assert cold._anchor_embs == {}
    cached_path.write_text(json.dumps({"version": 1, "anchors": []}), encoding="utf-8")
    assert BehaviorClassifier(second_embedder)._anchor_embs == {}

    broken = types.SimpleNamespace(
        backend="offline",
        dim=2,
        _model_path=str(tmp_path / "model.gguf"),
        embedding_format=lambda: (_ for _ in ()).throw(RuntimeError("format")),
    )
    key = BehaviorClassifier(broken)._cache_key()
    assert len(key) == 16

    monkeypatch.setitem(
        sys.modules,
        "idautils",
        types.SimpleNamespace(Functions=lambda: (_ for _ in ()).throw(OSError("ida"))),
    )
    monkeypatch.setattr(cold, "_get_anchor", lambda _label: None)
    report = cold.anchor_coverage_report()
    assert report["function_count"] == 0
    assert all(row["hit_count"] == 0 for row in report["anchors"])
