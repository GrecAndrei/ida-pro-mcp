"""Round-18 groups D/E gap closure for intelligence core (offline, deterministic).

Every test maps to coverage gaps in ``src/ida_pro_mcp/host/intelligence/core.py``
listed for groups D and E.  Idioms follow
``test_core_remaining_modes.py`` / ``test_core_runtime_modes.py`` plus
``test_embedder_fail_open.py``: stub embedders/servers via ``object.__new__``,
``tmp_path``, ``monkeypatch``; no real servers/models/network/IDA; no threads
with timing; no ``sys.modules`` monkeypatching (``builtins.__import__`` is
intercepted when an import must be faked).
"""

from __future__ import annotations

import builtins
import json
import os
import threading
import types
from pathlib import Path
from types import SimpleNamespace

from ida_pro_mcp.host.intelligence import core
from ida_pro_mcp.host.intelligence.core import BehaviorClassifier, BgeCodeEmbedder
from tests.host.intelligence.test_core_runtime_modes import (
    _embedder,
    _Process,
    _Response,
)

# ── helpers ──────────────────────────────────────────────────────────────────


class _HangingProc(_Process):
    """Process whose wait always times out (covers kill-fallback paths)."""

    pid = 999

    def __init__(self):
        super().__init__()
        self.returncode = None

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        raise TimeoutError("still running")


class _FailingPopDict(dict):
    """Dict whose pop always fails (covers cache-evict fallback)."""

    def pop(self, *args, **kwargs):
        raise RuntimeError("pop boom")


def _ida_interceptor(monkeypatch, funcs, decompile_fn):
    """Fake ``idautils``/``ida_hexrays`` via ``builtins.__import__``."""
    import types as _types

    real_import = builtins.__import__
    fake_utils = _types.SimpleNamespace(Functions=lambda: list(funcs))
    fake_hexrays = _types.SimpleNamespace(decompile=decompile_fn)

    def _intercept(name, *args, **kwargs):
        if name == "idautils":
            return fake_utils
        if name == "ida_hexrays":
            return fake_hexrays
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _intercept)


def _offline_classifier(monkeypatch, tmp_path, *, embed_dim=2, key="r18de-key"):
    """Classifier whose embedder stays cold and whose cache lives in tmp."""
    import ida_pro_mcp.host.config as host_config

    monkeypatch.setattr(core, "CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(host_config, "CACHE_DIR", str(tmp_path))

    class _Emb:
        backend = "offline"
        dim = embed_dim
        _model_path = str(tmp_path / "model.gguf")
        _profile = core.BGE_CODE_V1

        def embed(self, _text):
            return core._EmbedResult(None, "unavailable", False)

        def embedding_format(self):
            return key

    emb = _Emb()
    clf = BehaviorClassifier(emb)
    clf._save_anchor = BehaviorClassifier._save_anchor.__get__(clf)
    return clf, emb


# ── GROUP D ──────────────────────────────────────────────────────────────────
# 1604-1608: health-poll failure + exited child returns False.


def test_start_health_failure_with_exited_proc_covers_1604_1608(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=False, use_llama=True)
    obj._read_lease = dict
    obj._pick_port = lambda: 19003
    obj._lease_identity = lambda: {"profile": core.BGE_CODE_V1.key}
    obj._write_lease = lambda _lease: None
    obj._stop_registered = True
    exited = _Process(exited=True)
    monkeypatch.setattr(core.subprocess, "Popen", lambda *_a, **_k: exited)
    monkeypatch.setattr(
        core.urllib.request,
        "urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("not ready")),
    )
    monkeypatch.setattr(core.time, "sleep", lambda _s: None)
    monkeypatch.setattr(core.time, "time", lambda: 0.0)
    assert obj._start_server_locked() is False
    assert obj._ready is False


# 1624: stop() with a non-dict lease payload resets to {}.


def test_stop_nondict_lease_covers_1624(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    lease_file = tmp_path / "lease.json"
    lease_file.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(lease_file))
    obj._proc = None
    obj._owns_proc = False
    obj.stop()
    assert obj._ready is False
    assert obj._proc is None
    assert obj._owns_proc is False


# 1645-1646: terminate times out, kill times out, second wait raises -> pass.


def test_stop_both_waits_timeout_covers_1645_1646(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    lease_file = tmp_path / "lease.json"
    lease_file.write_text(
        json.dumps({"pid": 1, "owner_pid": 999999}), encoding="utf-8"
    )
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(lease_file))
    proc = _HangingProc()
    obj._proc = proc
    obj._owns_proc = True
    obj.stop()
    assert proc.terminated is True
    assert proc.killed is True
    assert proc.wait_calls == [5, 2]
    assert obj._proc is None


# 1650: owned pid with an already-exited proc marks stopped without signaling.


def test_stop_exited_proc_covers_1650(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    lease_file = tmp_path / "lease.json"
    lease_file.write_text(
        json.dumps({"pid": 1, "owner_pid": 999999}), encoding="utf-8"
    )
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(lease_file))
    proc = _Process(exited=True)
    obj._proc = proc
    obj._owns_proc = True
    obj.stop()
    assert proc.terminated is False
    assert proc.killed is False
    assert obj._proc is None


# 1660-1664: lease-owned kill loop sleeps, SIGKILL raises -> except pass.


def test_stop_lease_kill_loop_covers_1660_1664(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    token = core._process_start_token(os.getpid())
    lease = {"pid": 4321, "owner_pid": os.getpid(), "owner_start_token": token}
    lease_file = tmp_path / "lease.json"
    lease_file.write_text(json.dumps(lease), encoding="utf-8")
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(lease_file))
    obj._proc = None
    obj._owns_proc = False
    monkeypatch.setattr(obj, "_pid_is_expected_server", lambda *_a: True)
    monkeypatch.setattr(core, "_pid_alive", lambda _pid: True)

    def fake_kill(_pid, sig):
        if sig == 9:
            raise OSError("gone")

    monkeypatch.setattr(core.os, "kill", fake_kill)
    ticks = iter([100.0, 100.0, 100.5, 102.5])
    monkeypatch.setattr(core.time, "monotonic", lambda: next(ticks))
    slept = []

    def _sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(core.time, "sleep", _sleep)
    obj.stop()
    assert slept
    assert obj._proc is None


# 1676-1677: unlink failure while releasing the lease is swallowed.


def test_stop_unlink_failure_covers_1676_1677(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    token = core._process_start_token(os.getpid())
    lease = {"pid": 321, "owner_pid": os.getpid(), "owner_start_token": token}
    lease_file = tmp_path / "lease.json"
    lease_file.write_text(json.dumps(lease), encoding="utf-8")
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(lease_file))
    proc = _Process(exited=True)
    proc.pid = 321
    obj._proc = proc
    obj._owns_proc = True
    monkeypatch.setattr(
        core.os, "unlink", lambda _p: (_ for _ in ()).throw(OSError("busy"))
    )
    obj.stop()
    assert obj._ready is False
    assert obj._proc is None


# 1690: ensure_ready delegates to the gemini backend.


def test_ensure_ready_gemini_covers_1690(tmp_path):
    obj = _embedder(tmp_path, ready=False, use_llama=False)
    obj._gemini = SimpleNamespace(ensure_ready=lambda: True)
    assert obj.ensure_ready() is True


# 1694: ensure_ready schedules the idle shutdown after a successful start.


def test_ensure_ready_schedules_idle_covers_1694(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=False, use_llama=True)
    monkeypatch.setattr(obj, "_cancel_idle_shutdown", lambda: None)
    monkeypatch.setattr(obj, "_start_server", lambda: True)
    seen = []
    monkeypatch.setattr(
        obj, "_schedule_idle_shutdown", lambda timeout=None: seen.append(timeout)
    )
    assert obj.ensure_ready() is True
    assert seen == [core.EMBED_ACTIVATION_GRACE_TIMEOUT]


# 1712->1714, 1715->1717: cache and lock already valid, inflight missing.


def test_cache_state_skips_cache_and_lock_init_covers_1712_1715(monkeypatch, tmp_path):
    del monkeypatch, tmp_path
    obj = object.__new__(BgeCodeEmbedder)
    obj._embedding_cache = {}
    obj._embedding_cache_lock = threading.Lock()
    obj._embedding_inflight = None
    obj._embedding_cache_generation = None
    cache, lock, inflight = obj._embedding_cache_state()
    assert isinstance(cache, dict)
    assert callable(lock.acquire)
    assert isinstance(inflight, dict)
    assert obj._embedding_cache_generation == 0


# 1717->1719, 1719->1721: inflight and generation already valid.


def test_cache_state_skips_inflight_and_generation_init_covers_1717_1719(tmp_path):
    del tmp_path
    obj = object.__new__(BgeCodeEmbedder)
    obj._embedding_cache = None
    obj._embedding_cache_lock = threading.Lock()
    obj._embedding_inflight = {}
    obj._embedding_cache_generation = 0
    cache, _lock, inflight = obj._embedding_cache_state()
    assert isinstance(cache, dict)
    assert isinstance(inflight, dict)
    assert obj._embedding_cache_generation == 0


# 1833: row without an embedding raises "no embedding in response".


def test_request_no_embedding_covers_1833(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    obj._server_started_at = -core.EMBED_ACTIVATION_GRACE_TIMEOUT - 1.0
    obj._server_has_active_slots = lambda: False
    obj._cancel_idle_shutdown = lambda: None
    obj._schedule_idle_shutdown = lambda *_a, **_k: None
    obj._record_success_and_maybe_recycle = lambda: None
    obj._retire_lease_process = lambda *_a: None
    monkeypatch.setattr(
        core.urllib.request, "urlopen", lambda *_a, **_k: _Response([{"index": 0}])
    )
    assert (
        obj._request_embeddings(["query"], purpose="query", timeout=0.1) is None
    )


# 1849: queue timeout is load-shedding, never a server failure.


def test_request_queue_timeout_covers_1849(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)

    class _Busy:
        def __enter__(self):
            raise core.EmbeddingQueueTimeout("busy")

        def __exit__(self, *_a):
            return False

    monkeypatch.setattr(core, "_InterProcessLock", lambda *_a: _Busy())
    assert (
        obj._request_embeddings(["query"], purpose="query", timeout=0.1) is None
    )


# ── GROUP E ──────────────────────────────────────────────────────────────────
# 1935->1944: request miss (None) skips the cache store.


def test_llama_embed_miss_covers_1935_1944(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    monkeypatch.setattr(
        obj, "_request_embeddings", lambda *_a, **_k: None
    )
    assert obj._llama_embed("hello") is None
    assert obj._embedding_inflight == {}


# 1937->1944: generation changed mid-request, store is skipped but vector kept.


def test_llama_embed_generation_mismatch_covers_1937_1944(monkeypatch, tmp_path):
    del monkeypatch
    obj = _embedder(tmp_path, ready=True, use_llama=True)

    def _recycle(*_a, **_k):
        obj._invalidate_embedding_cache()
        return [[1.0, 0.0]]

    obj._request_embeddings = _recycle  # noqa: SLF001
    vec = obj._llama_embed("hello")
    assert vec == [1.0, 0.0]
    assert obj._embedding_cache == {}


# 1941-1942: eviction pop failure falls back to clear().


def test_llama_embed_evict_failure_covers_1941_1942(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    monkeypatch.setattr(core, "EMBED_CACHE_MAX", 1)
    obj._embedding_cache = _FailingPopDict({("old",): [0.0]})
    obj._embedding_cache_lock = threading.Lock()
    obj._embedding_inflight = {}
    obj._embedding_cache_generation = 0
    monkeypatch.setattr(
        obj, "_request_embeddings", lambda *_a, **_k: [[0.5, 0.5]]
    )
    vec = obj._llama_embed("brand new text")
    assert vec == [0.5, 0.5]
    assert len(obj._embedding_cache) == 1
    assert ("old",) not in obj._embedding_cache


# 1948->1946: finally with a missing inflight event skips set().


def test_llama_embed_missing_event_covers_1948_1946(tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)

    def _clear(*_a, **_k):
        obj._embedding_inflight.clear()
        return [[2.0, 0.0]]

    obj._request_embeddings = _clear  # noqa: SLF001
    assert obj._llama_embed("vanishing waiter") == [2.0, 0.0]
    assert obj._embedding_inflight == {}


# 1955: empty batch short-circuits.


def test_llama_embed_batch_empty_covers_1955(tmp_path):
    obj = _embedder(tmp_path, ready=True, use_llama=True)
    assert obj._llama_embed_batch([]) == []


# 2056, 2064: gemini property passthrough.


def test_gemini_property_passthrough_covers_2056_2064(tmp_path):
    obj = _embedder(tmp_path, ready=False, use_llama=False)
    obj._gemini = SimpleNamespace(max_input_chars=1234, decomp_document_chars=567)
    assert obj.max_input_chars == 1234
    assert obj.decomp_document_chars == 567


# 2181->2186: truthy embedding_format short-circuits the fallback identity.


def test_cache_key_direct_covers_2181_2186(monkeypatch, tmp_path):
    import hashlib

    class _Emb:
        backend = "offline"
        dim = 0
        _model_path = ""
        _profile = core.BGE_CODE_V1

        def embedding_format(self):
            return "my-key"

    monkeypatch.setattr(core, "CACHE_DIR", str(tmp_path))
    clf = BehaviorClassifier(_Emb())
    assert clf._cache_key() == hashlib.sha256(b"my-key").hexdigest()[:16]


# 2191-2192: first config import fails, host.config fallback supplies CACHE_DIR.


def test_cache_path_import_fallback_covers_2191_2192(monkeypatch, tmp_path):
    real_import = builtins.__import__
    calls = {"count": 0}

    def _intercept(name, *args, **kwargs):
        fromlist = args[2] if len(args) > 2 else kwargs.get("fromlist", ())
        if tuple(fromlist or ()) == ("CACHE_DIR",):
            calls["count"] += 1
            if calls["count"] == 1:
                raise ImportError("no relative config")
            return types.SimpleNamespace(CACHE_DIR=str(tmp_path))
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _intercept)

    class _Emb:
        backend = "offline"
        dim = 2
        _model_path = str(tmp_path / "model.gguf")
        _profile = core.BGE_CODE_V1

        def embedding_format(self):
            return "fallback-key"

    clf = BehaviorClassifier.__new__(BehaviorClassifier)
    clf._embedder = _Emb()
    clf._anchor_embs = {}
    clf._anchor_lock = threading.Lock()
    clf._anchor_generation = 0
    path = clf._cache_path()
    assert path.startswith(str(tmp_path))
    assert "fallback-key" not in path
    assert Path(path).name.startswith("anchor_cache_")


# 2218: wrong-width vector is skipped; 2220->exit: empty load leaves cache cold.


def test_load_anchor_wrong_dim_covers_2218(monkeypatch, tmp_path):
    import ida_pro_mcp.host.config as host_config

    monkeypatch.setattr(core, "CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(host_config, "CACHE_DIR", str(tmp_path))

    class _Emb:
        backend = "offline"
        dim = 2
        _model_path = str(tmp_path / "model.gguf")
        _profile = core.BGE_CODE_V1

    clf = BehaviorClassifier(_Emb())
    path = clf._cache_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        json.dumps(
            {
                "version": BehaviorClassifier.ANCHOR_CACHE_VERSION,
                "anchors": {
                    "crypto_hash": [1.0, 0.0],
                    "network_http": [1.0],
                },
            }
        ),
        encoding="utf-8",
    )
    reloaded = BehaviorClassifier(_Emb())
    assert reloaded._anchor_embs.get("crypto_hash") == [1.0, 0.0]
    assert "network_http" not in reloaded._anchor_embs


def test_load_anchor_empty_covers_2220_exit(monkeypatch, tmp_path):
    import ida_pro_mcp.host.config as host_config

    monkeypatch.setattr(core, "CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(host_config, "CACHE_DIR", str(tmp_path))

    class _Emb:
        backend = "offline"
        dim = 2
        _model_path = str(tmp_path / "model.gguf")
        _profile = core.BGE_CODE_V1

    clf = BehaviorClassifier(_Emb())
    path = clf._cache_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        json.dumps(
            {"version": BehaviorClassifier.ANCHOR_CACHE_VERSION, "anchors": {}}
        ),
        encoding="utf-8",
    )
    reloaded = BehaviorClassifier(_Emb())
    assert reloaded._anchor_embs == {}


# 2239->2243: non-dict existing anchor file is ignored, then overwritten.


def test_save_anchor_corrupt_existing_covers_2239_2243(monkeypatch, tmp_path):
    clf, _emb = _offline_classifier(monkeypatch, tmp_path)
    path = clf._cache_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("[]", encoding="utf-8")
    clf._embedder.dim = 2
    clf._embedder._model_path = str(tmp_path / "model.gguf")
    clf._save_anchor("crypto_hash", [1.0, 0.0])
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["anchors"]["crypto_hash"] == [1.0, 0.0]


# 2256-2257: outer save failure is swallowed.


def test_save_anchor_outer_failure_covers_2256_2257(monkeypatch, tmp_path):
    clf, _emb = _offline_classifier(monkeypatch, tmp_path)
    clf._embedder.dim = 2
    clf._embedder._model_path = str(tmp_path / "model.gguf")
    monkeypatch.setattr(
        clf, "_cache_path", lambda: "/proc/ida-mcp-no-such-dir/anchor.json"
    )
    clf._save_anchor("crypto_hash", [1.0, 0.0])


# 2352: block=True with an unavailable anchor skips that behavior.


def test_classify_vec_anchor_none_covers_2352(monkeypatch, tmp_path):
    clf, _emb = _offline_classifier(monkeypatch, tmp_path, embed_dim=0)
    monkeypatch.setattr(clf, "_get_anchor", lambda _label: None)
    assert clf.classify_vec([1.0, 0.0], block=True) == []


# 2446->2438: embed miss leaves the function cache empty across loop iterations.


def test_coverage_report_embed_miss_covers_2446_2438(monkeypatch, tmp_path):
    clf, _emb = _offline_classifier(monkeypatch, tmp_path)
    _ida_interceptor(
        monkeypatch, [0x1000, 0x2000], lambda _ea: "int foo() { return 0; }"
    )
    monkeypatch.setattr(clf, "_get_anchor", lambda _label: None)
    report = clf.anchor_coverage_report()
    assert report["function_count"] == 0
    assert all(row["hit_count"] == 0 for row in report["anchors"])


# 2448-2449: decompile failure for one function is skipped.


def test_coverage_report_exception_covers_2448_2449(monkeypatch, tmp_path):
    clf, _emb = _offline_classifier(monkeypatch, tmp_path)

    def _decompile(ea):
        if ea == 0x1000:
            raise OSError("no decompile")
        return "int bar() { return 1; }"

    _ida_interceptor(monkeypatch, [0x1000, 0x2000], _decompile)
    monkeypatch.setattr(clf, "_get_anchor", lambda _label: None)
    report = clf.anchor_coverage_report()
    assert report["function_count"] == 0


# 2459->2457: similarity below threshold iterates without a hit.


def test_coverage_report_below_threshold_covers_2459_2457(monkeypatch, tmp_path):
    clf, _emb = _offline_classifier(monkeypatch, tmp_path)
    _ida_interceptor(monkeypatch, [0x1000], lambda _ea: "int foo() { return 0; }")
    monkeypatch.setattr(
        clf._embedder,
        "embed",
        lambda _text: core._EmbedResult([1.0, 0.0], "offline", True),
    )
    monkeypatch.setattr(clf, "_get_anchor", lambda _label: [0.0, 1.0])
    report = clf.anchor_coverage_report()
    assert report["function_count"] == 1
    assert all(row["hit_count"] == 0 for row in report["anchors"])


# 2461->2457: second hit weaker than the best does not replace the example.


def test_coverage_report_weaker_second_hit_covers_2461_2457(monkeypatch, tmp_path):
    clf, _emb = _offline_classifier(monkeypatch, tmp_path)
    _ida_interceptor(
        monkeypatch, [0x1000, 0x2000], lambda ea: f"int f{ea:x}() {{ return 0; }}"
    )
    vectors = iter([[1.0, 0.0], [0.8, 0.6]])

    def _embed(_text):
        return core._EmbedResult(next(vectors), "offline", True)

    monkeypatch.setattr(clf._embedder, "embed", _embed)
    monkeypatch.setattr(clf, "_get_anchor", lambda _label: [1.0, 0.0])
    report = clf.anchor_coverage_report(min_similarity=0.4)
    assert report["function_count"] == 2
    assert all(row["hit_count"] == 2 for row in report["anchors"])
    assert all(row["top_example"] == hex(0x1000) for row in report["anchors"])
