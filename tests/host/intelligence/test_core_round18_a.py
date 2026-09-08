"""Round-18 group A: discovery/state head gaps in intelligence core."""

from __future__ import annotations

import importlib.util
import os
import sys
import types

import pytest

from ida_pro_mcp.host.intelligence import core
from tests.host.intelligence.test_core_runtime_modes import (
    _embedder,
    _Process,
    _Response,
)


def _clean_discovery_env(monkeypatch, tmp_path):
    for var in (
        "IDA_MCP_EMBED_SERVER_BIN",
        "IDA_MCP_EMBED_MODEL",
        "XDG_CONFIG_HOME",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(core, "_install_root", lambda: str(tmp_path))
    monkeypatch.setattr(core, "CACHE_DIR", str(tmp_path))
    return tmp_path


def test_install_root_posix_layout(monkeypatch):
    # conftest.py pins IDA_PRO_MCP_HOME to a sandbox for every test; drop
    # the override so the platform branch below actually executes.
    monkeypatch.delenv("IDA_PRO_MCP_HOME", raising=False)
    root = core._install_root()
    if sys.platform == "win32":
        assert root.endswith("ida-pro-mcp")
    else:
        assert root.endswith(os.path.join(".local", "share", "ida-pro-mcp"))


def test_read_embedder_state_survives_home_failure(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(core, "_install_root", lambda: (_ for _ in ()).throw(OSError("gone")))
    monkeypatch.setattr(core, "CACHE_DIR", str(tmp_path))

    def _boom():
        raise OSError("no home")

    monkeypatch.setattr(core.Path, "home", _boom)
    assert core._read_embedder_state() == {}


def _raise_once_expanduser(monkeypatch):
    real_expanduser = os.path.expanduser
    armed = {"fire": True}

    def _flaky(path):
        if armed["fire"]:
            armed["fire"] = False
            raise RuntimeError("expand failed")
        return real_expanduser(path)

    monkeypatch.setattr(os.path, "expanduser", _flaky)


def test_select_state_path_expand_failure(monkeypatch, tmp_path):
    probe = tmp_path / "embedder.json"
    probe.write_text("{}", encoding="utf-8")
    _raise_once_expanduser(monkeypatch)
    assert core._select_state_path(str(probe)) == ""


def test_find_server_rejects_empty_piece(monkeypatch, tmp_path):
    _clean_discovery_env(monkeypatch, tmp_path)
    monkeypatch.setenv("IDA_MCP_EMBED_SERVER_BIN", ";")
    assert core._find_llama_server() == ""


def test_find_server_scans_directory_without_binaries(monkeypatch, tmp_path):
    _clean_discovery_env(monkeypatch, tmp_path)
    candidate = tmp_path / "llama-server"
    candidate.write_text("not executable", encoding="utf-8")
    candidate.chmod(0o644)
    monkeypatch.setenv("IDA_MCP_EMBED_SERVER_BIN", str(tmp_path))
    assert core._find_llama_server() == ""


def test_find_server_accept_expand_failure(monkeypatch, tmp_path):
    _clean_discovery_env(monkeypatch, tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("IDA_MCP_EMBED_SERVER_BIN", str(tmp_path))
    _raise_once_expanduser(monkeypatch)
    assert core._find_llama_server() == ""


def test_find_server_dedupes_seen_roots(monkeypatch, tmp_path):
    _clean_discovery_env(monkeypatch, tmp_path)
    monkeypatch.delenv("IDA_MCP_EMBED_SERVER_BIN", raising=False)
    monkeypatch.setattr(core, "_install_root", lambda: "/usr")
    assert core._find_llama_server() == ""


def test_find_model_expand_failure(monkeypatch, tmp_path):
    install_root = tmp_path / "iroot"
    install_root.mkdir()
    for var in ("IDA_MCP_EMBED_SERVER_BIN", "IDA_MCP_EMBED_MODEL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(core, "_install_root", lambda: str(install_root))
    monkeypatch.setattr(core, "CACHE_DIR", str(install_root))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(install_root))
    probe = tmp_path / "model.gguf"
    probe.write_bytes(b"gguf")
    monkeypatch.setenv("IDA_MCP_EMBED_MODEL", str(probe))
    _raise_once_expanduser(monkeypatch)
    assert core._find_model() == ""


def test_reject_symlinked_state_path(tmp_path):
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(RuntimeError, match="symlinked"):
        core._reject_symlinked_state_path(str(link / "embedder.json"))


def test_write_embedder_state_minimal_and_cleanup(monkeypatch, tmp_path):
    with pytest.raises(TypeError):
        core.write_embedder_state(tmp_path, rerank={"k": object()})
    assert not list(tmp_path.glob(".embedder.*.tmp"))
    assert not (tmp_path / "embedder.json").exists()
    state_path = core.write_embedder_state(tmp_path)
    assert state_path == str(tmp_path / "embedder.json")


def test_status_probe_lease_absent(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, use_llama=False, ready=False)
    obj._port = None
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(tmp_path / "no-lease.json"))
    result = obj.status(probe=True)
    assert result["use_llama"] is False
    assert result["backend"] == obj.backend


def test_start_server_locked_without_paths(monkeypatch, tmp_path):
    obj = _embedder(tmp_path, use_llama=False, ready=False)
    obj._read_lease = lambda: None
    monkeypatch.setattr(core, "_find_llama_server", lambda: "")
    monkeypatch.setattr(core, "_find_model", lambda: "")
    monkeypatch.setattr(core, "_read_embedder_state", dict)
    assert obj._start_server_locked() is False


def _locked_server_harness(monkeypatch, tmp_path, *, urlopen):
    obj = _embedder(tmp_path, use_llama=True, ready=False)
    obj._read_lease = lambda: None
    monkeypatch.setattr(obj, "_pick_port", lambda: 19091)
    monkeypatch.setattr(core.subprocess, "Popen", lambda *a, **k: _Process())
    monkeypatch.setattr(core.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(core.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(core, "_process_start_token", lambda _pid: "token")
    monkeypatch.setattr(core, "_process_rss_bytes", lambda _pid: 42)
    return obj


def test_start_server_health_retry_then_lease(monkeypatch, tmp_path):
    calls = {"count": 0}

    def _flaky_urlopen(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("cold")
        return _Response(b'{"status":"ok"}')

    obj = _locked_server_harness(monkeypatch, tmp_path, urlopen=_flaky_urlopen)
    monkeypatch.setattr(obj, "_lease_identity", dict)
    published = []
    monkeypatch.setattr(obj, "_write_lease", published.append)
    assert obj._start_server_locked() is True
    assert calls["count"] == 2
    assert published and published[0]["port"] == 19091


def test_start_server_lease_write_failure_suppressed(monkeypatch, tmp_path):
    obj = _locked_server_harness(
        monkeypatch,
        tmp_path,
        urlopen=lambda *_a, **_k: _Response(b'{"status":"ok"}'),
    )

    def _boom(_payload):
        raise OSError("lease gone")

    monkeypatch.setattr(obj, "_write_lease", _boom)
    assert obj._start_server_locked() is True


def test_start_server_health_not_ready_then_lease(monkeypatch, tmp_path):
    calls = {"count": 0}

    def _warming_urlopen(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return _Response(b'{"status":"loading"}')
        return _Response(b'{"status":"ok"}')

    obj = _locked_server_harness(monkeypatch, tmp_path, urlopen=_warming_urlopen)
    monkeypatch.setattr(obj, "_lease_identity", dict)
    published = []
    monkeypatch.setattr(obj, "_write_lease", published.append)
    assert obj._start_server_locked() is True
    assert calls["count"] == 2
    assert published and published[0]["port"] == 19091


def test_embed_batch_empty_chunk_after_recycle(tmp_path):
    obj = _embedder(tmp_path, use_llama=True, ready=False)
    obj._batch_size = 0
    obj._last_recycle_reason = "recycled"
    results = obj.embed_batch(["alpha", "beta"])
    assert [r.ok for r in results] == [False, False]


def test_ensure_ready_propagates_start_failure(tmp_path):
    obj = _embedder(tmp_path, use_llama=False, ready=False)
    obj._start_server = lambda: False
    assert obj.ensure_ready() is False


def test_embed_query_forwards_purpose(tmp_path):
    from ida_pro_mcp.host.intelligence.helpers import _EmbedResult

    obj = _embedder(tmp_path, use_llama=False, ready=False)
    seen = {}

    def _fake_embed(text, purpose="document"):
        seen["purpose"] = purpose
        return _EmbedResult([1.0], "test", True)

    obj.embed = _fake_embed
    result = obj.embed_query("hello")
    assert seen["purpose"] == "query"
    assert result.vector == [1.0]


def test_classifier_instance_rebinds_backend(tmp_path):
    cls = core.BehaviorClassifier
    saved = cls._shared
    cls._shared = None
    try:
        first = _embedder(tmp_path, use_llama=False, ready=False)
        second = _embedder(tmp_path, use_llama=False, ready=False)
        assert cls.instance(first) is cls.instance(first)
        assert cls.instance(second)._embedder is second
    finally:
        cls._shared = saved


def test_text_tokens_covers_identifiers_and_literals():
    tokens = core.BehaviorClassifier._text_tokens(
        "the CreateFileW socket_connect the_value 0x401000 %d .."
    )
    assert {"createfilew", "socket_connect", "0x401000", "%d", ".."} <= tokens
    assert "the" not in tokens


def test_config_import_fallback_chain():
    import ida_pro_mcp.host.intelligence.embeddings as embeddings_mod
    import ida_pro_mcp.host.intelligence.gemini as gemini_mod
    import ida_pro_mcp.host.intelligence.helpers as helpers_mod
    import ida_pro_mcp.host.intelligence.model_profiles as profiles_mod

    pkg = types.ModuleType("fbpkg")
    pkg.__path__ = []
    sys.modules["fbpkg"] = pkg
    for name, mod in (
        ("fbpkg.embeddings", embeddings_mod),
        ("fbpkg.gemini", gemini_mod),
        ("fbpkg.helpers", helpers_mod),
        ("fbpkg.model_profiles", profiles_mod),
    ):
        sys.modules[name] = mod
    try:
        spec = importlib.util.spec_from_file_location(
            "fbpkg.core_fb", os.path.join(os.path.dirname(core.__file__), "core.py")
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        for name in (
            "fbpkg.core_fb",
            "fbpkg.embeddings",
            "fbpkg.gemini",
            "fbpkg.helpers",
            "fbpkg.model_profiles",
            "fbpkg",
        ):
            sys.modules.pop(name, None)
    tail = os.path.join(".local", "state", "ida-pro-mcp")
    assert module.CACHE_DIR.endswith(tail)
    assert module._EMBED_LEASE_FILE.startswith(module.CACHE_DIR)
