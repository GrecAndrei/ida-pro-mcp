"""Exercise installer runtime helpers through process and filesystem boundaries."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from ida_pro_mcp.installer import runtime
from ida_pro_mcp.installer.common import InstallReport


def test_kill_ida_processes_keeps_explicit_scope_on_posix_and_windows(tmp_path, monkeypatch):
    target = tmp_path / "idat64"
    target.write_text("binary", encoding="ascii")
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "pgrep":
            return subprocess.CompletedProcess(cmd, 0, stdout=f"123 {target} -A\n124 /other/idat64\n", stderr="")
        if cmd[0] == "wmic":
            return subprocess.CompletedProcess(cmd, 0, stdout=f"Node,{target},123\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(runtime.subprocess, "run", run)
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    assert runtime.kill_ida_processes(target) is True
    assert ["kill", "-KILL", "123"] in calls
    assert not any(cmd[:2] == ["kill", "-KILL"] and cmd[-1] == "124" for cmd in calls)

    calls.clear()
    assert runtime.kill_ida_processes() is True
    assert ["pkill", "-x", "idat"] in calls

    monkeypatch.setattr(runtime.sys, "platform", "win32")
    calls.clear()
    assert runtime.kill_ida_processes(target) is True
    assert any(cmd[:3] == ["taskkill", "/F", "/PID"] for cmd in calls)
    calls.clear()
    assert runtime.kill_ida_processes() is True
    assert ["taskkill", "/F", "/IM", "idat.exe"] in calls

    def failed(*_args, **_kwargs):
        raise OSError("pgrep unavailable")

    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime.subprocess, "run", failed)
    assert runtime.kill_ida_processes(target) is False


def test_download_copy_and_validation_helpers_are_atomic(tmp_path, monkeypatch):
    body = b"safe download"
    destination = tmp_path / "download.bin"

    class Response:
        headers = {"Content-Length": str(len(body))}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, size=-1):
            nonlocal body
            chunk, body = body, b""
            return chunk

    monkeypatch.setattr(runtime.urllib.request, "urlopen", lambda *_args, **_kwargs: Response())
    digest = hashlib.sha256(b"safe download").hexdigest()
    count, actual = runtime._download_to_file(
        runtime.urllib.request.Request("https://example.test/file"),
        destination,
        timeout=1,
        max_bytes=100,
        label="test",
        expected_sha256=f"sha256:{digest}",
        expected_size=len(b"safe download"),
    )
    assert count == len(b"safe download") and actual == digest
    assert destination.read_bytes() == b"safe download"
    with pytest.raises(RuntimeError, match="invalid expected SHA"):
        runtime._download_to_file(
            runtime.urllib.request.Request("https://example.test/file"),
            tmp_path / "bad.bin",
            timeout=1,
            max_bytes=100,
            label="test",
            expected_sha256="bad",
        )
    source = tmp_path / "source.txt"
    source.write_text("source", encoding="utf-8")
    copied = tmp_path / "nested" / "copy.txt"
    runtime._copy_file_atomically(source, copied)
    assert copied.read_text(encoding="utf-8") == "source"
    with pytest.raises(FileExistsError):
        runtime._copy_file_atomically(source, copied, overwrite=False)
    assert runtime._normalise_sha256("bad") == ""
    with pytest.raises(RuntimeError, match="untrusted"):
        runtime._validate_https_host("http://example.test/a", "example.test")


def test_snapshot_and_local_pth_setup_prune_stale_runtime_files(tmp_path, monkeypatch):
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "module.py").write_text("value = 1", encoding="utf-8")
    (source / ".coverage").write_text("machine output", encoding="utf-8")
    install = tmp_path / "install"
    report = InstallReport()
    dry = runtime._snapshot_source(source, install, True, report)
    assert not dry.exists() and report.steps[-1]["status"] == "dry-run"
    snapshot = runtime._snapshot_source(source, install, False, report)
    assert (snapshot / "src" / "module.py").exists()
    assert not (snapshot / ".coverage").exists()

    venv = install / ".venv"
    site = tmp_path / "site-packages"
    stale_pkg = site / "ida_pro_mcp"
    stale_dist = site / "ida_pro_mcp-1.dist-info"
    stale_pkg.mkdir(parents=True)
    stale_dist.mkdir()
    monkeypatch.setattr(runtime, "_venv_python_exe", lambda _venv: tmp_path / "python")
    monkeypatch.setattr(
        runtime,
        "run_checked",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout=f"{site}\n", stderr=""),
    )
    pth = runtime._write_dev_pth(venv, source, False, report)
    assert pth.read_text(encoding="utf-8").strip() == str(source / "src")
    assert not stale_pkg.exists() and not stale_dist.exists()
    runtime._remove_dev_pth(venv, report)
    assert not pth.exists()


def test_model_and_server_discovery_handles_env_and_profile_search(tmp_path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"model")
    server = tmp_path / "llama-server"
    server.write_bytes(b"server")
    server.chmod(0o755)
    monkeypatch.setenv("IDA_MCP_EMBED_MODEL", str(model))
    assert runtime.find_embed_model(tmp_path, "qwen3-embedding-0.6b") == str(model)
    monkeypatch.setenv("IDA_MCP_EMBED_SERVER_BIN", str(server))
    assert runtime.find_llama_server_bin(tmp_path) == str(server)
    monkeypatch.delenv("IDA_MCP_EMBED_SERVER_BIN")
    monkeypatch.setattr(runtime.shutil, "which", lambda _name: None)
    monkeypatch.setattr(runtime.os, "access", lambda *_args: False)
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core._read_embedder_state",
        dict,
    )
    assert runtime.find_llama_server_bin(tmp_path / "root" / "child") == ""
    monkeypatch.setenv("IDA_MCP_RERANK_MODEL", str(model))
    assert runtime.find_rerank_model(tmp_path) == str(model)
    assert runtime.choose_runtime_source("auto", tmp_path / "missing") == "pypi"
