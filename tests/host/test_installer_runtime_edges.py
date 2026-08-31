"""Boundary and failure-path tests for installer runtime helpers.

These tests exercise the installer through its filesystem, URL, and process
boundaries.  No real download, IDA install, or external tool is required.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest


class _Response:
    def __init__(self, body: bytes = b"", *, headers: dict[str, str] | None = None, error: Exception | None = None):
        self._body = body
        self.headers = headers or {}
        self._error = error
        self._read = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size: int = -1) -> bytes:
        if self._error is not None:
            raise self._error
        if self._read:
            return b""
        self._read = True
        return self._body


def _profile_with_test_digest(monkeypatch, module_name: str, key: str, body: bytes):
    module = __import__(module_name, fromlist=["MODEL_PROFILES"])
    profiles = (
        module.MODEL_PROFILES
        if hasattr(module, "MODEL_PROFILES")
        else module.RERANK_MODEL_PROFILES
    )
    profile = profiles[key]
    patched = replace(
        profile,
        download_sha256=hashlib.sha256(body).hexdigest(),
        download_size=len(body),
    )
    monkeypatch.setitem(profiles, key, patched)
    return patched


def test_download_embed_model_reuses_existing_nonempty_file(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.runtime import download_embed_model

    selected = _profile_with_test_digest(
        monkeypatch,
        "ida_pro_mcp.host.intelligence.model_profiles",
        "zembed-1",
        b"already-installed",
    )
    assert selected is not None
    destination = tmp_path / "models" / selected.download_filename
    destination.parent.mkdir()
    destination.write_bytes(b"already-installed")
    monkeypatch.setattr(
        "ida_pro_mcp.installer.runtime.urllib.request.urlopen",
        lambda *_args, **_kwargs: pytest.fail("existing model must not be downloaded"),
    )

    assert download_embed_model(tmp_path, "zembed-1") == str(destination)


def test_download_embed_model_cleans_partial_file_when_stream_fails(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence.model_profiles import get_model_profile
    from ida_pro_mcp.installer.runtime import download_embed_model

    selected = get_model_profile("zembed-1")
    assert selected is not None
    response = _Response(b"partial", error=RuntimeError("connection reset"))
    monkeypatch.setattr(
        "ida_pro_mcp.installer.runtime.urllib.request.urlopen",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(RuntimeError, match="connection reset"):
        download_embed_model(tmp_path, "zembed-1")

    destination = tmp_path / "models" / selected.download_filename
    assert not destination.exists()
    assert not destination.with_suffix(destination.suffix + ".part").exists()


def test_download_embed_model_rejects_declared_oversize_before_reading(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.runtime import download_embed_model

    response = _Response(b"should-not-be-read", headers={"Content-Length": str(8 * 1024**3 + 1)})
    monkeypatch.setattr(
        "ida_pro_mcp.installer.runtime.urllib.request.urlopen",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(RuntimeError, match="8 GiB safety limit"):
        download_embed_model(tmp_path, "zembed-1")

    assert not list((tmp_path / "models").glob("*.part"))
    assert response._read is False


def test_download_embed_model_rejects_symlinked_models_directory(tmp_path):
    from ida_pro_mcp.installer.runtime import download_embed_model

    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "models").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symlinked managed model path"):
        download_embed_model(tmp_path, "zembed-1")


def test_download_embed_model_rejects_empty_body_and_cleans_partial(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.runtime import download_embed_model

    monkeypatch.setattr(
        "ida_pro_mcp.installer.runtime.urllib.request.urlopen",
        lambda *_args, **_kwargs: _Response(b""),
    )

    with pytest.raises(RuntimeError, match="download was empty"):
        download_embed_model(tmp_path, "zembed-1")

    assert not list((tmp_path / "models").glob("*.part"))


def test_download_rerank_model_streams_to_install_root(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.runtime import download_rerank_model

    body = b"reranker-gguf"
    selected = _profile_with_test_digest(
        monkeypatch,
        "ida_pro_mcp.host.intelligence.rerank_profiles",
        "qwen3-reranker-0.6b",
        body,
    )
    monkeypatch.setattr(
        "ida_pro_mcp.installer.runtime.urllib.request.urlopen",
        lambda *_args, **_kwargs: _Response(body, headers={"Content-Length": str(len(body))}),
    )

    result = download_rerank_model(tmp_path, "qwen3-reranker-0.6b")

    assert result == str(tmp_path / "models" / selected.download_filename)
    assert Path(result).read_bytes() == body
    assert not list((tmp_path / "models").glob("*.part"))


def test_download_helpers_reject_unknown_or_unmanaged_profiles(tmp_path):
    from ida_pro_mcp.installer.runtime import download_embed_model, download_rerank_model

    with pytest.raises(RuntimeError, match="Unknown embedding profile"):
        download_embed_model(tmp_path, "does-not-exist")
    with pytest.raises(RuntimeError, match="Unknown rerank profile"):
        download_rerank_model(tmp_path, "does-not-exist")


def test_find_model_and_server_honor_valid_environment_overrides(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.runtime import find_embed_model, find_llama_server_bin, find_rerank_model

    embed = tmp_path / "embed.gguf"
    rerank = tmp_path / "rerank.gguf"
    server = tmp_path / "llama-server"
    for path in (embed, rerank, server):
        path.write_bytes(b"x")
    server.chmod(0o755)
    monkeypatch.setenv("IDA_MCP_EMBED_MODEL", str(embed))
    monkeypatch.setenv("IDA_MCP_RERANK_MODEL", str(rerank))
    monkeypatch.setenv("IDA_MCP_EMBED_SERVER_BIN", str(server))

    assert find_embed_model(tmp_path, "zembed-1") == str(embed)
    assert find_rerank_model(tmp_path) == str(rerank)
    assert find_llama_server_bin(tmp_path) == str(server)


def test_find_helpers_use_state_from_explicit_install_root(tmp_path, monkeypatch):
    """A custom install must not inherit state from the default install."""
    from ida_pro_mcp.installer.runtime import (
        find_embed_model,
        find_llama_server_bin,
        find_rerank_model,
    )

    target_root = tmp_path / "target-install"
    foreign_root = tmp_path / "foreign-install"
    target_root.mkdir()
    foreign_root.mkdir()

    target_embed = target_root / "qwen3-embedding-0.6b-q4_k_m.gguf"
    foreign_embed = foreign_root / "qwen3-embedding-0.6b-q4_k_m.gguf"
    target_rerank = target_root / "qwen3-reranker-0.6b-q4_k_m.gguf"
    foreign_rerank = foreign_root / "qwen3-reranker-0.6b-q4_k_m.gguf"
    target_server = target_root / "target-llama-server"
    foreign_server = foreign_root / "foreign-llama-server"
    for path in (target_embed, foreign_embed, target_rerank, foreign_rerank):
        path.write_bytes(b"model")
    for path in (target_server, foreign_server):
        path.write_bytes(b"server")
        path.chmod(0o755)

    target_state = {
        "profile": "qwen3-embedding-0.6b",
        "model_path": str(target_embed),
        "server_bin": str(target_server),
        "rerank": {
            "profile": "qwen3-reranker-0.6b",
            "model_path": str(target_rerank),
        },
    }
    foreign_state = {
        "profile": "qwen3-embedding-0.6b",
        "model_path": str(foreign_embed),
        "server_bin": str(foreign_server),
        "rerank": {
            "profile": "qwen3-reranker-0.6b",
            "model_path": str(foreign_rerank),
        },
    }
    (target_root / "embedder.json").write_text(json.dumps(target_state), encoding="utf-8")
    (foreign_root / "embedder.json").write_text(json.dumps(foreign_state), encoding="utf-8")

    monkeypatch.setenv("IDA_PRO_MCP_HOME", str(foreign_root))
    for name in (
        "IDA_MCP_EMBED_MODEL",
        "IDA_MCP_RERANK_MODEL",
        "IDA_MCP_EMBED_SERVER_BIN",
        "IDA_MCP_EMBED_PROFILE",
        "IDA_MCP_RERANK_PROFILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("ida_pro_mcp.installer.runtime.shutil.which", lambda _name: None)

    assert find_embed_model(target_root, "qwen3-embedding-0.6b") == str(target_embed)
    assert find_rerank_model(target_root, "qwen3-reranker-0.6b") == str(target_rerank)
    assert find_llama_server_bin(target_root) == str(target_server)


def test_find_llama_server_ignores_non_executable_environment_override(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence import core
    from ida_pro_mcp.installer.runtime import find_llama_server_bin

    monkeypatch.setenv("IDA_MCP_EMBED_SERVER_BIN", str(tmp_path / "not-executable"))
    monkeypatch.setattr(core, "_read_embedder_state", dict)
    monkeypatch.setattr(core, "_select_state_path", lambda _value: "")
    candidate = tmp_path / "bin" / "llama-server"
    candidate.parent.mkdir()
    candidate.write_bytes(b"server")
    candidate.chmod(0o755)
    monkeypatch.setattr("ida_pro_mcp.installer.runtime.shutil.which", lambda _name: None)

    assert find_llama_server_bin(tmp_path) == str(candidate)


def test_find_rerank_model_does_not_fallback_to_a_different_selected_profile(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.runtime import find_rerank_model

    monkeypatch.delenv("IDA_MCP_RERANK_MODEL", raising=False)
    monkeypatch.delenv("IDA_MCP_RERANK_PROFILE", raising=False)
    models = tmp_path / "models"
    models.mkdir()
    (models / "qwen3-reranker-0.6b-q8_0.gguf").write_bytes(b"wrong-profile")

    assert find_rerank_model(tmp_path, "qwen3-reranker-4b") == ""

    selected = models / "Qwen3-Reranker-4B-Q4_K_M.gguf"
    selected.write_bytes(b"selected-profile")
    assert find_rerank_model(tmp_path, "qwen3-reranker-4b") == str(selected)


def test_find_embed_model_searches_selected_profile_under_models(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.runtime import find_embed_model

    monkeypatch.delenv("IDA_MCP_EMBED_MODEL", raising=False)
    monkeypatch.delenv("IDA_MCP_EMBED_PROFILE", raising=False)
    model = tmp_path / "models" / "zembed-1-Q4_K_M.gguf"
    model.parent.mkdir()
    model.write_bytes(b"model")

    assert find_embed_model(tmp_path, "zembed-1") == str(model)


def test_find_llama_server_prefers_install_root_bin_and_requires_executable(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence import core
    from ida_pro_mcp.installer.runtime import find_llama_server_bin

    monkeypatch.delenv("IDA_MCP_EMBED_SERVER_BIN", raising=False)
    monkeypatch.setattr(core, "_read_embedder_state", dict)
    monkeypatch.setattr(core, "_select_state_path", lambda _value: "")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    candidate = bin_dir / "llama-server"
    candidate.write_bytes(b"server")
    candidate.chmod(0o755)
    monkeypatch.setattr("ida_pro_mcp.installer.runtime.shutil.which", lambda _name: None)

    assert find_llama_server_bin(tmp_path) == str(candidate)


def test_run_checked_returns_process_result_and_reports_stderr(monkeypatch):
    from ida_pro_mcp.installer.runtime import run_checked

    completed = SimpleNamespace(returncode=0, stdout="output", stderr="")
    monkeypatch.setattr("ida_pro_mcp.installer.runtime.subprocess.run", lambda *args, **kwargs: completed)
    assert run_checked(["tool", "--flag"]).stdout == "output"

    failed = SimpleNamespace(returncode=3, stdout="", stderr="line one\nline two\n")
    monkeypatch.setattr("ida_pro_mcp.installer.runtime.subprocess.run", lambda *args, **kwargs: failed)
    with pytest.raises(RuntimeError, match=r"tool --flag failed \(3\): line one \| line two"):
        run_checked(["tool", "--flag"])


def test_run_checked_converts_timeout_to_runtime_error(monkeypatch):
    import subprocess

    from ida_pro_mcp.installer.runtime import run_checked

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(["hung"], 2)

    monkeypatch.setattr("ida_pro_mcp.installer.runtime.subprocess.run", timeout)
    with pytest.raises(RuntimeError, match=r"hung timed out after 2s"):
        run_checked(["hung"], timeout=2)


def test_setup_runtime_rejects_symlinked_venv_path(tmp_path):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import setup_runtime_environment

    outside = tmp_path / "outside"
    outside.mkdir()
    install_root = tmp_path / "install"
    install_root.mkdir()
    (install_root / ".venv").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symlinked runtime environment path"):
        setup_runtime_environment(
            install_root,
            tmp_path,
            "snapshot",
            dry_run=True,
            report=InstallReport(),
        )


def test_archive_extraction_accepts_safe_zip_and_rejects_zip_slip(tmp_path):
    from ida_pro_mcp.installer.runtime import _extract_archive

    safe = tmp_path / "safe.zip"
    with zipfile.ZipFile(safe, "w") as archive:
        archive.writestr("nested/llama-server", b"binary")
    out = tmp_path / "out"
    out.mkdir()
    _extract_archive(safe, out)
    assert (out / "nested" / "llama-server").read_bytes() == b"binary"

    malicious = tmp_path / "bad.zip"
    with zipfile.ZipFile(malicious, "w") as archive:
        archive.writestr("../outside", b"escaped")
    with pytest.raises(RuntimeError, match="absolute or traversal path"):
        _extract_archive(malicious, tmp_path / "bad-out")
    assert not (tmp_path / "outside").exists()


def test_archive_extraction_rejects_tar_link_outside_root(tmp_path):
    from ida_pro_mcp.installer.runtime import _extract_archive

    malicious = tmp_path / "bad.tar.gz"
    with tarfile.open(malicious, "w:gz") as archive:
        link = tarfile.TarInfo("safe-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)

    with pytest.raises(RuntimeError, match="non-regular tar member"):
        _extract_archive(malicious, tmp_path / "tar-out")


def test_download_llama_server_uses_selected_asset_and_writes_binary(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import download_and_install_llama_server

    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        archive.writestr("llama-bin/llama-server", b"server-binary")
    archive_body = archive_bytes.getvalue()
    archive_sha256 = hashlib.sha256(archive_body).hexdigest()
    release = {
        "assets": [
            {
                "name": "llama-b123-bin-ubuntu-x64.zip",
                "browser_download_url": "https://github.com/ggml-org/llama.cpp/releases/download/b123/llama-b123-bin-ubuntu-x64.zip",
                "digest": f"sha256:{archive_sha256}",
                "size": len(archive_body),
            },
            {
                "name": "llama-b123-bin-win-cuda.zip",
                "browser_download_url": "https://github.com/ggml-org/llama.cpp/releases/download/b123/llama-b123-bin-win-cuda.zip",
                "digest": f"sha256:{'0' * 64}",
            },
        ]
    }
    responses = iter([
        _Response(json.dumps(release).encode()),
        _Response(archive_body, headers={"Content-Length": str(len(archive_body))}),
    ])
    monkeypatch.setattr(
        "ida_pro_mcp.installer.runtime.urllib.request.urlopen",
        lambda *_args, **_kwargs: next(responses),
    )
    report = InstallReport()

    result = download_and_install_llama_server(tmp_path, dry_run=False, report=report)

    target = tmp_path / "bin" / "llama-server"
    assert result == str(target)
    assert target.read_bytes() == b"server-binary"
    assert report.metadata["llama_server_asset"] == "llama-b123-bin-ubuntu-x64.zip"
    assert report.steps[-1]["status"] == "ok"


def test_download_llama_server_dry_run_and_existing_binary_skip_network(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import download_and_install_llama_server

    report = InstallReport()
    dry_result = download_and_install_llama_server(tmp_path, dry_run=True, report=report)
    assert dry_result == str(tmp_path / "bin" / "llama-server")
    assert report.steps[-1]["status"] == "dry-run"

    target = tmp_path / "bin" / "llama-server"
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(b"existing")
    target.chmod(0o755)
    monkeypatch.setattr(
        "ida_pro_mcp.installer.runtime.urllib.request.urlopen",
        lambda *_args, **_kwargs: pytest.fail("existing server must not be downloaded"),
    )
    assert download_and_install_llama_server(tmp_path, dry_run=False, report=InstallReport()) == str(target)


def test_download_llama_server_rejects_symlinked_bin_directory(tmp_path):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import download_and_install_llama_server

    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "bin").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symlinked managed llama-server path"):
        download_and_install_llama_server(tmp_path, dry_run=True, report=InstallReport())


def test_download_llama_server_rejects_missing_or_unsuitable_assets(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import download_and_install_llama_server

    for payload in ({}, {"assets": []}, {"assets": [{"name": "source.tar.gz", "browser_download_url": "x"}]}):
        monkeypatch.setattr(
            "ida_pro_mcp.installer.runtime.urllib.request.urlopen",
            lambda _request, payload=payload, **_kwargs: _Response(json.dumps(payload).encode()),
        )
        with pytest.raises(RuntimeError):
            download_and_install_llama_server(tmp_path / str(len(payload)), dry_run=False, report=InstallReport())


def test_discovery_version_parser_and_binary_architecture_edges(tmp_path):
    from ida_pro_mcp.installer.discovery import _binary_arch, parse_version

    assert parse_version("9.3rc2") == (9, 3, 2)
    assert parse_version("release-without-digits") == (0,)
    assert parse_version("IDA 9.3.260421") == (9, 3, 260421)

    elf64 = tmp_path / "elf64"
    elf64.write_bytes(b"\x7fELF\x02" + b"\x00" * 13 + (0xB7).to_bytes(2, "little"))
    assert _binary_arch(elf64) == "arm64"
    unknown = tmp_path / "unknown"
    unknown.write_bytes(b"not-a-binary")
    assert _binary_arch(unknown) == "unknown"
