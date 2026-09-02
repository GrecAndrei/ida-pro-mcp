"""Deep, offline coverage for installer runtime modes.

The installer is mostly boundary code.  These tests keep those boundaries
hermetic while exercising the combinations that are easy to miss in a happy
path-only suite: platform discovery, verification failures, stale runtimes,
and the generated client environment.
"""

from __future__ import annotations

import io
import subprocess
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from ida_pro_mcp.installer import runtime
from ida_pro_mcp.installer.common import InstallReport


class _Response:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None):
        self.body = body
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size: int = -1) -> bytes:
        body, self.body = self.body, b""
        return body


def _request() -> object:
    return runtime.urllib.request.Request("https://example.test/payload")


def test_download_to_file_validates_declared_received_and_stream_sizes(tmp_path, monkeypatch):
    destination = tmp_path / "payload.bin"

    monkeypatch.setattr(
        runtime.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(
            b"abc", {"Content-Length": "not-a-number"}
        ),
    )
    with pytest.raises(RuntimeError, match="received 3 bytes, expected 4"):
        runtime._download_to_file(
            _request(), destination, timeout=1, max_bytes=10, label="payload", expected_size=4
        )
    assert not destination.exists()

    monkeypatch.setattr(
        runtime.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b"abc", {"Content-Length": "3"}),
    )
    with pytest.raises(RuntimeError, match="declared 3 bytes, expected 4"):
        runtime._download_to_file(
            _request(), destination, timeout=1, max_bytes=10, label="payload", expected_size=4
        )

    monkeypatch.setattr(
        runtime.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b"0123456789x"),
    )
    with pytest.raises(RuntimeError, match="stream exceeded"):
        runtime._download_to_file(
            _request(), destination, timeout=1, max_bytes=10, label="payload"
        )
    assert not list(tmp_path.glob("*.part"))


def test_download_to_file_rejects_negative_budget_and_bad_expected_digest(tmp_path):
    with pytest.raises(ValueError, match="non-negative"):
        runtime._read_response_limited(io.BytesIO(b"x"), max_bytes=-1, label="metadata")
    with pytest.raises(RuntimeError, match="invalid expected SHA-256"):
        runtime._download_to_file(
            _request(), tmp_path / "payload", timeout=1, max_bytes=10,
            label="payload", expected_sha256="sha256:not-a-digest",
        )


def test_read_response_limited_handles_multiple_short_reads():
    class Chunks:
        def __init__(self):
            self.chunks = [b"first", b"second", b""]

        def read(self, _size):
            return self.chunks.pop(0)

    assert runtime._read_response_limited(Chunks(), max_bytes=20, label="metadata") == b"firstsecond"


def test_copy_file_atomically_cleans_up_copy_and_replace_failures(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"source")
    destination = tmp_path / "destination"

    monkeypatch.setattr(
        runtime.shutil,
        "copyfileobj",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("copy failed")),
    )
    with pytest.raises(OSError, match="copy failed"):
        runtime._copy_file_atomically(source, destination)
    assert not list(tmp_path.glob(".*.part"))

    monkeypatch.setattr(runtime.shutil, "copyfileobj", lambda source_file, output, **_kwargs: output.write(source_file.read()))
    monkeypatch.setattr(runtime.os, "replace", lambda *_args: (_ for _ in ()).throw(OSError("replace failed")))
    with pytest.raises(OSError, match="replace failed"):
        runtime._copy_file_atomically(source, destination)
    assert not list(tmp_path.glob(".*.part"))


def test_windows_install_root_and_binary_names(monkeypatch, tmp_path):
    monkeypatch.delenv("IDA_PRO_MCP_HOME", raising=False)
    monkeypatch.setattr(runtime.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert runtime.get_install_root() == tmp_path / "local" / "ida-pro-mcp"
    assert runtime._ida_binary_names() == ["idat64.exe", "idat.exe", "ida64.exe", "ida.exe"]


def test_kill_ida_processes_ignores_malformed_process_records(tmp_path, monkeypatch):
    target = tmp_path / "idat64"
    target.write_bytes(b"ida")
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        if command[0] == "pgrep":
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="bad\nnotpid /x\n123\n124 /other/idat64\n125 " + str(target) + " --ok\n",
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(runtime.subprocess, "run", run)
    assert runtime.kill_ida_processes(target) is True
    assert ["kill", "-KILL", "125"] in calls

    monkeypatch.setattr(runtime.sys, "platform", "win32")
    calls.clear()
    def wmic_run(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="Node,not-a-path,abc\nNode," + str(target) + ",126\nshort\n",
            stderr="",
        ) if command[0] == "wmic" else subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(runtime.subprocess, "run", wmic_run)
    assert runtime.kill_ida_processes(target) is True
    assert ["taskkill", "/F", "/PID", "126"] in calls


def test_find_embed_model_survives_broken_state_and_uses_profile_fallback(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence import core

    monkeypatch.delenv("IDA_MCP_EMBED_MODEL", raising=False)
    monkeypatch.delenv("IDA_MCP_EMBED_SEARCH_PATHS", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(core, "_read_embedder_state", lambda: (_ for _ in ()).throw(OSError("bad state")))
    model = tmp_path / "models" / "zembed-1-Q4_K_M.gguf"
    model.parent.mkdir()
    model.write_bytes(b"model")
    assert runtime.find_embed_model(tmp_path, "zembed-1") == str(model)


def test_download_model_rejects_unpinned_profiles_and_symlink_destinations(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence import model_profiles

    original = model_profiles.MODEL_PROFILES["qwen3-embedding-0.6b"]
    monkeypatch.setitem(model_profiles.MODEL_PROFILES, "qwen3-embedding-0.6b", replace(original, download_sha256=""))
    with pytest.raises(RuntimeError, match="missing a pinned"):
        runtime.download_embed_model(tmp_path, "qwen3-embedding-0.6b")
    monkeypatch.setitem(model_profiles.MODEL_PROFILES, "qwen3-embedding-0.6b", original)
    destination = tmp_path / "models" / original.download_filename
    destination.parent.mkdir()
    link_target = tmp_path / "target.gguf"
    link_target.write_bytes(b"target")
    destination.symlink_to(link_target)
    with pytest.raises(RuntimeError, match="managed model path symlink"):
        runtime.download_embed_model(tmp_path, "qwen3-embedding-0.6b")


def test_download_rerank_rejects_bad_digest_and_symlink_destination(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence import rerank_profiles

    original = rerank_profiles.RERANK_MODEL_PROFILES["qwen3-reranker-0.6b"]
    monkeypatch.setitem(rerank_profiles.RERANK_MODEL_PROFILES, "qwen3-reranker-0.6b", replace(original, download_size=0))
    with pytest.raises(RuntimeError, match="missing a pinned"):
        runtime.download_rerank_model(tmp_path, "qwen3-reranker-0.6b")
    monkeypatch.setitem(rerank_profiles.RERANK_MODEL_PROFILES, "qwen3-reranker-0.6b", original)
    destination = tmp_path / "models" / original.download_filename
    destination.parent.mkdir()
    destination.symlink_to(tmp_path / "target-rerank.gguf")
    with pytest.raises(RuntimeError, match="managed model path symlink"):
        runtime.download_rerank_model(tmp_path, "qwen3-reranker-0.6b")


def test_find_llama_server_uses_windows_extension_rules_and_path_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("IDA_MCP_EMBED_SERVER_BIN", raising=False)
    monkeypatch.setattr(runtime.sys, "platform", "win32")
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "programs"))
    candidate = tmp_path / "programs" / "llama.cpp" / "bin" / "llama-server.exe"
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(b"server")
    monkeypatch.setattr(runtime.shutil, "which", lambda _name: None)
    assert runtime.find_llama_server_bin(tmp_path / "missing") == str(candidate)

    candidate.unlink()
    monkeypatch.setattr(runtime.shutil, "which", lambda name: str(tmp_path / "llama-server.cmd") if name == "llama-server.exe" else None)
    path_candidate = tmp_path / "llama-server.cmd"
    path_candidate.write_bytes(b"server")
    assert runtime.find_llama_server_bin(tmp_path / "missing") == str(path_candidate)


def test_extract_archive_handles_safe_tar_and_existing_symlink(tmp_path):
    archive = tmp_path / "safe.tgz"
    import tarfile

    with tarfile.open(archive, "w:gz") as tar:
        directory = tarfile.TarInfo("nested/")
        directory.type = tarfile.DIRTYPE
        tar.addfile(directory)
        data = b"tar payload"
        member = tarfile.TarInfo("nested/file.bin")
        member.size = len(data)
        tar.addfile(member, io.BytesIO(data))
    output = tmp_path / "output"
    runtime._extract_archive(archive, output)
    assert (output / "nested" / "file.bin").read_bytes() == b"tar payload"

    zip_path = tmp_path / "existing-link.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("file", b"overwrite")
    existing = tmp_path / "link-output" / "file"
    existing.parent.mkdir(parents=True)
    existing.symlink_to(tmp_path / "outside")
    with pytest.raises(RuntimeError, match="outside extract root"):
        runtime._extract_archive(zip_path, existing.parent)


def test_install_root_and_ida_detection_cover_environment_path_and_platform(tmp_path, monkeypatch):
    monkeypatch.delenv("IDA_PRO_MCP_HOME", raising=False)
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime.Path, "home", staticmethod(lambda: tmp_path / "home"))
    assert runtime.get_install_root() == tmp_path / "home" / ".local" / "share" / "ida-pro-mcp"

    override = tmp_path / "custom"
    monkeypatch.setenv("IDA_PRO_MCP_HOME", str(override))
    assert runtime.get_install_root() == override

    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    ida_binary = ida_dir / "idat64"
    ida_binary.write_bytes(b"ida")
    monkeypatch.delenv("IDA_PRO_MCP_HOME", raising=False)
    monkeypatch.setenv("IDADIR", str(ida_dir))
    assert runtime.detect_ida_install_dir() == ida_dir.resolve()
    ida_file = tmp_path / "idat-file"
    ida_file.write_bytes(b"ida")
    monkeypatch.setenv("IDADIR", str(ida_file))
    assert runtime.detect_ida_install_dir() == tmp_path.resolve()

    monkeypatch.setenv("IDADIR", str(tmp_path / "missing"))
    monkeypatch.setenv("IDA_DIR", str(tmp_path / "also-missing"))
    monkeypatch.delenv("IDA_MCP_IDAT", raising=False)
    monkeypatch.setattr(runtime, "_ida_binary_names", lambda: ["idat64", "ida64"])
    monkeypatch.setattr(runtime.shutil, "which", lambda name: str(ida_binary) if name == "idat64" else None)
    assert runtime.detect_ida_install_dir() == ida_dir.resolve()

    monkeypatch.setattr(runtime.shutil, "which", lambda _name: None)
    assert runtime.detect_ida_install_dir() is None


def test_kill_ida_processes_fails_closed_and_accepts_empty_posix_enumeration(tmp_path, monkeypatch):
    target = tmp_path / "idat64"
    target.write_bytes(b"ida")
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    calls = []

    def run_empty(command, **_kwargs):
        calls.append(command)
        if command[0] == "pgrep":
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(runtime.subprocess, "run", run_empty)
    assert runtime.kill_ida_processes(target) is True
    assert not any(command[0] == "kill" for command in calls)

    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 2, stdout="", stderr="")
        if command[0] == "pgrep"
        else subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )
    assert runtime.kill_ida_processes(target) is False

    monkeypatch.setattr(runtime.sys, "platform", "win32")
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 1, stdout="", stderr="")
        if command[0] == "wmic"
        else subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )
    assert runtime.kill_ida_processes(target) is False


def test_find_embed_model_uses_state_search_paths_hf_cache_and_recursive_fallback(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence import core

    monkeypatch.delenv("IDA_MCP_EMBED_MODEL", raising=False)
    monkeypatch.delenv("IDA_MCP_EMBED_PROFILE", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")
    monkeypatch.setattr(core, "_read_embedder_state", dict)
    monkeypatch.setattr(core, "_select_state_path", lambda value: value if value and Path(value).is_file() else "")

    extra = tmp_path / "extra"
    extra.mkdir()
    extra_model = extra / "qwen3-embedding-0.6b-Q4_K_M.gguf"
    extra_model.write_bytes(b"extra")
    monkeypatch.setenv("IDA_MCP_EMBED_SEARCH_PATHS", f"{extra}:{extra}:{tmp_path / 'missing'}")
    assert runtime.find_embed_model(tmp_path / "install", "qwen3-embedding-0.6b") == str(extra_model)

    extra_model.unlink()
    hf_model = (
        tmp_path / "home" / ".cache" / "huggingface" / "hub" /
        "models--org--embedding" / "snapshots" / "abcdef" /
        "qwen3-embedding-0.6b-Q4_K_M.gguf"
    )
    hf_model.parent.mkdir(parents=True)
    hf_model.write_bytes(b"hf")
    assert runtime.find_embed_model(tmp_path / "install", "qwen3-embedding-0.6b") == str(hf_model)

    hf_model.unlink()
    nested = tmp_path / "install" / "deep" / "nested" / "qwen3-embedding-0.6b-Q4_K_M.gguf"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(b"nested")
    assert runtime.find_embed_model(tmp_path / "install", "qwen3-embedding-0.6b") == str(nested)

    nested.unlink()
    assert runtime.find_embed_model(tmp_path / "install", "qwen3-embedding-0.6b") == ""


def test_find_embed_model_respects_matching_and_mismatching_state_profiles(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence import core

    manual = tmp_path / "manual.gguf"
    manual.write_bytes(b"manual")
    monkeypatch.delenv("IDA_MCP_EMBED_MODEL", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")
    monkeypatch.setattr(core, "_read_embedder_state", lambda: {"model_path": str(manual), "profile": "zembed-1"})
    monkeypatch.setattr(core, "_select_state_path", lambda value: value)
    assert runtime.find_embed_model(tmp_path / "install", "zembed-1") == str(manual)

    fallback = tmp_path / "install" / "models" / "zembed-1-Q4_K_M.gguf"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"fallback")
    assert runtime.find_embed_model(tmp_path / "install", "qwen3-embedding-0.6b") == ""
    assert runtime.find_embed_model(tmp_path / "install", "zembed-1") == str(manual)


def test_model_and_server_discovery_handles_state_and_managed_profile_errors(tmp_path, monkeypatch):
    from ida_pro_mcp.host.intelligence import core

    server = tmp_path / "state-server"
    server.write_bytes(b"server")
    server.chmod(0o755)
    monkeypatch.delenv("IDA_MCP_EMBED_SERVER_BIN", raising=False)
    monkeypatch.setattr(core, "_read_embedder_state", lambda: {"server_bin": str(server)})
    monkeypatch.setattr(core, "_select_state_path", lambda value: value)
    assert runtime.find_llama_server_bin(tmp_path / "install") == str(server)

    monkeypatch.setattr(core, "_read_embedder_state", lambda: (_ for _ in ()).throw(RuntimeError("bad state")))
    monkeypatch.setattr(runtime.shutil, "which", lambda _name: None)
    assert runtime.find_llama_server_bin(tmp_path / "install") == ""

    monkeypatch.setenv("IDA_MCP_RERANK_MODEL", "")
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.rerank._find_rerank_model",
        lambda: str(server),
    )
    assert runtime.find_rerank_model(tmp_path) == str(server)
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.rerank._find_rerank_model",
        lambda: (_ for _ in ()).throw(RuntimeError("broken")),
    )
    assert runtime.find_rerank_model(tmp_path) == ""


def test_r2_version_probe_retries_and_resolve_handles_missing(monkeypatch):
    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="no")
        return subprocess.CompletedProcess(command, 0, stdout="\n banner \n", stderr="")

    monkeypatch.setattr(runtime.subprocess, "run", run)
    assert runtime._r2_version("rz") == "banner"
    assert calls == [["rz", "--version"], ["rz", "-v"]]

    def unavailable(*_args, **_kwargs):
        raise OSError("missing")

    monkeypatch.setattr(runtime.subprocess, "run", unavailable)
    assert runtime._r2_version("r2") == ""
    monkeypatch.setattr(runtime.shutil, "which", lambda _name: None)
    assert runtime.resolve_r2_binary() == ("", "")


def test_stage_sigs_supports_single_files_dry_run_and_skips_symlinks(tmp_path):
    source = tmp_path / "one.sig"
    source.write_bytes(b"sig")
    sig_dir = tmp_path / "sig"
    report = InstallReport()
    manifest = runtime.stage_sigs(source, sig_dir, dry_run=True, report=report)
    assert manifest.staged == [str(sig_dir.resolve() / "one.sig")]
    assert not sig_dir.exists()

    existing = sig_dir / "one.sig"
    existing.parent.mkdir()
    existing.write_bytes(b"old")
    manifest = runtime.stage_sigs(source, sig_dir, dry_run=False, report=InstallReport())
    assert manifest.skipped == [str(existing)]
    assert existing.read_bytes() == b"old"

    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "valid.sig").write_bytes(b"valid")
    if hasattr(Path, "symlink_to"):
        (pack / "link.sig").symlink_to(pack / "valid.sig")
    result = runtime.stage_sigs(pack, tmp_path / "sig2", dry_run=False, report=InstallReport())
    assert result.count == 1

    non_sig = tmp_path / "notes.txt"
    non_sig.write_text("notes", encoding="utf-8")
    assert runtime.stage_sigs(non_sig, tmp_path / "sig3", False, InstallReport()).count == 0


def test_extract_archive_rejects_special_members_and_size_limits(tmp_path, monkeypatch):
    symlink_zip = tmp_path / "link.zip"
    with zipfile.ZipFile(symlink_zip, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 << 16) | 0xA000
        archive.writestr(info, "target")
    with pytest.raises(RuntimeError, match="symlink member"):
        runtime._extract_archive(symlink_zip, tmp_path / "link-out")

    special_zip = tmp_path / "special.zip"
    with zipfile.ZipFile(special_zip, "w") as archive:
        info = zipfile.ZipInfo("device")
        info.external_attr = 0o060000 << 16
        archive.writestr(info, b"device")
    with pytest.raises(RuntimeError, match="special archive member"):
        runtime._extract_archive(special_zip, tmp_path / "special-out")

    oversized = tmp_path / "large.zip"
    with zipfile.ZipFile(oversized, "w") as archive:
        archive.writestr("large.bin", b"12345")
    monkeypatch.setattr(runtime, "_MAX_EXTRACTED_ARCHIVE_SIZE", 4)
    with pytest.raises(RuntimeError, match="over 4 bytes"):
        runtime._extract_archive(oversized, tmp_path / "large-out")

    with pytest.raises(RuntimeError, match="Unsupported archive"):
        runtime._extract_archive(tmp_path / "unknown.bin", tmp_path / "unknown-out")


def test_venv_probe_and_wipe_cover_launch_failures_and_stale_rename(tmp_path, monkeypatch):
    missing = tmp_path / "missing-python"
    assert runtime._probe_venv(missing) is False
    python = tmp_path / "python"
    python.write_bytes(b"python")
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, stdout="", stderr="bad"),
    )
    assert runtime._probe_venv(python) is False
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout="/other\n", stderr=""),
    )
    assert runtime._probe_venv(python) is False
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout=f"{python}\n", stderr=""),
    )
    assert runtime._probe_venv(python) is True

    absent = tmp_path / "absent"
    runtime._wipe_venv(absent)
    removable = tmp_path / "removable"
    removable.mkdir()
    monkeypatch.setattr(runtime.shutil, "rmtree", lambda path: Path(path).rmdir())
    runtime._wipe_venv(removable)
    assert not removable.exists()

    stale = tmp_path / "stale"
    stale.mkdir()
    now = [0]
    monkeypatch.setattr(runtime.shutil, "rmtree", lambda _path: (_ for _ in ()).throw(OSError("locked")))
    monkeypatch.setattr(runtime.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(runtime.time, "time", lambda: (now.__setitem__(0, now[0] + 16) or now[0]))
    runtime._wipe_venv(stale)
    assert len(list(tmp_path.glob(".venv.stale.*"))) == 1


def test_snapshot_replaces_same_timestamp_and_runtime_setup_dry_run(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    install = tmp_path / "install"
    monkeypatch.setattr(runtime.time, "strftime", lambda _fmt: "20260901-1200")
    first = runtime._snapshot_source(source, install, False, InstallReport())
    (first / "old.txt").write_text("old", encoding="utf-8")
    second = runtime._snapshot_source(source, install, False, InstallReport())
    assert second == first
    assert not (second / "old.txt").exists()

    report = InstallReport()
    python = runtime.setup_runtime_environment(
        install, source, "snapshot", True, report
    )
    assert python == install / ".venv" / "bin" / "python"
    assert report.metadata["venv_python"] == str(python)


def test_setup_runtime_environment_recreates_stale_venv_and_retries_probe(tmp_path, monkeypatch):
    install = tmp_path / "install"
    venv = install / ".venv"
    venv.mkdir(parents=True)
    source = tmp_path / "source"
    source.mkdir()
    (source / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    calls = []
    probe_results = iter([False, True, True])

    monkeypatch.setattr(runtime, "_probe_venv", lambda _python: next(probe_results))
    monkeypatch.setattr(runtime, "_wipe_venv", lambda path: calls.append(("wipe", path)))
    monkeypatch.setattr(
        runtime,
        "run_checked",
        lambda command, **_kwargs: calls.append(command) or SimpleNamespace(stdout="ok\n"),
    )
    result = runtime.setup_runtime_environment(install, source, "pypi", False, InstallReport())
    assert result == install / ".venv" / "bin" / "python"
    assert calls[0] == ("wipe", venv)
    assert any(command[-2:] == ["install", "ida-pro-mcp"] for command in calls if isinstance(command, list))


def test_idalib_activation_and_runtime_config_cover_success_failure_and_all_envs(tmp_path, monkeypatch):
    ida = tmp_path / "ida"
    python_dir = ida / "idalib" / "python"
    (python_dir / "idapro").mkdir(parents=True)
    script = python_dir / "py-activate-idalib.py"
    script.write_text("# activate\n", encoding="utf-8")
    assert runtime.find_idalib_python_dir(str(ida)) == str(python_dir)
    assert runtime.find_idalib_python_dir("") == ""
    assert runtime.find_idalib_python_dir(str(tmp_path / "missing")) == ""

    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout="", stderr=""),
    )
    assert runtime.activate_idalib(str(ida)) == (True, "activated")
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 3, stdout="out", stderr="failed"),
    )
    assert runtime.activate_idalib(str(ida)) == (False, "failed")
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired([], 1)),
    )
    assert runtime.activate_idalib(str(ida)) == (False, "activation timed out")
    assert runtime.activate_idalib(str(tmp_path / "no-activation"))[0] is False

    wiki = tmp_path / "install" / "wiki"
    wiki.mkdir(parents=True)
    monkeypatch.setenv("IDADIR", str(ida))
    config = runtime.build_stdio_config(
        tmp_path / "python",
        tmp_path / "install",
        embed_model="embed.gguf",
        embed_server_bin="llama-server",
        embed_profile="zembed-1",
        embed_backend="gemini",
        rerank_model="rerank.gguf",
        gemini_api_key="key",
        gemini_vertex_project="project",
        gemini_vertex_location="europe",
        disable_policy=True,
        r2_bin="rz",
        ida_runtime="idalib",
    )
    env = config["env"]
    assert env["IDADIR"] == str(ida)
    assert env["IDA_MCP_WIKI_DIR"] == str(wiki)
    assert env["IDA_MCP_EMBED_BACKEND"] == "gemini"
    assert env["GEMINI_API_KEY"] == "key"
    assert env["GOOGLE_CLOUD_PROJECT"] == "project"
    assert env["VERTEX_AI_LOCATION"] == "europe"
    assert env["IDA_MCP_RUNTIME"] == "idalib"
    assert env["IDA_MCP_R2_BIN"] == "rz"


def test_build_stdio_config_uses_detected_ida_and_optional_pip_is_nonfatal(tmp_path, monkeypatch):
    detected = tmp_path / "detected"
    detected.mkdir()
    monkeypatch.delenv("IDADIR", raising=False)
    monkeypatch.delenv("IDA_DIR", raising=False)
    monkeypatch.setattr(runtime, "detect_ida_install_dir", lambda: detected)
    config = runtime.build_stdio_config(tmp_path / "python", tmp_path)
    assert config["env"]["IDADIR"] == str(detected)

    assert runtime.install_optional_packages(None, ["google-auth"]) is False
    assert runtime.install_optional_packages(tmp_path / "python", []) is False
    monkeypatch.setattr(runtime, "run_checked", lambda *_args, **_kwargs: None)
    assert runtime.install_optional_packages(tmp_path / "python", ["google-auth"]) is True
    monkeypatch.setattr(runtime, "run_checked", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("pip")))
    assert runtime.install_optional_packages(tmp_path / "python", ["google-auth"]) is False


def test_download_profiles_reject_unmanaged_and_managed_symlink_paths(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError, match="no managed download"):
        runtime.download_embed_model(tmp_path, "bge-code-v1")

    with pytest.raises(RuntimeError, match="Unknown rerank profile"):
        runtime.download_rerank_model(tmp_path, "does-not-exist")

    # The reranker error above is unknown-profile; exercise the actual
    # unmanaged branch using a temporary profile object in the catalog.
    from ida_pro_mcp.host.intelligence import rerank_profiles

    original = rerank_profiles.RERANK_MODEL_PROFILES["qwen3-reranker-0.6b"]
    monkeypatch.setitem(
        rerank_profiles.RERANK_MODEL_PROFILES,
        "qwen3-reranker-0.6b",
        replace(original, download_url="", download_filename=""),
    )
    with pytest.raises(RuntimeError, match="no managed download"):
        runtime.download_rerank_model(tmp_path, "qwen3-reranker-0.6b")
