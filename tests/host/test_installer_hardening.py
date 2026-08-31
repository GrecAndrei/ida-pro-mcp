"""Regression tests for installer integrity, rollback, and destructive-action guards."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest


class _Response:
    def __init__(self, body: bytes, *, headers: dict[str, str] | None = None):
        self.body = io.BytesIO(body)
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size: int = -1) -> bytes:
        return self.body.read(size)


def _patch_model(monkeypatch, body: bytes):
    import importlib

    model_profiles = importlib.import_module("ida_pro_mcp.host.intelligence.model_profiles")

    profile = model_profiles.MODEL_PROFILES["zembed-1"]
    patched = replace(
        profile,
        download_sha256=hashlib.sha256(body).hexdigest(),
        download_size=len(body),
    )
    profiles = dict(model_profiles.MODEL_PROFILES)
    profiles["zembed-1"] = patched
    monkeypatch.setattr(model_profiles, "MODEL_PROFILES", profiles)
    return patched


def test_managed_model_hash_mismatch_keeps_existing_file_and_cleans_partial(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.runtime import download_embed_model

    expected = b"trusted-model"
    profile = _patch_model(monkeypatch, expected)
    destination = tmp_path / "models" / profile.download_filename
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"previous-good-install")
    monkeypatch.setattr(
        "ida_pro_mcp.installer.runtime.urllib.request.urlopen",
        lambda *_args, **_kwargs: _Response(b"tampered!!!!!", headers={"Content-Length": "13"}),
    )

    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        download_embed_model(tmp_path, "zembed-1")

    assert destination.read_bytes() == b"previous-good-install"
    assert not list(destination.parent.glob("*.part"))


def test_managed_model_request_is_pinned_to_profile_revision(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.runtime import download_embed_model

    body = b"pinned-model"
    profile = _patch_model(monkeypatch, body)
    captured: list[str] = []

    def _urlopen(request, **_kwargs):
        captured.append(request.full_url)
        return _Response(body, headers={"Content-Length": str(len(body))})

    monkeypatch.setattr("ida_pro_mcp.installer.runtime.urllib.request.urlopen", _urlopen)
    download_embed_model(tmp_path, "zembed-1")

    assert captured == [
        profile.download_url.replace("/resolve/main/", f"/resolve/{profile.download_revision}/", 1)
    ]


def test_llama_download_refuses_compatible_asset_without_digest(tmp_path, monkeypatch):
    from ida_pro_mcp.installer.common import InstallReport
    from ida_pro_mcp.installer.runtime import download_and_install_llama_server

    release = {
        "tag_name": "b123",
        "assets": [
            {
                "name": "llama-b123-bin-ubuntu-x64.zip",
                "browser_download_url": (
                    "https://github.com/ggml-org/llama.cpp/releases/download/"
                    "b123/llama-b123-bin-ubuntu-x64.zip"
                ),
            }
        ],
    }
    monkeypatch.setattr(
        "ida_pro_mcp.installer.runtime.urllib.request.urlopen",
        lambda *_args, **_kwargs: _Response(json.dumps(release).encode()),
    )

    with pytest.raises(RuntimeError, match="without a GitHub SHA-256 digest"):
        download_and_install_llama_server(tmp_path, dry_run=False, report=InstallReport())


def test_archive_extraction_rejects_safe_tar_links_too(tmp_path):
    from ida_pro_mcp.installer.runtime import _extract_archive

    archive = tmp_path / "link.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        link = tarfile.TarInfo("inside-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "inside"
        tar.addfile(link)

    with pytest.raises(RuntimeError, match="non-regular tar member"):
        _extract_archive(archive, tmp_path / "out")


def test_scoped_kill_fails_closed_when_process_listing_is_unavailable(monkeypatch, tmp_path):
    from ida_pro_mcp.installer import runtime

    calls: list[list[str]] = []

    def _run(command, **_kwargs):
        calls.append(command)
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime.subprocess, "run", _run)
    runtime.kill_ida_processes(tmp_path / "idat64")

    assert calls == [["pgrep", "-af", "(ida|idat)64?"]]


def test_client_backups_are_unique_and_rollback_removes_new_files(tmp_path):
    from ida_pro_mcp.installer.clients import backup_file, rollback_from_backups
    from ida_pro_mcp.installer.common import InstallReport

    existing = tmp_path / "settings.json"
    existing.write_text('{"version": 1}', encoding="utf-8")
    first = InstallReport()
    second = InstallReport()
    backup_a = backup_file(existing, first, dry_run=False)
    backup_b = backup_file(existing, second, dry_run=False)
    assert backup_a is not None and backup_b is not None
    assert backup_a != backup_b
    assert backup_a.read_text(encoding="utf-8") == backup_b.read_text(encoding="utf-8")

    new_file = tmp_path / "new.json"
    rollback_report = InstallReport()
    assert backup_file(new_file, rollback_report, dry_run=False) is None
    new_file.write_text("created by installer", encoding="utf-8")
    rollback_from_backups(rollback_report)
    assert not new_file.exists()


def test_skill_replacement_preserves_old_destination_when_staging_fails(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main

    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("new", encoding="utf-8")
    destination = tmp_path / "installed"
    destination.mkdir()
    (destination / "SKILL.md").write_text("old", encoding="utf-8")

    def _fail_copy(*_args, **_kwargs):
        raise OSError("copy failed")

    monkeypatch.setattr(main.os, "symlink", _fail_copy)
    monkeypatch.setattr(main.shutil, "copytree", _fail_copy)

    with pytest.raises(OSError, match="copy failed"):
        main._replace_with_symlink_or_copy(source, destination)
    assert (destination / "SKILL.md").read_text(encoding="utf-8") == "old"


def test_client_config_symlink_is_not_replaced(tmp_path):
    from ida_pro_mcp.installer import clients
    from ida_pro_mcp.installer.common import InstallReport

    target = tmp_path / "real-settings.json"
    target.write_text('{"keep": true}', encoding="utf-8")
    link = tmp_path / "settings.json"
    link.symlink_to(target)

    with pytest.raises(clients.ConfigParseError, match="symlinked client config"):
        clients.update_json_config(
            link,
            "ida-pro-mcp",
            {"command": "/x/python"},
            InstallReport(),
            dry_run=False,
        )
    assert json.loads(target.read_text(encoding="utf-8")) == {"keep": True}


def test_client_config_symlinked_parent_is_not_created_or_replaced(tmp_path):
    from ida_pro_mcp.installer import clients
    from ida_pro_mcp.installer.common import InstallReport

    outside = tmp_path / "outside"
    outside.mkdir()
    redirected_parent = tmp_path / "config-parent"
    redirected_parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(clients.ConfigParseError, match="symlinked client config"):
        clients.update_json_config(
            redirected_parent / "settings.json",
            "ida-pro-mcp",
            {"command": "/x/python"},
            InstallReport(),
            dry_run=False,
        )

    assert not (outside / "settings.json").exists()


def test_run_install_rejects_symlinked_install_root_without_writing_through_it(tmp_path):
    from ida_pro_mcp.installer import main
    from ida_pro_mcp.installer.common import InstallerOptions

    outside = tmp_path / "outside"
    outside.mkdir()
    install_root = tmp_path / "install"
    install_root.symlink_to(outside, target_is_directory=True)
    opts = InstallerOptions(
        interactive=False,
        only={"shell"},
        install_root=install_root,
        source_root=tmp_path,
    )

    assert main.run_install(opts, main.UI()) == 1
    assert not (outside / "install-report.json").exists()
    assert not (outside / "install-error.log").exists()


def test_install_report_rejects_symlinked_destination_parent(tmp_path):
    from ida_pro_mcp.installer.common import InstallReport

    outside = tmp_path / "outside"
    outside.mkdir()
    redirected_parent = tmp_path / "report-parent"
    redirected_parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symlinked installer report path"):
        InstallReport().write(redirected_parent / "install-report.json")

    assert not (outside / "install-report.json").exists()


def test_rollback_does_not_follow_a_replaced_config_symlink(tmp_path):
    from ida_pro_mcp.installer import clients
    from ida_pro_mcp.installer.common import InstallReport

    target = tmp_path / "settings.json"
    target.write_text('{"old": true}', encoding="utf-8")
    report = InstallReport()
    assert clients.backup_file(target, report, dry_run=False) is not None

    outside = tmp_path / "outside.json"
    outside.write_text('{"must": "remain"}', encoding="utf-8")
    target.unlink()
    target.symlink_to(outside)

    with pytest.raises(RuntimeError, match="symlinked rollback target"):
        clients.rollback_from_backups(report)

    assert outside.read_text(encoding="utf-8") == '{"must": "remain"}'


def test_bashrc_shim_shell_quotes_user_controlled_paths(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main
    from ida_pro_mcp.installer.common import InstallReport

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    install_root = tmp_path / "install $(touch SHOULD_NOT_RUN)"

    main.install_bashrc_cli(install_root, dry_run=False, report=InstallReport())
    content = (home / ".bashrc").read_text(encoding="utf-8")
    assert "export IDA_PRO_MCP_HOME='" in content
    assert "$(touch SHOULD_NOT_RUN)" in content


def test_bashrc_shim_rejects_symlinked_config(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import main
    from ida_pro_mcp.installer.common import InstallReport

    home = tmp_path / "home"
    home.mkdir()
    outside = tmp_path / "outside.bashrc"
    outside.write_text("# preserve", encoding="utf-8")
    (home / ".bashrc").symlink_to(outside)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    with pytest.raises(RuntimeError, match="symlinked bashrc path"):
        main.install_bashrc_cli(tmp_path / "install", dry_run=False, report=InstallReport())

    assert outside.read_text(encoding="utf-8") == "# preserve"


def test_corpus_hash_mismatch_never_replaces_existing_source(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import bron_corpus

    expected = b"trusted-corpus"
    spec = dict(bron_corpus.BRON_SOURCES["cwe"])
    spec["filename"] = "cwe-test.zip"
    monkeypatch.setitem(bron_corpus.BRON_SOURCES, "cwe", spec)
    monkeypatch.setenv(
        "IDA_MCP_BRON_CORPUS_SHA256_CWE", hashlib.sha256(expected).hexdigest()
    )
    destination = tmp_path / "cwe-test.zip"
    destination.write_bytes(b"previous-corpus")
    monkeypatch.setattr(
        bron_corpus.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b"tampered-corpus"),
    )

    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        bron_corpus.download_source("cwe", str(tmp_path), force=True)
    assert destination.read_bytes() == b"previous-corpus"
    assert not list(tmp_path.glob("*.part"))


def test_corpus_publish_failure_preserves_existing_source(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import bron_corpus

    spec = dict(bron_corpus.BRON_SOURCES["cwe"])
    spec["filename"] = "cwe-publish-failure.zip"
    monkeypatch.setitem(bron_corpus.BRON_SOURCES, "cwe", spec)
    destination = tmp_path / spec["filename"]
    destination.write_bytes(b"previous-corpus")
    monkeypatch.setattr(
        bron_corpus.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b"new-corpus"),
    )
    real_replace = bron_corpus.os.replace

    def _fail_publish(source, target):
        if Path(target) == destination:
            raise OSError("publish failed")
        return real_replace(source, target)

    monkeypatch.setattr(bron_corpus.os, "replace", _fail_publish)

    with pytest.raises(RuntimeError, match="download failed for cwe"):
        bron_corpus.download_source("cwe", str(tmp_path), force=True)

    assert destination.read_bytes() == b"previous-corpus"
    assert not list(tmp_path.glob(".dl-*.part"))


def test_corpus_empty_download_preserves_existing_source(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import bron_corpus

    spec = dict(bron_corpus.BRON_SOURCES["cwe"])
    spec["filename"] = "cwe-empty.zip"
    monkeypatch.setitem(bron_corpus.BRON_SOURCES, "cwe", spec)
    destination = tmp_path / spec["filename"]
    destination.write_bytes(b"previous-corpus")
    monkeypatch.setattr(
        bron_corpus.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b""),
    )

    with pytest.raises(RuntimeError, match="download was empty"):
        bron_corpus.download_source("cwe", str(tmp_path), force=True)

    assert destination.read_bytes() == b"previous-corpus"
    assert not list(tmp_path.glob(".dl-*.part"))


def test_corpus_cached_symlink_is_refused_without_following_it(tmp_path):
    from ida_pro_mcp.installer import bron_corpus

    outside = tmp_path / "outside.zip"
    outside.write_bytes(b"must remain untouched")
    cached = tmp_path / bron_corpus.BRON_SOURCES["cwe"]["filename"]
    cached.symlink_to(outside)

    with pytest.raises(RuntimeError, match="symlinked cached corpus source"):
        bron_corpus.download_source("cwe", str(tmp_path))

    assert outside.read_bytes() == b"must remain untouched"


def test_empty_cached_corpus_source_requires_a_refresh(tmp_path):
    from ida_pro_mcp.installer import bron_corpus

    cached = tmp_path / bron_corpus.BRON_SOURCES["cwe"]["filename"]
    cached.touch()

    with pytest.raises(RuntimeError, match="cached cwe source is empty"):
        bron_corpus.download_source("cwe", str(tmp_path))


def test_strict_corpus_mode_does_not_build_from_partial_verified_sources(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import bron_corpus

    monkeypatch.setattr(
        bron_corpus,
        "BRON_SOURCES",
        {
            "cwe": {"filename": "cwe.zip"},
            "attack_ics": {"filename": "ics.json"},
        },
    )

    def _download(key, _directory, **_kwargs):
        if key == "attack_ics":
            raise RuntimeError("missing expected SHA-256")
        return {"path": str(tmp_path / "cwe.zip")}

    monkeypatch.setattr(bron_corpus, "download_source", _download)
    result = bron_corpus.download_bron_corpus(
        sources_dir=str(tmp_path), force_verify=True
    )

    assert result["built"] is False
    assert "strict verification failed" in result["reason"]


def test_corpus_source_directory_rejects_symlinked_parent(tmp_path):
    from ida_pro_mcp.installer import bron_corpus

    outside = tmp_path / "outside"
    outside.mkdir()
    redirected_parent = tmp_path / "cache-parent"
    redirected_parent.symlink_to(outside, target_is_directory=True)
    sources_dir = redirected_parent / "threat-corpus"

    with pytest.raises(RuntimeError, match="symlinked corpus source directory"):
        bron_corpus.download_bron_corpus(
            sources_dir=str(sources_dir), only=["cwe"]
        )

    assert not (outside / "threat-corpus").exists()


def test_cwe_extraction_does_not_follow_existing_target_symlink(tmp_path):
    from ida_pro_mcp.installer import bron_corpus

    archive = tmp_path / "cwe.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("nested/cwe.xml", b"<cwe />")
    output = tmp_path / "cwe"
    output.mkdir()
    outside = tmp_path / "outside.xml"
    outside.write_bytes(b"must remain untouched")
    (output / "cwe.xml").symlink_to(outside)

    with pytest.raises(RuntimeError, match="symlinked CWE extraction target"):
        bron_corpus._unpack_cwe_zip(str(archive), str(output))

    assert outside.read_bytes() == b"must remain untouched"


def test_cwe_refresh_replaces_stale_materialized_files(tmp_path):
    from ida_pro_mcp.installer import bron_corpus

    first = tmp_path / "first.zip"
    with zipfile.ZipFile(first, "w") as zf:
        zf.writestr("old.xml", b"<old />")
    output = tmp_path / "cwe"
    bron_corpus._unpack_cwe_zip(str(first), str(output))

    second = tmp_path / "second.zip"
    with zipfile.ZipFile(second, "w") as zf:
        zf.writestr("new.xml", b"<new />")
    result = bron_corpus._unpack_cwe_zip(str(second), str(output))

    assert Path(result).read_bytes() == b"<new />"
    assert not (output / "old.xml").exists()


def test_signature_extraction_does_not_follow_existing_directory_symlink(tmp_path):
    from ida_pro_mcp.installer import bron_corpus

    archive = tmp_path / "signature-base.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        content = b"rule test { condition: true }"
        member = tarfile.TarInfo("signature-base/rules/test.yar")
        member.size = len(content)
        tf.addfile(member, io.BytesIO(content))
    output = tmp_path / "signature-base"
    output.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (output / "yara").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symlinked YARA extraction directory"):
        bron_corpus._unpack_signature_base_tar(str(archive), str(output))

    assert not (outside / "test.yar").exists()


def test_signature_refresh_replaces_stale_materialized_rules(tmp_path):
    from ida_pro_mcp.installer import bron_corpus

    def _archive(path: Path, name: str, content: bytes):
        with tarfile.open(path, "w:gz") as tf:
            member = tarfile.TarInfo(f"signature-base/rules/{name}")
            member.size = len(content)
            tf.addfile(member, io.BytesIO(content))

    first = tmp_path / "first.tar.gz"
    _archive(first, "old.yar", b"rule old { condition: true }")
    output = tmp_path / "signature-base"
    bron_corpus._unpack_signature_base_tar(str(first), str(output))

    second = tmp_path / "second.tar.gz"
    _archive(second, "new.yar", b"rule new { condition: true }")
    result = bron_corpus._unpack_signature_base_tar(str(second), str(output))

    assert Path(result, "new.yar").read_bytes() == b"rule new { condition: true }"
    assert not (output / "yara" / "old.yar").exists()


def test_corpus_verify_env_is_strict_when_expected_hash_is_missing(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import bron_corpus

    monkeypatch.setenv("IDA_MCP_BRON_CORPUS_VERIFY", "1")
    monkeypatch.delenv("IDA_MCP_BRON_CORPUS_SHA256_CWE", raising=False)

    with pytest.raises(RuntimeError, match="no expected SHA-256"):
        bron_corpus.download_source("cwe", str(tmp_path), force=True, force_verify=True)


def test_corpus_force_refresh_updates_manifest_after_upstream_change(tmp_path, monkeypatch):
    from ida_pro_mcp.installer import bron_corpus

    spec = dict(bron_corpus.BRON_SOURCES["cwe"])
    spec["filename"] = "cwe-test.zip"
    monkeypatch.setitem(bron_corpus.BRON_SOURCES, "cwe", spec)
    old = b"old-corpus"
    new = b"new-corpus"
    destination = tmp_path / "cwe-test.zip"
    destination.write_bytes(old)
    (tmp_path / ".sha256.json").write_text(
        json.dumps(
            {
                "sources": {
                    "cwe": {
                        "path": str(destination),
                        "sha256": hashlib.sha256(old).hexdigest(),
                    },
                    "attack_ics": {
                        "path": str(tmp_path / "ics.json"),
                        "sha256": "old-ics-digest",
                        "bytes": 7,
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        bron_corpus.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(new),
    )

    result = bron_corpus.download_bron_corpus(
        sources_dir=str(tmp_path), force=True, only=["cwe"]
    )
    assert result["built"] is False
    manifest = json.loads((tmp_path / ".sha256.json").read_text(encoding="utf-8"))
    assert manifest["sources"]["cwe"]["sha256"] == hashlib.sha256(new).hexdigest()
    assert manifest["sources"]["attack_ics"] == {
        "path": str(tmp_path / "ics.json"),
        "sha256": "old-ics-digest",
        "bytes": 7,
    }
