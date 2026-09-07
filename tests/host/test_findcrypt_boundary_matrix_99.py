"""Additional safety and rollback coverage for FindCrypt rule handling."""

from __future__ import annotations

import os
import stat
import zipfile
from pathlib import Path

import pytest

from ida_pro_mcp import findcrypt
from ida_pro_mcp.host import config


def _zip(path: Path, members: list[tuple[str, bytes | None, int | None]]):
    with zipfile.ZipFile(path, "w") as archive:
        for name, content, mode in members:
            info = zipfile.ZipInfo(name)
            if mode is not None:
                info.external_attr = mode << 16
            archive.writestr(info, content or b"")


def test_extract_rejects_archive_symlink_empty_and_member_symlink(tmp_path):
    real = tmp_path / "real.zip"
    _zip(real, [("rules/a.yar", b"rule a { condition: true }", None)])
    link = tmp_path / "link.zip"
    link.symlink_to(real)
    with pytest.raises(RuntimeError, match="symlinked FindCrypt archive"):
        findcrypt.extract_findcrypt_rules(str(link), str(tmp_path / "rules"))

    empty = tmp_path / "empty.zip"
    _zip(empty, [("README.md", b"not a rule", None)])
    with pytest.raises(RuntimeError, match="No YARA rules"):
        findcrypt.extract_findcrypt_rules(str(empty), str(tmp_path / "empty-rules"))

    symlink_member = tmp_path / "member-link.zip"
    _zip(symlink_member, [("rules/link.yar", None, stat.S_IFLNK | 0o777)])
    with pytest.raises(RuntimeError, match="Symlink in FindCrypt archive"):
        findcrypt.extract_findcrypt_rules(str(symlink_member), str(tmp_path / "member-rules"))


def test_extract_rejects_oversize_rule_and_symlinked_destination_root(tmp_path, monkeypatch):
    archive = tmp_path / "large.zip"
    _zip(archive, [("large.yar", b"0123456789", None)])
    monkeypatch.setattr(findcrypt, "_MAX_RULE_BYTES", 4)
    with pytest.raises(RuntimeError, match="Oversized FindCrypt rule"):
        findcrypt.extract_findcrypt_rules(str(archive), str(tmp_path / "large-rules"))

    monkeypatch.setattr(findcrypt, "_MAX_RULE_BYTES", 2_000_000)
    outside = tmp_path / "outside"
    outside.mkdir()
    target = tmp_path / "target"
    target.symlink_to(outside, target_is_directory=True)
    with pytest.raises(RuntimeError, match="Refusing symlinked FindCrypt extraction path"):
        findcrypt.extract_findcrypt_rules(str(archive), str(target))


def test_findcrypt_rules_dir_uses_config_default_and_ignores_non_rules(tmp_path, monkeypatch):
    source = tmp_path / "corpus_sources" / "findcrypt"
    source.mkdir(parents=True)
    (source / "notes.txt").write_text("no rule")
    monkeypatch.setattr(config, "CACHE_DIR", str(tmp_path))
    assert findcrypt.findcrypt_rules_dir() is None
    (source / "nested").mkdir()
    (source / "nested" / "crypto.rules").write_text("rule crypto { condition: true }")
    assert findcrypt.findcrypt_rules_dir() == str(source / "nested")


def test_replace_extraction_restores_previous_destination_on_install_failure(tmp_path, monkeypatch):
    destination = tmp_path / "rules"
    destination.mkdir()
    (destination / "old.yar").write_text("old")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "new.yar").write_text("new")
    real_replace = os.replace
    calls = []

    def fail_install(source, target):
        calls.append((source, target))
        if len(calls) == 2:
            raise OSError("install failed")
        return real_replace(source, target)

    monkeypatch.setattr(findcrypt.os, "replace", fail_install)
    with pytest.raises(OSError, match="install failed"):
        findcrypt._replace_extraction_directory(str(staging), str(destination))
    assert (destination / "old.yar").read_text() == "old"
    assert staging.exists()
