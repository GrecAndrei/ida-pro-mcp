from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from ida_pro_mcp import findcrypt
from ida_pro_mcp.host import config
from ida_pro_mcp.host.intelligence import yara_scanner


def _write_zip(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)


def test_archive_is_pinned_to_an_immutable_revision():
    assert findcrypt.FINDCRYPT_REVISION in findcrypt.FINDCRYPT_ARCHIVE_URL
    assert "/master" not in findcrypt.FINDCRYPT_ARCHIVE_URL


def test_safe_extract_keeps_only_rule_files(tmp_path: Path):
    archive = tmp_path / "findcrypt.zip"
    _write_zip(
        archive,
        {
            "findcrypt/rules/a.yar": b"rule a { condition: true }",
            "findcrypt/README.md": b"not needed at runtime",
        },
    )

    output = tmp_path / "rules"
    result = findcrypt.extract_findcrypt_rules(str(archive), str(output))

    assert result == os.path.realpath(output)
    assert (output / "findcrypt/rules/a.yar").read_bytes() == b"rule a { condition: true }"
    assert not (output / "findcrypt/README.md").exists()


def test_safe_extract_rejects_path_traversal(tmp_path: Path):
    archive = tmp_path / "malicious.zip"
    _write_zip(archive, {"../outside.yar": b"rule bad { condition: true }"})

    with pytest.raises(RuntimeError, match="Unsafe path"):
        findcrypt.extract_findcrypt_rules(str(archive), str(tmp_path / "rules"))

    assert not (tmp_path / "outside.yar").exists()


def test_cache_discovery_supports_both_download_paths(tmp_path: Path):
    for relative in (
        "corpus_sources/findcrypt/repo/rules",
        "threat_corpus_sources/findcrypt/repo/rules",
    ):
        cache = tmp_path / relative.split("/")[0]
        cache.mkdir(exist_ok=True)
        rule_dir = tmp_path / relative
        rule_dir.mkdir(parents=True, exist_ok=True)
        (rule_dir / "crypto.yara").write_text("rule crypto { condition: true }")
        assert findcrypt.findcrypt_rules_dir(str(tmp_path)) == str(rule_dir)
        for child in cache.iterdir():
            if child.is_dir():
                shutil.rmtree(child)


def test_host_scanner_adds_findcrypt_rules_without_loading_ida(tmp_path: Path):
    primary = tmp_path / "primary"
    primary.mkdir()
    (primary / "malware.yar").write_text("rule malware { condition: true }")
    findcrypt_dir = tmp_path / "corpus_sources/findcrypt/repo"
    findcrypt_dir.mkdir(parents=True)
    (findcrypt_dir / "crypto.rules").write_text("rule crypto { condition: true }")

    with patch.object(config, "CACHE_DIR", str(tmp_path)):
        files = yara_scanner._iter_rule_files(str(primary))

    paths = {path for _namespace, path in files}
    assert str(primary / "malware.yar") in paths
    assert str(findcrypt_dir / "crypto.rules") in paths
