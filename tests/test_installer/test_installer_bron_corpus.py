from __future__ import annotations

import io
import json
import os
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.installer.bron_corpus import (
    BRON_SOURCES,
    _copy_extracted,
    _download_to_file,
    _expected_sha256,
    _materialize_cwe_xml,
    _materialize_findcrypt,
    _materialize_signature_base,
    _read_sha_manifest,
    _record_sha_manifest,
    _sha256_file,
    _unpack_cwe_zip,
    _unpack_signature_base_tar,
    _verify_or_report,
    default_sources_dir,
    download_bron_corpus,
    download_source,
    main,
)


def test_default_sources_dir() -> None:
    path = default_sources_dir()
    assert "threat_corpus_sources" in path


def test_sha256_file_and_expected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / "sample.txt"
    f.write_text("Threat Intelligence Data", encoding="utf-8")
    h = _sha256_file(str(f))
    assert len(h) == 64

    monkeypatch.setenv("IDA_MCP_BRON_CORPUS_SHA256_CWE", h)
    assert _expected_sha256("cwe") == h
    assert _expected_sha256("unknown_source") is None


def test_copy_extracted_limit() -> None:
    src = io.BytesIO(b"A" * 1000)
    dst = io.BytesIO()
    copied = _copy_extracted(src, dst, already_written=0, declared_size=1000)
    assert copied == 1000

    # Over limit
    src_big = io.BytesIO(b"A" * 1000)
    with pytest.raises(RuntimeError, match="Refusing archive extraction"):
        _copy_extracted(src_big, io.BytesIO(), already_written=2 * 1024**3, declared_size=1000)


def test_unpack_cwe_zip(tmp_path: Path) -> None:
    zip_path = tmp_path / "cwe.zip"
    dst_dir = tmp_path / "cwe_extracted"

    # Valid CWE zip
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("cwec_v4.13.xml", "<cwe>catalog</cwe>")

    extracted_xml = _unpack_cwe_zip(str(zip_path), str(dst_dir))
    assert Path(extracted_xml).is_file()
    assert Path(extracted_xml).read_text() == "<cwe>catalog</cwe>"

    # Invalid CWE zip without XML
    bad_zip = tmp_path / "bad_cwe.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("notes.txt", "no xml here")
    with pytest.raises(RuntimeError, match="No .xml found in CWE archive"):
        _unpack_cwe_zip(str(bad_zip), str(dst_dir))


def test_unpack_signature_base_tar(tmp_path: Path) -> None:
    tar_path = tmp_path / "sig.tar.gz"
    dst_dir = tmp_path / "sig_extracted"

    # Valid tar with yara rules
    rule_data = b"rule TestRule { strings: $a = \"sample\" condition: $a }"
    with tarfile.open(tar_path, "w:gz") as tf:
        info = tarfile.TarInfo("signature-base/yara/test.yar")
        info.size = len(rule_data)
        tf.addfile(info, io.BytesIO(rule_data))

    yara_dir = _unpack_signature_base_tar(str(tar_path), str(dst_dir))
    assert Path(yara_dir).is_dir()
    rule_file = Path(yara_dir) / "test.yar"
    assert rule_file.is_file()
    assert rule_file.read_bytes() == rule_data

    # Bad tar without yara rules
    bad_tar = tmp_path / "bad.tar.gz"
    with tarfile.open(bad_tar, "w:gz") as tf:
        info = tarfile.TarInfo("readme.txt")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"test"))
    with pytest.raises(RuntimeError, match="No .yar/.yara members"):
        _unpack_signature_base_tar(str(bad_tar), str(dst_dir))


def test_sha_manifest_record_and_read(tmp_path: Path) -> None:
    sources_dir = str(tmp_path)
    results = {
        "cwe": {"path": "/tmp/cwe.zip", "sha256": "abcdef123456", "bytes": 1024}
    }
    _record_sha_manifest(sources_dir, results)

    manifest = _read_sha_manifest(sources_dir)
    assert "cwe" in manifest
    assert manifest["cwe"]["sha256"] == "abcdef123456"


def test_download_source_and_verify(tmp_path: Path) -> None:
    sources_dir = str(tmp_path)
    with pytest.raises(KeyError, match="unknown source"):
        download_source("invalid_key", sources_dir)

    cwe_file = tmp_path / BRON_SOURCES["cwe"]["filename"]
    cwe_file.write_bytes(b"<xml>cwe</xml>")

    with patch("ida_pro_mcp.installer.bron_corpus._download_to_file"):
        res = download_source("cwe", sources_dir, force=False)
        assert res["path"] == str(cwe_file)
        assert res["bytes"] > 0
        assert "sha256" in res


def test_download_bron_corpus_flow(tmp_path: Path) -> None:
    sources_dir = str(tmp_path)

    # All failed case
    with patch(
        "ida_pro_mcp.installer.bron_corpus.download_source",
        side_effect=RuntimeError("Network offline"),
    ):
        res = download_bron_corpus(sources_dir, only=["cwe"])
        assert res["built"] is False
        assert res["reason"] == "all source downloads failed"


def test_main_cli(tmp_path: Path) -> None:
    with patch(
        "ida_pro_mcp.installer.bron_corpus.download_bron_corpus",
        return_value={"built": True, "counts": {}},
    ):
        rc = main(["--sources-dir", str(tmp_path), "--only", "cwe"])
        assert rc == 0

    with patch(
        "ida_pro_mcp.installer.bron_corpus.download_bron_corpus",
        return_value={"built": False, "reason": "failed"},
    ):
        rc = main(["--sources-dir", str(tmp_path)])
        assert rc == 1
