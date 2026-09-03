"""Offline boundary coverage for BRON corpus staging and verification."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from ida_pro_mcp.installer import bron_corpus


class _Response:
    def __init__(self, payload: bytes, content_length: str | None = None):
        self._payload = io.BytesIO(payload)
        self.headers = (
            {"Content-Length": content_length}
            if content_length is not None
            else {}
        )

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size=-1):
        return self._payload.read(_size)


def _minimal_zip(path: Path, name: str = "catalog.xml") -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(name, "<catalog/>")


def test_directory_validation_and_atomic_extraction_restore(monkeypatch, tmp_path):
    class _NotDirectory:
        def mkdir(self, **_kwargs):
            return None

        def is_dir(self):
            return False

        def exists(self):
            return True

    fake = _NotDirectory()
    monkeypatch.setattr(bron_corpus, "_reject_symlink", lambda *_args: fake)
    with pytest.raises(RuntimeError, match="not a directory"):
        bron_corpus._ensure_directory(tmp_path / "bad", "cache directory")
    with pytest.raises(RuntimeError, match="not a directory"):
        bron_corpus._prepare_extraction_directory(tmp_path / "bad", "extract directory")

    destination = tmp_path / "destination"
    destination.mkdir()
    staging = tmp_path / "staging"
    staging.mkdir()
    real_replace = bron_corpus.os.replace
    calls = []

    def fail_publish(source, target):
        calls.append((source, target))
        if len(calls) == 2:
            raise OSError("publish failed")
        return real_replace(source, target)

    monkeypatch.setattr(bron_corpus.os, "replace", fail_publish)
    with pytest.raises(OSError, match="publish failed"):
        bron_corpus._replace_extraction_directory(staging, destination)
    assert destination.is_dir()

    with monkeypatch.context() as isolated:
        isolated.setattr(
            bron_corpus.os, "replace", lambda *_args: (_ for _ in ()).throw(OSError("no destination"))
        )
        staging_without_backup = tmp_path / "staging-without-backup"
        staging_without_backup.mkdir()
        with pytest.raises(OSError, match="no destination"):
            bron_corpus._replace_extraction_directory(
                staging_without_backup, tmp_path / "new-destination"
            )


def test_download_rejects_bad_length_and_stream_overflow(monkeypatch, tmp_path):
    monkeypatch.setattr(
        bron_corpus.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b"payload", "not-a-number"),
    )
    # The invalid Content-Length is tolerated; this confirms the parser's
    # fallback while the normal payload path remains exercised.
    result = bron_corpus._download_to_file(
        "https://example.test/raw", str(tmp_path / "raw")
    )
    assert result["bytes"] == len(b"payload")

    monkeypatch.setattr(
        bron_corpus.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b"payload", str(bron_corpus._MAX_DOWNLOAD_BYTES + 1)),
    )
    with pytest.raises(RuntimeError, match="Content-Length"):
        bron_corpus._download_to_file("https://example.test/raw", str(tmp_path / "too-large"))

    monkeypatch.setattr(bron_corpus, "_MAX_DOWNLOAD_BYTES", 2)
    monkeypatch.setattr(
        bron_corpus.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b"123"),
    )
    with pytest.raises(RuntimeError, match="stream exceeded"):
        bron_corpus._download_to_file("https://example.test/raw", str(tmp_path / "stream"))


def test_verification_manifest_mismatch_and_strict_missing_hash(monkeypatch, tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    (tmp_path / ".sha256.json").write_text(
        json.dumps({"sources": {"x": {"sha256": "wrong"}}}), encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="changed since"):
        bron_corpus._verify_or_report(
            "x", str(source), force_verify=False, sources_dir=str(tmp_path)
        )

    monkeypatch.delenv("IDA_MCP_BRON_CORPUS_SHA256_X", raising=False)
    with pytest.raises(RuntimeError, match="no expected SHA-256"):
        bron_corpus._verify_or_report(
            "x", str(source), force_verify=True, sources_dir=str(tmp_path)
        )


def test_archive_member_and_target_safety_guards(monkeypatch, tmp_path):
    zip_path = tmp_path / "cwe.zip"
    _minimal_zip(zip_path)

    class _DirectoryInfo:
        file_size = 0

        @staticmethod
        def is_dir():
            return True

    monkeypatch.setattr(
        bron_corpus.zipfile.ZipFile, "getinfo", lambda *_args: _DirectoryInfo()
    )
    with pytest.raises(RuntimeError, match="member is a directory"):
        bron_corpus._unpack_cwe_zip(str(zip_path), str(tmp_path / "cwe-dir"))

    monkeypatch.undo()
    monkeypatch.setattr(bron_corpus, "_MAX_EXTRACTED_BYTES", 0)
    with pytest.raises(RuntimeError, match="archive extraction"):
        bron_corpus._unpack_cwe_zip(str(zip_path), str(tmp_path / "cwe-large"))

    monkeypatch.setattr(bron_corpus, "_MAX_EXTRACTED_BYTES", 1 * 1024**3)
    destination = tmp_path / "cwe-target"
    (destination / "catalog.xml").mkdir(parents=True)
    with pytest.raises(RuntimeError, match="not a regular file"):
        bron_corpus._unpack_cwe_zip(str(zip_path), str(destination))


class _FakeTar:
    def __init__(self, member, extracted=None):
        self.member = member
        self.extracted = extracted

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def getmembers(self):
        return [self.member]

    def extractfile(self, _member):
        return self.extracted


def _regular_member(name="rule.yar", size=1):
    member = tarfile.TarInfo(name)
    member.size = size
    return member


def test_signature_archive_guard_modes(monkeypatch, tmp_path):
    tar_path = tmp_path / "sig.tar.gz"
    tar_path.write_bytes(b"placeholder")

    yara_file = tmp_path / "existing" / "yara"
    yara_file.parent.mkdir()
    yara_file.write_text("not a directory", encoding="utf-8")
    with pytest.raises(RuntimeError, match="not a directory"):
        bron_corpus._unpack_signature_base_tar(str(tar_path), str(tmp_path / "existing"))

    member = tarfile.TarInfo("directory.yar")
    member.type = tarfile.DIRTYPE
    monkeypatch.setattr(bron_corpus.tarfile, "open", lambda *_a, **_k: _FakeTar(member))
    with pytest.raises(RuntimeError, match="non-regular"):
        bron_corpus._unpack_signature_base_tar(str(tar_path), str(tmp_path / "nonregular"))

    monkeypatch.setattr(bron_corpus, "_MAX_EXTRACTED_BYTES", 0)
    monkeypatch.setattr(
        bron_corpus.tarfile,
        "open",
        lambda *_a, **_k: _FakeTar(_regular_member(size=1)),
    )
    with pytest.raises(RuntimeError, match="archive extraction"):
        bron_corpus._unpack_signature_base_tar(str(tar_path), str(tmp_path / "oversize"))

    long_member = _regular_member("a/" + ("x" * 4100) + ".yar", size=0)
    monkeypatch.setattr(
        bron_corpus.tarfile,
        "open",
        lambda *_a, **_k: _FakeTar(long_member),
    )
    assert bron_corpus._unpack_signature_base_tar(
        str(tar_path), str(tmp_path / "long-name")
    ).endswith("/yara")

    monkeypatch.setattr(bron_corpus, "_MAX_EXTRACTED_BYTES", 1 * 1024**3)
    monkeypatch.setattr(
        bron_corpus.tarfile,
        "open",
        lambda *_a, **_k: _FakeTar(_regular_member(), extracted=None),
    )
    assert bron_corpus._unpack_signature_base_tar(
        str(tar_path), str(tmp_path / "no-extracted")
    ).endswith("/yara")

    empty_basename = _regular_member("folder/rule.yar", size=0)
    with monkeypatch.context() as isolated:
        real_basename = bron_corpus.os.path.basename
        isolated.setattr(
            bron_corpus.os.path,
            "basename",
            lambda value: "" if value == empty_basename.name else real_basename(value),
        )
        isolated.setattr(
            bron_corpus.tarfile,
            "open",
            lambda *_a, **_k: _FakeTar(empty_basename),
        )
        assert bron_corpus._unpack_signature_base_tar(
            str(tar_path), str(tmp_path / "empty-basename")
        ).endswith("/yara")


def test_materializers_and_findcrypt_wrapper_cover_missing_inputs(monkeypatch, tmp_path):
    with pytest.raises(FileNotFoundError, match="missing CWE"):
        bron_corpus._materialize_cwe_xml(str(tmp_path))
    with pytest.raises(FileNotFoundError, match="missing signature-base"):
        bron_corpus._materialize_signature_base(str(tmp_path))
    with pytest.raises(FileNotFoundError, match="missing findcrypt"):
        bron_corpus._materialize_findcrypt(str(tmp_path))

    monkeypatch.setattr(bron_corpus, "extract_findcrypt_rules", lambda *_args: "rules")
    assert bron_corpus._unpack_findcrypt_zip("archive.zip", "rules") == "rules"

    cwe_archive = tmp_path / bron_corpus.BRON_SOURCES["cwe"]["filename"]
    signature_archive = tmp_path / bron_corpus.BRON_SOURCES["signature_base"]["filename"]
    findcrypt_archive = tmp_path / bron_corpus.BRON_SOURCES["findcrypt"]["filename"]
    cwe_archive.write_bytes(b"cwe")
    signature_archive.write_bytes(b"signature")
    findcrypt_archive.write_bytes(b"findcrypt")
    monkeypatch.setattr(bron_corpus, "_unpack_cwe_zip", lambda *_args: "cwe.xml")
    monkeypatch.setattr(bron_corpus, "_unpack_signature_base_tar", lambda *_args: "yara")
    monkeypatch.setattr(bron_corpus, "_unpack_findcrypt_zip", lambda *_args: "rules")
    assert bron_corpus._materialize_cwe_xml(str(tmp_path)) == "cwe.xml"
    assert bron_corpus._materialize_signature_base(str(tmp_path)) == "yara"
    assert bron_corpus._materialize_findcrypt(str(tmp_path)) == "rules"


def _successful_source(key, sources_dir):
    return {
        "path": str(Path(sources_dir) / bron_corpus.BRON_SOURCES[key]["filename"]),
        "sha256": "a" * 64,
        "bytes": 1,
    }


def test_download_status_strict_unpack_and_corpus_outcomes(monkeypatch, tmp_path):
    specs = {
        key: {"filename": f"{key}.raw"}
        for key in ("attack_enterprise", "signature_base", "findcrypt")
    }
    monkeypatch.setattr(bron_corpus, "BRON_SOURCES", specs)
    monkeypatch.setattr(
        bron_corpus,
        "download_source",
        lambda key, directory, **_kwargs: (
            {"error": "bad", "path": str(Path(directory) / specs[key]["filename"])}
            if key == "signature_base"
            else _successful_source(key, directory)
        ),
    )
    strict = bron_corpus.download_bron_corpus(
        str(tmp_path / "strict"), only=list(specs), force_verify=True
    )
    assert strict["built"] is False
    assert "signature_base" in strict["reason"]

    monkeypatch.setattr(
        bron_corpus,
        "download_source",
        lambda key, directory, **_kwargs: _successful_source(key, directory),
    )
    monkeypatch.setattr(bron_corpus, "_record_sha_manifest", lambda *_args: "manifest")
    monkeypatch.setattr(
        bron_corpus,
        "_materialize_signature_base",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("bad yara")),
    )
    monkeypatch.setattr(
        bron_corpus,
        "_materialize_findcrypt",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("bad findcrypt")),
    )
    monkeypatch.setattr(
        bron_corpus,
        "build_corpus_from_sources",
        lambda **_kwargs: SimpleNamespace(
            is_empty=lambda: False,
            count_by_type=lambda: {"attack": 1},
            source_fingerprint="fingerprint",
        ),
    )
    monkeypatch.setattr(bron_corpus, "save_corpus", lambda _corpus: "cache.json")
    built = bron_corpus.download_bron_corpus(
        str(tmp_path / "partial"), only=list(specs)
    )
    assert built["built"] is True
    assert built["counts"] == {"attack": 1}
    assert built["source_fingerprint"] == "fingerprint"
    assert "unpack_error" in built["downloads"]["signature_base"]

    verified = bron_corpus.download_bron_corpus(
        str(tmp_path / "verified"), only=["attack_enterprise"], force_verify=True
    )
    assert verified["built"] is True

    monkeypatch.setattr(
        bron_corpus,
        "_materialize_signature_base",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("bad yara")),
    )
    unusable = bron_corpus.download_bron_corpus(
        str(tmp_path / "unusable"), only=["signature_base"]
    )
    assert unusable["reason"] == "no usable sources after unpacking"

    monkeypatch.setattr(
        bron_corpus,
        "build_corpus_from_sources",
        lambda **_kwargs: SimpleNamespace(is_empty=lambda: True),
    )
    empty = bron_corpus.download_bron_corpus(
        str(tmp_path / "empty-corpus"), only=["attack_enterprise"]
    )
    assert empty["reason"] == "corpus built but is empty"


def test_verify_hash_success_uses_real_digest(monkeypatch, tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"ok")
    digest = hashlib.sha256(b"ok").hexdigest()
    monkeypatch.setenv("IDA_MCP_BRON_CORPUS_SHA256_X", digest)
    result = bron_corpus._verify_or_report(
        "x", str(source), force_verify=False, sources_dir=str(tmp_path)
    )
    assert result["verified"] is True
