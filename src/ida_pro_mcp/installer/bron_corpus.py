"""
BRON-style threat corpus downloader.

Downloads the raw data sources needed to build the threat corpus:
  - CWE catalog XML (MITRE)
  - MITRE ATT&CK STIX bundles (Enterprise, ICS, Mobile)
  - Florian Roth signature-base YARA archive (Neo23x0)

All sources are SHA-256 verifiable. If the env var
``IDA_MCP_BRON_CORPUS_VERIFY=1`` is set, downloads are verified against
``IDA_MCP_BRON_CORPUS_SHA256_*`` env vars (one per source). Otherwise the
computed SHA is reported and persisted to ``<sources_dir>/.sha256.json``;
subsequent cache reads reject unexpected changes.

The downloader is intentionally minimal — no subcommands, no UI prompts.
It is meant to be invoked from the installer or directly via
``python -m ida_pro_mcp.installer.bron_corpus``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path
from typing import Any

from ..findcrypt import (
    FINDCRYPT_ARCHIVE_FILENAME,
    FINDCRYPT_ARCHIVE_URL,
    extract_findcrypt_rules,
)
from ..host.config import CACHE_DIR
from ..host.intelligence.threat_corpus import (
    build_corpus_from_sources,
    save_corpus,
)
from .common import atomic_write_text

__all__ = [
    "download_bron_corpus",
    "BRON_SOURCES",
    "default_sources_dir",
]


_MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
_MAX_EXTRACTED_BYTES = 1 * 1024**3
_DOWNLOAD_CHUNK_BYTES = 64 * 1024
_DOWNLOAD_TIMEOUT = 180
_DEFAULT_USER_AGENT = "ida-pro-mcp-installer/bron-corpus"


def _reject_symlink(path: str | Path, description: str) -> Path:
    """Reject a cache path that would make the installer follow a link."""
    candidate = Path(path)
    if candidate.is_symlink():
        raise RuntimeError(f"Refusing symlinked {description}: {candidate}")
    return candidate


def _ensure_directory(path: str | Path, description: str) -> Path:
    candidate = _reject_symlink(path, description)
    candidate.mkdir(parents=True, exist_ok=True)
    if not candidate.is_dir():
        raise RuntimeError(f"{description.capitalize()} is not a directory: {candidate}")
    return candidate


def _prepare_extraction_directory(path: str | Path, description: str) -> Path:
    """Validate an extraction target without destroying its old contents."""
    candidate = _reject_symlink(path, description)
    if candidate.exists() and not candidate.is_dir():
        raise RuntimeError(f"{description.capitalize()} is not a directory: {candidate}")
    _ensure_directory(candidate.parent, f"{description} parent")
    return candidate


def _replace_extraction_directory(staging: Path, destination: Path) -> None:
    """Atomically replace a managed extraction directory after validation."""
    backup: Path | None = None
    if destination.exists():
        backup = destination.parent / f".{destination.name}.backup-{uuid.uuid4().hex}"
        os.replace(destination, backup)
    try:
        os.replace(staging, destination)
    except BaseException:
        if backup is not None and not destination.exists():
            os.replace(backup, destination)
        raise
    if backup is not None:
        with contextlib.suppress(OSError):
            shutil.rmtree(backup)


def default_sources_dir() -> str:
    return os.path.join(CACHE_DIR, "threat_corpus_sources")


BRON_SOURCES: dict[str, dict[str, Any]] = {
    "cwe": {
        "url": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "filename": "cwec_latest.xml.zip",
        "kind": "cwe_zip",
    },
    "attack_enterprise": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "filename": "enterprise-attack.json",
        "kind": "attack_stix",
    },
    "attack_ics": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
        "filename": "ics-attack.json",
        "kind": "attack_stix",
    },
    "attack_mobile": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
        "filename": "mobile-attack.json",
        "kind": "attack_stix",
    },
    "signature_base": {
        "url": "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.tar.gz",
        "filename": "signature-base.tar.gz",
        "kind": "signature_base_tar",
    },
    "findcrypt": {
        "url": FINDCRYPT_ARCHIVE_URL,
        "filename": FINDCRYPT_ARCHIVE_FILENAME,
        "kind": "findcrypt_zip",
    },
}


def _sha256_file(path: str, chunk: int = 64 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def _expected_sha256(source_key: str) -> str | None:
    env_name = f"IDA_MCP_BRON_CORPUS_SHA256_{source_key.upper()}"
    val = os.environ.get(env_name, "").strip().lower()
    return val or None


def _download_to_file(
    url: str,
    dst_path: str,
    *,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    destination = _reject_symlink(dst_path, "download destination")
    _ensure_directory(destination.parent, "download directory")
    req = urllib.request.Request(
        url,
        headers={"User-Agent": _DEFAULT_USER_AGENT, "Accept": "*/*"},
    )
    with tempfile.NamedTemporaryFile(
        delete=False, dir=os.path.dirname(dst_path), prefix=".dl-", suffix=".part"
    ) as tmp:
        tmp_path = tmp.name
        total = 0
        digest = hashlib.sha256()
        try:
            with urllib.request.urlopen(req, timeout=_DOWNLOAD_TIMEOUT) as resp:
                declared = resp.headers.get("Content-Length")
                if declared:
                    try:
                        declared_int = int(declared)
                    except ValueError:
                        declared_int = -1
                    if declared_int > _MAX_DOWNLOAD_BYTES:
                        raise RuntimeError(
                            f"Refusing download: Content-Length={declared_int} > max {_MAX_DOWNLOAD_BYTES}"
                        )
                while True:
                    block = resp.read(_DOWNLOAD_CHUNK_BYTES)
                    if not block:
                        break
                    total += len(block)
                    if total > _MAX_DOWNLOAD_BYTES:
                        raise RuntimeError(
                            f"Refusing download: stream exceeded max {_MAX_DOWNLOAD_BYTES}"
                        )
                    digest.update(block)
                    tmp.write(block)
                actual = digest.hexdigest()
                if expected_sha256 and actual != expected_sha256:
                    raise RuntimeError(
                        f"SHA-256 mismatch: expected={expected_sha256} actual={actual}"
                    )
                tmp.flush()
                os.fsync(tmp.fileno())
        except Exception:
            with contextlib.suppress(OSError):
                os.remove(tmp_path)
            raise
    try:
        os.replace(tmp_path, destination)
    except OSError:
        with contextlib.suppress(OSError):
            os.remove(tmp_path)
        raise
    return {"bytes": total, "path": str(destination)}


def _copy_extracted(source, destination, *, already_written: int, declared_size: int) -> int:
    """Copy an archive member with a decompression-bomb size cap."""
    if declared_size < 0 or already_written + declared_size > _MAX_EXTRACTED_BYTES:
        raise RuntimeError(
            f"Refusing archive extraction over {_MAX_EXTRACTED_BYTES} bytes"
        )
    copied = 0
    while True:
        block = source.read(_DOWNLOAD_CHUNK_BYTES)
        if not block:
            break
        copied += len(block)
        if already_written + copied > _MAX_EXTRACTED_BYTES:
            raise RuntimeError(
                f"Refusing archive extraction over {_MAX_EXTRACTED_BYTES} bytes"
            )
        destination.write(block)
    return copied


def _read_sha_manifest(sources_dir: str) -> dict[str, Any]:
    path = _reject_symlink(
        Path(sources_dir) / ".sha256.json", "corpus checksum manifest"
    )
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    sources = payload.get("sources") if isinstance(payload, dict) else None
    return sources if isinstance(sources, dict) else {}


def _verify_or_report(
    source_key: str,
    path: str,
    *,
    force_verify: bool,
    sources_dir: str,
    check_manifest: bool = True,
) -> dict[str, Any]:
    actual = _sha256_file(path)
    expected = _expected_sha256(source_key)
    previous = _read_sha_manifest(sources_dir).get(source_key)
    recorded = previous.get("sha256") if isinstance(previous, dict) else ""
    if recorded and recorded != actual and check_manifest and not force_verify:
        raise RuntimeError(
            f"cached {source_key} changed since its last verified manifest; "
            "re-download it explicitly with --force"
        )
    out: dict[str, Any] = {"path": path, "sha256": actual, "bytes": os.path.getsize(path)}
    if expected:
        if expected != actual:
            raise RuntimeError(
                f"SHA-256 mismatch for {source_key}: expected={expected} actual={actual}"
            )
        out["verified"] = True
    elif force_verify:
        raise RuntimeError(
            f"no expected SHA-256 in IDA_MCP_BRON_CORPUS_SHA256_{source_key.upper()}"
        )
    else:
        out["verified"] = False
    return out


def _unpack_cwe_zip(zip_path: str, dst_dir: str) -> str:
    _reject_symlink(zip_path, "CWE archive")
    destination_dir = _prepare_extraction_directory(dst_dir, "CWE extraction directory")
    with zipfile.ZipFile(zip_path) as zf:
        xml_members = [n for n in zf.namelist() if n.lower().endswith(".xml")]
        if not xml_members:
            raise RuntimeError(f"No .xml found in CWE archive: {zip_path}")
        member = xml_members[0]
        info = zf.getinfo(member)
        if info.is_dir():
            raise RuntimeError(f"CWE XML member is a directory: {member}")
        if not info.is_dir() and info.file_size > _MAX_EXTRACTED_BYTES:
            raise RuntimeError(f"Refusing archive extraction over {_MAX_EXTRACTED_BYTES} bytes")
        final_target = _reject_symlink(
            destination_dir / os.path.basename(member), "CWE extraction target"
        )
        if final_target.exists() and not final_target.is_file():
            raise RuntimeError(f"CWE extraction target is not a regular file: {final_target}")
        staging = Path(tempfile.mkdtemp(prefix=f".{destination_dir.name}.staging-", dir=str(destination_dir.parent)))
        try:
            target = staging / final_target.name
            with zf.open(member) as src, open(target, "wb") as out:
                _copy_extracted(src, out, already_written=0, declared_size=info.file_size)
            _replace_extraction_directory(staging, destination_dir)
            return str(destination_dir / target.name)
        finally:
            shutil.rmtree(staging, ignore_errors=True)


def _unpack_signature_base_tar(tar_path: str, dst_dir: str) -> str:
    _reject_symlink(tar_path, "signature-base archive")
    destination_dir = _prepare_extraction_directory(dst_dir, "signature-base extraction directory")
    existing_yara = destination_dir / "yara"
    _reject_symlink(existing_yara, "YARA extraction directory")
    if existing_yara.exists() and not existing_yara.is_dir():
        raise RuntimeError(f"YARA extraction directory is not a directory: {existing_yara}")
    with tarfile.open(tar_path, "r:gz") as tf:
        members = tf.getmembers()
        yara_members = [m for m in members if m.name.endswith((".yar", ".yara"))]
        if not yara_members:
            raise RuntimeError(f"No .yar/.yara members in {tar_path}")
        staging = Path(tempfile.mkdtemp(prefix=f".{destination_dir.name}.staging-", dir=str(destination_dir.parent)))
        yara_dst = _ensure_directory(staging / "yara", "YARA extraction directory")
        extracted_bytes = 0
        try:
            for m in yara_members:
                base = os.path.basename(m.name)
                if not base:
                    continue
                if not m.isfile():
                    raise RuntimeError(f"Refusing non-regular YARA archive member: {m.name}")
                if m.size < 0 or extracted_bytes + m.size > _MAX_EXTRACTED_BYTES:
                    raise RuntimeError(
                        f"Refusing archive extraction over {_MAX_EXTRACTED_BYTES} bytes"
                    )
                target_path = yara_dst / base
                if len(str(target_path)) > 4096:
                    continue
                extracted = tf.extractfile(m)
                if extracted is None:
                    continue
                try:
                    with open(target_path, "wb") as out:
                        extracted_bytes += _copy_extracted(
                            extracted,
                            out,
                            already_written=extracted_bytes,
                            declared_size=m.size,
                        )
                finally:
                    extracted.close()
            _replace_extraction_directory(staging, destination_dir)
            return str(destination_dir / "yara")
        finally:
            shutil.rmtree(staging, ignore_errors=True)


def download_source(
    source_key: str,
    sources_dir: str,
    *,
    force: bool = False,
    force_verify: bool = False,
) -> dict[str, Any]:
    if source_key not in BRON_SOURCES:
        raise KeyError(f"unknown source: {source_key}")
    spec = BRON_SOURCES[source_key]
    _ensure_directory(sources_dir, "corpus source directory")
    dst = os.path.join(sources_dir, spec["filename"])
    _reject_symlink(dst, "cached corpus source")
    expected = _expected_sha256(source_key)
    if force_verify and not expected:
        raise RuntimeError(
            f"no expected SHA-256 in IDA_MCP_BRON_CORPUS_SHA256_{source_key.upper()}"
        )
    if os.path.isfile(dst) and not force:
        return _verify_or_report(
            source_key, dst, force_verify=force_verify, sources_dir=sources_dir
        )
    try:
        _download_to_file(spec["url"], dst, expected_sha256=expected)
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"download failed for {source_key}: {e}") from e
    return _verify_or_report(
        source_key,
        dst,
        force_verify=force_verify,
        sources_dir=sources_dir,
        check_manifest=False,
    )


def _materialize_cwe_xml(sources_dir: str) -> str:
    zip_path = os.path.join(sources_dir, BRON_SOURCES["cwe"]["filename"])
    _reject_symlink(zip_path, "CWE archive")
    if not os.path.isfile(zip_path):
        raise FileNotFoundError(f"missing CWE archive: {zip_path}")
    unpack_dir = os.path.join(sources_dir, "cwe")
    return _unpack_cwe_zip(zip_path, unpack_dir)


def _materialize_signature_base(sources_dir: str) -> str:
    tar_path = os.path.join(sources_dir, BRON_SOURCES["signature_base"]["filename"])
    _reject_symlink(tar_path, "signature-base archive")
    if not os.path.isfile(tar_path):
        raise FileNotFoundError(f"missing signature-base archive: {tar_path}")
    unpack_dir = os.path.join(sources_dir, "signature-base")
    return _unpack_signature_base_tar(tar_path, unpack_dir)


def _unpack_findcrypt_zip(zip_path: str, dst_dir: str) -> str:
    return extract_findcrypt_rules(zip_path, dst_dir)


def _materialize_findcrypt(sources_dir: str) -> str:
    zip_path = os.path.join(sources_dir, BRON_SOURCES["findcrypt"]["filename"])
    _reject_symlink(zip_path, "FindCrypt archive")
    if not os.path.isfile(zip_path):
        raise FileNotFoundError(f"missing findcrypt archive: {zip_path}")
    unpack_dir = os.path.join(sources_dir, "findcrypt")
    return _unpack_findcrypt_zip(zip_path, unpack_dir)


def _record_sha_manifest(sources_dir: str, results: dict[str, dict[str, Any]]) -> str:
    manifest_path = os.path.join(sources_dir, ".sha256.json")
    manifest = {
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sources": {k: {"path": v["path"], "sha256": v["sha256"], "bytes": v["bytes"]} for k, v in results.items()},
    }
    atomic_write_text(Path(manifest_path), json.dumps(manifest, indent=2))
    return manifest_path


def _parse_only(value: str) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


def download_bron_corpus(
    sources_dir: str | None = None,
    *,
    force: bool = False,
    only: list[str] | None = None,
    force_verify: bool = False,
) -> dict[str, Any]:
    """Download the raw sources, build the corpus, and persist the cache.

    Returns a status dict with per-source download results, corpus counts,
    and cache path. Raises on hard failures (download error, missing
    files); returns ``status["built"] is False`` if no sources are usable.
    """
    sources_dir = sources_dir or default_sources_dir()
    os.makedirs(sources_dir, exist_ok=True)
    force_verify = force_verify or os.environ.get("IDA_MCP_BRON_CORPUS_VERIFY", "").lower() in {"1", "true", "yes", "on"}
    selected = [k for k in BRON_SOURCES if not only or k in only]
    results: dict[str, dict[str, Any]] = {}
    for source_key in selected:
        try:
            results[source_key] = download_source(
                source_key, sources_dir, force=force, force_verify=force_verify
            )
        except Exception as e:
            results[source_key] = {"error": str(e), "path": os.path.join(sources_dir, BRON_SOURCES[source_key]["filename"])}
    if not results or all("error" in v for v in results.values()):
        return {
            "built": False,
            "sources_dir": sources_dir,
            "downloads": results,
            "reason": "all source downloads failed",
        }
    _record_sha_manifest(sources_dir, {k: v for k, v in results.items() if "error" not in v})
    cwe_path: str | None = None
    attack_paths: list[str] = []
    yara_dir: str | None = None
    if "cwe" in results and "error" not in results["cwe"]:
        try:
            cwe_path = _materialize_cwe_xml(sources_dir)
        except Exception as e:
            results["cwe"]["unpack_error"] = str(e)
    for ak in ("attack_enterprise", "attack_ics", "attack_mobile"):
        if ak in results and "error" not in results[ak]:
            attack_paths.append(results[ak]["path"])
    if "signature_base" in results and "error" not in results["signature_base"]:
        try:
            yara_dir = _materialize_signature_base(sources_dir)
        except Exception as e:
            results["signature_base"]["unpack_error"] = str(e)
    if "findcrypt" in results and "error" not in results["findcrypt"]:
        try:
            _materialize_findcrypt(sources_dir)
        except Exception as e:
            results["findcrypt"]["unpack_error"] = str(e)
    if not (cwe_path or attack_paths or yara_dir):
        return {
            "built": False,
            "sources_dir": sources_dir,
            "downloads": results,
            "reason": "no usable sources after unpacking",
        }
    corpus = build_corpus_from_sources(
        cwe_path=cwe_path,
        attack_paths=attack_paths,
        yara_dir=yara_dir,
    )
    if corpus.is_empty():
        return {
            "built": False,
            "sources_dir": sources_dir,
            "downloads": results,
            "reason": "corpus built but is empty",
        }
    cache_path = save_corpus(corpus)
    return {
        "built": True,
        "sources_dir": sources_dir,
        "cache_path": cache_path,
        "downloads": results,
        "counts": corpus.count_by_type(),
        "source_fingerprint": corpus.source_fingerprint,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Download and build the BRON-style threat corpus cache."
    )
    parser.add_argument("--sources-dir", default="", help="where to stage raw downloads")
    parser.add_argument("--force", action="store_true", help="re-download even if files exist")
    parser.add_argument(
        "--only",
        default="",
        help="comma-separated source keys to download (default: all)",
    )
    parser.add_argument(
        "--force-verify",
        action="store_true",
        help="require IDA_MCP_BRON_CORPUS_SHA256_* env vars and reject mismatches",
    )
    args = parser.parse_args(argv)
    sources_dir = args.sources_dir or default_sources_dir()
    only_list = _parse_only(args.only)
    status = download_bron_corpus(
        sources_dir=sources_dir,
        force=args.force,
        only=only_list or None,
        force_verify=args.force_verify,
    )
    print(json.dumps(status, indent=2, default=str))
    return 0 if status.get("built") else 1


if __name__ == "__main__":
    raise SystemExit(main())
