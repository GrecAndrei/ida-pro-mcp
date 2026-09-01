"""Shared FindCrypt archive metadata and cache discovery.

This module is deliberately outside both the host and IDA runtime packages so
either process can import it without loading IDA SDK modules.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import tempfile
import uuid
import zipfile

FINDCRYPT_REVISION = "044644b9c52ae3e7b2305bac15b0c12c9e31a282"
FINDCRYPT_ARCHIVE_URL = (
    "https://github.com/polymorf/findcrypt-yara/archive/"
    f"{FINDCRYPT_REVISION}.zip"
)
FINDCRYPT_ARCHIVE_FILENAME = f"findcrypt-yara-{FINDCRYPT_REVISION}.zip"

_RULE_SUFFIXES = (".yar", ".yara", ".rules")
_MAX_RULE_BYTES = 2_000_000
_MAX_TOTAL_RULE_BYTES = 64 * 1024 * 1024


def _reject_symlink_component(root: str, path: str) -> None:
    """Reject existing links between an extraction root and a target."""
    relative = os.path.relpath(path, root)
    current = root
    for part in relative.split(os.sep):
        if part in {"", "."}:
            continue
        current = os.path.join(current, part)
        if os.path.islink(current):
            raise RuntimeError(f"Symlink in FindCrypt extraction path: {current}")


def _reject_symlink_path(path: str) -> None:
    """Reject an existing symlink anywhere in a destination path."""
    current = os.path.abspath(path)
    while current and current != os.path.dirname(current):
        if os.path.islink(current):
            raise RuntimeError(f"Refusing symlinked FindCrypt extraction path: {current}")
        current = os.path.dirname(current)


def _replace_extraction_directory(staging: str, destination: str) -> None:
    """Install a fully validated extraction while retaining rollback safety."""
    parent = os.path.dirname(destination)
    backup: str | None = None
    if os.path.lexists(destination):
        backup = os.path.join(
            parent,
            f".{os.path.basename(destination)}.backup-{uuid.uuid4().hex}",
        )
        os.replace(destination, backup)
    try:
        os.replace(staging, destination)
    except BaseException:
        if backup is not None and not os.path.lexists(destination):
            os.replace(backup, destination)
        raise
    if backup is not None:
        with contextlib.suppress(OSError):
            shutil.rmtree(backup)


def findcrypt_rules_dir(cache_dir: str | None = None) -> str | None:
    """Return the first downloaded FindCrypt rule directory, if available."""
    if cache_dir is None:
        from .host.config import CACHE_DIR

        cache_dir = CACHE_DIR

    candidates = (
        os.path.join(cache_dir, "corpus_sources", "findcrypt"),
        os.path.join(cache_dir, "threat_corpus_sources", "findcrypt"),
    )
    for source_dir in candidates:
        if not os.path.isdir(source_dir):
            continue
        for root, dirs, files in os.walk(source_dir):
            dirs[:] = sorted(
                name for name in dirs
                if not os.path.islink(os.path.join(root, name))
            )
            if any(
                name.lower().endswith(_RULE_SUFFIXES)
                and not os.path.islink(os.path.join(root, name))
                for name in files
            ):
                return root
    return None


def extract_findcrypt_rules(zip_path: str, dst_dir: str) -> str:
    """Safely extract bounded YARA rule files from a FindCrypt ZIP archive."""
    if os.path.islink(zip_path):
        raise RuntimeError(f"Refusing symlinked FindCrypt archive: {zip_path}")
    if not os.path.isfile(zip_path):
        raise RuntimeError(f"FindCrypt archive is not a regular file: {zip_path}")
    _reject_symlink_path(dst_dir)
    root = os.path.abspath(dst_dir)
    os.makedirs(root, exist_ok=True)
    staging = tempfile.mkdtemp(
        prefix=f".{os.path.basename(root)}.staging-",
        dir=os.path.dirname(root),
    )
    extracted = 0
    total_bytes = 0

    try:
        with zipfile.ZipFile(zip_path) as archive:
            for member in archive.infolist():
                normalized = member.filename.replace("\\", "/")
                parts = [part for part in normalized.split("/") if part not in {"", "."}]
                if normalized.startswith("/") or ".." in parts:
                    raise RuntimeError(f"Unsafe path in FindCrypt archive: {member.filename}")

                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise RuntimeError(f"Symlink in FindCrypt archive: {member.filename}")
                if member.is_dir() or not normalized.lower().endswith(_RULE_SUFFIXES):
                    continue
                if member.file_size < 0 or member.file_size > _MAX_RULE_BYTES:
                    raise RuntimeError(f"Oversized FindCrypt rule: {member.filename}")

                total_bytes += member.file_size
                if total_bytes > _MAX_TOTAL_RULE_BYTES:
                    raise RuntimeError("FindCrypt rules exceed extraction size limit")

                requested_target = os.path.join(root, *parts)
                _reject_symlink_component(root, requested_target)
                target = os.path.realpath(requested_target)
                if os.path.commonpath((root, target)) != root:
                    raise RuntimeError(f"Unsafe path in FindCrypt archive: {member.filename}")
                staged_target = os.path.join(staging, *parts)
                os.makedirs(os.path.dirname(staged_target), exist_ok=True)
                with archive.open(member) as source, open(staged_target, "wb") as output:
                    shutil.copyfileobj(source, output, length=64 * 1024)
                extracted += 1

        if not extracted:
            raise RuntimeError(f"No YARA rules found in FindCrypt archive: {zip_path}")
        _replace_extraction_directory(staging, root)
        return os.path.realpath(root)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


__all__ = [
    "FINDCRYPT_ARCHIVE_FILENAME",
    "FINDCRYPT_ARCHIVE_URL",
    "FINDCRYPT_REVISION",
    "extract_findcrypt_rules",
    "findcrypt_rules_dir",
]
