"""Shared FindCrypt archive metadata and cache discovery.

This module is deliberately outside both the host and IDA runtime packages so
either process can import it without loading IDA SDK modules.
"""

from __future__ import annotations

import os
import shutil
import stat
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
            dirs.sort()
            if any(name.lower().endswith(_RULE_SUFFIXES) for name in files):
                return root
    return None


def extract_findcrypt_rules(zip_path: str, dst_dir: str) -> str:
    """Safely extract bounded YARA rule files from a FindCrypt ZIP archive."""
    if os.path.islink(dst_dir):
        raise RuntimeError(f"Refusing symlinked FindCrypt extraction directory: {dst_dir}")
    root = os.path.realpath(dst_dir)
    os.makedirs(root, exist_ok=True)
    extracted = 0
    total_bytes = 0

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
            if member.file_size > _MAX_RULE_BYTES:
                raise RuntimeError(f"Oversized FindCrypt rule: {member.filename}")

            total_bytes += member.file_size
            if total_bytes > _MAX_TOTAL_RULE_BYTES:
                raise RuntimeError("FindCrypt rules exceed extraction size limit")

            requested_target = os.path.join(root, *parts)
            _reject_symlink_component(root, requested_target)
            target = os.path.realpath(requested_target)
            if os.path.commonpath((root, target)) != root:
                raise RuntimeError(f"Unsafe path in FindCrypt archive: {member.filename}")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with archive.open(member) as source, open(target, "wb") as output:
                shutil.copyfileobj(source, output, length=64 * 1024)
            extracted += 1

    if not extracted:
        raise RuntimeError(f"No YARA rules found in FindCrypt archive: {zip_path}")
    return root


__all__ = [
    "FINDCRYPT_ARCHIVE_FILENAME",
    "FINDCRYPT_ARCHIVE_URL",
    "FINDCRYPT_REVISION",
    "extract_findcrypt_rules",
    "findcrypt_rules_dir",
]
