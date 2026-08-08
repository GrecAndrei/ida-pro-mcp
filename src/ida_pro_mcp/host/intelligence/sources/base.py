"""Base protocol for threat corpus source parsers."""

from __future__ import annotations

import contextlib
import hashlib
import os
import zipfile
from abc import ABC, abstractmethod
from typing import Any, Iterable


class SourceParser(ABC):
    """Protocol for a threat corpus source module.

    To add a new source:
      1. Subclass SourceParser
      2. Set class attributes: name, description, urls, cache_key
      3. Implement parse()
      4. Add to SOURCES in sources/__init__.py
    """

    name: str = ""
    description: str = ""
    urls: list[str] = []
    cache_key: str = ""
    is_multi_type: bool = False

    @abstractmethod
    def parse(self, data_dir: str) -> list[dict[str, Any]]:
        """Parse downloaded source data into normalized entry dicts."""
        ...

    def download(self, dest_dir: str, *, force: bool = False,
                 progress_cb: Any = None) -> dict[str, Any]:
        """Download source files. Returns {downloaded, errors, data_dir}."""
        from ..threat_corpus import _download_url

        result: dict[str, Any] = {"downloaded": [], "errors": [], "data_dir": ""}
        source_dir = os.path.join(dest_dir, self.cache_key)
        os.makedirs(source_dir, exist_ok=True)

        for url in self.urls:
            fname = url.rstrip("/").rsplit("/", 1)[-1] or f"{self.cache_key}_data"
            fpath = os.path.join(source_dir, fname)
            if not force and os.path.isfile(fpath):
                continue
            wrote = False
            try:
                if progress_cb:
                    progress_cb(f"Downloading {self.name}: {fname}...")
                data = _download_url(url)
                with open(fpath, "wb") as f:
                    f.write(data)
                wrote = True
                self._post_download(fpath, source_dir)
                result["downloaded"].append(fname)
            except Exception as e:
                result["errors"].append(f"{self.name} {fname}: {e}")
                # A file written during this attempt is incomplete or corrupt
                # (e.g. a truncated archive rejected by _post_download). Remove
                # it so a later non-forced run re-downloads instead of skipping
                # a poisoned cache entry forever. Files that predate this
                # attempt are left untouched.
                if wrote:
                    with contextlib.suppress(OSError):
                        os.remove(fpath)

        result["data_dir"] = source_dir
        return result

    def _post_download(self, fpath: str, dest_dir: str) -> None:  # noqa: B027
        """Hook for post-download processing (e.g. zip extraction). Override if needed."""

    @staticmethod
    def _safe_extract(zf: zipfile.ZipFile, dest_dir: str, members: Iterable[str] | None = None) -> None:
        """Extract archive members without zip-slip path traversal.

        Rejects absolute member paths and any member that resolves outside
        ``dest_dir`` after normalisation (``..`` hops).  Mirrors the standard
        zipfile guard: ``_is_safe_path`` + ``os.path.realpath`` containment.
        """
        dest_abs = os.path.realpath(dest_dir)
        selected = members if members is not None else zf.namelist()
        for member in selected:
            arcname = member.replace("\\", "/")
            if arcname.startswith(("/", "\\\\", "//")):
                raise zipfile.BadZipFile(f"absolute member path in archive: {member!r}")
            target = os.path.realpath(os.path.join(dest_dir, *arcname.split("/")))
            if os.path.commonpath([dest_abs, target]) != dest_abs:
                raise zipfile.BadZipFile(f"archive member escapes destination: {member!r}")
        # All members checked; now extract the filtered set.
        filtered = [m for m in selected if _member_is_safe(m)]
        zf.extractall(dest_dir, members=filtered)

    def fingerprint(self, data_dir: str) -> str:
        """SHA-256 over source files to detect changes."""
        h = hashlib.sha256()
        h.update(self.name.encode("utf-8"))
        if not data_dir or not os.path.isdir(data_dir):
            h.update(b"MISSING")
            return h.hexdigest()[:32]
        for root, _dirs, files in os.walk(data_dir):
            for fname in sorted(files):
                full = os.path.join(root, fname)
                try:
                    st = os.stat(full)
                    h.update(fname.encode("utf-8"))
                    h.update(str(st.st_size).encode("utf-8"))
                    h.update(str(int(st.st_mtime)).encode("utf-8"))
                except OSError:
                    h.update(fname.encode("utf-8"))
                    h.update(b"MISSING")
        return h.hexdigest()[:32]


def _member_is_safe(member: str) -> bool:
    """Basic sanity filter mirroring _safe_extract's checks."""
    arcname = member.replace("\\", "/")
    if arcname.startswith(("/", "\\\\", "//")):
        return False
    # Reject any hop that would escape the destination root.
    return ".." not in arcname.split("/")
