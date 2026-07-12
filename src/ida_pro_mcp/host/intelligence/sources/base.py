"""Base protocol for threat corpus source parsers."""

from __future__ import annotations

import hashlib
import os
from abc import ABC, abstractmethod
from typing import Any


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
            try:
                if progress_cb:
                    progress_cb(f"Downloading {self.name}: {fname}...")
                data = _download_url(url)
                with open(fpath, "wb") as f:
                    f.write(data)
                self._post_download(fpath, source_dir)
                result["downloaded"].append(fname)
            except Exception as e:
                result["errors"].append(f"{self.name} {fname}: {e}")

        result["data_dir"] = source_dir
        return result

    def _post_download(self, fpath: str, dest_dir: str) -> None:  # noqa: B027
        """Hook for post-download processing (e.g. zip extraction). Override if needed."""

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
