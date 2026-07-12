"""Source parser for URLhaus malicious URL feed."""

from __future__ import annotations

import json
import os
from typing import Any

from .base import SourceParser


class UrlhausSource(SourceParser):
    name = "urlhaus"
    description = "URLhaus malicious URL feed (abuse.ch)"
    cache_key = "urlhaus"

    def __init__(self) -> None:
        self.urls = [
            "https://urlhaus.abuse.ch/downloads/json/",
        ]

    def parse(self, data_dir: str) -> list[dict[str, Any]]:
        json_path = self._find_json(data_dir)
        if not json_path:
            return []
        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []

        items: list[Any] = []
        if isinstance(data, dict):
            # Format: {"id": [{entry}, ...], ...} or {"urls": [...], ...}
            if "urls" in data:
                items = data["urls"]
            elif "data" in data:
                items = data["data"]
            else:
                # Each key is an ID, each value is a list of entries
                for val in data.values():
                    if isinstance(val, list):
                        items.extend(val)
                    elif isinstance(val, dict):
                        items.append(val)
        elif isinstance(data, list):
            items = data

        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in items[:10000]:
            if not isinstance(item, dict):
                continue
            url = (item.get("url") or item.get("urlhaus_url") or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
            threat = item.get("threat") or item.get("tags") or ""
            if isinstance(threat, list):
                threat = ", ".join(str(t) for t in threat[:5])
            entries.append({
                "id": f"URLHAUS-{len(entries)}",
                "url": url,
                "threat": str(threat)[:200],
                "date_added": str(item.get("dateadded") or item.get("date") or "")[:32],
                "source": "urlhaus",
            })
        return entries

    def _post_download(self, fpath: str, dest_dir: str) -> None:
        """URLhaus JSON is inside a zip."""
        if fpath.endswith(".zip") or self._is_zip(fpath):
            import zipfile

            with zipfile.ZipFile(fpath) as zf:
                zf.extractall(dest_dir)
        # Rename if needed — the downloaded file may not have .zip extension
        elif not fpath.endswith(".json"):
            # Try reading as zip anyway
            try:
                import zipfile

                with zipfile.ZipFile(fpath) as zf:
                    zf.extractall(dest_dir)
            except Exception:
                pass

    @staticmethod
    def _is_zip(path: str) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read(2) == b"PK"
        except OSError:
            return False

    @staticmethod
    def _find_json(data_dir: str) -> str | None:
        if not os.path.isdir(data_dir):
            return None
        for f in os.listdir(data_dir):
            if f.endswith(".json"):
                return os.path.join(data_dir, f)
        return None
