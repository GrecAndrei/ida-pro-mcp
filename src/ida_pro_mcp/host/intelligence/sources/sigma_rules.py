"""Source parser for SigmaHQ detection rules (titles, descriptions, tags)."""

from __future__ import annotations

import os
import re
from typing import Any

from .base import SourceParser


class SigmaRulesSource(SourceParser):
    name = "sigma_rules"
    description = "SigmaHQ detection rules (titles, descriptions, tags)"
    cache_key = "sigma_rules"

    def __init__(self) -> None:
        self.urls = [
            "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip",
        ]

    def parse(self, data_dir: str) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()

        sigma_root = data_dir
        for candidate in ("sigma-master", "sigma-main"):
            maybe = os.path.join(data_dir, candidate)
            if os.path.isdir(maybe):
                sigma_root = maybe
                break

        for root, _dirs, files in os.walk(sigma_root):
            for fname in sorted(files):
                if not fname.endswith((".yml", ".yaml")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > 500_000:
                        continue
                    with open(fpath, encoding="utf-8", errors="replace") as f:
                        # Read the whole file: rule metadata (title, id) can sit
                        # below a long comment/license preamble, so a fixed short
                        # prefix would silently stamp a non-stable SIGMA-N id.
                        content = f.read()
                except OSError:
                    continue

                title = self._extract_yaml_field(content, "title")
                if not title or title in seen:
                    continue
                seen.add(title)

                description = self._extract_yaml_field(content, "description")
                status = self._extract_yaml_field(content, "status")
                level = self._extract_yaml_field(content, "level")

                tags: list[str] = []
                for m in re.finditer(r"^\s*-\s+(sigma\.\S+)", content, re.MULTILINE):
                    tag = m.group(1).strip()
                    if tag not in tags:
                        tags.append(tag)

                rule_id = self._extract_yaml_field(content, "id")

                entries.append({
                    "id": rule_id or f"SIGMA-{len(entries)}",
                    "name": title,
                    "description": description or "",
                    "status": status or "",
                    "level": level or "",
                    "tags": tags[:16],
                    "file": os.path.relpath(fpath, sigma_root),
                    "source": "sigma_rules",
                })
        return entries

    @staticmethod
    def _extract_yaml_field(content: str, field: str) -> str:
        m = re.search(rf'^{field}\s*:\s*"?(.+?)"?\s*$', content, re.MULTILINE)
        return m.group(1).strip().strip('"') if m else ""

    def _post_download(self, fpath: str, dest_dir: str) -> None:
        if fpath.endswith(".zip"):
            import zipfile

            with zipfile.ZipFile(fpath) as zf:
                self._safe_extract(zf, dest_dir)
