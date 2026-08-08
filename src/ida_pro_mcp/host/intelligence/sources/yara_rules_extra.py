"""Source parser for additional YARA rules from Yara-Rules/rules repository."""

from __future__ import annotations

import os
from typing import Any

from .base import SourceParser


class YaraRulesExtraSource(SourceParser):
    name = "yara_rules_extra"
    description = "Additional YARA rules from Yara-Rules/rules repository"
    cache_key = "yara_rules_extra"

    def __init__(self) -> None:
        self.urls = [
            "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip",
        ]

    def parse(self, data_dir: str) -> list[dict[str, Any]]:
        from ..threat_corpus import parse_yara_dir

        for candidate in ("rules-master",):
            yara_root = os.path.join(data_dir, candidate)
            if os.path.isdir(yara_root):
                rules = parse_yara_dir(yara_root)
                for r in rules:
                    r["source"] = "yara_rules_extra"
                return rules
        rules = parse_yara_dir(data_dir)
        for r in rules:
            r["source"] = "yara_rules_extra"
        return rules

    def _post_download(self, fpath: str, dest_dir: str) -> None:
        if fpath.endswith(".zip"):
            import zipfile

            with zipfile.ZipFile(fpath) as zf:
                self._safe_extract(zf, dest_dir)
