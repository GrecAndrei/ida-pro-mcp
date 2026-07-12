"""Source parser for Florian Roth signature-base YARA rules."""

from __future__ import annotations

import os
from typing import Any

from .base import SourceParser

_YARA_SUBPATH = "signature-base-master/yara"


class YaraSource(SourceParser):
    name = "yara_rules"
    description = "Florian Roth signature-base YARA rules"
    cache_key = "yara"

    def __init__(self) -> None:
        self.urls = [os.environ.get(
            "IDA_MCP_YARA_URL",
            "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
        )]

    def parse(self, data_dir: str) -> list[dict[str, Any]]:
        from ..threat_corpus import parse_yara_dir

        yara_dir = os.path.join(data_dir, _YARA_SUBPATH)
        if not os.path.isdir(yara_dir):
            for root, _dirs, files in os.walk(data_dir):
                if any(f.endswith((".yar", ".yara")) for f in files):
                    yara_dir = root
                    break
        return parse_yara_dir(yara_dir)

    def _post_download(self, fpath: str, dest_dir: str) -> None:
        if fpath.endswith(".zip"):
            import zipfile

            with zipfile.ZipFile(fpath) as zf:
                zf.extractall(dest_dir)
