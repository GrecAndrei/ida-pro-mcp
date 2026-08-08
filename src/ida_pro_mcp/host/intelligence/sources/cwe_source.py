"""Source parser for MITRE CWE catalog XML."""

from __future__ import annotations

import glob
import os
from typing import Any

from .base import SourceParser


class CweSource(SourceParser):
    name = "cwe"
    description = "MITRE CWE Weakness Catalog"
    cache_key = "cwe"

    def __init__(self) -> None:
        self.urls = [os.environ.get(
            "IDA_MCP_CWE_URL",
            "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        )]

    def parse(self, data_dir: str) -> list[dict[str, Any]]:
        from ..threat_corpus import parse_cwe_xml

        xmls = glob.glob(os.path.join(data_dir, "**", "*.xml"), recursive=True)
        if not xmls:
            return []
        return parse_cwe_xml(xmls[0])

    def _post_download(self, fpath: str, dest_dir: str) -> None:
        if fpath.endswith(".zip"):
            import zipfile

            with zipfile.ZipFile(fpath) as zf:
                self._safe_extract(zf, dest_dir, members=[m for m in zf.namelist() if ".xml" in m])
