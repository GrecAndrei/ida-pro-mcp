"""Source parser for FindCrypt crypto constant YARA rules.

Downloads the polymorf/findcrypt-yara repo. YARA rules are compiled
and matched directly by the YARA scanner — no hex-to-bytes parsing needed.
"""

from __future__ import annotations

import os
import re
from typing import Any

from .base import SourceParser

_FINDCRYPT_REPO_ZIP = os.environ.get(
    "IDA_MCP_FINDCRYPT_URL",
    "https://github.com/polymorf/findcrypt-yara/archive/refs/heads/master.zip",
)

_RULE_NAME_RE = re.compile(r"^\s*rule\s+(\w+)", re.MULTILINE)
_DESC_RE = re.compile(r'description\s*=\s*"([^"]+)"')


class FindCryptSource(SourceParser):
    name = "findcrypt"
    description = "FindCrypt YARA crypto constant signatures"
    cache_key = "findcrypt"

    def __init__(self) -> None:
        self.urls = [_FINDCRYPT_REPO_ZIP]

    def parse(self, data_dir: str) -> list[dict[str, Any]]:
        """Parse downloaded FindCrypt YARA rules into lightweight metadata entries.

        The actual crypto detection is done by the YARA scanner compiling
        the .yar/.rules files directly — this just provides metadata for
        the threat corpus index.
        """
        yara_files: list[str] = []
        for root, _dirs, files in os.walk(data_dir):
            for fname in files:
                if fname.endswith((".yar", ".yara", ".rules")):
                    yara_files.append(os.path.join(root, fname))

        entries: list[dict[str, Any]] = []
        for yara_path in yara_files:
            try:
                with open(yara_path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
                for name_match in _RULE_NAME_RE.finditer(content):
                    rule_name = name_match.group(1)
                    # Try to find description in the same rule block
                    start = name_match.start()
                    next_rule = _RULE_NAME_RE.search(content, start + 1)
                    block = content[start:next_rule.start()] if next_rule else content[start:]
                    desc_match = _DESC_RE.search(block)
                    description = desc_match.group(1) if desc_match else rule_name
                    entries.append({
                        "name": rule_name,
                        "display_name": description,
                        "source": "findcrypt-yara",
                        "file": os.path.basename(yara_path),
                    })
            except OSError:
                continue

        return entries

    def _post_download(self, fpath: str, dest_dir: str) -> None:
        if fpath.endswith(".zip"):
            import zipfile

            with zipfile.ZipFile(fpath) as zf:
                zf.extractall(dest_dir)
