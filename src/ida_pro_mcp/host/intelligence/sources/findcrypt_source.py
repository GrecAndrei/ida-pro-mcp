"""Source parser for FindCrypt crypto constant YARA rules.

Downloads the polymorf/findcrypt-yara repo. YARA rules are compiled
and matched directly by the YARA scanner — no hex-to-bytes parsing needed.
"""

from __future__ import annotations

import os
import re
from typing import Any

from ....findcrypt import FINDCRYPT_ARCHIVE_URL, extract_findcrypt_rules
from .base import SourceParser

_FINDCRYPT_REPO_ZIP = os.environ.get(
    "IDA_MCP_FINDCRYPT_URL",
    FINDCRYPT_ARCHIVE_URL,
)

# Mirrors threat_corpus._YARA_RULE_RE: optional private/global prefix, rule
# name, then the opening brace.
_RULE_NAME_RE = re.compile(
    r"^\s*(?:(?:private|global)\s+)?rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{",
    re.MULTILINE,
)
# description key=value line inside a rule's meta section. The value pattern is
# escaped-quote-aware: a description containing \" parses in full instead of
# truncating at the first inner quote.
_DESC_RE = re.compile(r'^\s*description\s*=\s*"((?:[^"\\]|\\.)*)"\s*$', re.MULTILINE)
_META_SECTION_RE = re.compile(
    r"\bmeta\s*:\s*(.*?)\b(?:strings|condition)\s*:",
    re.DOTALL | re.IGNORECASE,
)
_STRINGS_SECTION_RE = re.compile(
    r"\bstrings\s*:\s*(.*?)\bcondition\s*:",
    re.DOTALL | re.IGNORECASE,
)
_STRING_LINE_RE = re.compile(r"\$\s*([A-Za-z0-9_]+)\s*(?:=\s*)?(.*?)$", re.MULTILINE)
_STRING_QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _extract_quoted_strings(block: str) -> list[str]:
    """Return the quoted strings in a rule's strings: section, in order."""
    strings: list[str] = []
    section = _STRINGS_SECTION_RE.search(block)
    if not section:
        return strings
    for line_match in _STRING_LINE_RE.finditer(section.group(1)):
        for sm in _STRING_QUOTED_RE.finditer(line_match.group(2)):
            s = sm.group(1)
            if s and s not in strings:
                strings.append(s)
    return strings


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
        the threat corpus index. Each entry is keyed by rule name (id) and
        carries the rule's quoted strings so it is reachable through the
        corpus's indexed lookups (get_by_id / all_yara_strings /
        search_yara_strings).
        """
        yara_files: list[str] = []
        for root, _dirs, files in os.walk(data_dir):
            for fname in files:
                if fname.endswith((".yar", ".yara", ".rules")):
                    yara_files.append(os.path.join(root, fname))

        entries: list[dict[str, Any]] = []
        seen_rules: set[str] = set()
        for yara_path in yara_files:
            try:
                with open(yara_path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
                for name_match in _RULE_NAME_RE.finditer(content):
                    rule_name = name_match.group(1)
                    # The same rule can appear in several files; keep the first.
                    if rule_name in seen_rules:
                        continue
                    seen_rules.add(rule_name)
                    # Bound every lookup to this rule's block so a comment in a
                    # neighbouring rule cannot be captured.
                    start = name_match.start()
                    next_rule = _RULE_NAME_RE.search(content, start + 1)
                    block = content[start:next_rule.start()] if next_rule else content[start:]
                    description = rule_name
                    meta_match = _META_SECTION_RE.search(block)
                    if meta_match:
                        desc_match = _DESC_RE.search(meta_match.group(1))
                        if desc_match:
                            description = desc_match.group(1)
                    entries.append({
                        "id": rule_name,
                        "name": rule_name,
                        "display_name": description,
                        "source": "findcrypt-yara",
                        "file": os.path.basename(yara_path),
                        "strings": _extract_quoted_strings(block),
                    })
            except OSError:
                continue

        return entries

    def _post_download(self, fpath: str, dest_dir: str) -> None:
        if fpath.endswith(".zip"):
            extract_findcrypt_rules(fpath, dest_dir)
