"""Threat corpus source parsers.

Each source is a SourceParser subclass. To add a new source:
  1. Create a file here with your SourceParser subclass
  2. Import it below and add an instance to SOURCES
"""

from __future__ import annotations

from .attack_source import AttackSource
from .base import SourceParser
from .cwe_source import CweSource
from .lolbas import LolbasSource
from .sigma_rules import SigmaRulesSource
from .urlhaus import UrlhausSource
from .yara_rules_extra import YaraRulesExtraSource
from .yara_source import YaraSource

__all__ = ["SOURCES", "SourceParser", "get_source", "source_names"]

# === ADD NEW SOURCES HERE (one line) ===
SOURCES: list[SourceParser] = [
    CweSource(),
    AttackSource(),
    YaraSource(),
    YaraRulesExtraSource(),
    LolbasSource(),
    SigmaRulesSource(),
    UrlhausSource(),
]


def get_source(name: str) -> SourceParser | None:
    for s in SOURCES:
        if s.name == name:
            return s
    return None


def source_names() -> list[str]:
    return [s.name for s in SOURCES]
