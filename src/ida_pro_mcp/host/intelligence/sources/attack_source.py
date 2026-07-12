"""Source parser for MITRE ATT&CK STIX bundles."""

from __future__ import annotations

import glob
import os
from typing import Any

from .base import SourceParser

_STIX_KEYS = ("attack_pattern", "malware", "intrusion_set", "tool", "course_of_action")
_KEY_TO_ENTRY_FIELD = {
    "attack_pattern": "attack_patterns",
    "malware": "malware",
    "intrusion_set": "intrusion_sets",
    "tool": "tools",
    "course_of_action": "mitigations",
}


class AttackSource(SourceParser):
    name = "attack"
    description = "MITRE ATT&CK STIX bundles (enterprise/ics/mobile)"
    cache_key = "attack"
    is_multi_type = True

    def __init__(self) -> None:
        self.urls = [
            os.environ.get(
                "IDA_MCP_ATTACK_ENTERPRISE_URL",
                "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
            ),
            os.environ.get(
                "IDA_MCP_ATTACK_ICS_URL",
                "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
            ),
            os.environ.get(
                "IDA_MCP_ATTACK_MOBILE_URL",
                "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
            ),
        ]

    def parse(self, data_dir: str) -> list[dict[str, Any]]:
        """Parse all STIX bundles. Each entry gets an `_attack_type` field for splitting."""
        from ..threat_corpus import parse_attack_stix

        merged: dict[str, list] = {k: [] for k in _STIX_KEYS}
        jsons = glob.glob(os.path.join(data_dir, "*.json"))
        for jf in jsons:
            parsed = parse_attack_stix(jf)
            for key in _STIX_KEYS:
                merged[key].extend(parsed.get(key) or [])

        out: list[dict[str, Any]] = []
        for key, entries in merged.items():
            for e in entries:
                e["_attack_type"] = _KEY_TO_ENTRY_FIELD[key]
                out.append(e)
        return out
