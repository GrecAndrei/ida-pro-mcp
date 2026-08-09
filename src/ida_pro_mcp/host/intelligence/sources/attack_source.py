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
        """Parse all STIX bundles into a flat entry list.

        Entries are tagged with a transient ``_attack_type`` marker recording
        which corpus bucket (attack_patterns/malware/...) each belongs to. The
        marker is consumed only by ``threat_corpus._build_from_sources``,
        which strips it before persisting — direct callers must strip it too
        before saving parse output into a corpus.
        """
        from ..threat_corpus import parse_attack_stix

        merged: dict[str, list] = {k: [] for k in _STIX_KEYS}
        # Technique ids repeat across the enterprise/ics/mobile bundles; keep
        # the first copy so _rebuild_indexes does not resolve duplicates
        # arbitrarily.
        seen_ids: dict[str, set[str]] = {k: set() for k in _STIX_KEYS}
        jsons = glob.glob(os.path.join(data_dir, "*.json"))
        for jf in jsons:
            parsed = parse_attack_stix(jf)
            for key in _STIX_KEYS:
                for entry in parsed.get(key) or []:
                    eid = entry.get("id")
                    if eid:
                        if eid in seen_ids[key]:
                            continue
                        seen_ids[key].add(eid)
                    merged[key].append(entry)

        out: list[dict[str, Any]] = []
        for key, entries in merged.items():
            bucket = _KEY_TO_ENTRY_FIELD[key]
            for e in entries:
                # Tag a shallow copy rather than mutating the merged entries.
                out.append({**e, "_attack_type": bucket})
        return out
