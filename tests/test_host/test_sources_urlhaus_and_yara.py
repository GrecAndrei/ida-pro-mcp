from __future__ import annotations

import json
from pathlib import Path

import pytest

from ida_pro_mcp.host.intelligence.sources.urlhaus import UrlhausSource
from ida_pro_mcp.host.intelligence.sources.yara_rules_extra import YaraRulesExtraSource


def test_urlhaus_source_parse(tmp_path: Path) -> None:
    source = UrlhausSource()
    assert source.name == "urlhaus"

    # Empty directory returns []
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    assert source.parse(str(empty_dir)) == []

    # Valid JSON payload
    data_dir = tmp_path / "urlhaus_data"
    data_dir.mkdir()
    payload = {
        "urls": [
            {
                "url": "http://malicious-domain.com/payload.exe",
                "threat": "malware_download",
                "dateadded": "2026-09-01 12:00:00",
            },
            {
                "url": "http://c2-server.net/beacon",
                "tags": ["c2", "trojan"],
                "date": "2026-09-01 12:05:00",
            },
        ]
    }
    json_file = data_dir / "urlhaus.json"
    json_file.write_text(json.dumps(payload), encoding="utf-8")

    entries = source.parse(str(data_dir))
    assert len(entries) == 2
    assert entries[0]["url"] == "http://malicious-domain.com/payload.exe"
    assert entries[0]["threat"] == "malware_download"
    assert entries[1]["threat"] == "c2, trojan"


def test_yara_rules_extra_source_parse(tmp_path: Path) -> None:
    source = YaraRulesExtraSource()
    assert source.name == "yara_rules_extra"

    data_dir = tmp_path / "yara_extra"
    data_dir.mkdir()
    rules_dir = data_dir / "rules-master"
    rules_dir.mkdir()

    rule_file = rules_dir / "extra.yar"
    rule_file.write_text(
        """
        rule ExtraRule {
            meta:
                author = "Community"
            strings:
                $a = "test_string"
            condition:
                $a
        }
        """,
        encoding="utf-8",
    )

    rules = source.parse(str(data_dir))
    assert len(rules) == 1
    assert rules[0]["name"] == "ExtraRule"
    assert rules[0]["source"] == "yara_rules_extra"
